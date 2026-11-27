//! Batches of reads and writes in one `io_uring_enter` each.
//!
//! Every request carries `RWF_NOWAIT`, so the kernel completes it inside the call: a read finds
//! a packet or fails with `EAGAIN`, a write is taken or fails with `EAGAIN`. Nothing is left in
//! flight, nothing runs on the kernel's worker threads, and readiness still comes from the
//! descriptor through the reactor. Writes are linked so that they happen in order, and a failed
//! one cancels the rest, which are then submitted again.

use std::io::{Error, ErrorKind, Result};
use std::os::fd::RawFd;

use xtun_wire::Writes as List;
use io_uring::{IoUring, opcode, squeue, types};

use super::kernel_version;
use crate::device::{Options, Uring};
use crate::io::{Filled, ReaderStats, WriterStats};
use crate::sys::unix::transport::{BATCH_BYTES, Each, Found, Gathered, IoVecs, Read, Slots, Write, Wrote, nothing, read_each, wrote};

/// The position argument that means "no position" for a stream such as a TUN device.
const NO_OFFSET: u64 = u64::MAX;
/// Writes submitted in one call at most.
const WRITE_ENTRIES: usize = 256;
/// Batches expected to hold fewer frames than this are read with plain system calls: for one or
/// two frames they cost less than a round through the ring.
const RING_FRAMES: usize = 3;

pub(super) fn choose(options: &Options) -> Result<bool> {
    match options.uring {
        Uring::Off => Ok(false),
        Uring::Auto => Ok(available().is_ok()),
        Uring::Required => available().map(|()| true),
    }
}

/// Whether io_uring can be used, for a descriptor adopted without options.
pub(super) fn usable() -> bool {
    available().is_ok()
}

fn available() -> Result<()> {
    if kernel_version() < (6, 4) {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "io_uring completes TUN reads and writes without waiting only from Linux 6.4 on",
        ));
    }
    IoUring::new(2).map(drop).map_err(|error| Error::new(error.kind(), format!("io_uring is not available: {error}")))
}

fn enter(ring: &IoUring, want: usize) -> Result<()> {
    loop {
        match ring.submit_and_wait(want) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

/// How a queue is read: through a ring where the device uses one, a frame per call otherwise.
pub struct Reads {
    ring: Option<ReadRing>,
}

impl Reads {
    pub(super) fn new(uring: bool, frames: usize) -> Result<Reads> {
        Ok(Reads { ring: if uring { Some(ReadRing::new(frames)?) } else { None } })
    }
}

impl Read for Reads {
    fn read(&mut self, fd: RawFd, slots: &mut Slots, frames: usize, stats: &mut ReaderStats, frame: impl FnMut(Found<'_>)) -> Filled {
        match &mut self.ring {
            Some(ring) => ring.read(fd, slots, stats, frame),
            None => Each.read(fd, slots, frames, stats, frame),
        }
    }
}

struct ReadRing {
    ring: IoUring,
    frames: usize,
    /// How many frames the next batch is expected to hold: more after a batch that stopped at
    /// its limit, as many as the last one after a batch that emptied the queue.
    want: usize,
    results: Vec<i32>,
}

impl ReadRing {
    fn new(frames: usize) -> Result<ReadRing> {
        Ok(ReadRing { ring: IoUring::new(frames.next_power_of_two() as u32)?, frames, want: 1, results: vec![0; frames] })
    }

    fn read(&mut self, fd: RawFd, slots: &mut Slots, stats: &mut ReaderStats, mut frame: impl FnMut(Found<'_>)) -> Filled {
        if self.want < RING_FRAMES || self.frames < RING_FRAMES {
            let (filled, read) = read_each(fd, slots, 0, self.frames, stats, frame);
            self.want = if filled.dry { read } else { read * 2 };
            return filled;
        }
        // One frame with a plain system call, which also finds an empty queue the cheapest way,
        // and the rest of the batch through the ring.
        let mut first = 0;
        let (filled, read) = read_each(fd, slots, 0, 1, stats, |found| {
            first = found.bytes.len();
            frame(found);
        });
        if read == 0 {
            return filled;
        }
        let want = (self.want - 1).min(self.frames - 1);
        {
            let mut queue = self.ring.submission();
            for index in 0..want {
                let room = slots.room(index + 1);
                let entry = opcode::Read::new(types::Fd(fd), room.as_mut_ptr(), room.len() as u32)
                    .offset(NO_OFFSET)
                    .rw_flags(libc::RWF_NOWAIT)
                    .build()
                    .user_data(index as u64);
                // SAFETY: the slots outlive the call below, which completes every request.
                unsafe { queue.push(&entry).expect("the ring holds a whole batch") };
            }
        }
        stats.calls += 1;
        if let Err(error) = enter(&self.ring, want) {
            return Filled::failed(error);
        }
        for completion in self.ring.completion() {
            self.results[completion.user_data() as usize] = completion.result();
        }
        let mut filled = Filled::more();
        let (mut read, mut bytes) = (1, first);
        for (index, result) in self.results[..want].iter().enumerate() {
            match *result {
                length if length > 0 => {
                    let length = length as usize;
                    frame(slots.filled(index + 1, length));
                    read += 1;
                    bytes += length;
                }
                code if code == -libc::EAGAIN => filled.dry = true,
                code if filled.error.is_none() => {
                    filled.error = Some(if code == 0 { nothing() } else { Error::from_raw_os_error(-code) });
                }
                _ => {}
            }
        }
        let grown = if filled.dry { read } else { (want + 1) * 2 };
        // Frames as large as the last ones, up to the batch's bytes.
        let fitting = (BATCH_BYTES * read / bytes).max(1);
        self.want = grown.min(fitting).min(self.frames);
        filled
    }
}

/// How a queue is written: through a ring where the device uses one and there is more than one
/// write, a frame per call otherwise. One write costs less as a plain system call than as a
/// round through the ring.
pub struct Writes {
    each: Gathered,
    ring: Option<WriteRing>,
}

impl Writes {
    pub(super) fn new(uring: bool) -> Result<Writes> {
        Ok(Writes { each: Gathered::default(), ring: if uring { Some(WriteRing::new()?) } else { None } })
    }
}

impl Write for Writes {
    fn write(&mut self, fd: RawFd, list: &impl List, stats: &mut WriterStats) -> Result<usize> {
        match &mut self.ring {
            Some(ring) if list.count() > 1 => ring.write(fd, list, stats),
            _ => self.each.write(fd, list, stats),
        }
    }

    fn try_clone(&self) -> Result<Writes> {
        Writes::new(self.ring.is_some())
    }
}

struct WriteRing {
    ring: IoUring,
    iov: IoVecs,
    spans: Vec<(usize, usize)>,
    results: Vec<i32>,
}

impl WriteRing {
    fn new() -> Result<WriteRing> {
        Ok(WriteRing { ring: IoUring::new(WRITE_ENTRIES as u32)?, iov: IoVecs::default(), spans: Vec::new(), results: vec![0; WRITE_ENTRIES] })
    }

    /// Writes the list until the device is full. Returns how many writes it took.
    fn write(&mut self, fd: RawFd, list: &impl List, stats: &mut WriterStats) -> Result<usize> {
        let total = list.count();
        self.iov.clear();
        self.spans.clear();
        for index in 0..total {
            let start = self.iov.len();
            let count = self.iov.gather(list, index);
            self.spans.push((start, count));
        }
        let taken = self.submit(fd, total, stats);
        self.iov.clear();
        taken
    }

    fn submit(&mut self, fd: RawFd, total: usize, stats: &mut WriterStats) -> Result<usize> {
        let mut next = 0;
        while next < total {
            let chunk = (total - next).min(WRITE_ENTRIES);
            {
                let base = self.iov.as_ptr();
                let mut queue = self.ring.submission();
                for (position, &(start, count)) in self.spans[next..next + chunk].iter().enumerate() {
                    // SAFETY: `start` is inside the list, which is not changed until the batch
                    // is written.
                    let iov = unsafe { base.add(start) };
                    let mut entry = opcode::Writev::new(types::Fd(fd), iov, count as u32)
                        .offset(NO_OFFSET)
                        .rw_flags(libc::RWF_NOWAIT)
                        .build()
                        .user_data(position as u64);
                    if position + 1 < chunk {
                        entry = entry.flags(squeue::Flags::IO_LINK);
                    }
                    // SAFETY: the pieces outlive the call below, which completes every request.
                    unsafe { queue.push(&entry).expect("the ring holds a whole chunk") };
                }
            }
            stats.calls += 1;
            enter(&self.ring, chunk)?;
            for completion in self.ring.completion() {
                self.results[completion.user_data() as usize] = completion.result();
            }
            for result in &self.results[..chunk] {
                let failed = *result < 0;
                let result = if failed { Err(Error::from_raw_os_error(-*result)) } else { Ok(()) };
                if let Wrote::Full = wrote(result, stats)? {
                    return Ok(next);
                }
                next += 1;
                if failed {
                    // Everything after the refused write was cancelled and goes again.
                    break;
                }
            }
        }
        Ok(next)
    }
}
