//! How the queues of every Unix system move frames: a descriptor that is read into slots, a
//! block of memory each, and written with gathered pieces. A system brings only the calls that
//! move more than one frame at a time, where it has any; the rest is the same everywhere.

use std::io::{self, ErrorKind};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use xtun_wire::{Takes, Writes};

use super::{Port, Queue, Signal};
use crate::block::{Block, Pool};
use crate::io::{Filled, Loan, ReaderStats, Wait, WriterStats};

/// The room for one frame: the largest IPv6 packet of 65,535 bytes of payload and its header,
/// behind the longest prefix, rounded to a cache line.
pub const SLOT: usize = 65_536 + 128;

/// The slots of a reader: a block for each frame of a batch. A frame that was taken out of its
/// batch keeps its block, and the slot gets another before it is read into again.
pub struct Slots {
    blocks: Vec<Arc<Block>>,
    /// The slots whose frames were lent since their blocks were last known to be held alone.
    lent: Vec<bool>,
    pool: Arc<Pool>,
}

impl Slots {
    /// `count` slots.
    pub fn new(count: usize) -> Slots {
        let (pool, blocks) = Pool::new(SLOT, count);
        Slots { blocks, lent: vec![false; count], pool }
    }

    /// The room of slot `index`, for the device to fill.
    pub fn room(&mut self, index: usize) -> &mut [u8] {
        if self.lent[index] {
            if Arc::get_mut(&mut self.blocks[index]).is_none() {
                self.blocks[index] = self.pool.block();
            }
            self.lent[index] = false;
        }
        let block = &self.blocks[index];
        // SAFETY: no frame was lent from the block since it was found to be held alone, so
        // nothing else refers to its memory.
        unsafe { std::slice::from_raw_parts_mut(block.start().as_ptr(), block.len()) }
    }

    /// The first `len` bytes of slot `index`, which the device filled since the slot's room was
    /// asked for, as what a read found.
    pub fn filled(&mut self, index: usize, len: usize) -> Found<'_> {
        assert!(!self.lent[index], "a slot is filled once before its room is asked for again");
        self.lent[index] = true;
        let block = &self.blocks[index];
        // SAFETY: as in `room`; the bytes are lent until the slot's room is asked for again.
        let bytes = unsafe { std::slice::from_raw_parts_mut(block.start().as_ptr(), len.min(block.len())) };
        Found { bytes, block: Some(block) }
    }
}

/// What a read found for one frame: its bytes with whatever the device put in front.
pub struct Found<'a> {
    pub bytes: &'a mut [u8],
    /// The block the bytes lie in, if no other frame lies there.
    pub block: Option<&'a Arc<Block>>,
}

/// A batch stops growing at this many bytes, so its first frame is written again while it is
/// still in the cache and the flow's round trip does not stretch.
#[cfg(not(target_vendor = "apple"))]
pub const BATCH_BYTES: usize = 256 * 1024;

/// What a device says about itself to the ends of its queues.
pub trait Facts: Send + Sync + 'static {
    /// What the device takes, and how its frames are laid out, as of now.
    fn takes(&self) -> Takes;
}

/// How a system reads the frames that are ready.
pub trait Read: Send + 'static {
    /// How many slots a reader of up to `frames` frames per batch reads into.
    fn slots(&self, frames: usize) -> usize {
        frames
    }

    /// Reads what is ready, without waiting, at most `frames` frames, a frame into a slot, and
    /// hands `frame` each of them in order.
    fn read(&mut self, fd: RawFd, slots: &mut Slots, frames: usize, stats: &mut ReaderStats, frame: impl FnMut(Found<'_>)) -> Filled;
}

/// How a system hands a device the writes of a list.
pub trait Write: Send + 'static {
    /// Hands the device the writes of `list` in order, without waiting, until it takes no more,
    /// and returns how many it took.
    fn write(&mut self, fd: RawFd, list: &impl Writes, stats: &mut WriterStats) -> io::Result<usize>;
}

/// The reading end of a queue.
pub struct Source<T: Facts, R: Read> {
    reads: R,
    slots: Slots,
    frames: usize,
    port: Port,
    /// The device, which keeps the descriptor open.
    tunnel: Arc<T>,
}

impl<T: Facts, R: Read> Source<T, R> {
    pub(crate) fn new(tunnel: Arc<T>, queue: &Arc<Queue>, reads: R, frames: usize) -> Source<T, R> {
        let slots = Slots::new(reads.slots(frames));
        Source { reads, slots, frames, port: Port::new(queue.clone(), false), tunnel }
    }
}

impl<T: Facts, R: Read> Wait for Source<T, R> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.port.poll_ready(cx)
    }

    fn wait(&mut self, signal: Option<&Signal>, deadline: Option<Instant>) -> io::Result<()> {
        self.port.wait(signal, deadline)
    }
}

// SAFETY: every frame lies in a slot of its own, or in its own stretch of memory that the way
// of reading owns; the source writes to either only when it fills, and to a slot's block only
// while no frame that was taken out of a batch holds the block.
unsafe impl<T: Facts, R: Read> crate::io::Source for Source<T, R> {
    fn fill(&mut self, frames: &mut Vec<Loan>, stats: &mut ReaderStats) -> Filled {
        let framing = self.tunnel.takes().framing;
        let mut malformed = 0;
        let filled = self.reads.read(self.port.fd(), &mut self.slots, self.frames, stats, |found| match framing.decode(found.bytes) {
            Some(decoded) => frames.push(Loan::new(found.bytes, decoded, found.block)),
            None => malformed += 1,
        });
        stats.malformed += malformed;
        filled
    }
}

/// The writing end of a queue.
pub struct Sink<T: Facts, W: Write> {
    writes: W,
    port: Port,
    /// The device, which keeps the descriptor open.
    tunnel: Arc<T>,
}

impl<T: Facts, W: Write> Sink<T, W> {
    pub(crate) fn new(tunnel: Arc<T>, queue: &Arc<Queue>, writes: W) -> Sink<T, W> {
        Sink { writes, port: Port::new(queue.clone(), true), tunnel }
    }
}

impl<T: Facts, W: Write> Wait for Sink<T, W> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.port.poll_ready(cx)
    }

    fn wait(&mut self, signal: Option<&Signal>, deadline: Option<Instant>) -> io::Result<()> {
        self.port.wait(signal, deadline)
    }
}

impl<T: Facts, W: Write> crate::io::Sink for Sink<T, W> {
    fn takes(&self) -> Takes {
        self.tunnel.takes()
    }

    fn write(&mut self, list: &impl Writes, stats: &mut WriterStats) -> io::Result<usize> {
        self.writes.write(self.port.fd(), list, stats)
    }
}

/// Reads a frame per call, one into each slot: what every system can do.
#[cfg(not(target_vendor = "apple"))]
#[derive(Default)]
pub struct Each;

#[cfg(not(target_vendor = "apple"))]
impl Read for Each {
    fn read(&mut self, fd: RawFd, slots: &mut Slots, frames: usize, stats: &mut ReaderStats, frame: impl FnMut(Found<'_>)) -> Filled {
        read_each(fd, slots, 0, frames, stats, frame).0
    }
}

/// Reads a frame per call into the slots from `first` on, until the device is empty, slot
/// `frames` is reached or the batch has its bytes. Also returns how many frames it read.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn read_each(
    fd: RawFd,
    slots: &mut Slots,
    first: usize,
    frames: usize,
    stats: &mut ReaderStats,
    mut frame: impl FnMut(Found<'_>),
) -> (Filled, usize) {
    let (mut slot, mut bytes) = (first, 0);
    while slot < frames && bytes < BATCH_BYTES {
        let room = slots.room(slot);
        // SAFETY: `room` is writable for its whole length.
        let read = unsafe { libc::read(fd, room.as_mut_ptr().cast(), room.len()) };
        stats.calls += 1;
        if read > 0 {
            frame(slots.filled(slot, read as usize));
            bytes += read as usize;
            slot += 1;
            continue;
        }
        let error = if read == 0 { nothing() } else { io::Error::last_os_error() };
        match error.kind() {
            ErrorKind::WouldBlock => return (Filled::dry(), slot - first),
            ErrorKind::Interrupted => continue,
            _ => return (Filled::failed(error), slot - first),
        }
    }
    (Filled::more(), slot - first)
}

/// A read that came back with nothing: these devices hand over whole frames or fail.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn nothing() -> io::Error {
    io::Error::new(ErrorKind::UnexpectedEof, "the device returned nothing")
}

/// Pointers to the pieces of writes, which are borrowed for the length of one call.
#[derive(Default)]
pub struct IoVecs(Vec<libc::iovec>);

// SAFETY: the pointers are only dereferenced by the system call made while the pieces they
// point at are borrowed, and the list is cleared before it is filled again.
unsafe impl Send for IoVecs {}
// SAFETY: as above; shared access never dereferences the pointers.
unsafe impl Sync for IoVecs {}

impl IoVecs {
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }

    /// Appends the pieces of write `index` of `list`, and returns how many they are.
    pub(crate) fn gather(&mut self, list: &impl Writes, index: usize) -> usize {
        let before = self.0.len();
        list.pieces(index, |piece| self.0.push(libc::iovec { iov_base: piece.as_ptr().cast_mut().cast(), iov_len: piece.len() }));
        self.0.len() - before
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn as_ptr(&self) -> *const libc::iovec {
        self.0.as_ptr()
    }
}

/// Writes a frame per call, its pieces gathered: what every system can do.
#[cfg(not(target_vendor = "apple"))]
#[derive(Default)]
pub struct Gathered {
    iov: IoVecs,
}

#[cfg(not(target_vendor = "apple"))]
impl Write for Gathered {
    fn write(&mut self, fd: RawFd, list: &impl Writes, stats: &mut WriterStats) -> io::Result<usize> {
        for index in 0..list.count() {
            self.iov.clear();
            self.iov.gather(list, index);
            stats.calls += 1;
            // SAFETY: the pointers refer to pieces that `list` lends for this call.
            let result = retry(|| unsafe { libc::writev(fd, self.iov.as_ptr(), self.iov.len() as libc::c_int) });
            self.iov.clear();
            if let Wrote::Full = wrote(result, stats)? {
                return Ok(index);
            }
        }
        Ok(list.count())
    }
}

/// Makes a system call again while a signal interrupts it. A negative result becomes the error.
pub(crate) fn retry(mut call: impl FnMut() -> isize) -> io::Result<usize> {
    loop {
        let result = call();
        if result >= 0 {
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Whether a device took a write.
pub(crate) enum Wrote {
    /// Taken, or refused on its own and counted as dropped.
    Taken,
    /// The device is full.
    Full,
}

/// What a write came to: counted as taken, counted as dropped when the system refused it on its
/// own, such as a packet it found malformed or a write to an interface that is down, or an error
/// when the device is gone.
pub(crate) fn wrote<T>(result: io::Result<T>, stats: &mut WriterStats) -> io::Result<Wrote> {
    let Err(error) = result else {
        stats.writes += 1;
        return Ok(Wrote::Taken);
    };
    match error.raw_os_error() {
        Some(libc::EAGAIN) => Ok(Wrote::Full),
        Some(code) if gone(code) => Err(error),
        _ => {
            stats.dropped += 1;
            Ok(Wrote::Taken)
        }
    }
}

/// Whether a failed write says that the device is gone for good.
pub(crate) fn gone(code: i32) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if code == libc::EBADFD {
        return true;
    }
    matches!(code, libc::EBADF | libc::ENXIO | libc::ENODEV | libc::ENOTCONN | libc::EPIPE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_whose_frame_was_taken_gets_another_block() {
        let mut slots = Slots::new(2);
        let first = slots.room(0).as_mut_ptr();
        slots.room(0)[..3].copy_from_slice(b"abc");
        let found = slots.filled(0, 3);
        assert_eq!(found.bytes, b"abc");
        let taken = found.block.expect("a slot's frame lies in a block of its own").clone();
        // The frame keeps the block, and the slot is read into another.
        let second = slots.room(0).as_mut_ptr();
        assert_ne!(second, first);
        slots.room(0).fill(0xff);
        // SAFETY: the block is the taken frame's alone.
        assert_eq!(unsafe { std::slice::from_raw_parts(taken.start().as_ptr(), 3) }, b"abc");
        // A frame that was lent and not taken leaves the slot its block.
        assert!(slots.filled(0, 1).block.is_some());
        assert_eq!(slots.room(0).as_mut_ptr(), second);
        // The block of a frame that is dropped serves the next slot that needs one.
        drop(taken);
        let other = slots.filled(1, 1).block.expect("a block of its own").clone();
        assert_eq!(slots.room(1).as_mut_ptr(), first);
        drop(other);
    }

    #[test]
    #[should_panic(expected = "a slot is filled once")]
    fn a_slot_is_not_lent_twice() {
        let mut slots = Slots::new(1);
        slots.filled(0, 1);
        slots.filled(0, 1);
    }
}
