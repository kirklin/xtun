//! Ethernet frames of a TAP-Windows adapter through overlapped reads and writes. Many reads wait
//! in the driver at once, so that frames that come close together are taken in one batch without
//! a call each; the driver completes reads in the order they were posted. Writes do not wait for
//! one another either.

use std::io::{Error, Result};
use std::mem::zeroed;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use xtun_wire::{Framing, Prefix, Takes, Writes};
use windows_sys::Win32::Foundation::{
    ERROR_DEVICE_NOT_CONNECTED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE, ERROR_IO_PENDING, GetLastError, HANDLE, STATUS_PENDING,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::tap::Tap;
use super::wait::{Event, Signal, Watch, wait};
use crate::io::{Filled, Loan, ReaderStats, Wait, WriterStats};

/// Room around the Ethernet payload the driver carries: the Ethernet header and one VLAN tag.
const FRAME_OVERHEAD: usize = 14 + 4;
/// Writes that may wait in the driver at once.
const WRITES: usize = 64;

/// A TAP-Windows adapter moves bare Ethernet frames.
const FRAMING: Framing = Framing { prefix: Prefix::None, ethernet: true };

/// One overlapped transfer: the structure the driver reports to, which stays in place while the
/// transfer runs, its event and its buffer.
struct Transfer {
    overlapped: Box<OVERLAPPED>,
    event: Event,
    buffer: Box<[u8]>,
    /// The transfer was started and not yet collected.
    running: bool,
}

// SAFETY: the structure and the buffer belong to the transfer and the driver; the handles may
// be used from any thread.
unsafe impl Send for Transfer {}
// SAFETY: shared access touches nothing the driver writes.
unsafe impl Sync for Transfer {}

impl Transfer {
    fn new(size: usize) -> Result<Transfer> {
        // SAFETY: plain old data.
        Ok(Transfer { overlapped: Box::new(unsafe { zeroed() }), event: Event::new(true)?, buffer: vec![0u8; size].into_boxed_slice(), running: false })
    }

    /// Resets the structure for a new transfer.
    fn prepare(&mut self) -> *mut OVERLAPPED {
        // SAFETY: plain old data.
        *self.overlapped = unsafe { zeroed() };
        self.overlapped.hEvent = self.event.handle();
        &mut *self.overlapped
    }

    /// Whether the driver finished the transfer, as `HasOverlappedIoCompleted` tells.
    fn finished(&self) -> bool {
        // SAFETY: the driver writes the status in place; it is read as it is now.
        let status = unsafe { std::ptr::read_volatile(&self.overlapped.Internal) };
        status != STATUS_PENDING as usize
    }

    /// The bytes a finished transfer moved, or why it failed.
    fn result(&self, handle: HANDLE) -> Result<usize> {
        let mut moved = 0u32;
        // SAFETY: the transfer finished, so this does not wait.
        if unsafe { GetOverlappedResult(handle, &*self.overlapped, &mut moved, 0) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(moved as usize)
    }

    /// Stops a running transfer and waits for it, so that its structure and buffer may go.
    fn cancel(&mut self, handle: HANDLE) {
        if self.running {
            let mut moved = 0u32;
            // SAFETY: the transfer runs with this structure; waits until the driver lets go.
            unsafe {
                CancelIoEx(handle, &*self.overlapped);
                GetOverlappedResult(handle, &*self.overlapped, &mut moved, 1);
            }
            self.running = false;
        }
    }
}

/// The reading end of a TAP-Windows adapter's queue.
pub struct Source {
    /// Keeps the adapter's file open while reads run.
    tap: Arc<Tap>,
    reads: Box<[Transfer]>,
    /// The read posted first of those the driver holds or the last fill collected.
    next: usize,
    /// How many reads from `next` on the last fill collected. Their buffers hold its frames
    /// until the next fill posts them again.
    collected: usize,
    /// Calls made to post reads that the reader's statistics have not counted.
    calls: u64,
    watch: Watch,
}

impl Source {
    pub(super) fn new(tap: Arc<Tap>, capacity: usize) -> Result<Source> {
        let size = tap.frame_mtu()? as usize + FRAME_OVERHEAD;
        let reads = (0..capacity).map(|_| Transfer::new(size)).collect::<Result<Vec<_>>>()?.into_boxed_slice();
        let mut source = Source { tap, reads, next: 0, collected: 0, calls: 0, watch: Watch::new()? };
        for index in 0..capacity {
            source.post(index)?;
        }
        Ok(source)
    }

    /// Starts read `index`.
    fn post(&mut self, index: usize) -> Result<()> {
        let handle = self.tap.handle();
        let read = &mut self.reads[index];
        let overlapped = read.prepare();
        // SAFETY: the buffer and the structure stay in place until the read is collected or
        // cancelled.
        let started = unsafe { ReadFile(handle, read.buffer.as_mut_ptr(), read.buffer.len() as u32, std::ptr::null_mut(), overlapped) };
        self.calls += 1;
        // SAFETY: reads the calling thread's last error.
        if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(Error::last_os_error());
        }
        read.running = true;
        Ok(())
    }

    /// Posts again the reads whose frames were handed out, then collects the reads that
    /// finished, in the order they were posted.
    fn refill(&mut self, frames: &mut Vec<Loan>, stats: &mut ReaderStats) -> Filled {
        let count = self.reads.len();
        while self.collected > 0 {
            if let Err(error) = self.post(self.next) {
                return Filled::failed(error);
            }
            self.next = (self.next + 1) % count;
            self.collected -= 1;
        }
        let handle = self.tap.handle();
        while self.collected < count {
            let read = &mut self.reads[self.awaited()];
            if !read.finished() {
                return Filled::dry();
            }
            let length = match read.result(handle) {
                Ok(length) => length,
                Err(error) => return Filled::failed(error),
            };
            read.running = false;
            self.collected += 1;
            let raw = &mut read.buffer[..length];
            match FRAMING.decode(raw) {
                Some(decoded) => frames.push(Loan::new(raw, decoded, None)),
                None => stats.malformed += 1,
            }
        }
        Filled::more()
    }

    /// Which read finishes next.
    fn awaited(&self) -> usize {
        (self.next + self.collected) % self.reads.len()
    }
}

impl Wait for Source {
    /// Resolves at once when the read that finishes next has finished already.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let read = &self.reads[self.awaited()];
        self.watch.poll_signalled(cx, read.event.handle(), None, || Ok(read.finished()))
    }

    fn wait(&mut self, signal: Option<&Signal>, deadline: Option<Instant>) -> Result<()> {
        wait(Some(self.reads[self.awaited()].event.handle()), signal, deadline, None)
    }
}

// SAFETY: every listed frame lies in the buffer of a read of its own, which the source owns.
// A buffer goes back to the driver only when the source fills again and posts its read anew,
// and is freed only when the source is dropped, after the reads that still run were cancelled.
unsafe impl crate::io::Source for Source {
    fn fill(&mut self, frames: &mut Vec<Loan>, stats: &mut ReaderStats) -> Filled {
        let filled = self.refill(frames, stats);
        stats.calls += std::mem::take(&mut self.calls);
        filled
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        let handle = self.tap.handle();
        for read in self.reads.iter_mut() {
            read.cancel(handle);
        }
        self.watch.disarm();
    }
}

/// The writing end of a TAP-Windows adapter's queue.
pub struct Sink {
    /// Keeps the adapter's file open while writes run.
    tap: Arc<Tap>,
    writes: Box<[Transfer]>,
    /// The write to use next; the oldest of the running ones is `running` writes before it.
    next: usize,
    running: usize,
    /// The largest frame the driver takes.
    frame: usize,
    watch: Watch,
}

impl Sink {
    pub(super) fn new(tap: Arc<Tap>) -> Result<Sink> {
        let frame = tap.frame_mtu()? as usize + FRAME_OVERHEAD;
        let writes = (0..WRITES).map(|_| Transfer::new(frame)).collect::<Result<Vec<_>>>()?.into_boxed_slice();
        Ok(Sink { tap, writes, next: 0, running: 0, frame, watch: Watch::new()? })
    }

    /// Starts the next write with the first `size` bytes of its buffer.
    fn start(&mut self, size: usize, stats: &mut WriterStats) -> Result<()> {
        let handle = self.tap.handle();
        let write = &mut self.writes[self.next];
        let overlapped = write.prepare();
        // SAFETY: the buffer and the structure stay in place until the write is collected or
        // cancelled.
        let started = unsafe { WriteFile(handle, write.buffer.as_ptr(), size as u32, std::ptr::null_mut(), overlapped) };
        stats.calls += 1;
        // SAFETY: reads the calling thread's last error.
        if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            let error = Error::last_os_error();
            stats.dropped += 1;
            // The adapter is gone, or its file is: nothing will be written any more.
            let gone = [ERROR_INVALID_HANDLE, ERROR_DEVICE_NOT_CONNECTED, ERROR_FILE_NOT_FOUND].map(|code| code as i32);
            return if error.raw_os_error().is_some_and(|code| gone.contains(&code)) { Err(error) } else { Ok(()) };
        }
        write.running = true;
        self.next = (self.next + 1) % self.writes.len();
        self.running += 1;
        Ok(())
    }

    /// Collects the writes that finished, oldest first; a write the driver refused counts as
    /// dropped.
    fn reap(&mut self, stats: &mut WriterStats) {
        let handle = self.tap.handle();
        while self.running > 0 {
            let write = &mut self.writes[self.oldest()];
            if !write.finished() {
                break;
            }
            let result = write.result(handle);
            write.running = false;
            self.running -= 1;
            match result {
                Ok(_) => stats.writes += 1,
                Err(_) => stats.dropped += 1,
            }
        }
    }

    /// Which write is the oldest running one.
    fn oldest(&self) -> usize {
        let count = self.writes.len();
        (self.next + count - self.running) % count
    }
}

impl Wait for Sink {
    /// Resolves at once when the oldest running write has finished already.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let write = &self.writes[self.oldest()];
        self.watch.poll_signalled(cx, write.event.handle(), None, || Ok(write.finished()))
    }

    fn wait(&mut self, signal: Option<&Signal>, deadline: Option<Instant>) -> Result<()> {
        wait(Some(self.writes[self.oldest()].event.handle()), signal, deadline, None)
    }
}

impl crate::io::Sink for Sink {
    fn takes(&self) -> Takes {
        Takes { framing: FRAMING, tcp: false, udp: false, udp_max_segments: 0, max_frame: self.frame }
    }

    /// Copies each write into the buffer of a free transfer and starts it, until every transfer
    /// runs.
    fn write(&mut self, list: &impl Writes, stats: &mut WriterStats) -> Result<usize> {
        self.reap(stats);
        for index in 0..list.count() {
            if self.running == self.writes.len() {
                self.reap(stats);
                if self.running == self.writes.len() {
                    return Ok(index);
                }
            }
            let buffer = &mut self.writes[self.next].buffer;
            let mut size = 0;
            list.pieces(index, |piece| {
                buffer[size..size + piece.len()].copy_from_slice(piece);
                size += piece.len();
            });
            self.start(size, stats)?;
        }
        Ok(list.count())
    }

    /// One more set of overlapped writes on the adapter's file.
    fn try_clone(&self) -> Result<Sink> {
        Sink::new(self.tap.clone())
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        let handle = self.tap.handle();
        for write in self.writes.iter_mut() {
            write.cancel(handle);
        }
        self.watch.disarm();
    }
}
