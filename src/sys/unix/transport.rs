//! How the queues of every Unix system move frames: a descriptor that is read into slots of one
//! buffer and written with gathered pieces. A system brings only the calls that move more than
//! one frame at a time, where it has any; the rest is the same everywhere.

use std::io::{self, ErrorKind};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use xtun_wire::{Takes, Writes};

use super::{Port, Queue, Signal};
use crate::io::{Filled, Lent, ReaderStats, Wait, WriterStats};

/// The room for one frame: the largest IPv6 packet of 65,535 bytes of payload and its header,
/// behind the longest prefix, rounded to a cache line.
pub const SLOT: usize = 65_536 + 128;

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
    /// How large the buffer of a reader of up to `frames` frames per batch is.
    fn buffer_len(&self, frames: usize) -> usize {
        frames * SLOT
    }

    /// Reads what is ready into `buffer`, without waiting, at most `frames` frames, and hands
    /// `frame` each of them in order, with whatever the device put in front.
    fn read(&mut self, fd: RawFd, buffer: &mut [u8], frames: usize, stats: &mut ReaderStats, frame: impl FnMut(&mut [u8])) -> Filled;
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
    buffer: Box<[u8]>,
    frames: usize,
    port: Port,
    /// The device, which keeps the descriptor open.
    tunnel: Arc<T>,
}

impl<T: Facts, R: Read> Source<T, R> {
    pub(crate) fn new(tunnel: Arc<T>, queue: &Arc<Queue>, reads: R, frames: usize) -> Source<T, R> {
        let buffer = vec![0u8; reads.buffer_len(frames)].into_boxed_slice();
        Source { reads, buffer, frames, port: Port::new(queue.clone(), false), tunnel }
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

// SAFETY: every frame lies in its own stretch of the buffer, which the source owns and writes
// to only when it fills.
unsafe impl<T: Facts, R: Read> crate::io::Source for Source<T, R> {
    fn fill(&mut self, frames: &mut Vec<Lent>, stats: &mut ReaderStats) -> Filled {
        let framing = self.tunnel.takes().framing;
        let mut malformed = 0;
        let filled = self.reads.read(self.port.fd(), &mut self.buffer, self.frames, stats, |raw| match framing.decode(raw) {
            Some(decoded) => frames.push(Lent::new(raw, decoded)),
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
    fn read(&mut self, fd: RawFd, buffer: &mut [u8], frames: usize, stats: &mut ReaderStats, frame: impl FnMut(&mut [u8])) -> Filled {
        read_each(fd, buffer, 0, frames, stats, frame).0
    }
}

/// Reads a frame per call into the slots from `first` on, until the device is empty, slot
/// `frames` is reached or the batch has its bytes. Also returns how many frames it read.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn read_each(
    fd: RawFd,
    buffer: &mut [u8],
    first: usize,
    frames: usize,
    stats: &mut ReaderStats,
    mut frame: impl FnMut(&mut [u8]),
) -> (Filled, usize) {
    let (mut slot, mut bytes) = (first, 0);
    while slot < frames && bytes < BATCH_BYTES {
        let room = &mut buffer[slot * SLOT..(slot + 1) * SLOT];
        // SAFETY: `room` is writable for its whole length.
        let read = unsafe { libc::read(fd, room.as_mut_ptr().cast(), room.len()) };
        stats.calls += 1;
        if read > 0 {
            frame(&mut room[..read as usize]);
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
