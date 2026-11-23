//! The queues of a device and their two ends, the same on every system. A system brings a
//! [`Source`] that reads what is ready and a [`Sink`] that takes what it can, and says how to
//! wait for either; everything else happens here.

use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSlice, IoSliceMut};
use std::ops::Range;
use std::ptr::NonNull;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use xtun_wire::{Checksum, Decoded, Frame, Gso, Packet, Plan, Takes, Writes, take_first};

use crate::layer::{Ip, Layer};
use crate::sys::{self, Tunnel};

/// How long a reader that finds frames waiting every time it looks keeps its thread before it
/// hands the thread back to the scheduler.
const SLICE: Duration = Duration::from_micros(1000);

/// Frames a reader holds per batch unless told otherwise.
const FRAMES: usize = 64;

/// How one end of a queue waits for its device.
pub trait Wait {
    /// Resolves once the device may have more to read, or room to write, after an attempt
    /// found it had none. Whoever calls makes an attempt after every time this resolves, and
    /// calls again only after an attempt that came up empty.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// The same, blocking the thread until then, until `signal` is triggered or until
    /// `deadline` passes.
    fn wait(&mut self, signal: Option<&sys::Signal>, deadline: Option<Instant>) -> io::Result<()>;
}

/// A frame in the memory of a [`Source`], lent to the reader.
pub struct Lent {
    data: NonNull<u8>,
    len: usize,
    link: usize,
    checksum: Checksum,
    gso: Option<Gso>,
}

// SAFETY: a lent frame is a stretch of memory that only the reader touches while it is lent.
unsafe impl Send for Lent {}
// SAFETY: as above; shared access never reads through the pointer.
unsafe impl Sync for Lent {}

impl Lent {
    /// The frame that [`xtun_wire::Framing::decode`] found in `raw`.
    pub fn new(raw: &mut [u8], decoded: Decoded) -> Lent {
        let frame = &mut raw[decoded.start..decoded.start + decoded.len];
        Lent { data: NonNull::from(frame).cast(), len: decoded.len, link: decoded.link, checksum: decoded.checksum, gso: decoded.gso }
    }

    /// # Safety
    ///
    /// The source that lent the frame has not read again since, nor been told that the frame
    /// is done with, and no other reference to the bytes is alive.
    unsafe fn bytes<'a>(&mut self) -> &'a mut [u8] {
        // SAFETY: the source keeps `len` bytes at `data` valid and to the reader alone.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }
}

/// What reading what was ready came to.
pub struct Filled {
    /// The device was found empty.
    pub dry: bool,
    /// A failure met on the way. Frames read before it stay lent.
    pub error: Option<io::Error>,
}

impl Filled {
    /// The device ran empty.
    pub fn dry() -> Filled {
        Filled { dry: true, error: None }
    }

    /// The batch is full and the device may hold more.
    pub fn more() -> Filled {
        Filled { dry: false, error: None }
    }

    /// Reading failed.
    pub fn failed(error: io::Error) -> Filled {
        Filled { dry: false, error: Some(error) }
    }
}

/// The reading end of a queue as a system has it.
///
/// # Safety
///
/// Every frame that [`Source::fill`] lists lies in memory that no other listed frame shares and
/// that stays valid, and untouched by the source, until the source fills again, is told by
/// [`Source::release`] that the frame is done with, or is dropped.
pub unsafe trait Source: Wait + Send {
    /// Reads the frames that are ready into the source's own memory, without waiting, and lists
    /// them in order. Frames lent before are done with.
    fn fill(&mut self, frames: &mut Vec<Lent>, stats: &mut ReaderStats) -> Filled;

    /// The first `upto` frames of the last fill are done with. A source that lends memory of
    /// its driver gives it back here.
    fn release(&mut self, upto: usize) {
        let _ = upto;
    }
}

/// The writing end of a queue as a system has it.
pub trait Sink: Wait + Send {
    /// What the device takes, as it is now.
    fn takes(&self) -> Takes;

    /// Hands the device the writes of `list`, in order and without waiting, until it takes no
    /// more. Returns how many it took. A write the device refuses on its own counts as taken,
    /// and as dropped; an error means the device is gone.
    fn write(&mut self, list: &impl Writes, stats: &mut WriterStats) -> io::Result<usize>;
}

/// Keeps a reader whose queue never runs empty from holding its thread for good: tasks woken
/// meanwhile, such as another queue's reader, would wait behind it.
struct Slice {
    /// When the task last gave its thread up, by waiting or by yielding.
    since: Instant,
    /// The task returned to wait for the device.
    waiting: bool,
}

impl Slice {
    fn new() -> Slice {
        Slice { since: Instant::now(), waiting: false }
    }

    /// Before the next batch: hands the thread back to the scheduler once the task has kept it
    /// for a whole slice.
    fn poll_turn(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.waiting {
            self.waiting = false;
            self.since = Instant::now();
            return Poll::Ready(());
        }
        if self.since.elapsed() < SLICE {
            return Poll::Ready(());
        }
        self.since = Instant::now();
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// The task is about to wait for the device, which frees its thread.
    fn wait(&mut self) {
        self.waiting = true;
    }
}

/// How the `blocking_` calls of a reader or writer wait.
#[derive(Clone, Default)]
struct Blocking {
    interrupt: Option<Interrupt>,
    timeout: Option<Duration>,
}

impl Blocking {
    /// Fails if the interrupt is triggered; otherwise, when a call that starts now gives up.
    fn start(&self) -> io::Result<Option<Instant>> {
        if self.signal().is_some_and(|signal| signal.is_set()) {
            return Err(sys::interrupted());
        }
        Ok(self.timeout.map(|timeout| Instant::now() + timeout))
    }

    fn signal(&self) -> Option<&sys::Signal> {
        self.interrupt.as_ref().map(|interrupt| &*interrupt.signal)
    }
}

/// Writes the device did not take when they were made, copied, in order.
#[derive(Default)]
struct Backlog {
    bytes: Vec<u8>,
    writes: Vec<Range<usize>>,
    next: usize,
}

impl Backlog {
    fn is_empty(&self) -> bool {
        self.next == self.writes.len()
    }

    /// Keeps the writes of `list` from `from` on.
    fn keep(&mut self, list: &impl Writes, from: usize) {
        for index in from..list.count() {
            let start = self.bytes.len();
            list.pieces(index, |piece| self.bytes.extend_from_slice(piece));
            self.writes.push(start..self.bytes.len());
        }
    }

    /// Drops the `count` oldest writes, which went out or were refused.
    fn done(&mut self, count: usize) {
        self.next += count;
        if self.is_empty() {
            self.bytes.clear();
            self.writes.clear();
            self.next = 0;
        }
    }
}

impl Writes for Backlog {
    fn count(&self) -> usize {
        self.writes.len() - self.next
    }

    fn pieces<'a>(&'a self, index: usize, mut each: impl FnMut(&'a [u8])) {
        let bytes = &self.bytes[self.writes[self.next + index].clone()];
        if !bytes.is_empty() {
            each(bytes);
        }
    }
}

/// One packet whose bytes come in pieces, behind the prefix its device takes.
struct Vectored<'a> {
    prefix: &'a [u8],
    bufs: &'a [IoSlice<'a>],
}

impl Writes for Vectored<'_> {
    fn count(&self) -> usize {
        1
    }

    fn pieces<'a>(&'a self, _index: usize, mut each: impl FnMut(&'a [u8])) {
        for piece in std::iter::once(self.prefix).chain(self.bufs.iter().map(|buf| &**buf)) {
            if !piece.is_empty() {
                each(piece);
            }
        }
    }
}

/// Wakes a reader or writer that is blocked in one of its `blocking_` calls, from any thread.
///
/// A reader or writer watches the interrupt it was given with `set_interrupt`. Once triggered,
/// the interrupt stays triggered: every blocking call that watches it fails at once with
/// [`io::ErrorKind::Interrupted`] until [`Interrupt::reset`]. One interrupt can be given to any
/// number of readers and writers, of any devices.
#[derive(Clone)]
pub struct Interrupt {
    signal: Arc<sys::Signal>,
}

impl Interrupt {
    /// A new interrupt that is not triggered.
    pub fn new() -> io::Result<Interrupt> {
        Ok(Interrupt { signal: Arc::new(sys::Signal::new()?) })
    }

    /// Wakes every blocking call that watches the interrupt, now and until it is reset.
    pub fn trigger(&self) -> io::Result<()> {
        self.signal.trigger()
    }

    /// Lets blocking calls wait again.
    pub fn reset(&self) -> io::Result<()> {
        self.signal.reset()
    }

    /// Whether the interrupt is triggered.
    pub fn is_triggered(&self) -> bool {
        self.signal.is_set()
    }
}

impl fmt::Debug for Interrupt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interrupt").field("triggered", &self.is_triggered()).finish()
    }
}

/// One queue of a device, with both of its ends. A device hands out each of its queues once,
/// when it is built, and a queue is split into its two ends once, so there is never more than
/// one reader and one writer of a queue.
pub struct Queue<L: Layer = Ip> {
    pub(crate) tunnel: Arc<L::Tunnel>,
    pub(crate) index: usize,
}

impl<L: Layer> Queue<L> {
    /// Which of its device's queues this is, counted from zero.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The two ends of the queue. The reader holds up to 64 frames per batch.
    pub fn split(self) -> io::Result<(Reader<L>, Writer<L>)> {
        self.split_with_capacity(FRAMES)
    }

    /// The two ends of the queue, with a reader that holds up to `frames` frames per batch.
    pub fn split_with_capacity(self, frames: usize) -> io::Result<(Reader<L>, Writer<L>)> {
        if frames == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a batch holds at least one frame"));
        }
        let source = self.tunnel.source(self.index, frames)?;
        let sink = self.tunnel.sink(self.index)?;
        let reader = Reader {
            source,
            lent: Vec::with_capacity(frames),
            next: 0,
            pending: None,
            dry: false,
            slice: Slice::new(),
            blocking: Blocking::default(),
            stats: ReaderStats::default(),
        };
        let writer =
            Writer { sink, plan: Plan::new(), backlog: Backlog::default(), full: false, blocking: Blocking::default(), stats: WriterStats::default() };
        Ok((reader, writer))
    }
}

impl<L: Layer> fmt::Debug for Queue<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Queue").field("index", &self.index).finish_non_exhaustive()
    }
}

/// Reads one queue of a device: a batch of frames at a time, or one packet at a time.
///
/// Every way of reading comes in four forms: an `async` method, a `poll_` method for code
/// that implements futures itself, a `try_` method that never waits, and a `blocking_` method
/// that blocks the thread and needs no runtime. The asynchronous forms run on Tokio inside a
/// Tokio runtime and on async-io elsewhere, depending on the features enabled. Waiting can be
/// cancelled at any point without losing a frame.
pub struct Reader<L: Layer = Ip> {
    source: <L::Tunnel as Tunnel>::Source,
    /// The frames of the last read.
    lent: Vec<Lent>,
    /// The first frame that has not been handed out.
    next: usize,
    /// An error met after some frames had been read, reported once they are handed out.
    pending: Option<io::Error>,
    /// The last read found the device empty, and nothing has said since that it may have more.
    dry: bool,
    slice: Slice,
    blocking: Blocking,
    stats: ReaderStats,
}

/// Writes to one queue of a device: a batch of packets at a time, or one packet in pieces.
///
/// Every way of writing comes in the same four forms as reading. The writer hands the packets
/// it is given to the device; what the device cannot take yet is copied and written before
/// anything that comes later, so a call that returns has taken every packet, and cancelling a
/// wait never loses or repeats one.
pub struct Writer<L: Layer = Ip> {
    sink: <L::Tunnel as Tunnel>::Sink,
    plan: Plan,
    backlog: Backlog,
    /// The device took less than it was handed, and nothing has said since that it has room.
    full: bool,
    blocking: Blocking,
    stats: WriterStats,
}

/// The frames of one read. They live in the reader's buffers until the batch is dropped.
pub struct Batch<'a> {
    source: &'a mut dyn Source,
    lent: &'a mut [Lent],
    /// How many frames of the read came before these.
    first: usize,
}

/// What a reader has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReaderStats {
    /// Frames read.
    pub frames: u64,
    /// Bytes read.
    pub bytes: u64,
    /// System calls made to read.
    pub calls: u64,
    /// Frames the system handed over in a shape the device never agreed to, and that were
    /// dropped.
    pub malformed: u64,
}

/// What a writer has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriterStats {
    /// Packets handed in.
    pub packets: u64,
    /// Writes the device took: a segment joined from many packets counts once.
    pub writes: u64,
    /// System calls made to write.
    pub calls: u64,
    /// Writes the system refused, such as packets it found malformed or writes to an interface
    /// that is down. Their packets are lost, as on a real link.
    pub dropped: u64,
}

impl<L: Layer> Reader<L> {
    /// Waits for at least one frame and takes every frame that is ready, up to the reader's
    /// capacity.
    pub async fn recv(&mut self) -> io::Result<Batch<'_>> {
        poll_fn(|cx| self.poll_fill(cx)).await?;
        Ok(self.batch())
    }

    /// [`Reader::recv`] for code that polls.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Batch<'_>>> {
        ready!(self.poll_fill(cx))?;
        Poll::Ready(Ok(self.batch()))
    }

    /// Takes the frames that are ready, or fails with [`io::ErrorKind::WouldBlock`].
    pub fn try_recv(&mut self) -> io::Result<Batch<'_>> {
        self.try_fill()?;
        Ok(self.batch())
    }

    /// [`Reader::recv`], blocking the thread.
    pub fn blocking_recv(&mut self) -> io::Result<Batch<'_>> {
        self.blocking_fill()?;
        Ok(self.batch())
    }

    /// Waits for one packet and copies it into `buf`, cut from its segment and with a complete
    /// checksum. Returns its length. A packet longer than `buf` is kept for the next call, which
    /// fails with [`io::ErrorKind::InvalidInput`] until a buffer is large enough.
    pub async fn recv_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_recv_packet(cx, &mut *buf)).await
    }

    /// [`Reader::recv_packet`] for code that polls.
    pub fn poll_recv_packet(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.poll_recv_vectored(cx, &mut [IoSliceMut::new(buf)])
    }

    /// [`Reader::recv_packet`] without waiting.
    pub fn try_recv_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.try_recv_vectored(&mut [IoSliceMut::new(buf)])
    }

    /// [`Reader::recv_packet`], blocking the thread.
    pub fn blocking_recv_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.blocking_recv_vectored(&mut [IoSliceMut::new(buf)])
    }

    /// [`Reader::recv_packet`] into several buffers, filled in order.
    pub async fn recv_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_recv_vectored(cx, &mut *bufs)).await
    }

    /// [`Reader::recv_vectored`] for code that polls.
    pub fn poll_recv_vectored(&mut self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>]) -> Poll<io::Result<usize>> {
        ready!(self.poll_fill(cx))?;
        Poll::Ready(self.take_packet(bufs))
    }

    /// [`Reader::recv_vectored`] without waiting.
    pub fn try_recv_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.try_fill()?;
        self.take_packet(bufs)
    }

    /// [`Reader::recv_vectored`], blocking the thread.
    pub fn blocking_recv_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.blocking_fill()?;
        self.take_packet(bufs)
    }

    /// Waits until a read would not wait. The frames that came in are kept for the next read.
    pub async fn readable(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_fill(cx)).await
    }

    /// [`Reader::readable`] for code that polls.
    pub fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_fill(cx)
    }

    /// [`Reader::readable`], blocking the thread.
    pub fn blocking_readable(&mut self) -> io::Result<()> {
        self.blocking_fill()
    }

    /// The interrupt that wakes the `blocking_` calls.
    pub fn set_interrupt(&mut self, interrupt: Option<Interrupt>) {
        self.blocking.interrupt = interrupt;
    }

    /// How long a `blocking_` call waits before it fails with [`io::ErrorKind::TimedOut`].
    /// Without a timeout it waits for good.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.blocking.timeout = timeout;
    }

    /// What the reader has done so far.
    pub fn stats(&self) -> ReaderStats {
        self.stats
    }

    /// Whether frames of the last read have not been handed out.
    fn holds(&self) -> bool {
        self.next < self.lent.len()
    }

    /// Reads until there is a frame or the device is empty. Returns whether there is a frame.
    fn attempt(&mut self) -> io::Result<bool> {
        loop {
            self.lent.clear();
            self.next = 0;
            let filled = self.source.fill(&mut self.lent, &mut self.stats);
            self.dry = filled.dry;
            self.stats.frames += self.lent.len() as u64;
            self.stats.bytes += self.lent.iter().map(|frame| frame.len as u64).sum::<u64>();
            if let Some(error) = filled.error {
                if self.lent.is_empty() {
                    return Err(error);
                }
                self.pending = Some(error);
            }
            if !self.lent.is_empty() {
                return Ok(true);
            }
            if self.dry {
                return Ok(false);
            }
        }
    }

    /// Makes frames available, reading if every frame was handed out.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.holds() {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = self.pending.take() {
            return Poll::Ready(Err(error));
        }
        ready!(self.slice.poll_turn(cx));
        loop {
            if self.dry {
                if self.source.poll_ready(cx)?.is_pending() {
                    self.slice.wait();
                    return Poll::Pending;
                }
                self.dry = false;
            }
            if self.attempt()? {
                return Poll::Ready(Ok(()));
            }
        }
    }

    fn try_fill(&mut self) -> io::Result<()> {
        if self.holds() {
            return Ok(());
        }
        if let Some(error) = self.pending.take() {
            return Err(error);
        }
        if self.attempt()? { Ok(()) } else { Err(io::ErrorKind::WouldBlock.into()) }
    }

    fn blocking_fill(&mut self) -> io::Result<()> {
        let deadline = self.blocking.start()?;
        if self.holds() {
            return Ok(());
        }
        if let Some(error) = self.pending.take() {
            return Err(error);
        }
        while !self.attempt()? {
            self.source.wait(self.blocking.signal(), deadline)?;
        }
        Ok(())
    }

    /// Hands out every frame that is left.
    fn batch(&mut self) -> Batch<'_> {
        let first = self.next;
        self.next = self.lent.len();
        Batch { source: &mut self.source, lent: &mut self.lent[first..], first }
    }

    /// Copies the next packet into `out`. There must be a frame left.
    fn take_packet(&mut self, out: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let frame = &mut self.lent[self.next];
        // SAFETY: the source has not read again since it lent the frame, and nothing else
        // refers to its bytes: a batch that did has been dropped.
        let bytes = unsafe { frame.bytes() };
        let (length, rest) = take_first(bytes, frame.link, frame.checksum, frame.gso, out)?;
        match rest {
            Some(rest) => {
                // SAFETY: the frame left over lies inside the frame that was lent.
                frame.data = unsafe { frame.data.add(rest.skip) };
                frame.len -= rest.skip;
                frame.gso = rest.gso;
            }
            None => {
                self.next += 1;
                self.source.release(self.next);
            }
        }
        Ok(length)
    }
}

impl<L: Layer> Writer<L> {
    /// Writes every packet, in order within each flow, and returns once the device has taken
    /// them all. Packets the system refuses one by one are counted in
    /// [`WriterStats::dropped`]; an error means the device itself is gone.
    pub async fn send(&mut self, packets: &[Packet<'_>]) -> io::Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await?;
        self.put(packets)?;
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// Takes the packets: what the device takes at once is written, the rest is copied and
    /// written first by later calls. Pending only while packets of an earlier call wait.
    pub fn poll_send(&mut self, cx: &mut Context<'_>, packets: &[Packet<'_>]) -> Poll<io::Result<()>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(self.put(packets))
    }

    /// [`Writer::poll_send`] without waiting: takes nothing and fails with
    /// [`io::ErrorKind::WouldBlock`] while packets of an earlier call wait.
    pub fn try_send(&mut self, packets: &[Packet<'_>]) -> io::Result<()> {
        self.try_flush()?;
        self.put(packets)
    }

    /// [`Writer::send`], blocking the thread.
    pub fn blocking_send(&mut self, packets: &[Packet<'_>]) -> io::Result<()> {
        self.blocking_flush()?;
        self.put(packets)?;
        self.blocking_flush()
    }

    /// Writes one packet whose bytes come in pieces, such as a header and a payload, without
    /// joining them first. Its checksums are taken as they are.
    pub async fn send_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await?;
        self.put_vectored(bufs)?;
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// [`Writer::send_vectored`] for code that polls, taking the packet as
    /// [`Writer::poll_send`] does.
    pub fn poll_send_vectored(&mut self, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<()>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(self.put_vectored(bufs))
    }

    /// [`Writer::send_vectored`] without waiting, as [`Writer::try_send`].
    pub fn try_send_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        self.try_flush()?;
        self.put_vectored(bufs)
    }

    /// [`Writer::send_vectored`], blocking the thread.
    pub fn blocking_send_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        self.blocking_flush()?;
        self.put_vectored(bufs)?;
        self.blocking_flush()
    }

    /// Waits until the device has taken every packet handed in so far, so that the next send
    /// is taken without waiting.
    pub async fn writable(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// [`Writer::writable`] for code that polls.
    pub fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }

    /// [`Writer::writable`], blocking the thread.
    pub fn blocking_writable(&mut self) -> io::Result<()> {
        self.blocking_flush()
    }

    /// The interrupt that wakes the `blocking_` calls.
    pub fn set_interrupt(&mut self, interrupt: Option<Interrupt>) {
        self.blocking.interrupt = interrupt;
    }

    /// How long a `blocking_` call waits before it fails with [`io::ErrorKind::TimedOut`].
    /// Without a timeout it waits for good. Packets it took stay taken.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.blocking.timeout = timeout;
    }

    /// What the writer has done so far.
    pub fn stats(&self) -> WriterStats {
        self.stats
    }

    /// Writes what the device takes now and keeps the rest. Nothing waits from before.
    fn put(&mut self, packets: &[Packet<'_>]) -> io::Result<()> {
        self.stats.packets += packets.len() as u64;
        self.plan.plan(&self.sink.takes(), packets)?;
        let list = self.plan.writes(packets);
        let taken = self.sink.write(&list, &mut self.stats)?;
        if taken < list.count() {
            self.backlog.keep(&list, taken);
            self.full = true;
        }
        Ok(())
    }

    /// Writes one packet given in pieces, or keeps it. Nothing waits from before.
    fn put_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        let takes = self.sink.takes();
        let size: usize = bufs.iter().map(|buf| buf.len()).sum();
        if size > takes.max_frame {
            let reason = format!("a packet is longer than the {} bytes the device takes", takes.max_frame);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, reason));
        }
        self.stats.packets += 1;
        // Only a tun device takes the address family, and its packets start with the IP version.
        let first = bufs.iter().find(|buf| !buf.is_empty()).and_then(|buf| buf.first());
        let (prefix, len) = takes.framing.prefix.plain(first.is_some_and(|byte| byte >> 4 == 6));
        let list = Vectored { prefix: &prefix[..len], bufs };
        if self.sink.write(&list, &mut self.stats)? == 0 {
            self.backlog.keep(&list, 0);
            self.full = true;
        }
        Ok(())
    }

    /// Hands the device what waits. Returns whether nothing waits any more.
    fn drain(&mut self) -> io::Result<bool> {
        let taken = self.sink.write(&self.backlog, &mut self.stats)?;
        self.backlog.done(taken);
        self.full = !self.backlog.is_empty();
        Ok(!self.full)
    }

    /// Writes what the device did not take before, waiting while it cannot.
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.backlog.is_empty() {
            if self.full {
                ready!(self.sink.poll_ready(cx))?;
                self.full = false;
            }
            self.drain()?;
        }
        Poll::Ready(Ok(()))
    }

    fn try_flush(&mut self) -> io::Result<()> {
        if self.backlog.is_empty() || self.drain()? { Ok(()) } else { Err(io::ErrorKind::WouldBlock.into()) }
    }

    fn blocking_flush(&mut self) -> io::Result<()> {
        let deadline = self.blocking.start()?;
        while !self.backlog.is_empty() && !self.drain()? {
            self.sink.wait(self.blocking.signal(), deadline)?;
        }
        Ok(())
    }
}

impl Batch<'_> {
    /// How many frames there are.
    pub fn len(&self) -> usize {
        self.lent.len()
    }

    /// Whether there is no frame.
    pub fn is_empty(&self) -> bool {
        self.lent.is_empty()
    }

    /// The frames, in the order they were read.
    pub fn frames(&mut self) -> impl Iterator<Item = Frame<'_>> {
        self.lent.iter_mut().map(|frame| {
            // SAFETY: the source has not read again since it lent the frames, each lies apart
            // from the others, and the batch, borrowed for as long as the frame lives, is the
            // only way to them.
            let bytes = unsafe { frame.bytes() };
            Frame::trusted(bytes, frame.link, frame.checksum, frame.gso)
        })
    }
}

impl Drop for Batch<'_> {
    fn drop(&mut self) {
        self.source.release(self.first + self.lent.len());
    }
}

impl<L: Layer> fmt::Debug for Reader<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader").field("stats", &self.stats()).finish_non_exhaustive()
    }
}

impl<L: Layer> fmt::Debug for Writer<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer").field("stats", &self.stats()).finish_non_exhaustive()
    }
}

impl fmt::Debug for Batch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batch").field("frames", &self.len()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use xtun_wire::gather;

    use super::*;

    #[test]
    fn a_backlog_keeps_writes_in_order() {
        let (header, payload) = (*b"ab", *b"c");
        let pieces = [IoSlice::new(&header), IoSlice::new(&payload)];
        let mut backlog = Backlog::default();
        assert!(backlog.is_empty());
        backlog.keep(&Vectored { prefix: b"", bufs: &pieces }, 0);
        backlog.keep(&Vectored { prefix: b"d", bufs: &pieces[1..] }, 0);
        let mut bytes = Vec::new();
        assert_eq!(backlog.count(), 2);
        gather(&backlog, 0, &mut bytes);
        assert_eq!(bytes, b"abc");
        backlog.done(1);
        gather(&backlog, 0, &mut bytes);
        assert_eq!((backlog.count(), &bytes[..]), (1, &b"dc"[..]));
        backlog.done(1);
        assert!(backlog.is_empty());
    }

    #[test]
    fn an_interrupt_stays_triggered_until_reset() {
        let interrupt = Interrupt::new().unwrap();
        assert!(!interrupt.is_triggered());
        interrupt.trigger().unwrap();
        interrupt.trigger().unwrap();
        assert!(interrupt.clone().is_triggered());
        interrupt.reset().unwrap();
        assert!(!interrupt.is_triggered());
        interrupt.reset().unwrap();
    }
}
