//! IP packets of a Wintun adapter, lent from the session's receive ring and copied into its
//! send ring.

use std::io::{Error, ErrorKind, Result};
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use xtun_wire::{Framing, Prefix, Takes, Writes};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, GetLastError, HANDLE};

use super::tunnel::{Session, Tun};
use super::wait::{Keep, Signal, Timer, Watch, signalled, wait};
use crate::io::{Filled, Loan, ReaderStats, Wait, WriterStats};

/// The largest packet Wintun moves.
const MAX_PACKET: usize = 0xffff;

/// Wintun moves bare IP packets.
const FRAMING: Framing = Framing { prefix: Prefix::None, ethernet: false };

/// Packets lent from the receive ring, given back once they are done with.
struct Held(Vec<*mut u8>);

// SAFETY: the pointers refer to the ring of the session the source holds, and are given back
// through the session, which any thread may do.
unsafe impl Send for Held {}
// SAFETY: as above; shared access never dereferences the pointers.
unsafe impl Sync for Held {}

/// The reading end of a Wintun adapter's queue.
pub struct Source {
    tunnel: Arc<Tun>,
    /// The session whose packets are held, for as long as any of them is: a session that the
    /// device ended meanwhile runs until then.
    session: Option<Arc<Session>>,
    watch: Watch,
    /// The packets of the last fill, in the order they were listed.
    held: Held,
    /// How many of the held packets, from the first on, were given back to the ring.
    given_back: usize,
    capacity: usize,
}

impl Source {
    pub(super) fn new(tunnel: Arc<Tun>, capacity: usize) -> Result<Source> {
        let watch = Watch::new()?;
        Ok(Source { tunnel, session: None, watch, held: Held(Vec::with_capacity(capacity)), given_back: 0, capacity })
    }

    /// Gives the first `upto` held packets back to the ring, except those given back before,
    /// and lets go of the session with the last of them.
    fn give_back(&mut self, upto: usize) {
        if upto <= self.given_back {
            return;
        }
        let session = self.session.as_deref().expect("held packets come from a session");
        for packet in &self.held.0[self.given_back..upto] {
            // SAFETY: the packet came from this session and is given back once.
            unsafe { (session.wintun().release_receive_packet)(session.session, *packet) };
        }
        self.given_back = upto;
        if upto == self.held.0.len() {
            self.session = None;
        }
    }
}

/// What a source with nothing to read waits for: packets of the session, or the device coming
/// up.
fn awaited(tunnel: &Tun, session: Option<&Session>) -> HANDLE {
    match session {
        Some(session) => session.read_event,
        None => tunnel.up_event(),
    }
}

impl Wait for Source {
    /// Resolves at once when the event is signalled already: by packets that came since the
    /// ring was found empty, or by the device that came up meanwhile. The device that ends
    /// the session signals the session's event.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let session = self.tunnel.session();
        let event = awaited(&self.tunnel, session.as_deref());
        self.watch.poll_signalled(cx, event, session.map(|session| session as Keep), || signalled(event))
    }

    /// Holds the session only for as long as it waits.
    fn wait(&mut self, signal: Option<&Signal>, deadline: Option<Instant>) -> Result<()> {
        let session = self.tunnel.session();
        wait(Some(awaited(&self.tunnel, session.as_deref())), signal, deadline, None)
    }
}

// SAFETY: every listed frame is a packet of its own in the receive ring of the session the
// source holds until the last of them is given back. The driver leaves a packet alone, and the
// ring stays mapped, until the packet is given back, which happens only when the source fills
// again, in `release` for the frames it covers, and when the source is dropped.
unsafe impl crate::io::Source for Source {
    /// Takes the packets in the ring, up to the capacity, without copying them.
    fn fill(&mut self, frames: &mut Vec<Loan>, stats: &mut ReaderStats) -> Filled {
        self.give_back(self.held.0.len());
        self.held.0.clear();
        self.given_back = 0;
        let Some(session) = self.tunnel.session() else {
            return Filled::dry();
        };
        let mut filled = Filled::more();
        while self.held.0.len() < self.capacity {
            let mut size = 0u32;
            // SAFETY: the session runs as long as it is held.
            let packet = unsafe { (session.wintun().receive_packet)(session.session, &mut size) };
            stats.calls += 1;
            if packet.is_null() {
                // SAFETY: reads the calling thread's last error.
                filled = match unsafe { GetLastError() } {
                    ERROR_NO_MORE_ITEMS => Filled::dry(),
                    ERROR_HANDLE_EOF => Filled::failed(gone()),
                    code => Filled::failed(Error::from_raw_os_error(code as i32)),
                };
                break;
            }
            // SAFETY: the packet is a stretch of the ring of `size` bytes, writable and lent to
            // the source alone until it is given back.
            let raw = unsafe { std::slice::from_raw_parts_mut(packet, size as usize) };
            match FRAMING.decode(raw) {
                Some(decoded) => {
                    frames.push(Loan::new(raw, decoded, None));
                    self.held.0.push(packet);
                }
                None => {
                    stats.malformed += 1;
                    // SAFETY: the packet came from this session and is given back once.
                    unsafe { (session.wintun().release_receive_packet)(session.session, packet) };
                }
            }
        }
        if !self.held.0.is_empty() {
            self.session = Some(session);
        }
        filled
    }

    fn release(&mut self, upto: usize) {
        self.give_back(upto);
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.give_back(self.held.0.len());
        self.watch.disarm();
    }
}

fn gone() -> Error {
    Error::new(ErrorKind::BrokenPipe, "the Wintun adapter is gone")
}

/// Sleeps while the send ring is full: Wintun has no event for room in the ring. The sleep is
/// as long as a flow of 8 Gbit/s takes to fill a quarter of the ring, so that the driver does
/// not run out of packets meanwhile, and the writer then finds room for many packets at once:
/// the driver takes those faster than packets that trickle in one by one. A timer of the
/// system keeps the time, to a fraction of a millisecond with any runtime and with none.
struct Backoff {
    nap: Duration,
    timer: Timer,
    watch: Watch,
    /// The timer is set and a task waits for it.
    napping: bool,
}

impl Backoff {
    fn new(ring_capacity: u32) -> Result<Backoff> {
        // 8 Gbit/s are a byte each nanosecond.
        let nap = Duration::from_nanos(u64::from(ring_capacity) / 4);
        Ok(Backoff { nap, timer: Timer::new()?, watch: Watch::new()?, napping: false })
    }

    /// A write went through: a task that waited for the timer no longer does.
    fn reset(&mut self) {
        if self.napping {
            self.watch.disarm();
            self.napping = false;
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if !self.napping {
            self.timer.set(self.nap)?;
            self.napping = true;
        }
        let timer = self.timer.handle();
        ready!(self.watch.poll_signalled(cx, timer, None, || signalled(timer)))?;
        self.napping = false;
        Poll::Ready(Ok(()))
    }

    fn block(&mut self, signal: Option<&Signal>, deadline: Option<Instant>) -> Result<()> {
        self.timer.set(self.nap)?;
        wait(Some(self.timer.handle()), signal, deadline, None)
    }
}

/// The writing end of a Wintun adapter's queue.
pub struct Sink {
    tunnel: Arc<Tun>,
    backoff: Backoff,
}

impl Sink {
    pub(super) fn new(tunnel: Arc<Tun>) -> Result<Sink> {
        let backoff = Backoff::new(tunnel.ring_capacity())?;
        Ok(Sink { tunnel, backoff })
    }
}

impl Wait for Sink {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.backoff.poll(cx)
    }

    fn wait(&mut self, signal: Option<&Signal>, deadline: Option<Instant>) -> Result<()> {
        self.backoff.block(signal, deadline)
    }
}

impl crate::io::Sink for Sink {
    fn takes(&self) -> Takes {
        Takes { framing: FRAMING, tcp: false, udp: false, udp_max_segments: 0, max_frame: MAX_PACKET }
    }

    /// Copies each write into the send ring until the ring is full. While the device is down,
    /// packets are lost.
    fn write(&mut self, list: &impl Writes, stats: &mut WriterStats) -> Result<usize> {
        let session = self.tunnel.session();
        for index in 0..list.count() {
            let mut size = 0;
            list.pieces(index, |piece| size += piece.len());
            let Some(session) = session.as_deref().filter(|_| size > 0) else {
                stats.dropped += 1;
                self.backoff.reset();
                continue;
            };
            let Some(packet) = allocate(session, size, stats)? else {
                return Ok(index);
            };
            // SAFETY: the driver lends `size` writable bytes until the packet is sent.
            let room = unsafe { std::slice::from_raw_parts_mut(packet, size) };
            let mut at = 0;
            list.pieces(index, |piece| {
                room[at..at + piece.len()].copy_from_slice(piece);
                at += piece.len();
            });
            // SAFETY: the packet came from this session's send ring and is filled in.
            unsafe { (session.wintun().send_packet)(session.session, packet) };
            stats.writes += 1;
            self.backoff.reset();
        }
        Ok(list.count())
    }

    /// Wintun takes packets for the send ring from any number of threads at once.
    fn try_clone(&self) -> Result<Sink> {
        Sink::new(self.tunnel.clone())
    }
}

/// Room for one packet in the send ring, or `None` while the ring is full.
fn allocate(session: &Session, size: usize, stats: &mut WriterStats) -> Result<Option<*mut u8>> {
    // SAFETY: the session runs while it is held.
    let packet = unsafe { (session.wintun().allocate_send_packet)(session.session, size as u32) };
    stats.calls += 1;
    if !packet.is_null() {
        return Ok(Some(packet));
    }
    // SAFETY: reads the calling thread's last error.
    match unsafe { GetLastError() } {
        ERROR_BUFFER_OVERFLOW => Ok(None),
        ERROR_HANDLE_EOF => Err(gone()),
        code => Err(Error::from_raw_os_error(code as i32)),
    }
}
