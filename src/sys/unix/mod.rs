//! What the Unix systems share: descriptors watched by Tokio or async-io, waits without a
//! runtime, interrupts, and the one way their queues move frames.

pub mod transport;

use std::io::{self, ErrorKind};
#[cfg(any(feature = "tokio", feature = "async-io"))]
use std::os::fd::{AsFd, BorrowedFd};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Instant;

/// A descriptor number for a reactor, which watches the descriptor but does not own it: the
/// queue does, and drops the reactor first.
#[cfg(any(feature = "tokio", feature = "async-io"))]
pub(crate) struct Watched(RawFd);

#[cfg(any(feature = "tokio", feature = "async-io"))]
impl AsRawFd for Watched {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(any(feature = "tokio", feature = "async-io"))]
impl AsFd for Watched {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the queue keeps the descriptor open for as long as the reactor exists.
        unsafe { BorrowedFd::borrow_raw(self.0) }
    }
}

/// The reactor that wakes a queue's reader and writer: Tokio's inside a Tokio runtime,
/// async-io's elsewhere.
pub(crate) enum Reactor {
    #[cfg(feature = "tokio")]
    Tokio(tokio::io::unix::AsyncFd<Watched>),
    #[cfg(feature = "async-io")]
    AsyncIo(async_io::Async<Watched>),
}

/// What a reactor watches a descriptor for.
#[derive(Clone, Copy)]
enum Watches {
    /// Readability: the descriptor never reports writability.
    #[cfg(target_os = "macos")]
    Read,
    /// Readability and writability: the descriptor of a queue's reader and its first writer.
    Both,
    /// Writability: the descriptor of one more writer.
    Write,
}

impl Reactor {
    /// Watches `fd` for what `watches` says.
    fn new(fd: RawFd, watches: Watches) -> io::Result<Reactor> {
        #[cfg(feature = "tokio")]
        if tokio::runtime::Handle::try_current().is_ok() {
            use tokio::io::Interest;
            let interest = match watches {
                #[cfg(target_os = "macos")]
                Watches::Read => Interest::READABLE,
                Watches::Both => Interest::READABLE | Interest::WRITABLE,
                Watches::Write => Interest::WRITABLE,
            };
            // SAFETY: the queue keeps the descriptor open, and does not change what it refers
            // to, for as long as the reactor that holds the registration.
            let fd = unsafe { tokio::io::unix::AsyncFd::register_with_interest(Watched(fd), interest) }
                .map_err(|error| error.into_parts().1)?;
            return Ok(Reactor::Tokio(fd));
        }
        // async-io watches for readability or writability only while a task waits for it.
        let _ = watches;
        #[cfg(feature = "async-io")]
        return Ok(Reactor::AsyncIo(async_io::Async::new_nonblocking(Watched(fd))?));
        #[cfg(not(feature = "async-io"))]
        {
            let _ = fd;
            Err(io::Error::new(ErrorKind::Unsupported, crate::NO_RUNTIME))
        }
    }

    /// Resolves once the descriptor may be readable, or writable with `write`, after an attempt
    /// found it was not. What the reactor remembered of its readiness is used up by the call,
    /// so an attempt has to follow: Tokio forgets only what it saw before this call, and an
    /// attempt made after it meets everything that came before.
    pub fn poll_ready(&self, cx: &mut Context<'_>, write: bool) -> Poll<io::Result<()>> {
        #[cfg(not(any(feature = "tokio", feature = "async-io")))]
        let _ = (cx, write);
        match *self {
            #[cfg(feature = "tokio")]
            Reactor::Tokio(ref fd) => {
                let mut guard = std::task::ready!(if write { fd.poll_write_ready(cx) } else { fd.poll_read_ready(cx) })?;
                guard.clear_ready();
                Poll::Ready(Ok(()))
            }
            #[cfg(feature = "async-io")]
            Reactor::AsyncIo(ref source) => {
                if write {
                    source.poll_writable(cx)
                } else {
                    source.poll_readable(cx)
                }
            }
        }
    }

    /// Resolves once the descriptor reports an error condition, which a TUN device whose
    /// interface was deleted reports instead of readability.
    #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
    pub fn gone(self: Arc<Reactor>) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>> {
        self.tokio()?;
        Some(Box::pin(async move {
            if let Some(fd) = self.tokio() {
                let _ = fd.ready(tokio::io::Interest::ERROR).await;
            }
        }))
    }

    #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
    fn tokio(&self) -> Option<&tokio::io::unix::AsyncFd<Watched>> {
        match self {
            Reactor::Tokio(fd) => Some(fd),
            #[cfg(feature = "async-io")]
            Reactor::AsyncIo(_) => None,
        }
    }
}

/// A queue's descriptor, and the reactor that watches it once a reader or writer first waits
/// asynchronously.
pub(crate) struct Queue {
    reactor: Mutex<Option<Arc<Reactor>>>,
    fd: OwnedFd,
    /// What the reactor watches the descriptor for.
    watches: Watches,
}

impl Queue {
    pub fn new(fd: OwnedFd) -> Queue {
        Queue { reactor: Mutex::new(None), fd, watches: Watches::Both }
    }

    /// A queue whose descriptor reports only readability, such as a BPF device, whose writes
    /// never wait.
    #[cfg(target_os = "macos")]
    pub fn read_only_readiness(fd: OwnedFd) -> Queue {
        Queue { watches: Watches::Read, ..Queue::new(fd) }
    }

    /// The same queue behind a descriptor of its own, for one more writer. A reactor wakes one
    /// task that waits to write on a descriptor, so every writer that may wait at the same
    /// time as another has its own descriptor and its own reactor, which watches for
    /// writability alone: frames that arrive do not wake it.
    pub fn for_writer(&self) -> io::Result<Queue> {
        let watches = match self.watches {
            // Such a queue's writers never wait.
            #[cfg(target_os = "macos")]
            Watches::Read => Watches::Read,
            Watches::Both | Watches::Write => Watches::Write,
        };
        Ok(Queue { reactor: Mutex::new(None), fd: self.fd.try_clone()?, watches })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The descriptor, after the reactor let go of it.
    pub fn into_fd(self) -> OwnedFd {
        drop(self.reactor);
        self.fd
    }

    /// The reactor, set up on the first call.
    pub fn reactor(&self) -> io::Result<Arc<Reactor>> {
        let mut slot = self.reactor.lock().expect("queue reactor");
        if let Some(reactor) = &*slot {
            return Ok(reactor.clone());
        }
        let reactor = Arc::new(Reactor::new(self.fd.as_raw_fd(), self.watches)?);
        *slot = Some(reactor.clone());
        Ok(reactor)
    }
}

/// One end of a queue: its descriptor and how that end waits for it. The fields that hold the
/// reactor come before the queue, which may be this end's alone: the reactor lets go of the
/// descriptor before the descriptor is closed.
pub(crate) struct Port {
    /// Resolves when the interface is deleted: the queue then reports only an error condition,
    /// which Tokio's readability does not cover.
    #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
    gone: Option<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>,
    /// The queue's reactor, looked up when the end first waits asynchronously.
    reactor: Option<Arc<Reactor>>,
    /// The writing end.
    write: bool,
    /// The queue reported the error condition. The kernel reports it a moment before reads
    /// fail, and nothing after: from then on every wait is over at once, until a read fails.
    #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
    going: bool,
    queue: Arc<Queue>,
}

impl Port {
    pub fn new(queue: Arc<Queue>, write: bool) -> Port {
        Port {
            #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
            gone: None,
            reactor: None,
            write,
            #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
            going: false,
            queue,
        }
    }

    /// One more writing end of the same queue, behind a descriptor of its own.
    pub fn for_writer(&self) -> io::Result<Port> {
        Ok(Port::new(Arc::new(self.queue.for_writer()?), true))
    }

    pub fn fd(&self) -> RawFd {
        self.queue.raw_fd()
    }

    /// [`crate::io::Wait::poll_ready`] for this end.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.reactor.is_none() {
            let reactor = self.queue.reactor()?;
            #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
            if !self.write {
                self.gone = reactor.clone().gone();
            }
            self.reactor = Some(reactor);
        }
        #[cfg(all(feature = "tokio", any(target_os = "linux", target_os = "android")))]
        {
            if let Some(gone) = &mut self.gone
                && gone.as_mut().poll(cx).is_ready()
            {
                self.gone = None;
                self.going = true;
            }
            if self.going {
                // An attempt that follows meets the error, at once or a moment later.
                return Poll::Ready(Ok(()));
            }
        }
        self.reactor.as_ref().expect("the reactor was looked up").poll_ready(cx, self.write)
    }

    /// [`crate::io::Wait::wait`] for this end.
    pub fn wait(&self, signal: Option<&Signal>, deadline: Option<Instant>) -> io::Result<()> {
        wait(self.fd(), if self.write { libc::POLLOUT } else { libc::POLLIN }, signal, deadline)
    }
}

/// What an interrupt is made of: a descriptor that turns readable once it is triggered.
pub struct Signal {
    read: OwnedFd,
    /// The other end of a pipe; an eventfd is both ends.
    write: Option<OwnedFd>,
    /// Whether the interrupt is triggered: the descriptor is readable while it is.
    set: AtomicBool,
    /// Held while a trigger or a reset changes the flag and the descriptor, so that one that
    /// comes at the same time finds both changed or neither.
    changing: Mutex<()>,
}

impl Signal {
    pub fn new() -> io::Result<Signal> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: plain eventfd creation; the descriptor is owned right away.
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is new and owned by nobody else.
            Ok(Signal { read: unsafe { OwnedFd::from_raw_fd(fd) }, write: None, set: AtomicBool::new(false), changing: Mutex::new(()) })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let (read, write) = pipe()?;
            Ok(Signal { read, write: Some(write), set: AtomicBool::new(false), changing: Mutex::new(()) })
        }
    }

    pub fn fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }

    /// Makes the descriptor readable, then sets the flag.
    pub fn trigger(&self) -> io::Result<()> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        if self.set.load(Ordering::Acquire) {
            return Ok(());
        }
        let one = 1u64.to_ne_bytes();
        let (fd, bytes) = match &self.write {
            Some(write) => (write.as_raw_fd(), &one[..1]),
            None => (self.read.as_raw_fd(), &one[..]),
        };
        // SAFETY: `bytes` is readable for its length.
        transport::retry(|| unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) })?;
        self.set.store(true, Ordering::Release);
        Ok(())
    }

    /// Empties the descriptor, then clears the flag.
    pub fn reset(&self) -> io::Result<()> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.set.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut sink = [0u8; 64];
        loop {
            // SAFETY: `sink` is writable for its length.
            let read = unsafe { libc::read(self.read.as_raw_fd(), sink.as_mut_ptr().cast(), sink.len()) };
            if read <= 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    ErrorKind::WouldBlock => break,
                    ErrorKind::Interrupted => continue,
                    _ if read == 0 => break,
                    _ => return Err(error),
                }
            }
        }
        self.set.store(false, Ordering::Release);
        Ok(())
    }
}

/// Creates a pipe whose ends do not block and are closed on exec.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` holds two descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are new and owned by nobody else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&read, &write] {
        set_nonblocking(fd.as_raw_fd())?;
        set_cloexec(fd.as_raw_fd())?;
    }
    Ok((read, write))
}

/// Blocks until `fd` is ready for `events`, the interrupt is triggered or the deadline passes.
/// An error condition on `fd` counts as ready, so that the next attempt reports it.
pub(crate) fn wait(fd: RawFd, events: libc::c_short, signal: Option<&Signal>, deadline: Option<Instant>) -> io::Result<()> {
    let mut fds = [
        libc::pollfd { fd, events, revents: 0 },
        libc::pollfd { fd: signal.map_or(-1, Signal::fd), events: libc::POLLIN, revents: 0 },
    ];
    loop {
        if signal.is_some_and(Signal::is_set) {
            return Err(interrupted());
        }
        let timeout = match deadline {
            None => -1,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(ErrorKind::TimedOut, "the wait timed out"));
                }
                // Rounded up, so that a wait never ends before its deadline.
                left.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as libc::c_int
            }
        };
        // SAFETY: `fds` holds two entries; a negative descriptor is skipped.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if fds[1].revents != 0 {
            return Err(interrupted());
        }
        if fds[0].revents != 0 {
            return Ok(());
        }
    }
}

pub(crate) fn interrupted() -> io::Error {
    io::Error::new(ErrorKind::Interrupted, "the wait was interrupted")
}

pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL take and return plain integers.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFD and F_SETFD take and return plain integers.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The index of the interface called `name`.
pub(crate) fn index_of(name: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(name).map_err(|_| io::Error::new(ErrorKind::InvalidInput, "the name has a NUL byte"))?;
    // SAFETY: `name` is a NUL-terminated string that lives through the call.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}

/// Copies an interface name into the fixed array of an `ifreq`.
pub(crate) fn copy_name(name: &str, out: &mut [libc::c_char]) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= out.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("an interface name has 1 to {} bytes and no NUL", out.len() - 1),
        ));
    }
    out.fill(0);
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    Ok(())
}

/// Reads the NUL-terminated name in an `ifreq`.
pub(crate) fn read_name(name: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = name.iter().take_while(|byte| **byte != 0).map(|byte| byte.to_ne_bytes()[0]).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A socket for interface ioctls.
#[cfg(any(target_vendor = "apple", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd", target_os = "illumos"))]
pub(crate) fn control_socket(family: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain socket creation; the descriptor is owned right away.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor nobody else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    set_cloexec(fd.as_raw_fd())?;
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wait_ends_on_the_interrupt_or_the_deadline() {
        let (read, _write) = std::os::unix::net::UnixStream::pair().unwrap();
        let signal = Signal::new().unwrap();
        let soon = Some(Instant::now() + std::time::Duration::from_millis(20));
        let error = wait(read.as_raw_fd(), libc::POLLIN, Some(&signal), soon).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        signal.trigger().unwrap();
        let error = wait(read.as_raw_fd(), libc::POLLIN, Some(&signal), None).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Interrupted);
        signal.reset().unwrap();
        let error = wait(read.as_raw_fd(), libc::POLLIN, Some(&signal), soon).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut, "a reset interrupt lets waits go on");
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn the_writers_of_a_queue_each_wait_for_room() {
        use std::io::Read;
        let (ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let first = Port::new(Arc::new(Queue::new(OwnedFd::from(ours))), true);
        let second = first.for_writer().unwrap();
        assert_ne!(first.fd(), second.fd(), "one more writer has a descriptor of its own");
        let chunk = [0u8; 4096];
        let mut written = 0;
        loop {
            // SAFETY: `chunk` is readable for its length.
            let wrote = unsafe { libc::write(second.fd(), chunk.as_ptr().cast(), chunk.len()) };
            if wrote < 0 {
                assert_eq!(io::Error::last_os_error().kind(), ErrorKind::WouldBlock);
                break;
            }
            written += wrote as usize;
        }
        let waits = [first, second].map(|mut port| {
            tokio::spawn(async move {
                std::future::poll_fn(|cx| port.poll_ready(cx)).await.unwrap();
                port
            })
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(waits.iter().all(|wait| !wait.is_finished()), "neither writer has room while the queue is full");
        let mut taken = vec![0u8; written];
        theirs.read_exact(&mut taken).unwrap();
        for wait in waits {
            tokio::time::timeout(std::time::Duration::from_secs(5), wait).await.expect("each writer is woken once there is room").unwrap();
        }
    }

    /// However triggers and resets from several threads interleave, the flag and the descriptor
    /// agree once they are done.
    #[test]
    fn an_interrupt_that_threads_trigger_and_reset_at_once_stays_whole() {
        let (read, _write) = std::os::unix::net::UnixStream::pair().unwrap();
        let signal = Signal::new().unwrap();
        for _ in 0..200 {
            std::thread::scope(|scope| {
                for thread in 0..4 {
                    let signal = &signal;
                    scope.spawn(move || {
                        for turn in 0..250 {
                            if (turn + thread) % 2 == 0 { signal.trigger().unwrap() } else { signal.reset().unwrap() }
                        }
                    });
                }
            });
            signal.reset().unwrap();
            let soon = Some(Instant::now() + std::time::Duration::from_millis(1));
            let error = wait(read.as_raw_fd(), libc::POLLIN, Some(&signal), soon).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::TimedOut, "a reset interrupt lets waits go on");
            signal.trigger().unwrap();
            let error = wait(read.as_raw_fd(), libc::POLLIN, Some(&signal), soon).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Interrupted, "a triggered interrupt ends waits");
        }
    }

    #[test]
    fn a_wait_ends_when_the_descriptor_is_ready() {
        use std::io::Write;
        let (read, mut write) = std::os::unix::net::UnixStream::pair().unwrap();
        write.write_all(b"x").unwrap();
        wait(read.as_raw_fd(), libc::POLLIN, None, None).unwrap();
    }
}
