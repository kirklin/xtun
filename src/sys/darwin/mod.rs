//! The Apple systems: `utun` interfaces behind a kernel control socket and, on macOS, pairs of
//! `feth` interfaces for Ethernet frames, which go through BPF on the second interface of the
//! pair. Configured with interface ioctls and the routing socket.

mod io;
pub(super) mod sys;
#[cfg(target_os = "macos")]
mod tap;

use std::io::{Error, ErrorKind, Result};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use xtun_wire::{Family, Framing, Prefix, Takes};

use sys::*;
#[cfg(target_os = "macos")]
pub use tap::Tap;

pub use super::bsdlike::Interface;
use super::unix::transport::{Facts, Sink, Source};
use super::unix::{Queue, read_name, set_cloexec, set_nonblocking};
use crate::device::{Offload, Options};

/// The socket buffer for packets the interface hands over, unless the builder names one; the
/// kernel caps it at `kern.ipc.maxsockbuf`.
const RECEIVE_BUFFER: libc::c_int = 8 << 20;
const RECEIVE_BUFFER_MINIMUM: libc::c_int = 1 << 20;
/// Packets the interface may queue for the reader before it pauses, unless the builder names a
/// number.
const MAX_PENDING_PACKETS: libc::c_int = 64;

/// What a utun socket was told about its receive buffer and the packets its interface queues
/// for the reader. A change of the MTU applies both again.
#[derive(Clone, Copy, Default)]
struct Tuning {
    /// The receive buffer in bytes; left out, the largest the system allows up to 8 MiB.
    receive_buffer: Option<libc::c_int>,
    /// The most packets queued for the reader; left out, 64.
    max_pending_packets: Option<libc::c_int>,
}

/// A utun device.
pub struct Tun {
    interface: Interface,
    queue: Arc<Queue>,
    /// Whether packets pass with the address family in front; the kernel always has it there.
    packet_information: AtomicBool,
    /// Held while the socket is tuned, so that what it was told and what it has agree.
    tuning: Mutex<Tuning>,
}

impl Facts for Tun {
    fn takes(&self) -> Takes {
        // Packets with the address family in front are not looked into.
        let prefix = if self.packet_information.load(Ordering::Relaxed) {
            Prefix::None
        } else {
            Prefix::Family(Family { inet: libc::AF_INET as u32, inet6: libc::AF_INET6 as u32 })
        };
        Takes { framing: Framing { prefix, ethernet: false }, tcp: false, udp: false, udp_max_segments: 0, max_frame: usize::MAX }
    }
}

impl super::Tunnel for Tun {
    type Source = Source<Tun, io::MessageReads>;
    type Sink = Sink<Tun, io::MessageWrites>;

    fn create(options: &Options) -> Result<Tun> {
        if options.queues != 1 {
            return Err(Error::new(ErrorKind::Unsupported, "these interfaces have one queue"));
        }
        if options.persist == Some(true) {
            return Err(Error::new(ErrorKind::Unsupported, "a utun interface goes away with its socket"));
        }
        let unit = match options.name.as_deref() {
            None => 0,
            Some(name) => name
                .strip_prefix("utun")
                .and_then(|number| number.parse::<u32>().ok())
                .and_then(|number| number.checked_add(1))
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "a utun interface is called utun and a number"))?,
        };
        let tuning = Tuning {
            receive_buffer: options.receive_buffer.map(|bytes| positive(bytes, "the receive buffer in bytes")).transpose()?,
            max_pending_packets: options.max_pending_packets.map(|packets| positive(packets, "the number of pending packets")).transpose()?,
        };
        let tun = Tun::wrap(connect(unit)?, tuning)?;
        tun.packet_information.store(options.packet_information, Ordering::Relaxed);
        Ok(tun)
    }

    fn queues(&self) -> usize {
        1
    }

    fn source(self: &Arc<Tun>, queue: usize, frames: usize) -> Result<Self::Source> {
        Source::new(self.clone(), self.queue(queue)?, io::MessageReads::new()?, frames)
    }

    fn sink(self: &Arc<Tun>, queue: usize) -> Result<Self::Sink> {
        Ok(Sink::new(self.clone(), self.queue(queue)?, io::MessageWrites::default()))
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn offload(&self) -> Offload {
        Offload::default()
    }

    fn packet_information(&self) -> bool {
        self.packet_information.load(Ordering::Relaxed)
    }

    fn set_persist(&self, persist: bool) -> Result<()> {
        if persist {
            return Err(Error::new(ErrorKind::Unsupported, "a utun interface goes away with its socket"));
        }
        Ok(())
    }

    fn set_mtu(&self, mtu: u32) -> Result<()> {
        let tuning = self.tuning.lock().unwrap_or_else(PoisonError::into_inner);
        self.interface.set_mtu(mtu)?;
        // Larger packets fit fewer to the receive buffer.
        tune(self.queue.raw_fd(), mtu as usize, *tuning)
    }
}

impl super::Descriptors for Tun {
    fn queue_fd(&self, queue: usize) -> Result<BorrowedFd<'_>> {
        let fd = self.queue(queue)?.raw_fd();
        // SAFETY: the queue lives as long as the device.
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    fn into_fd(self) -> std::result::Result<OwnedFd, Tun> {
        let Tun { interface, queue, packet_information, tuning } = self;
        match Arc::try_unwrap(queue) {
            Ok(queue) => Ok(queue.into_fd()),
            Err(queue) => Err(Tun { interface, queue, packet_information, tuning }),
        }
    }
}

impl super::Adopt for Tun {
    fn adopt(fd: OwnedFd, ethernet: bool) -> Result<Tun> {
        if ethernet {
            return Err(Error::new(ErrorKind::InvalidInput, "a utun interface carries IP packets, not Ethernet frames"));
        }
        Tun::wrap(fd, Tuning::default())
    }
}

impl Tun {
    /// Finds the utun interface that Network Extension opened for this process's packet
    /// tunnel provider, and adopts a duplicate of its descriptor.
    pub fn packet_tunnel() -> Result<Tun> {
        // SAFETY: plain query of the descriptor table's size.
        let limit = unsafe { libc::getdtablesize() }.max(0);
        // The id of the utun control, which a control socket of the process tells: a provider may
        // not be allowed a socket of its own to ask with. A socket that does not tell, or that
        // another thread closes meanwhile, is passed over.
        let mut utun = None;
        let mut refused = None;
        for fd in 0..limit {
            let Some(peer) = peer_control(fd) else {
                continue;
            };
            let id = match utun {
                Some(id) => id,
                None => match control_id(fd) {
                    Ok(id) => *utun.insert(id),
                    Err(error) => {
                        refused = Some(error);
                        continue;
                    }
                },
            };
            if id != peer {
                continue;
            }
            // SAFETY: duplicates a descriptor of this process; the duplicate is owned right away.
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if copy < 0 {
                return Err(Error::last_os_error());
            }
            // SAFETY: `copy` is new and owned by nobody else.
            return Tun::wrap(unsafe { OwnedFd::from_raw_fd(copy) }, Tuning::default());
        }
        Err(match refused.filter(|_| utun.is_none()) {
            Some(error) => Error::new(error.kind(), format!("no control socket of the process tells the id of the utun control: {error}")),
            None => Error::new(ErrorKind::NotFound, "the process has no utun interface"),
        })
    }

    /// Sets whether packets pass with the address family in front, from the next read and
    /// write on.
    pub fn set_packet_information(&self, on: bool) -> Result<()> {
        self.packet_information.store(on, Ordering::Relaxed);
        Ok(())
    }

    /// The receive buffer of the socket, in bytes.
    pub fn receive_buffer(&self) -> Result<u32> {
        Ok(getsockopt(self.queue.raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF)? as u32)
    }

    /// Sets the receive buffer of the socket, and limits the packets queued for the reader to
    /// what fits it. A size above what the system allows is refused.
    pub fn set_receive_buffer(&self, bytes: u32) -> Result<()> {
        let size = positive(bytes, "the receive buffer in bytes")?;
        let mut tuning = self.tuning.lock().unwrap_or_else(PoisonError::into_inner);
        let wanted = Tuning { receive_buffer: Some(size), ..*tuning };
        tune(self.queue.raw_fd(), self.interface.mtu()? as usize, wanted)?;
        *tuning = wanted;
        Ok(())
    }

    /// How many packets the interface may queue for the reader before it pauses.
    pub fn max_pending_packets(&self) -> Result<u32> {
        Ok(getsockopt(self.queue.raw_fd(), SYSPROTO_CONTROL, UTUN_OPT_MAX_PENDING_PACKETS)? as u32)
    }

    /// Sets how many packets the interface may queue for the reader: as many as fit the receive
    /// buffer at most.
    pub fn set_max_pending_packets(&self, packets: u32) -> Result<()> {
        let most = positive(packets, "the number of pending packets")?;
        let mut tuning = self.tuning.lock().unwrap_or_else(PoisonError::into_inner);
        queue_pending(self.queue.raw_fd(), self.interface.mtu()? as usize, most)?;
        tuning.max_pending_packets = Some(most);
        Ok(())
    }

    /// Wraps the control socket of a utun interface. Its flags, which every duplicate of the
    /// socket shares, change only once it is known to be one.
    fn wrap(fd: OwnedFd, tuning: Tuning) -> Result<Tun> {
        let utun = match peer_control(fd.as_raw_fd()) {
            Some(peer) => control_id(fd.as_raw_fd())? == peer,
            None => false,
        };
        if !utun {
            return Err(Error::new(ErrorKind::InvalidInput, "the descriptor is not a utun interface"));
        }
        let name = interface_name(fd.as_raw_fd())?;
        set_nonblocking(fd.as_raw_fd())?;
        set_cloexec(fd.as_raw_fd())?;
        let interface = Interface::new(&name, false)?;
        tune(fd.as_raw_fd(), interface.mtu()? as usize, tuning)?;
        Ok(Tun { interface, queue: Arc::new(Queue::new(fd)), packet_information: AtomicBool::new(false), tuning: Mutex::new(tuning) })
    }

    fn queue(&self, queue: usize) -> Result<&Arc<Queue>> {
        one_queue(&self.queue, queue)
    }
}

/// The queue of a device with one, when `queue` asks for it.
fn one_queue(only: &Arc<Queue>, queue: usize) -> Result<&Arc<Queue>> {
    if queue != 0 {
        return Err(Error::new(ErrorKind::InvalidInput, format!("the device has one queue, there is no queue {queue}")));
    }
    Ok(only)
}

/// The id of the kernel control that `fd` is connected to, if it is a kernel control socket.
fn peer_control(fd: RawFd) -> Option<u32> {
    // SAFETY: plain old data.
    let mut address: sockaddr_ctl = unsafe { zeroed() };
    let mut length = size_of::<sockaddr_ctl>() as libc::socklen_t;
    // SAFETY: `address` is writable for `length` bytes; a descriptor that is not a socket fails.
    if unsafe { libc::getpeername(fd, (&raw mut address).cast(), &mut length) } < 0 {
        return None;
    }
    (i32::from(address.sc_family) == AF_SYSTEM && address.ss_sysaddr == AF_SYS_CONTROL).then_some(address.sc_id)
}

/// The id of the utun kernel control, asked through the kernel control socket `fd`.
fn control_id(fd: RawFd) -> Result<u32> {
    // SAFETY: plain old data.
    let mut info: ctl_info = unsafe { zeroed() };
    for (slot, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: CTLIOCGINFO reads the name and writes the id.
    if unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(info.ctl_id)
}

/// Opens a kernel control socket to the utun driver; unit 0 lets the kernel pick the interface.
fn connect(unit: u32) -> Result<OwnedFd> {
    // SAFETY: plain socket creation.
    let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `fd` is new and owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // The system makes no socket with the flag set; it is set before the socket has an interface
    // that a program started meanwhile would keep.
    set_cloexec(fd.as_raw_fd())?;
    let id = control_id(fd.as_raw_fd())?;
    let address = sockaddr_ctl {
        sc_len: size_of::<sockaddr_ctl>() as u8,
        sc_family: AF_SYSTEM as u8,
        ss_sysaddr: AF_SYS_CONTROL,
        sc_id: id,
        sc_unit: unit,
        sc_reserved: [0; 5],
    };
    // SAFETY: `address` is a complete `sockaddr_ctl` of the length given.
    let connected = unsafe {
        libc::connect(fd.as_raw_fd(), (&raw const address).cast(), size_of::<sockaddr_ctl>() as libc::socklen_t)
    };
    if connected < 0 {
        let error = Error::last_os_error();
        return Err(Error::new(error.kind(), format!("creating the utun interface: {error}")));
    }
    Ok(fd)
}

fn interface_name(fd: RawFd) -> Result<String> {
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    // SAFETY: the option writes at most `length` bytes into `name`.
    if unsafe { libc::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name.as_mut_ptr().cast(), &mut length) } < 0 {
        let error = Error::last_os_error();
        return Err(Error::new(error.kind(), format!("the descriptor is not a utun interface: {error}")));
    }
    Ok(read_name(&name))
}

/// `value` as the system takes it: an `int` above zero.
fn positive(value: u32, what: &str) -> Result<libc::c_int> {
    libc::c_int::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("{what} is between 1 and {}", libc::c_int::MAX)))
}

/// Sets the receive buffer and lets the interface queue packets for the reader, so one
/// `recvmsg_x` takes many. The driver queues one packet by default and pauses until it is read.
fn tune(fd: RawFd, mtu: usize, tuning: Tuning) -> Result<()> {
    match tuning.receive_buffer {
        Some(size) => exact_receive_buffer(fd, size)?,
        None => large_receive_buffer(fd, RECEIVE_BUFFER, RECEIVE_BUFFER_MINIMUM)?,
    }
    queue_pending(fd, mtu, tuning.max_pending_packets.unwrap_or(MAX_PENDING_PACKETS))
}

/// Gives the socket a receive buffer of `size` bytes. The system cuts a size above its limit,
/// `kern.ipc.maxsockbuf`, down to the limit without a word: such a size is refused here, and the
/// socket keeps the buffer it had.
fn exact_receive_buffer(fd: RawFd, size: libc::c_int) -> Result<()> {
    let before = getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)?;
    setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size)
        .map_err(|error| Error::new(error.kind(), format!("a receive buffer of {size} bytes: {error}")))?;
    let given = getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)?;
    if given != size {
        setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, before)?;
        return Err(Error::new(ErrorKind::InvalidInput, format!("the system gives a receive buffer of {given} bytes at most")));
    }
    Ok(())
}

/// Gives the socket the largest receive buffer the system allows, from `most` bytes down to
/// `least`. The system cuts a size above its limit down to the limit, and refuses it for a
/// socket that is at the limit already: a socket keeps a buffer that is larger than the next
/// size to try.
fn large_receive_buffer(fd: RawFd, most: libc::c_int, least: libc::c_int) -> Result<()> {
    let mut size = most;
    while size >= least && getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)? < size {
        if setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size).is_ok() {
            break;
        }
        size /= 2;
    }
    Ok(())
}

/// Lets the interface queue up to `most` packets for the reader, and no more than fit the
/// receive buffer: the driver drops packets once the buffer is full.
fn queue_pending(fd: RawFd, mtu: usize, most: libc::c_int) -> Result<()> {
    let buffer = getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF)?;
    setsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_MAX_PENDING_PACKETS, pending(buffer, mtu, most))
}

/// How many packets of `mtu` bytes a receive buffer of `buffer` bytes has room for: `most` at
/// most, and one at least.
fn pending(buffer: libc::c_int, mtu: usize, most: libc::c_int) -> libc::c_int {
    let fit = buffer.max(0) as usize / 8 * 7 / mtu.saturating_add(4);
    libc::c_int::try_from(fit).unwrap_or(libc::c_int::MAX).clamp(1, most)
}

fn getsockopt(fd: RawFd, level: libc::c_int, option: libc::c_int) -> Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the option writes one int.
    let got = unsafe { libc::getsockopt(fd, level, option, (&raw mut value).cast(), &mut length) };
    if got < 0 { Err(Error::last_os_error()) } else { Ok(value) }
}

fn setsockopt(fd: RawFd, level: libc::c_int, option: libc::c_int, value: libc::c_int) -> Result<()> {
    // SAFETY: the option reads one int.
    let set = unsafe {
        libc::setsockopt(fd, level, option, (&raw const value).cast(), size_of::<libc::c_int>() as libc::socklen_t)
    };
    if set < 0 { Err(Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A descriptor that is no utun socket is refused before anything changes the flags that
    /// its duplicates share.
    #[test]
    fn a_descriptor_that_is_no_utun_socket_keeps_its_flags() {
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let blocking = |fd: RawFd| {
            // SAFETY: F_GETFL takes no argument.
            unsafe { libc::fcntl(fd, libc::F_GETFL) & libc::O_NONBLOCK == 0 }
        };
        assert!(blocking(ours.as_raw_fd()));
        let duplicate = OwnedFd::from(ours.try_clone().unwrap());
        assert!(Tun::wrap(duplicate, Tuning::default()).is_err());
        assert!(blocking(ours.as_raw_fd()), "the socket still blocks");
    }

    /// A receive buffer or a number of pending packets that the system could not take is
    /// refused before an interface is made.
    #[test]
    fn a_receive_buffer_and_a_number_of_pending_packets_are_above_zero() {
        for refused in [
            crate::Tun::builder().receive_buffer(0),
            crate::Tun::builder().receive_buffer(u32::MAX),
            crate::Tun::builder().max_pending_packets(0),
            crate::Tun::builder().max_pending_packets(u32::MAX),
        ] {
            assert_eq!(refused.build().unwrap_err().kind(), ErrorKind::InvalidInput);
        }
    }

    /// The receive buffer of a datagram socket of the system's own.
    fn buffer_of(socket: &std::os::unix::net::UnixDatagram) -> libc::c_int {
        getsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap()
    }

    #[test]
    fn a_receive_buffer_above_the_limit_of_the_system_is_refused_and_leaves_the_one_before() {
        let (socket, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
        exact_receive_buffer(socket.as_raw_fd(), 256 << 10).unwrap();
        assert_eq!(buffer_of(&socket), 256 << 10);
        assert!(exact_receive_buffer(socket.as_raw_fd(), libc::c_int::MAX).is_err());
        assert_eq!(buffer_of(&socket), 256 << 10);
    }

    /// The system refuses a size above its limit for a socket that is at the limit, and takes
    /// a smaller one: a socket that got the largest buffer keeps it when it is tuned again.
    #[test]
    fn a_socket_keeps_the_largest_receive_buffer_when_it_is_tuned_again() {
        let (socket, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
        large_receive_buffer(socket.as_raw_fd(), libc::c_int::MAX, 1).unwrap();
        let largest = buffer_of(&socket);
        assert!(largest > 4096, "the buffer grew: {largest}");
        large_receive_buffer(socket.as_raw_fd(), libc::c_int::MAX, 1).unwrap();
        assert_eq!(buffer_of(&socket), largest);
    }

    #[test]
    fn the_packets_queued_for_the_reader_fit_the_receive_buffer() {
        // A buffer with room to spare queues as many packets as it is told.
        assert_eq!(pending(8 << 20, 1500, 64), 64);
        assert_eq!(pending(8 << 20, 1500, 16), 16);
        assert_eq!(pending(4 << 20, 1500, 1000), 1000);
        // One with less room queues what fits seven eighths of it.
        assert_eq!(pending(256 << 10, 1500, 1000), 152);
        assert_eq!(pending(256 << 10, 3000, 100), 76);
        assert_eq!(pending(8192, 1500, 64), 4);
        // One packet is queued at least.
        assert_eq!(pending(512, 1500, 64), 1);
        assert_eq!(pending(0, 1500, 64), 1);
    }
}
