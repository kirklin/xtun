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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use xtun_wire::{Family, Framing, Prefix, Takes};

use sys::*;
#[cfg(target_os = "macos")]
pub use tap::Tap;

pub use super::bsdlike::Interface;
use super::unix::transport::{Facts, Sink, Source};
use super::unix::{Queue, read_name, set_cloexec, set_nonblocking};
use crate::device::{Offload, Options};

/// The socket buffer for packets the interface hands over; the kernel caps it at
/// `kern.ipc.maxsockbuf`.
const RECEIVE_BUFFER: libc::c_int = 8 << 20;
const RECEIVE_BUFFER_MINIMUM: libc::c_int = 1 << 20;
/// Packets the interface may queue for the reader before it pauses.
const MAX_PENDING_PACKETS: usize = 64;

/// A utun device.
pub struct Tun {
    interface: Interface,
    queue: Arc<Queue>,
    /// Whether packets pass with the address family in front; the kernel always has it there.
    packet_information: AtomicBool,
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
        let tun = Tun::wrap(connect(unit)?)?;
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
        self.interface.set_mtu(mtu)?;
        // Larger packets fit fewer to the receive buffer.
        tune(self.queue.raw_fd(), mtu as usize)
    }
}

impl super::Descriptors for Tun {
    fn queue_fd(&self, queue: usize) -> Result<BorrowedFd<'_>> {
        let fd = self.queue(queue)?.raw_fd();
        // SAFETY: the queue lives as long as the device.
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    fn into_fd(self) -> std::result::Result<OwnedFd, Tun> {
        let Tun { interface, queue, packet_information } = self;
        match Arc::try_unwrap(queue) {
            Ok(queue) => Ok(queue.into_fd()),
            Err(queue) => Err(Tun { interface, queue, packet_information }),
        }
    }
}

impl super::Adopt for Tun {
    fn adopt(fd: OwnedFd, ethernet: bool) -> Result<Tun> {
        if ethernet {
            return Err(Error::new(ErrorKind::InvalidInput, "a utun interface carries IP packets, not Ethernet frames"));
        }
        Tun::wrap(fd)
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
            return Tun::wrap(unsafe { OwnedFd::from_raw_fd(copy) });
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

    /// Wraps the control socket of a utun interface. Its flags, which every duplicate of the
    /// socket shares, change only once it is known to be one.
    fn wrap(fd: OwnedFd) -> Result<Tun> {
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
        tune(fd.as_raw_fd(), interface.mtu()? as usize)?;
        Ok(Tun { interface, queue: Arc::new(Queue::new(fd)), packet_information: AtomicBool::new(false) })
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

/// Raises the receive buffer and lets the interface queue that many packets for the reader, so
/// one `recvmsg_x` takes many. The driver queues one packet by default and pauses until it is
/// read; it drops packets once the buffer is full, so the count stays inside the buffer.
fn tune(fd: RawFd, mtu: usize) -> Result<()> {
    let mut size = RECEIVE_BUFFER;
    while size >= RECEIVE_BUFFER_MINIMUM {
        if setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size).is_ok() {
            break;
        }
        size /= 2;
    }
    let mut current: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: SO_RCVBUF writes one int.
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, (&raw mut current).cast(), &mut length) } < 0 {
        return Err(Error::last_os_error());
    }
    let pending = (current.max(0) as usize / 8 * 7 / (mtu + 4)).clamp(1, MAX_PENDING_PACKETS);
    setsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_MAX_PENDING_PACKETS, pending as libc::c_int)
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
        assert!(Tun::wrap(duplicate).is_err());
        assert!(blocking(ours.as_raw_fd()), "the socket still blocks");
    }
}
