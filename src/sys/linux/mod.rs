//! Linux and Android: `/dev/net/tun`, which Android has as `/dev/tun`, with `IFF_VNET_HDR`
//! offloads and multiple queues. TUN and TAP interfaces are the same device, opened with
//! another flag.

mod interface;
mod netlink;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod uring;
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
#[path = "nouring.rs"]
mod uring;

use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, RwLock};

use xtun_wire::{Framing, MAX_PREFIX, Prefix, Takes, VIRTIO_HEADER};

pub use interface::Interface;

use super::unix::transport::{Facts, Sink, Source};
use super::unix::{Queue, copy_name, index_of, read_name, set_nonblocking};
use crate::device::{Offload, Options};

/// Stop the queue instead of dropping packets when the ring is full (Linux 7.3).
const IFF_BACKPRESSURE: libc::c_int = 0x0080;
/// Fail instead of attaching to an interface that exists.
const IFF_TUN_EXCL: libc::c_int = 0x8000;
const TUN_F_TCP: libc::c_uint = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6 | libc::TUN_F_TSO_ECN;
const TUN_F_UDP: libc::c_uint = libc::TUN_F_USO4 | libc::TUN_F_USO6;

/// A TUN or TAP device.
pub struct Tunnel {
    interface: Interface,
    /// The device carries Ethernet frames.
    ethernet: bool,
    /// The flags the queues are opened with, for opening more.
    flags: libc::c_int,
    /// Queues are only ever added, so a queue lives as long as the device.
    queues: RwLock<Vec<Arc<Queue>>>,
    /// The size of the `virtio_net_hdr` in front of every frame, or zero without offloads.
    vnet_len: usize,
    offload: Offload,
    packet_information: bool,
    udp_max_segments: usize,
    uring: bool,
}

impl Facts for Tunnel {
    fn takes(&self) -> Takes {
        let prefix = if self.vnet_len > 0 { Prefix::Virtio(self.vnet_len) } else { Prefix::None };
        Takes {
            // Frames with packet information in front are not looked into.
            framing: Framing { prefix, ethernet: self.ethernet && !self.packet_information },
            tcp: self.offload.tcp,
            udp: self.offload.udp,
            udp_max_segments: self.udp_max_segments,
            // The system refuses what is too long for the interface, write by write.
            max_frame: usize::MAX,
        }
    }
}

impl super::Tunnel for Tunnel {
    type Source = Source<Tunnel, uring::Reads>;
    type Sink = Sink<Tunnel, uring::Writes>;

    fn create(options: &Options) -> Result<Tunnel> {
        let probe = open_tun()?;
        let mut features: libc::c_uint = 0;
        // SAFETY: TUNGETFEATURES writes one unsigned int.
        if unsafe { libc::ioctl(probe.as_raw_fd(), libc::TUNGETFEATURES, &mut features) } < 0 {
            return Err(Error::last_os_error());
        }
        drop(probe);
        let features = features as libc::c_int;
        let mut flags = if options.ethernet { libc::IFF_TAP } else { libc::IFF_TUN };
        if !options.packet_information {
            flags |= libc::IFF_NO_PI;
        }
        // Frames with packet information are taken as they are, so they carry no virtio header.
        if options.offload && !options.packet_information {
            flags |= libc::IFF_VNET_HDR;
        }
        if options.queues > 1 {
            flags |= libc::IFF_MULTI_QUEUE;
        }
        if options.backpressure && features & IFF_BACKPRESSURE != 0 {
            flags |= IFF_BACKPRESSURE;
        }
        if flags & !features != 0 {
            return Err(Error::new(ErrorKind::Unsupported, format!("the kernel's TUN driver lacks the features {:#x}", flags & !features)));
        }
        // The driver takes it without listing it among its features.
        let exclusive = if options.reuse { 0 } else { IFF_TUN_EXCL };

        let (first, name) = attach(options.name.as_deref(), flags | exclusive)?;
        let mut fds = vec![first];
        for _ in 1..options.queues {
            fds.push(attach(Some(&name), flags)?.0);
        }
        let (vnet_len, offload) =
            if flags & libc::IFF_VNET_HDR != 0 { (vnet_size(fds[0].as_raw_fd())?, negotiate(fds[0].as_raw_fd())?) } else { (0, Offload::default()) };
        Ok(Tunnel {
            interface: Interface::new(index_of(&name)?),
            ethernet: options.ethernet,
            flags,
            queues: RwLock::new(fds.into_iter().map(|fd| Arc::new(Queue::new(fd))).collect()),
            vnet_len,
            offload,
            packet_information: options.packet_information,
            udp_max_segments: udp_max_segments(),
            uring: uring::choose(options)?,
        })
    }

    fn queues(&self) -> usize {
        self.queues.read().expect("queues").len()
    }

    fn source(self: &Arc<Tunnel>, queue: usize, frames: usize) -> Result<Self::Source> {
        let reads = uring::Reads::new(self.uring, frames)?;
        Source::new(self.clone(), &self.queue(queue)?, reads, frames)
    }

    fn sink(self: &Arc<Tunnel>, queue: usize) -> Result<Self::Sink> {
        let writes = uring::Writes::new(self.uring)?;
        Ok(Sink::new(self.clone(), &self.queue(queue)?, writes))
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn offload(&self) -> Offload {
        self.offload
    }

    fn packet_information(&self) -> bool {
        self.packet_information
    }

    fn set_persist(&self, persist: bool) -> Result<()> {
        self.tun_ioctl(libc::TUNSETPERSIST, libc::c_ulong::from(persist))
    }

    fn prepare(&self, options: &Options) -> Result<()> {
        if let Some(length) = options.tx_queue_len {
            self.interface.set_tx_queue_len(length)?;
        }
        if let Some(uid) = options.owner {
            self.set_owner(uid)?;
        }
        if let Some(gid) = options.group {
            self.set_group(gid)?;
        }
        Ok(())
    }
}

impl super::Descriptors for Tunnel {
    fn queue_fd(&self, queue: usize) -> Result<BorrowedFd<'_>> {
        let fd = self.queue(queue)?.raw_fd();
        // SAFETY: queues are never removed, so the descriptor stays open as long as the device.
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    fn into_fd(self) -> std::result::Result<OwnedFd, Tunnel> {
        if self.queues.read().expect("queues").len() != 1 {
            return Err(self);
        }
        let queue = self.queues.write().expect("queues").pop().expect("one queue");
        match Arc::try_unwrap(queue) {
            Ok(queue) => Ok(queue.into_fd()),
            Err(queue) => {
                self.queues.write().expect("queues").push(queue);
                Err(self)
            }
        }
    }
}

impl super::Adopt for Tunnel {
    fn adopt(fd: OwnedFd, ethernet: bool) -> Result<Tunnel> {
        let (name, flags) = match get_iff(fd.as_raw_fd()) {
            Ok(found) => found,
            // An application on Android or OpenHarmony may not be allowed to ask; the system's
            // VPN interface is a TUN interface without packet information or virtio header.
            Err(error) if refused_to_application(&error) => (String::new(), libc::IFF_TUN | libc::IFF_NO_PI),
            Err(error) => return Err(error),
        };
        set_nonblocking(fd.as_raw_fd())?;
        if (flags & libc::IFF_TAP != 0) != ethernet {
            let (is, wanted) = if ethernet { ("TUN", "TAP") } else { ("TAP", "TUN") };
            return Err(Error::new(ErrorKind::InvalidInput, format!("the descriptor is of a {is} interface, not of a {wanted} interface")));
        }
        let (vnet_len, offload) = if flags & libc::IFF_VNET_HDR != 0 {
            (vnet_size(fd.as_raw_fd())?, negotiate(fd.as_raw_fd())?)
        } else {
            (0, Offload::default())
        };
        // The interface is known by its name where it lives: one of the same name in another
        // network namespace is another interface.
        let index = if name.is_empty() || !lives_here(fd.as_raw_fd())? {
            0
        } else {
            match index_of(&name) {
                Ok(index) => index,
                Err(error) if refused_to_application(&error) => 0,
                Err(error) => return Err(error),
            }
        };
        Ok(Tunnel {
            interface: Interface::new(index),
            ethernet,
            flags: flags & !libc::IFF_PERSIST,
            queues: RwLock::new(vec![Arc::new(Queue::new(fd))]),
            vnet_len,
            offload,
            packet_information: flags & libc::IFF_NO_PI == 0,
            udp_max_segments: udp_max_segments(),
            uring: uring::usable(),
        })
    }
}

impl Tunnel {
    pub fn set_owner(&self, uid: u32) -> Result<()> {
        self.tun_ioctl(libc::TUNSETOWNER, libc::c_ulong::from(uid))
    }

    pub fn set_group(&self, gid: u32) -> Result<()> {
        self.tun_ioctl(libc::TUNSETGROUP, libc::c_ulong::from(gid))
    }

    /// Opens one more queue of a device made with several, and returns its number.
    pub fn add_queue(&self) -> Result<usize> {
        if self.flags & libc::IFF_MULTI_QUEUE == 0 {
            return Err(Error::new(ErrorKind::Unsupported, "the device was made with one queue"));
        }
        let (fd, _) = attach(Some(&self.interface.name()?), self.flags)?;
        let mut queues = self.queues.write().expect("queues");
        queues.push(Arc::new(Queue::new(fd)));
        Ok(queues.len() - 1)
    }

    /// A TUN ioctl that takes its argument by value, on the first queue.
    fn tun_ioctl(&self, request: libc::Ioctl, value: libc::c_ulong) -> Result<()> {
        let fd = self.queue(0)?.raw_fd();
        // SAFETY: the request takes its argument by value.
        if unsafe { libc::ioctl(fd, request, value) } < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    fn queue(&self, queue: usize) -> Result<Arc<Queue>> {
        let queues = self.queues.read().expect("queues");
        queues.get(queue).cloned().ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, format!("the device has {} queues, there is no queue {queue}", queues.len()))
        })
    }
}

/// The device that hands out interfaces, which Android keeps at a place of its own.
const CLONE_DEVICE: &std::ffi::CStr = if cfg!(target_os = "android") { c"/dev/tun" } else { c"/dev/net/tun" };

fn open_tun() -> Result<OwnedFd> {
    // SAFETY: a plain open of a NUL-terminated path.
    let fd = unsafe { libc::open(CLONE_DEVICE.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if fd < 0 {
        let error = Error::last_os_error();
        return Err(Error::new(error.kind(), format!("opening {}: {error}", CLONE_DEVICE.to_string_lossy())));
    }
    // SAFETY: `fd` is new and owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens a queue of the interface `name`, creating the interface for the first queue.
fn attach(name: Option<&str>, flags: libc::c_int) -> Result<(OwnedFd, String)> {
    let fd = open_tun()?;
    // SAFETY: `ifreq` is plain old data.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    if let Some(name) = name {
        copy_name(name, &mut request.ifr_name)?;
    }
    request.ifr_ifru.ifru_flags = flags as libc::c_short;
    // SAFETY: TUNSETIFF reads and writes the `ifreq`.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
        let error = Error::last_os_error();
        let what = if flags & IFF_TUN_EXCL != 0 && error.raw_os_error() == Some(libc::EBUSY) {
            "an interface of that name exists"
        } else {
            "creating the interface"
        };
        return Err(Error::new(error.kind(), format!("{what}: {error}")));
    }
    Ok((fd, read_name(&request.ifr_name)))
}

/// Whether `error` is the system refusing an application on Android or OpenHarmony what it lets
/// only itself do.
fn refused_to_application(error: &Error) -> bool {
    cfg!(any(target_os = "android", target_env = "ohos")) && matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM))
}

/// `TUNGETDEVNETNS`, Linux 5.2: a descriptor of the network namespace the interface lives in.
const TUNGETDEVNETNS: libc::Ioctl = 0x54e3;

/// Whether the interface of the queue `fd` lives in the network namespace of this thread. A
/// kernel before 5.2, and one that does not tell a process without the privilege, leaves the
/// interface where it is looked for.
fn lives_here(fd: RawFd) -> Result<bool> {
    // SAFETY: TUNGETDEVNETNS takes no argument and returns a new descriptor.
    let namespace = unsafe { libc::ioctl(fd, TUNGETDEVNETNS) };
    if namespace < 0 {
        let error = Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOTTY | libc::EINVAL | libc::EPERM | libc::EACCES) => Ok(true),
            _ => Err(error),
        };
    }
    // SAFETY: `namespace` is new and owned by nobody else.
    let namespace = unsafe { OwnedFd::from_raw_fd(namespace) };
    let here = std::fs::metadata("/proc/thread-self/ns/net")?;
    // SAFETY: plain old data, which fstat fills in.
    let mut theirs: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `theirs` is writable.
    if unsafe { libc::fstat(namespace.as_raw_fd(), &mut theirs) } < 0 {
        return Err(Error::last_os_error());
    }
    use std::os::unix::fs::MetadataExt;
    Ok((theirs.st_dev as u64, theirs.st_ino as u64) == (here.dev(), here.ino()))
}

fn get_iff(fd: RawFd) -> Result<(String, libc::c_int)> {
    // SAFETY: `ifreq` is plain old data.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: TUNGETIFF writes the `ifreq`.
    if unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut request) } < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: TUNGETIFF filled in the flags member.
    let flags = unsafe { request.ifr_ifru.ifru_flags };
    Ok((read_name(&request.ifr_name), libc::c_int::from(flags) & 0xffff))
}

fn vnet_size(fd: RawFd) -> Result<usize> {
    let mut size: libc::c_int = 0;
    // SAFETY: TUNGETVNETHDRSZ writes one int.
    if unsafe { libc::ioctl(fd, libc::TUNGETVNETHDRSZ, &mut size) } < 0 {
        return Err(Error::last_os_error());
    }
    let size = usize::try_from(size).map_err(|_| Error::other("the virtio header size is negative"))?;
    if !(VIRTIO_HEADER..=MAX_PREFIX).contains(&size) {
        return Err(Error::other(format!("a virtio header of {size} bytes is not supported")));
    }
    Ok(size)
}

/// Tells the kernel which segments this side takes: TCP always, UDP where the kernel knows how
/// (Linux 6.2 and later).
fn negotiate(fd: RawFd) -> Result<Offload> {
    // SAFETY: TUNSETOFFLOAD takes its argument by value.
    if unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD, libc::c_ulong::from(TUN_F_TCP | TUN_F_UDP)) } == 0 {
        return Ok(Offload { tcp: true, udp: true });
    }
    let error = Error::last_os_error();
    if error.raw_os_error() != Some(libc::EINVAL) {
        return Err(error);
    }
    // SAFETY: as above.
    if unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD, libc::c_ulong::from(TUN_F_TCP)) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(Offload { tcp: true, udp: false })
}

/// The kernel release as major and minor number.
pub(crate) fn kernel_version() -> (u32, u32) {
    // SAFETY: `utsname` is plain old data that `uname` fills in.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `name` is writable.
    if unsafe { libc::uname(&mut name) } < 0 {
        return (0, 0);
    }
    let release = read_name(&name.release);
    let mut numbers = release.split(|c: char| !c.is_ascii_digit()).filter(|part| !part.is_empty());
    let major = numbers.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let minor = numbers.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// `UDP_MAX_SEGMENTS`: 64 until Linux 6.10, 128 since.
fn udp_max_segments() -> usize {
    if kernel_version() >= (6, 10) { 128 } else { 64 }
}
