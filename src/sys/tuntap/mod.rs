//! FreeBSD, NetBSD and OpenBSD: the tun and tap character devices, configured with interface
//! ioctls and the routing socket. A tun device hands over and takes each packet behind its
//! address family, which the framing takes off and puts on unless the device was asked for
//! packet information. FreeBSD's tap devices hand over and take TCP segments of up to 64 KiB and
//! partial checksums behind a virtio header, OpenBSD's tun and tap devices behind a `tun_hdr`.

#[cfg_attr(target_os = "freebsd", path = "freebsd.rs")]
#[cfg_attr(target_os = "netbsd", path = "netbsd.rs")]
#[cfg_attr(target_os = "openbsd", path = "openbsd.rs")]
pub(super) mod os;

use std::io::{Error, ErrorKind, Result};
use std::mem::{ManuallyDrop, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use xtun_wire::{Family, Framing, Prefix, Takes};

pub use super::bsdlike::Interface;
#[cfg(target_os = "netbsd")]
use super::bsdlike::tolerate;
use super::bsdlike::{ioctl, name_of, request};
#[cfg(target_os = "freebsd")]
use super::unix::copy_name;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
use super::unix::read_name;
use super::unix::transport::{Each, Facts, Gathered, Sink, Source};
use super::unix::{Queue, index_of, set_nonblocking};
use crate::device::{Offload, Options, Up};

/// What happens to the interface when the device goes.
enum Removal {
    /// The system removes it once the device's descriptor is closed.
    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    WithDevice,
    /// It stays until destroyed: the device destroys it unless it persists.
    Explicit { persist: AtomicBool },
    /// FreeBSD 15: as `Explicit`, and while it does not persist its descriptor is transient, so
    /// that the system removes it should the process end without dropping the device.
    #[cfg(target_os = "freebsd")]
    Transient { persist: AtomicBool },
}

/// The device's descriptor and interface: dropped, it closes the descriptor and then destroys
/// the interface, as its removal says. The system waits for the descriptor to be closed before
/// it destroys an interface.
struct Lifetime {
    queue: ManuallyDrop<Arc<Queue>>,
    index: u32,
    removal: Removal,
}

impl Lifetime {
    /// The descriptor, for something else to use; the interface is left as it is.
    fn into_fd(self) -> OwnedFd {
        let mut lifetime = ManuallyDrop::new(self);
        // SAFETY: `lifetime` is never dropped, so the queue is taken out of it once; the rest of
        // it holds nothing to release.
        let queue = unsafe { ManuallyDrop::take(&mut lifetime.queue) };
        Arc::into_inner(queue).expect("the device holds the only handle of its queue").into_fd()
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        let destroy = match &self.removal {
            #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
            Removal::WithDevice => false,
            Removal::Explicit { persist } => !persist.load(Ordering::Relaxed),
            #[cfg(target_os = "freebsd")]
            Removal::Transient { persist } => {
                let destroy = !persist.load(Ordering::Relaxed);
                // FreeBSD destroys the device node of a transient interface later, on a task
                // queue, and panics when an interface of the same unit is made meanwhile, as the
                // next device usually is. Destroyed here, the node goes at once. Should this
                // fail, closing the descriptor removes the interface as before.
                if destroy {
                    let _ = set_transient(self.queue.raw_fd(), false);
                }
                destroy
            }
        };
        // SAFETY: the queue is not used after this.
        unsafe { ManuallyDrop::drop(&mut self.queue) };
        if destroy && let Ok(name) = name_of(self.index) {
            // Nothing is left to report a failure to; the interface stays behind.
            let _ = destroy_interface(&name);
        }
    }
}

/// A tun or tap device.
pub struct Tunnel {
    interface: Interface,
    /// The device carries Ethernet frames.
    ethernet: bool,
    /// Whether packets of a tun device pass with the address family in front; the device always
    /// has it there.
    packet_information: AtomicBool,
    /// The length of the virtio header in front of each frame, or zero without offloads.
    #[cfg(target_os = "freebsd")]
    vnet_len: usize,
    /// Each frame comes and goes behind a `tun_hdr`, and then without packet information.
    #[cfg(target_os = "openbsd")]
    tun_hdr: bool,
    offload: Offload,
    lifetime: Lifetime,
}

/// What a device does about offloads as it is wrapped.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Offloads {
    /// Turned on where the system has them.
    On,
    /// Left off.
    Off,
    /// As the descriptor has them: one that something else opened.
    AsFound,
}

/// A device that was opened: its descriptor, its interface and what happens to the interface.
struct Opened {
    fd: OwnedFd,
    name: String,
    removal: Removal,
}

impl Facts for Tunnel {
    fn takes(&self) -> Takes {
        let family = Family { inet: libc::AF_INET as u32, inet6: libc::AF_INET6 as u32 };
        // Packets with the address family in front are not looked into.
        let plain = if self.ethernet || self.packet_information.load(Ordering::Relaxed) { Prefix::None } else { Prefix::Family(family) };
        #[cfg(target_os = "freebsd")]
        let prefix = if self.vnet_len > 0 { Prefix::Virtio(self.vnet_len) } else { plain };
        // A tun device takes the address family behind its `tun_hdr`.
        #[cfg(target_os = "openbsd")]
        let prefix = if self.tun_hdr { Prefix::TunHdr { family: (!self.ethernet).then_some(family) } } else { plain };
        #[cfg(target_os = "netbsd")]
        let prefix = plain;
        Takes {
            framing: Framing { prefix, ethernet: self.ethernet },
            tcp: self.offload.tcp,
            udp: false,
            udp_max_segments: 0,
            // The system refuses what is too long for the interface, write by write.
            max_frame: usize::MAX,
        }
    }
}

impl super::Tunnel for Tunnel {
    type Source = Source<Tunnel, Each>;
    type Sink = Sink<Tunnel, Gathered>;

    fn create(options: &Options) -> Result<Tunnel> {
        if options.queues != 1 {
            return Err(Error::new(ErrorKind::Unsupported, "tun and tap devices have one queue"));
        }
        if options.ethernet && options.packet_information {
            return Err(Error::new(ErrorKind::InvalidInput, "Ethernet frames carry no packet information"));
        }
        let opened = open(options.ethernet, options.name.as_deref(), options.reuse, options.persist == Some(true))?;
        let offloads = if options.offload && !options.packet_information { Offloads::On } else { Offloads::Off };
        let tunnel = Tunnel::wrap(opened, options.ethernet, offloads)?;
        tunnel.packet_information.store(options.packet_information, Ordering::Relaxed);
        Ok(tunnel)
    }

    fn queues(&self) -> usize {
        1
    }

    fn source(self: &Arc<Tunnel>, queue: usize, frames: usize) -> Result<Self::Source> {
        Source::new(self.clone(), self.queue(queue)?, Each, frames)
    }

    fn sink(self: &Arc<Tunnel>, queue: usize) -> Result<Self::Sink> {
        Ok(Sink::new(self.clone(), self.queue(queue)?, Gathered::default()))
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn offload(&self) -> Offload {
        self.offload
    }

    fn packet_information(&self) -> bool {
        self.packet_information.load(Ordering::Relaxed)
    }

    fn set_persist(&self, persist: bool) -> Result<()> {
        match &self.lifetime.removal {
            #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
            Removal::WithDevice if persist => {
                Err(Error::new(ErrorKind::Unsupported, "the interface goes away with the device that made it"))
            }
            #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
            Removal::WithDevice => Ok(()),
            Removal::Explicit { persist: flag } => {
                flag.store(persist, Ordering::Relaxed);
                Ok(())
            }
            #[cfg(target_os = "freebsd")]
            Removal::Transient { persist: flag } => {
                set_transient(self.lifetime.queue.raw_fd(), !persist)?;
                flag.store(persist, Ordering::Relaxed);
                Ok(())
            }
        }
    }

    /// The addresses are added first and checked for duplicates together after, once the
    /// interface is up.
    fn configure(&self, options: &Options) -> Result<()> {
        if let Some(mtu) = options.mtu {
            self.interface.set_mtu(mtu)?;
        }
        if let Some(mac) = options.mac_address {
            self.interface.set_mac_address(mac)?;
        }
        for address in &options.addresses {
            self.interface
                .insert_address(*address, options.prefix_routes)
                .map_err(|error| Error::new(error.kind(), format!("adding {}: {error}", address.net)))?;
        }
        match options.up {
            Up::Yes => self.interface.set_up(true)?,
            Up::No => self.interface.set_up(false)?,
            Up::Unchanged => self.interface.settle()?,
        }
        // Last, so that an interface whose setup failed does not stay behind.
        if let Some(persist) = options.persist {
            super::Tunnel::set_persist(self, persist)?;
        }
        Ok(())
    }
}

impl super::Descriptors for Tunnel {
    fn queue_fd(&self, queue: usize) -> Result<BorrowedFd<'_>> {
        let fd = self.queue(queue)?.raw_fd();
        // SAFETY: the queue lives as long as the device.
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    /// The descriptor, for something else to use; the interface stays as long as it is open,
    /// and on NetBSD after that too.
    fn into_fd(self) -> std::result::Result<OwnedFd, Tunnel> {
        if Arc::strong_count(&self.lifetime.queue) > 1 {
            return Err(self);
        }
        Ok(self.lifetime.into_fd())
    }
}

impl super::Adopt for Tunnel {
    /// Wraps the descriptor of a tun or tap device that something else opened; its interface
    /// is left to whoever made it.
    fn adopt(fd: OwnedFd, ethernet: bool) -> Result<Tunnel> {
        let name = fd_name(fd.as_raw_fd())?;
        if is_tap(fd.as_raw_fd(), &name)? != ethernet {
            let (is, wanted) = if ethernet { ("tun", "tap") } else { ("tap", "tun") };
            return Err(Error::new(ErrorKind::InvalidInput, format!("the descriptor is of a {is} device, not of a {wanted} device")));
        }
        let removal = Removal::Explicit { persist: AtomicBool::new(true) };
        Tunnel::wrap(Opened { fd, name, removal }, ethernet, Offloads::AsFound)
    }
}

impl Tunnel {
    /// Sets whether packets of a tun device pass with the address family in front, from the
    /// next read and write on.
    pub fn set_packet_information(&self, on: bool) -> Result<()> {
        if self.ethernet {
            return Err(Error::new(ErrorKind::InvalidInput, "Ethernet frames carry no packet information"));
        }
        #[cfg(target_os = "openbsd")]
        if on && self.tun_hdr {
            return Err(Error::new(ErrorKind::InvalidInput, "a device with offloads takes no packet information"));
        }
        self.packet_information.store(on, Ordering::Relaxed);
        Ok(())
    }

    fn wrap(opened: Opened, ethernet: bool, offloads: Offloads) -> Result<Tunnel> {
        let Opened { fd, name, removal } = opened;
        let interface = Interface::new(&name, ethernet)?;
        // From here on a failure closes the descriptor and removes the interface.
        let lifetime = Lifetime { queue: ManuallyDrop::new(Arc::new(Queue::new(fd))), index: interface.index(), removal };
        let fd = lifetime.queue.raw_fd();
        set_nonblocking(fd)?;
        // NetBSD's tun driver keeps a flag of its own, which only this sets.
        let mut on: libc::c_int = 1;
        // SAFETY: FIONBIO reads one int.
        if unsafe { libc::ioctl(fd, libc::FIONBIO, &mut on) } < 0 {
            return Err(Error::last_os_error());
        }
        if !ethernet {
            prepare_tun(fd)?;
        }
        // FreeBSD can panic when an interface goes away while one of its IPv6 addresses is checked
        // for duplicates, as its link-local address is right after it comes up: an interface the
        // device made, and removes, has none checked.
        #[cfg(target_os = "freebsd")]
        if let Removal::Transient { persist } | Removal::Explicit { persist } = &lifetime.removal
            && !persist.load(Ordering::Relaxed)
        {
            without_duplicate_detection(&name)?;
        }
        // FreeBSD's tap devices take a virtio header.
        #[cfg(target_os = "freebsd")]
        let (vnet_len, offload) = match (ethernet, offloads) {
            (true, Offloads::On) => enable_offload(fd, &name)?,
            (true, Offloads::AsFound) => offload_in_place(fd)?,
            _ => (0, Offload::default()),
        };
        #[cfg(target_os = "openbsd")]
        let (tun_hdr, offload) = match offloads {
            Offloads::On => enable_offload(fd)?,
            Offloads::Off => (false, Offload::default()),
            Offloads::AsFound => offload_in_place(fd)?,
        };
        #[cfg(target_os = "netbsd")]
        let offload = {
            let _ = offloads;
            Offload::default()
        };
        Ok(Tunnel {
            interface,
            ethernet,
            packet_information: AtomicBool::new(false),
            #[cfg(target_os = "freebsd")]
            vnet_len,
            #[cfg(target_os = "openbsd")]
            tun_hdr,
            offload,
            lifetime,
        })
    }

    fn queue(&self, queue: usize) -> Result<&Arc<Queue>> {
        if queue != 0 {
            return Err(Error::new(ErrorKind::InvalidInput, format!("the device has one queue, there is no queue {queue}")));
        }
        Ok(&self.lifetime.queue)
    }
}

fn exists(name: &str) -> bool {
    index_of(name).is_ok()
}

/// Opens a character device without blocking, closed on exec.
fn open_node(path: &str) -> Result<OwnedFd> {
    let path = std::ffi::CString::new(path).map_err(|_| Error::new(ErrorKind::InvalidInput, "the name has a NUL byte"))?;
    // SAFETY: a plain open of a NUL-terminated path.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `fd` is new and owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// What the interfaces of a kind are called, before their unit number.
fn prefix(ethernet: bool) -> &'static str {
    if ethernet { os::TAP_PREFIX } else { os::TUN_PREFIX }
}

/// Checks that `name` is the kind's prefix and a unit number, as the device nodes are called.
fn check_name(ethernet: bool, name: &str) -> Result<()> {
    let prefix = prefix(ethernet);
    match name.strip_prefix(prefix) {
        Some(unit) if !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit()) => Ok(()),
        _ => Err(Error::new(ErrorKind::InvalidInput, format!("the interface is called {prefix} and a number"))),
    }
}

/// Checks that the interface called `name` may be used: an interface that exists is taken over
/// only with `reuse`. Returns whether it exists.
fn claim(ethernet: bool, name: &str, reuse: bool) -> Result<bool> {
    check_name(ethernet, name)?;
    let existed = exists(name);
    if existed && !reuse {
        return Err(Error::new(ErrorKind::AlreadyExists, format!("an interface is called {name}")));
    }
    Ok(existed)
}

/// Opens the device node of the interface called `name`.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn open_device(name: &str) -> Result<OwnedFd> {
    open_node(&format!("/dev/{name}")).map_err(|error| Error::new(error.kind(), format!("opening /dev/{name}: {error}")))
}

/// Opens the device of the first unit that is free: no interface has its name, and nothing
/// else opens its device meanwhile.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn open_free(ethernet: bool) -> Result<(OwnedFd, String)> {
    let prefix = prefix(ethernet);
    for unit in 0.. {
        let name = format!("{prefix}{unit}");
        if exists(&name) {
            continue;
        }
        match open_node(&format!("/dev/{name}")) {
            Ok(fd) => return Ok((fd, name)),
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => continue,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return Err(Error::new(ErrorKind::NotFound, format!("no free {prefix} device is left in /dev")));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("units run out before the loop ends")
}

#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn create_interface(name: &str) -> Result<()> {
    let mut request = request(name)?;
    ioctl(libc::AF_INET, os::SIOCIFCREATE, &mut request)
}

fn destroy_interface(name: &str) -> Result<()> {
    let mut request = request(name)?;
    ioctl(libc::AF_INET, os::SIOCIFDESTROY, &mut request)
}

/// FreeBSD: how long a device node that is going away may still be handed out.
#[cfg(target_os = "freebsd")]
const GOING: std::time::Duration = std::time::Duration::from_secs(1);

/// FreeBSD: opens the device node at `path`, the cloning device or the device of one unit. When
/// an interface of the kind has just gone away, the system has freed its unit before the
/// deferred destruction of its device has finished, and a lookup may still find the device
/// that is going: opening it fails with ENXIO, and a moment later it is gone and the lookup
/// makes a new one.
#[cfg(target_os = "freebsd")]
fn open_settled(path: &str) -> Result<OwnedFd> {
    let deadline = std::time::Instant::now() + GOING;
    loop {
        match open_node(path) {
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            result => return result.map_err(|error| Error::new(error.kind(), format!("opening {path}: {error}"))),
        }
    }
}

/// FreeBSD: the cloning devices hand out a new interface each; one opened by name stays, unless
/// it is transient (FreeBSD 15).
#[cfg(target_os = "freebsd")]
fn open(ethernet: bool, name: Option<&str>, reuse: bool, _persist: bool) -> Result<Opened> {
    let (fd, existed) = match name {
        // The system creates the interface when its device node is looked up.
        Some(name) => {
            let existed = claim(ethernet, name, reuse)?;
            (open_settled(&format!("/dev/{name}"))?, existed)
        }
        None => (open_settled(if ethernet { os::TAP_CLONER } else { os::TUN_CLONER })?, false),
    };
    let name = fd_name(fd.as_raw_fd())?;
    // An interface that was there before stays, as a persistent interface does on Linux, until
    // the device is told it may go. One that is to persist does once it is set up.
    let removal = if existed {
        Removal::Explicit { persist: AtomicBool::new(true) }
    } else {
        match set_transient(fd.as_raw_fd(), true) {
            Ok(()) => Removal::Transient { persist: AtomicBool::new(false) },
            // Before FreeBSD 15.
            Err(error) if error.raw_os_error() == Some(libc::ENOTTY) => Removal::Explicit { persist: AtomicBool::new(false) },
            Err(error) => return Err(error),
        }
    };
    Ok(Opened { fd, name, removal })
}

/// NetBSD: a tun device makes its interface when it is opened, and the interface stays; the tap
/// cloning device hands out an interface that goes away with it.
#[cfg(target_os = "netbsd")]
fn open(ethernet: bool, name: Option<&str>, reuse: bool, persist: bool) -> Result<Opened> {
    match (ethernet, name) {
        (true, None) if !persist => {
            let fd = open_node(os::TAP_CLONER).map_err(|error| Error::new(error.kind(), format!("opening {}: {error}", os::TAP_CLONER)))?;
            let name = fd_name(fd.as_raw_fd())?;
            Ok(Opened { fd, name, removal: Removal::WithDevice })
        }
        (_, Some(name)) => {
            let existed = claim(ethernet, name, reuse)?;
            // Opening a tun device makes its interface; a tap device's has to be made first.
            if ethernet && !existed {
                create_interface(name)?;
            }
            let fd = open_device(name)?;
            // One that is to persist does once it is set up.
            let removal = Removal::Explicit { persist: AtomicBool::new(existed) };
            Ok(Opened { fd, name: name.to_owned(), removal })
        }
        // A tap device node opens an interface that exists: a persistent one is made first.
        (true, None) => {
            let name = (0..).map(|unit| format!("{}{unit}", os::TAP_PREFIX)).find(|name| !exists(name)).expect("a free unit");
            create_interface(&name)?;
            let fd = open_device(&name)?;
            Ok(Opened { fd, name, removal: Removal::Explicit { persist: AtomicBool::new(false) } })
        }
        (false, None) => {
            let (fd, name) = open_free(ethernet)?;
            Ok(Opened { fd, name, removal: Removal::Explicit { persist: AtomicBool::new(false) } })
        }
    }
}

/// OpenBSD: a device makes its interface when it is opened and removes it when it is closed,
/// unless the interface was made before; a persistent one is made first.
#[cfg(target_os = "openbsd")]
fn open(ethernet: bool, name: Option<&str>, reuse: bool, persist: bool) -> Result<Opened> {
    let name = match name {
        Some(name) => name.to_owned(),
        None if persist => {
            let prefix = prefix(ethernet);
            (0..).map(|unit| format!("{prefix}{unit}")).find(|name| !exists(name)).expect("a free unit")
        }
        None => {
            let (fd, name) = open_free(ethernet)?;
            return Ok(Opened { fd, name, removal: Removal::WithDevice });
        }
    };
    let existed = claim(ethernet, &name, reuse)?;
    // An interface made before its device is opened stays when the device is closed.
    if persist && !existed {
        create_interface(&name)?;
    }
    let fd = open_device(&name)?;
    // One made to persist does once it is set up.
    let removal = match (existed, persist) {
        (true, _) => Removal::Explicit { persist: AtomicBool::new(true) },
        (false, true) => Removal::Explicit { persist: AtomicBool::new(false) },
        (false, false) => Removal::WithDevice,
    };
    Ok(Opened { fd, name, removal })
}

/// The interface of a device's descriptor.
#[cfg(target_os = "freebsd")]
fn fd_name(fd: RawFd) -> Result<String> {
    // SAFETY: plain old data.
    let mut request: os::ifreq = unsafe { zeroed() };
    // SAFETY: TUNGIFNAME writes an `ifreq`; tap devices take it too.
    if unsafe { libc::ioctl(fd, os::TUNGIFNAME, &mut request) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(read_name(&request.ifr_name))
}

/// The interface of a device's descriptor.
#[cfg(target_os = "netbsd")]
fn fd_name(fd: RawFd) -> Result<String> {
    // SAFETY: plain old data.
    let mut request: os::ifreq = unsafe { zeroed() };
    // SAFETY: TAPGIFNAME writes an `ifreq`; a tun device refuses it.
    if unsafe { libc::ioctl(fd, os::TAPGIFNAME, &mut request) } == 0 {
        return Ok(read_name(&request.ifr_name));
    }
    device_name(fd)
}

/// The interface of a device's descriptor.
#[cfg(target_os = "openbsd")]
fn fd_name(fd: RawFd) -> Result<String> {
    device_name(fd)
}

/// The name of the device node behind a descriptor, which is its interface's name.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn device_name(fd: RawFd) -> Result<String> {
    // SAFETY: plain old data.
    let mut status: libc::stat = unsafe { zeroed() };
    // SAFETY: `status` is writable.
    if unsafe { libc::fstat(fd, &mut status) } < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `devname` returns a NUL-terminated name or null; it is copied at once.
    let name = unsafe { libc::devname(status.st_rdev, libc::S_IFCHR) };
    if name.is_null() {
        return Err(Error::new(ErrorKind::InvalidInput, "the descriptor is not a tun or tap device"));
    }
    // SAFETY: as above.
    let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_string_lossy().into_owned();
    if !name.starts_with(os::TUN_PREFIX) && !name.starts_with(os::TAP_PREFIX) {
        return Err(Error::new(ErrorKind::InvalidInput, format!("{name} is not a tun or tap device")));
    }
    Ok(name)
}

/// Whether a descriptor is of a tap device. FreeBSD renames interfaces, so the name of the
/// device node says it, which stays as it was made.
#[cfg(target_os = "freebsd")]
fn is_tap(fd: RawFd, _name: &str) -> Result<bool> {
    // SAFETY: plain old data.
    let mut status: libc::stat = unsafe { zeroed() };
    // SAFETY: `status` is writable.
    if unsafe { libc::fstat(fd, &mut status) } < 0 {
        return Err(Error::last_os_error());
    }
    let mut node = [0 as libc::c_char; 64];
    // SAFETY: `devname_r` writes a NUL-terminated name of at most the length given.
    unsafe { libc::devname_r(status.st_rdev, libc::S_IFCHR, node.as_mut_ptr(), node.len() as libc::c_int) };
    Ok(read_name(&node).starts_with(os::TAP_PREFIX))
}

/// Whether a descriptor is of a tap device: its interface is called after its kind.
#[cfg(not(target_os = "freebsd"))]
fn is_tap(_fd: RawFd, name: &str) -> Result<bool> {
    Ok(name.starts_with(os::TAP_PREFIX))
}

/// Makes a tun device hand over and take the address family in front of every packet; OpenBSD
/// always has it.
fn prepare_tun(fd: RawFd) -> Result<()> {
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let mut on: libc::c_int = 1;
        // SAFETY: TUNSIFHEAD reads one int.
        if unsafe { libc::ioctl(fd, os::TUNSIFHEAD, &mut on) } < 0 {
            return Err(Error::last_os_error());
        }
    }
    // NetBSD makes tun interfaces without multicast, and enables IPv6 only on interfaces that
    // have it. An interface that is up already keeps its kind.
    #[cfg(target_os = "netbsd")]
    {
        let mut mode: libc::c_int = libc::IFF_POINTOPOINT | libc::IFF_MULTICAST;
        // SAFETY: TUNSIFMODE reads one int.
        if unsafe { libc::ioctl(fd, os::TUNSIFMODE, &mut mode) } < 0 {
            tolerate(Err(Error::last_os_error()), libc::EBUSY)?;
        }
    }
    let _ = fd;
    Ok(())
}

/// FreeBSD: no address of the interface called `name` is checked for duplicates on the link.
#[cfg(target_os = "freebsd")]
fn without_duplicate_detection(name: &str) -> Result<()> {
    // SAFETY: plain old data.
    let mut request: os::in6_ndireq = unsafe { zeroed() };
    copy_name(name, &mut request.ifname)?;
    ioctl(libc::AF_INET6, os::SIOCGIFINFO_IN6, &mut request)?;
    request.ndi.flags |= os::ND6_IFF_NO_DAD;
    ioctl(libc::AF_INET6, os::SIOCSIFINFO_FLAGS, &mut request)
}

#[cfg(target_os = "freebsd")]
fn set_transient(fd: RawFd, on: bool) -> Result<()> {
    let mut on = libc::c_int::from(on);
    // SAFETY: TUNSTRANSIENT reads one int.
    if unsafe { libc::ioctl(fd, os::TUNSTRANSIENT, &mut on) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// FreeBSD: puts a virtio header in front of a tap device's frames and turns on what it brings,
/// so that the system hands over and takes TCP segments and partial checksums.
#[cfg(target_os = "freebsd")]
fn enable_offload(fd: RawFd, name: &str) -> Result<(usize, Offload)> {
    let mut length = os::VNET_LEN;
    // SAFETY: TAPSVNETHDR reads one int.
    if unsafe { libc::ioctl(fd, os::TAPSVNETHDR, &mut length) } < 0 {
        return Err(Error::last_os_error());
    }
    let mut request = request(name)?;
    ioctl(libc::AF_INET, os::SIOCGIFCAP, &mut request)?;
    // SAFETY: SIOCGIFCAP filled in the requested and the current capabilities.
    let current = unsafe { request.ifr_ifru.ifru_cap[1] };
    request.ifr_ifru.ifru_cap = [current | os::OFFLOAD_CAPABILITIES, 0];
    ioctl(libc::AF_INET, os::SIOCSIFCAP, &mut request)?;
    Ok((os::VNET_LEN as usize, Offload { tcp: true, udp: false }))
}

/// FreeBSD: the virtio header a tap device that something else opened already has.
#[cfg(target_os = "freebsd")]
fn offload_in_place(fd: RawFd) -> Result<(usize, Offload)> {
    let mut length: libc::c_int = 0;
    // SAFETY: TAPGVNETHDR writes one int.
    if unsafe { libc::ioctl(fd, os::TAPGVNETHDR, &mut length) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(match length {
        0 => (0, Offload::default()),
        length => (length as usize, Offload { tcp: true, udp: false }),
    })
}

/// OpenBSD: puts a `tun_hdr` in front of every packet and offers the interface checksums and TCP
/// segments, which the system then leaves to the reader. Systems before `tun_hdr` came, in
/// OpenBSD 7.6, go without.
#[cfg(target_os = "openbsd")]
fn enable_offload(fd: RawFd) -> Result<(bool, Offload)> {
    let mut capabilities = os::tun_capabilities {
        tun_if_capabilities: os::IFCAP_CSUM_TCPv4
            | os::IFCAP_CSUM_UDPv4
            | os::IFCAP_CSUM_TCPv6
            | os::IFCAP_CSUM_UDPv6
            | os::IFCAP_TSOv4
            | os::IFCAP_TSOv6,
    };
    // SAFETY: TUNSCAP reads a `tun_capabilities`.
    if unsafe { libc::ioctl(fd, os::TUNSCAP, &mut capabilities) } < 0 {
        let error = Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOTTY) => Ok((false, Offload::default())),
            _ => Err(error),
        };
    }
    Ok((true, Offload { tcp: true, udp: false }))
}

/// OpenBSD: whether a device that something else opened has a `tun_hdr`, and the segments it
/// offers.
#[cfg(target_os = "openbsd")]
fn offload_in_place(fd: RawFd) -> Result<(bool, Offload)> {
    let mut capabilities = os::tun_capabilities { tun_if_capabilities: 0 };
    // SAFETY: TUNGCAP writes a `tun_capabilities`.
    if unsafe { libc::ioctl(fd, os::TUNGCAP, &mut capabilities) } < 0 {
        let error = Error::last_os_error();
        return match error.raw_os_error() {
            // Without a `tun_hdr`, or before it came.
            Some(libc::ENODEV | libc::ENOTTY) => Ok((false, Offload::default())),
            _ => Err(error),
        };
    }
    let tcp = capabilities.tun_if_capabilities & (os::IFCAP_TSOv4 | os::IFCAP_TSOv6) != 0;
    Ok((true, Offload { tcp, udp: false }))
}
