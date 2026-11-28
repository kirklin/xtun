//! Ethernet on macOS: a pair of cloned `feth` interfaces. The first is the device's interface
//! and carries its addresses; what it sends, the second receives, and what the second sends, it
//! receives. A BPF device on the second interface reads and writes the device's frames.

use std::io::{Error, ErrorKind, Result};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use xtun_wire::{Framing, Prefix, Takes};

use super::sys::*;
use super::{Interface, io, one_queue};
use crate::device::{Offload, Options};
use crate::sys::bsdlike::{ioctl, request, tolerate};
use crate::sys::unix::transport::{Facts, Sink, Source};
use crate::sys::unix::{Queue, copy_name, read_name};

/// The BPF buffer of a device: the frames that came in since the last read are read at once.
const BPF_BUFFER: usize = 1 << 20;

/// A pair of `feth` interfaces and the BPF device on the second one.
pub struct Tap {
    interface: Interface,
    /// The second interface of the pair.
    peer: Interface,
    /// Before `pair`, so that BPF lets go of the second interface before the pair goes away.
    queue: Arc<Queue>,
    pair: Pair,
}

impl Facts for Tap {
    fn takes(&self) -> Takes {
        Takes {
            framing: Framing { prefix: Prefix::None, ethernet: true },
            tcp: false,
            udp: false,
            udp_max_segments: 0,
            max_frame: usize::MAX,
        }
    }
}

impl crate::sys::Tunnel for Tap {
    type Source = Source<Tap, io::BpfReads>;
    type Sink = Sink<Tap, io::BpfWrites>;

    fn create(options: &Options) -> Result<Tap> {
        if options.queues != 1 {
            return Err(Error::new(ErrorKind::Unsupported, "these interfaces have one queue"));
        }
        if options.packet_information {
            return Err(Error::new(ErrorKind::InvalidInput, "Ethernet frames carry no packet information"));
        }
        let wanted = options.name.as_deref().unwrap_or("feth");
        let wanted_peer = options.peer_name.as_deref().unwrap_or("feth");
        if !wanted.starts_with("feth") || !wanted_peer.starts_with("feth") {
            return Err(Error::new(ErrorKind::InvalidInput, "a layer 2 interface and its peer are called feth and a number"));
        }
        let (name, created) = create_interface(wanted, options.reuse)?;
        let mut pair = Pair {
            name: name.clone(),
            peer: String::new(),
            created: [created, false],
            persist: AtomicBool::new(false),
            released: AtomicBool::new(false),
        };
        match if created { None } else { peer_of(&name)? } {
            Some(peer) => pair.peer = peer,
            None => {
                let (peer, created) = create_interface(wanted_peer, options.reuse)?;
                pair.peer = peer;
                pair.created[1] = created;
                set_peer(&name, &pair.peer)?;
            }
        }
        let bpf = open_bpf(&pair.peer)?;
        without_duplicate_detection(&name)?;
        let interface = Interface::new(&name, true)?;
        let peer = Interface::new(&pair.peer, true)?;
        Ok(Tap { interface, peer, queue: Arc::new(Queue::read_only_readiness(bpf)), pair })
    }

    fn queues(&self) -> usize {
        1
    }

    fn source(self: &Arc<Tap>, queue: usize, frames: usize) -> Result<Self::Source> {
        let queue = one_queue(&self.queue, queue)?;
        Source::new(self.clone(), queue, io::BpfReads::new(queue.raw_fd())?, frames)
    }

    fn sink(self: &Arc<Tap>, queue: usize) -> Result<Self::Sink> {
        Ok(Sink::new(self.clone(), one_queue(&self.queue, queue)?, io::BpfWrites::default()))
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn offload(&self) -> Offload {
        Offload::default()
    }

    /// Told not to persist, the device also takes interfaces that were there before it along
    /// when it goes.
    fn set_persist(&self, persist: bool) -> Result<()> {
        self.pair.persist.store(persist, Ordering::Relaxed);
        if !persist {
            self.pair.released.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Sets the MTU of both interfaces of the pair.
    fn set_mtu(&self, mtu: u32) -> Result<()> {
        self.interface.set_mtu(mtu)?;
        self.peer.set_mtu(mtu)
    }

    /// Brings the interface up or down; the second interface of the pair only comes up.
    fn set_up(&self, up: bool) -> Result<()> {
        self.interface.set_up(up)?;
        if up {
            self.peer.set_up(true)?;
        }
        Ok(())
    }
}

impl crate::sys::Descriptors for Tap {
    fn queue_fd(&self, queue: usize) -> Result<BorrowedFd<'_>> {
        let fd = one_queue(&self.queue, queue)?.raw_fd();
        // SAFETY: the queue lives as long as the device.
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    /// The descriptor; the device leaves its interfaces behind, since its frames go through
    /// them.
    fn into_fd(self) -> std::result::Result<OwnedFd, Tap> {
        let Tap { interface, peer, queue, pair } = self;
        match Arc::try_unwrap(queue) {
            Ok(queue) => {
                pair.persist.store(true, Ordering::Relaxed);
                Ok(queue.into_fd())
            }
            Err(queue) => Err(Tap { interface, peer, queue, pair }),
        }
    }
}

/// The two `feth` interfaces of a device by their names: the device's own and the second one.
/// Unless the device persists, those created for it go away with it; one that was there before
/// stays, as a persistent interface does on Linux, until the device is told it may go.
struct Pair {
    name: String,
    peer: String,
    /// Which of the two were created for the device.
    created: [bool; 2],
    persist: AtomicBool,
    /// The device was told it may take the interfaces that were there before it along.
    released: AtomicBool,
}

impl Drop for Pair {
    fn drop(&mut self) {
        if self.persist.load(Ordering::Relaxed) {
            return;
        }
        let released = self.released.load(Ordering::Relaxed);
        for (name, created) in [(&self.peer, self.created[1]), (&self.name, self.created[0])] {
            if created || released {
                // Nothing is left to report the failure to; the interface stays behind.
                let _ = destroy(name);
            }
        }
    }
}

/// Creates the cloned interface `name`, or the next free unit when `name` has no number.
/// Returns its name and whether it was created; an interface that exists is taken over with
/// `reuse`.
fn create_interface(name: &str, reuse: bool) -> Result<(String, bool)> {
    let mut request = request(name)?;
    match ioctl(libc::AF_INET, SIOCIFCREATE, &mut request) {
        Ok(()) => Ok((read_name(&request.ifr_name), true)),
        Err(error) if error.raw_os_error() == Some(libc::EEXIST) && reuse => Ok((name.to_owned(), false)),
        Err(error) => Err(Error::new(error.kind(), format!("creating {name}: {error}"))),
    }
}

fn destroy(name: &str) -> Result<()> {
    let mut request = request(name)?;
    ioctl(libc::AF_INET, SIOCIFDESTROY, &mut request)
}

/// Lets IPv6 addresses of the interface `name` be used as soon as they are added: macOS checks
/// the addresses of an Ethernet interface for duplicates first, which takes a second or two and
/// cannot find any, since the far end of the pair is this process. The interface gets its
/// link-local address, as with its first IPv6 address.
fn without_duplicate_detection(name: &str) -> Result<()> {
    // SAFETY: plain old data.
    let mut attach: in6_aliasreq = unsafe { zeroed() };
    copy_name(name, &mut attach.ifra_name)?;
    tolerate(ioctl(libc::AF_INET6, SIOCPROTOATTACH_IN6, &mut attach), libc::EEXIST)?;
    // SAFETY: plain old data.
    let mut current: in6_ondireq = unsafe { zeroed() };
    copy_name(name, &mut current.ifname)?;
    ioctl(libc::AF_INET6, SIOCGIFINFO_IN6, &mut current)?;
    // SAFETY: plain old data.
    let mut settings: in6_ndireq = unsafe { zeroed() };
    copy_name(name, &mut settings.ifname)?;
    settings.ndi.flags = current.ndi.flags & !ND6_IFF_DAD;
    ioctl(libc::AF_INET6, SIOCSIFINFO_FLAGS, &mut settings)?;
    // SAFETY: plain old data.
    let mut link_local: in6_aliasreq = unsafe { zeroed() };
    copy_name(name, &mut link_local.ifra_name)?;
    tolerate(ioctl(libc::AF_INET6, SIOCLL_START, &mut link_local), libc::EEXIST)
}

/// Pairs the `feth` interface `name` with `peer`: what one sends, the other receives.
fn set_peer(name: &str, peer: &str) -> Result<()> {
    // SAFETY: plain old data.
    let mut data: if_fake_request = unsafe { zeroed() };
    copy_name(peer, &mut data.iffr_peer_name[..libc::IFNAMSIZ])?;
    driver_request(name, SIOCSDRVSPEC, IF_FAKE_S_CMD_SET_PEER, &mut data)
}

/// The interface that the `feth` interface `name` is paired with, if any.
fn peer_of(name: &str) -> Result<Option<String>> {
    // SAFETY: plain old data.
    let mut data: if_fake_request = unsafe { zeroed() };
    driver_request(name, SIOCGDRVSPEC, IF_FAKE_G_CMD_GET_PEER, &mut data)?;
    let peer = read_name(&data.iffr_peer_name);
    Ok((!peer.is_empty()).then_some(peer))
}

fn driver_request(name: &str, request: libc::c_ulong, command: libc::c_ulong, data: &mut if_fake_request) -> Result<()> {
    // SAFETY: plain old data.
    let mut drv: ifdrv = unsafe { zeroed() };
    copy_name(name, &mut drv.ifd_name)?;
    drv.ifd_cmd = command;
    drv.ifd_len = size_of::<if_fake_request>();
    drv.ifd_data = (data as *mut if_fake_request).cast();
    ioctl(libc::AF_INET, request, &mut drv)
}

/// Opens a BPF device on `name` that hands over every frame the interface receives, at once
/// and in batches, and sends frames as they are.
fn open_bpf(name: &str) -> Result<OwnedFd> {
    let mut unit = 0;
    let fd = loop {
        let path = std::ffi::CString::new(format!("/dev/bpf{unit}")).expect("no NUL in the path");
        // SAFETY: a plain open of a NUL-terminated path.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if fd >= 0 {
            // SAFETY: `fd` is new and owned by nobody else.
            break unsafe { OwnedFd::from_raw_fd(fd) };
        }
        let error = Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBUSY) {
            return Err(Error::new(error.kind(), format!("opening a BPF device: {error}")));
        }
        unit += 1;
    };
    let raw = fd.as_raw_fd();
    let mut size: libc::c_uint = BPF_BUFFER as libc::c_uint;
    bpf_ioctl(raw, BIOCSBLEN, &mut size)?;
    let mut request = request(name)?;
    bpf_ioctl(raw, BIOCSETIF, &mut request)?;
    for (option, value) in [(BIOCIMMEDIATE, 1), (BIOCSHDRCMPLT, 1), (BIOCSSEESENT, 0)] {
        // Frames come at once, carry their own source address, and those written here are not
        // read back.
        let mut value: libc::c_uint = value;
        bpf_ioctl(raw, option, &mut value)?;
    }
    // SAFETY: BIOCPROMISC takes no argument.
    if unsafe { libc::ioctl(raw, BIOCPROMISC) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(fd)
}

fn bpf_ioctl<T>(fd: RawFd, request: libc::c_ulong, argument: &mut T) -> Result<()> {
    // SAFETY: each request is paired with the type it reads and writes.
    if unsafe { libc::ioctl(fd, request, argument as *mut T) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}
