use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ipnet::IpNet;

use crate::io::Queue;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
use crate::layer::Ethernet;
use crate::layer::{Ip, Layer};
use crate::sys::{self, Tunnel};

/// A virtual network interface, as a handle to configure it: a [`Tun`] interface carries IP
/// packets, a [`Tap`] interface Ethernet frames. Its packets go through its [`Queue`]s, which
/// come with it when it is built.
///
/// Cloning gives another handle to the same interface. Unless it persists, the interface goes
/// away once every handle, queue, reader and writer is dropped, also when the process dies.
pub struct Device<L: Layer = Ip> {
    tunnel: Arc<L::Tunnel>,
    /// Whether addresses added from now on bring routes to their subnets.
    prefix_routes: Arc<AtomicBool>,
}

/// A TUN interface: IP packets in and out.
pub type Tun = Device<Ip>;

/// A TAP interface: Ethernet frames in and out. On Windows it is a TAP-Windows adapter, whose
/// driver (tap-windows6) has to be installed; on macOS a pair of `feth` interfaces.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
pub type Tap = Device<Ethernet>;

/// How serious a message of Wintun's is.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WintunLevel {
    /// Something worth knowing.
    Info,
    /// Something went wrong and was worked around.
    Warning,
    /// Something failed.
    Error,
}

/// What a device does with segments larger than the MTU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Offload {
    /// TCP segments of up to 64 KiB are read and written whole.
    pub tcp: bool,
    /// UDP segments are read and written whole.
    pub udp: bool,
}

/// How a device is created.
pub struct Builder<L: Layer = Ip> {
    options: Options,
    layer: PhantomData<fn() -> L>,
}

/// Whether the interface is brought up once it is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Up {
    /// Brought up.
    Yes,
    /// Brought down.
    No,
    /// As it is: for an interface that already exists.
    Unchanged,
}

/// An address with the prefix of its subnet and, on a point-to-point link, the address of the
/// far end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    /// The address and its subnet.
    pub net: IpNet,
    /// The far end of a point-to-point link.
    pub peer: Option<IpAddr>,
}

/// Everything a builder was told.
#[derive(Clone, Debug)]
pub struct Options {
    /// The interface name.
    pub name: Option<String>,
    /// Whether the device carries Ethernet frames.
    pub ethernet: bool,
    /// The MTU.
    pub mtu: Option<u32>,
    /// The addresses to add.
    pub addresses: Vec<Address>,
    /// The hardware address of a layer 2 interface.
    pub mac_address: Option<[u8; 6]>,
    /// How many queues to open.
    pub queues: usize,
    /// Whether segments of up to 64 KiB are asked for.
    pub offload: bool,
    /// Whether frames carry the system's packet information in front.
    pub packet_information: bool,
    /// Whether the interface is brought up.
    pub up: Up,
    /// Whether each address brings a route to its subnet.
    pub prefix_routes: bool,
    /// Whether the interface stays after the device is gone; left out, an interface that is
    /// taken over stays as it was.
    pub persist: Option<bool>,
    /// Whether an interface of the name that already exists is taken over.
    pub reuse: bool,
    /// Whether reads and writes go through io_uring.
    #[cfg(target_os = "linux")]
    pub uring: Uring,
    /// Whether a full queue pauses the kernel's sending.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub backpressure: bool,
    /// The length of the transmit queue.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub tx_queue_len: Option<u32>,
    /// The user who may open a persistent interface.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub owner: Option<u32>,
    /// The group whose members may open a persistent interface.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub group: Option<u32>,
    /// The name of the second `feth` interface of a TAP device.
    #[cfg(target_os = "macos")]
    pub peer_name: Option<String>,
    /// What only Windows has.
    #[cfg(windows)]
    pub windows: sys::WindowsOptions,
}

/// Whether reads and writes on Linux go through io_uring, one system call for a whole batch.
/// Only 64-bit Linux has it; Android does not let applications use it.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Uring {
    /// io_uring where the kernel can complete reads and writes of the device without waiting
    /// (Linux 6.4 and later) and the system allows it; plain system calls otherwise.
    #[default]
    Auto,
    /// Plain system calls only.
    Off,
    /// io_uring or nothing: creating the device fails where it cannot be used.
    Required,
}

impl<L: Layer> Default for Builder<L> {
    fn default() -> Builder<L> {
        Builder {
            options: Options {
                name: None,
                ethernet: L::ETHERNET,
                mtu: None,
                addresses: Vec::new(),
                mac_address: None,
                queues: 1,
                offload: true,
                packet_information: false,
                up: Up::Yes,
                prefix_routes: true,
                persist: None,
                reuse: true,
                #[cfg(target_os = "linux")]
                uring: Uring::Auto,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                backpressure: true,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                tx_queue_len: None,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                owner: None,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                group: None,
                #[cfg(target_os = "macos")]
                peer_name: None,
                #[cfg(windows)]
                windows: sys::WindowsOptions::default(),
            },
            layer: PhantomData,
        }
    }
}

impl<L: Layer> Clone for Builder<L> {
    fn clone(&self) -> Builder<L> {
        Builder { options: self.options.clone(), layer: PhantomData }
    }
}

impl<L: Layer> fmt::Debug for Builder<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Builder").field("options", &self.options).finish()
    }
}

impl<L: Layer> Builder<L> {
    /// The interface name. Left out, the system picks one. On macOS a TUN interface must be
    /// called `utun` and a number, and a TAP interface `feth` and a number; on the BSDs `tun` or
    /// `tap` and a number.
    pub fn name(mut self, name: impl Into<String>) -> Builder<L> {
        self.options.name = Some(name.into());
        self
    }

    /// The MTU. Left out, the system default stays.
    pub fn mtu(mut self, mtu: u32) -> Builder<L> {
        self.options.mtu = Some(mtu);
        self
    }

    /// Adds an address with the prefix of its subnet.
    pub fn address(mut self, net: IpNet) -> Builder<L> {
        self.options.addresses.push(Address { net, peer: None });
        self
    }

    /// Adds an address on a point-to-point link, with the address of the far end.
    pub fn peer_address(mut self, net: IpNet, peer: IpAddr) -> Builder<L> {
        self.options.addresses.push(Address { net, peer: Some(peer) });
        self
    }

    /// Whether the system hands over and takes segments of up to 64 KiB: TCP and UDP on Linux,
    /// TCP on OpenBSD and on FreeBSD's TAP interfaces. On by default; other systems have no such
    /// offload, and packet information rules it out.
    pub fn offload(mut self, offload: bool) -> Builder<L> {
        self.options.offload = offload;
        self
    }

    /// Whether the interface is brought up once it is configured. Up by default.
    pub fn up(mut self, up: bool) -> Builder<L> {
        self.options.up = if up { Up::Yes } else { Up::No };
        self
    }

    /// Leaves an interface that already exists up or down as it is.
    pub fn keep_up_state(mut self) -> Builder<L> {
        self.options.up = Up::Unchanged;
        self
    }

    /// Whether each address brings a route to its subnet through the interface. On by default.
    pub fn prefix_routes(mut self, on: bool) -> Builder<L> {
        self.options.prefix_routes = on;
        self
    }

    /// Whether the interface stays after the last handle is dropped. Left out, a new interface
    /// does not, and one that is taken over stays as it was.
    pub fn persist(mut self, persist: bool) -> Builder<L> {
        self.options.persist = Some(persist);
        self
    }

    /// Whether an interface of the given name that already exists is taken over. On by default;
    /// without it, creating the device fails if the name is taken.
    pub fn reuse(mut self, reuse: bool) -> Builder<L> {
        self.options.reuse = reuse;
        self
    }

    /// Creates and configures the interface, and hands it over with its queues. Needs the
    /// privilege to create interfaces.
    pub fn build(self) -> io::Result<(Device<L>, Vec<Queue<L>>)> {
        let options = &self.options;
        if options.queues == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a device needs at least one queue"));
        }
        if let Some(address) = options.addresses.iter().find(|address| address.peer.is_some_and(|peer| peer.is_ipv4() != address.net.addr().is_ipv4())) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("the peer of {} is of the other IP version", address.net)));
        }
        let tunnel = L::Tunnel::create(options)?;
        tunnel.configure(options)?;
        let tunnel = Arc::new(tunnel);
        let queues = (0..tunnel.queues()).map(|index| Queue { tunnel: tunnel.clone(), index }).collect();
        Ok((Device { tunnel, prefix_routes: Arc::new(AtomicBool::new(options.prefix_routes)) }, queues))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl<L: Layer> Builder<L> {
    /// How many queues to open, each with its own reader and writer. The kernel keeps every flow
    /// on one queue.
    pub fn queues(mut self, queues: usize) -> Builder<L> {
        self.options.queues = queues;
        self
    }

    /// Whether frames carry flags and the protocol in front (`struct tun_pi`). Frames are then
    /// read and written as they are, without checksum work or segmentation.
    pub fn packet_information(mut self, on: bool) -> Builder<L> {
        self.options.packet_information = on;
        self
    }

    /// Whether reads and writes go through io_uring.
    #[cfg(target_os = "linux")]
    pub fn uring(mut self, uring: Uring) -> Builder<L> {
        self.options.uring = uring;
        self
    }

    /// Whether a full queue pauses the kernel's sending, so its queueing discipline holds the
    /// packets, instead of dropping them (`IFF_BACKPRESSURE`, Linux 7.3 and later). On by
    /// default where the kernel has it.
    pub fn backpressure(mut self, backpressure: bool) -> Builder<L> {
        self.options.backpressure = backpressure;
        self
    }

    /// The length of the interface's transmit queue, in packets.
    pub fn tx_queue_len(mut self, packets: u32) -> Builder<L> {
        self.options.tx_queue_len = Some(packets);
        self
    }

    /// The user who may open a persistent interface without privileges.
    pub fn owner(mut self, uid: u32) -> Builder<L> {
        self.options.owner = Some(uid);
        self
    }

    /// The group whose members may open a persistent interface without privileges.
    pub fn group(mut self, gid: u32) -> Builder<L> {
        self.options.group = Some(gid);
        self
    }
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
impl Builder<Ip> {
    /// Whether packets carry the address family, four bytes, in front. Packets are then read
    /// and written as they are, without checksum work or segmentation.
    pub fn packet_information(mut self, on: bool) -> Builder<Ip> {
        self.options.packet_information = on;
        self
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
impl Builder<Ethernet> {
    /// The hardware address. Left out, the system makes one up.
    pub fn mac_address(mut self, mac: [u8; 6]) -> Builder<Ethernet> {
        self.options.mac_address = Some(mac);
        self
    }

    /// The name of the other `feth` interface of the pair, through which frames are read and
    /// written. Left out, the system picks one.
    #[cfg(target_os = "macos")]
    pub fn peer_name(mut self, name: impl Into<String>) -> Builder<Ethernet> {
        self.options.peer_name = Some(name.into());
        self
    }
}

#[cfg(windows)]
impl<L: Layer> Builder<L> {
    /// The MTU of IPv6, at least 1280, when it differs from IPv4's; [`Builder::mtu`] sets both.
    pub fn mtu_v6(mut self, mtu: u32) -> Builder<L> {
        self.options.windows.mtu_v6 = Some(mtu);
        self
    }

    /// The interface metric of both IP versions. A low metric makes Windows prefer the
    /// interface, its routes and its name servers.
    pub fn metric(mut self, metric: u32) -> Builder<L> {
        self.options.windows.metric = Some(metric);
        self
    }
}

#[cfg(windows)]
impl Builder<Ip> {
    /// The adapter's GUID. Left out, it is derived from the name, so that the same name gets the
    /// same adapter identity and Windows keeps its network profile. A TAP-Windows adapter gets
    /// its GUID from the system.
    pub fn guid(mut self, guid: u128) -> Builder<Ip> {
        self.options.windows.guid = Some(guid);
        self
    }

    /// Where `wintun.dll` is; a relative path is taken from the current directory. Left out, it
    /// is looked for next to the program and in the system directory.
    pub fn wintun(mut self, path: impl Into<std::path::PathBuf>) -> Builder<Ip> {
        self.options.windows.wintun = Some(path.into());
        self
    }

    /// The size of each of Wintun's two rings, a power of two from 128 KiB to 64 MiB. 8 MiB by
    /// default.
    pub fn ring_capacity(mut self, bytes: u32) -> Builder<Ip> {
        self.options.windows.ring_capacity = bytes;
        self
    }

    /// The tunnel type shown for the adapter.
    pub fn tunnel_type(mut self, tunnel_type: impl Into<String>) -> Builder<Ip> {
        self.options.windows.tunnel_type = tunnel_type.into();
        self
    }

    /// Whether the Wintun driver is removed from the system once the device is dropped and no
    /// other adapter uses it. Off by default.
    pub fn delete_driver(mut self, delete: bool) -> Builder<Ip> {
        self.options.windows.delete_driver = delete;
        self
    }

    /// Hands Wintun's own messages to `logger`, with their level and time. Wintun keeps one
    /// logger for the whole process, which the last device built with one sets.
    pub fn wintun_logger(mut self, logger: fn(WintunLevel, std::time::SystemTime, &str)) -> Builder<Ip> {
        self.options.windows.logger = Some(logger);
        self
    }
}

impl<L: Layer> Clone for Device<L> {
    fn clone(&self) -> Device<L> {
        Device { tunnel: self.tunnel.clone(), prefix_routes: self.prefix_routes.clone() }
    }
}

impl<L: Layer> Device<L> {
    /// Starts describing a new interface.
    pub fn builder() -> Builder<L> {
        Builder::default()
    }

    /// The interface name, as it is now.
    pub fn name(&self) -> io::Result<String> {
        self.tunnel.interface().name()
    }

    /// Renames the interface. Linux before 6.2 renames an interface only while it is down;
    /// Windows renames the adapter. Fails with [`io::ErrorKind::Unsupported`] where interfaces
    /// keep their names.
    pub fn set_name(&self, name: &str) -> io::Result<()> {
        self.tunnel.set_name(name)
    }

    /// The interface index.
    pub fn index(&self) -> u32 {
        self.tunnel.interface().index()
    }

    /// What the device does with segments larger than the MTU.
    pub fn offload(&self) -> Offload {
        self.tunnel.offload()
    }

    /// Whether frames carry the system's packet information in front.
    pub fn packet_information(&self) -> bool {
        self.tunnel.packet_information()
    }

    /// The current MTU.
    pub fn mtu(&self) -> io::Result<u32> {
        self.tunnel.interface().mtu()
    }

    /// Changes the MTU.
    pub fn set_mtu(&self, mtu: u32) -> io::Result<()> {
        self.tunnel.set_mtu(mtu)
    }

    /// Whether the interface is up.
    pub fn is_up(&self) -> io::Result<bool> {
        self.tunnel.is_up()
    }

    /// Brings the interface up or down. A Wintun adapter on Windows is up while a session runs
    /// on it: bringing it down ends the session once the reader gives back the packets it holds,
    /// and packets written meanwhile are lost. A TAP-Windows adapter is up while its medium is
    /// connected. illumos keeps a flag for each address and brings up only addresses: the device
    /// brings its addresses up and down with it. NetBSD and OpenBSD check IPv6 addresses for
    /// duplicates on the link again when the interface comes up: the call returns once they can
    /// be used, as [`Device::add_address`] does.
    pub fn set_up(&self, up: bool) -> io::Result<()> {
        self.tunnel.set_up(up)
    }

    /// Whether the interface is up and its link is too: a TUN or TAP interface has a link while
    /// a queue is open; on FreeBSD a TUN interface needs an address as well.
    pub fn is_running(&self) -> io::Result<bool> {
        self.tunnel.is_running()
    }

    /// The addresses of the interface with the prefixes of their subnets.
    pub fn addresses(&self) -> io::Result<Vec<IpNet>> {
        self.tunnel.interface().addresses()
    }

    /// Adds an address; with prefix routes on, its subnet is reached through the interface. The
    /// address can be used once the call returns: NetBSD and OpenBSD check a new IPv6 address for
    /// duplicates on the link first, which takes them about a second, and the call fails with
    /// [`io::ErrorKind::AddrInUse`] when another host has it.
    pub fn add_address(&self, net: IpNet) -> io::Result<()> {
        self.insert(Address { net, peer: None })
    }

    /// Adds an address on a point-to-point link, with the address of the far end, which is
    /// reached through the interface.
    pub fn add_peer_address(&self, net: IpNet, peer: IpAddr) -> io::Result<()> {
        self.insert(peer_address(net, peer)?)
    }

    fn insert(&self, address: Address) -> io::Result<()> {
        self.tunnel.interface().add_address(address, self.prefix_routes())
    }

    /// Removes an address.
    pub fn remove_address(&self, net: IpNet) -> io::Result<()> {
        self.tunnel.interface().remove_address(net)
    }

    /// Makes `net` the only address of its IP version: it is added first, and the others are
    /// removed after, so the interface is never without one. An address that is there with
    /// another prefix is removed and added again with this one, as the systems keep one prefix
    /// for an address.
    pub fn set_address(&self, net: IpNet) -> io::Result<()> {
        self.replace_addresses(Address { net, peer: None })
    }

    /// [`Device::set_address`] for an address on a point-to-point link, with the address of the
    /// far end.
    pub fn set_peer_address(&self, net: IpNet, peer: IpAddr) -> io::Result<()> {
        self.replace_addresses(peer_address(net, peer)?)
    }

    fn replace_addresses(&self, address: Address) -> io::Result<()> {
        let net = address.net;
        let current: Vec<IpNet> = self.addresses()?.into_iter().filter(|other| other.addr().is_ipv4() == net.addr().is_ipv4()).collect();
        // The far end of an address may be another one: the address is added again with it.
        let kept = address.peer.is_none() && current.contains(&net);
        if !kept {
            // The systems know an address by itself: with another prefix, or another far end, it
            // goes before it comes again.
            for same in current.iter().filter(|other| other.addr() == net.addr()) {
                self.remove_address(*same)?;
            }
            self.insert(address)?;
        }
        for other in current.iter().filter(|other| other.addr() != net.addr() || (kept && **other != net)) {
            self.remove_address(*other)?;
        }
        Ok(())
    }

    /// The broadcast address of the interface's first IPv4 address, if it has one. A
    /// point-to-point interface of the BSDs and the Apple systems has none and fails with
    /// [`io::ErrorKind::Unsupported`].
    pub fn broadcast(&self) -> io::Result<Option<Ipv4Addr>> {
        self.tunnel.interface().broadcast()
    }

    /// Sets the broadcast address of the interface's first IPv4 address.
    pub fn set_broadcast(&self, broadcast: Ipv4Addr) -> io::Result<()> {
        self.tunnel.interface().set_broadcast(broadcast)
    }

    /// Whether addresses added from now on bring routes to their subnets.
    pub fn prefix_routes(&self) -> bool {
        self.prefix_routes.load(Ordering::Relaxed)
    }

    /// Sets whether addresses added from now on bring routes to their subnets.
    pub fn set_prefix_routes(&self, on: bool) {
        self.prefix_routes.store(on, Ordering::Relaxed);
    }

    /// Routes `net` through the interface: to the far end of the link, or through the gateway
    /// `via`.
    pub fn add_route(&self, net: IpNet, via: Option<IpAddr>) -> io::Result<()> {
        if via.is_some_and(|via| via.is_ipv4() != net.addr().is_ipv4()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "the gateway is of the other IP version"));
        }
        self.tunnel.interface().add_route(net.trunc(), via)
    }

    /// Removes a route that [`Device::add_route`] added.
    pub fn remove_route(&self, net: IpNet, via: Option<IpAddr>) -> io::Result<()> {
        self.tunnel.interface().remove_route(net.trunc(), via)
    }

    /// Sets whether the interface stays after the last handle is dropped.
    pub fn set_persist(&self, persist: bool) -> io::Result<()> {
        self.tunnel.set_persist(persist)
    }
}

fn peer_address(net: IpNet, peer: IpAddr) -> io::Result<Address> {
    if peer.is_ipv4() != net.addr().is_ipv4() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the peer is of the other IP version"));
    }
    Ok(Address { net, peer: Some(peer) })
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
impl Device<Ethernet> {
    /// The hardware address.
    pub fn mac_address(&self) -> io::Result<[u8; 6]> {
        self.tunnel.mac_address()
    }

    /// Changes the hardware address. A TAP-Windows adapter takes its address only when it
    /// starts, which restarts it under the open device: give it to [`Builder::mac_address`]
    /// instead; here Windows fails with [`io::ErrorKind::Unsupported`].
    pub fn set_mac_address(&self, mac: [u8; 6]) -> io::Result<()> {
        self.tunnel.set_mac_address(mac)
    }
}

#[cfg(unix)]
impl<L: Layer> Device<L>
where
    L::Tunnel: sys::Adopt,
{
    /// Wraps an interface that something else created, such as the descriptor Android's
    /// `VpnService` or iOS's packet tunnel hands to an application, and hands it over with its
    /// one queue. Fails for a descriptor of the other kind of interface. On Linux a descriptor
    /// with `IFF_VNET_HDR` gets the offloads this library asks for, and one whose interface lives
    /// in another network namespace is adopted without its interface: its queue reads and writes,
    /// and the interface is configured where it lives. On OpenBSD a descriptor with
    /// `tun_hdr` keeps the offloads it has. On the BSDs and Apple systems packets come without
    /// the address family in front.
    pub fn from_fd(fd: std::os::fd::OwnedFd) -> io::Result<(Device<L>, Queue<L>)> {
        let tunnel = Arc::new(<L::Tunnel as sys::Adopt>::adopt(fd, L::ETHERNET)?);
        let queue = Queue { tunnel: tunnel.clone(), index: 0 };
        Ok((Device { tunnel, prefix_routes: Arc::new(AtomicBool::new(true)) }, queue))
    }
}

#[cfg(unix)]
impl<L: Layer> Device<L>
where
    L::Tunnel: sys::Descriptors,
{
    /// The descriptor of queue `queue`.
    pub fn queue_fd(&self, queue: usize) -> io::Result<std::os::fd::BorrowedFd<'_>> {
        sys::Descriptors::queue_fd(&*self.tunnel, queue)
    }

    /// The descriptor of a device with one queue, for something else to use, in exchange for
    /// the device and its queue. Fails, giving both back, while other handles of the device
    /// exist or when the queue is another device's. NetBSD keeps the interface after the
    /// descriptor is closed; a device that [`Device::from_fd`] made of it removes it once told
    /// [`Device::set_persist`]`(false)`.
    pub fn into_fd(self, queue: Queue<L>) -> Result<std::os::fd::OwnedFd, (Device<L>, Queue<L>)> {
        if !Arc::ptr_eq(&self.tunnel, &queue.tunnel) {
            return Err((self, queue));
        }
        let Device { tunnel, prefix_routes } = self;
        let Queue { tunnel: queued, index } = queue;
        drop(queued);
        let tunnel = match Arc::try_unwrap(tunnel) {
            Ok(tunnel) => match sys::Descriptors::into_fd(tunnel) {
                Ok(fd) => return Ok(fd),
                Err(tunnel) => Arc::new(tunnel),
            },
            Err(tunnel) => tunnel,
        };
        Err((Device { tunnel: tunnel.clone(), prefix_routes }, Queue { tunnel, index }))
    }
}

#[cfg(target_vendor = "apple")]
impl Device<Ip> {
    /// Wraps the utun interface that Network Extension opened for the packet tunnel provider
    /// this process runs, without going through `NEPacketTunnelFlow`. The provider keeps its own
    /// descriptor; the device holds a duplicate.
    pub fn from_packet_tunnel() -> io::Result<(Device<Ip>, Queue<Ip>)> {
        let tunnel = Arc::new(sys::Tun::packet_tunnel()?);
        let queue = Queue { tunnel: tunnel.clone(), index: 0 };
        Ok((Device { tunnel, prefix_routes: Arc::new(AtomicBool::new(true)) }, queue))
    }
}

#[cfg(any(target_vendor = "apple", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
impl Device<Ip> {
    /// Changes whether packets carry the address family in front, from the next read and write
    /// on. These systems always have it in the kernel, so only the framing changes. On OpenBSD a
    /// device with offloads takes none.
    pub fn set_packet_information(&self, on: bool) -> io::Result<()> {
        self.tunnel.set_packet_information(on)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl<L: Layer<Tunnel = sys::linux::Tunnel>> Device<L> {
    /// The length of the interface's transmit queue, in packets.
    pub fn tx_queue_len(&self) -> io::Result<u32> {
        self.tunnel.interface().tx_queue_len()
    }

    /// Changes the length of the interface's transmit queue.
    pub fn set_tx_queue_len(&self, packets: u32) -> io::Result<()> {
        self.tunnel.interface().set_tx_queue_len(packets)
    }

    /// Lets the user `uid` open the persistent interface without privileges.
    pub fn set_owner(&self, uid: u32) -> io::Result<()> {
        self.tunnel.set_owner(uid)
    }

    /// Lets members of the group `gid` open the persistent interface without privileges.
    pub fn set_group(&self, gid: u32) -> io::Result<()> {
        self.tunnel.set_group(gid)
    }

    /// Opens one more queue of a device made with several. The kernel spreads flows over the
    /// queues anew.
    pub fn add_queue(&self) -> io::Result<Queue<L>> {
        let index = self.tunnel.add_queue()?;
        Ok(Queue { tunnel: self.tunnel.clone(), index })
    }
}

#[cfg(windows)]
impl<L: Layer> Device<L> {
    /// The interface's locally unique identifier, which the IP Helper API takes.
    pub fn luid(&self) -> u64 {
        self.tunnel.interface().luid()
    }

    /// The MTU of IPv6, which Windows keeps apart from IPv4's.
    pub fn mtu_v6(&self) -> io::Result<u32> {
        self.tunnel.interface().mtu_v6()
    }

    /// Changes the MTU of IPv6 only, to at least 1280. [`Device::set_mtu`] changes both IP
    /// versions, IPv6 only when the MTU is at least that.
    pub fn set_mtu_v6(&self, mtu: u32) -> io::Result<()> {
        self.tunnel.interface().set_mtu_v6(mtu)
    }

    /// The interface metric of IPv4.
    pub fn metric(&self) -> io::Result<u32> {
        self.tunnel.interface().metric()
    }

    /// Sets the interface metric of both IP versions. A low metric makes Windows prefer the
    /// interface, its routes and its name servers.
    pub fn set_metric(&self, metric: u32) -> io::Result<()> {
        self.tunnel.interface().set_metric(metric)
    }

    /// The version of the running driver, Wintun or TAP-Windows, as `major.minor`.
    pub fn driver_version(&self) -> io::Result<String> {
        self.tunnel.driver_version()
    }

    /// Makes `servers` the interface's name servers, in order of preference: the IPv4 ones for
    /// IPv4 and the IPv6 ones for IPv6. An IP version without servers in the list has none
    /// configured afterwards, so an empty list clears both.
    pub fn set_dns_servers(&self, servers: &[IpAddr]) -> io::Result<()> {
        self.tunnel.interface().set_dns_servers(servers)
    }
}

impl<L: Layer> fmt::Debug for Device<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(if L::ETHERNET { "Tap" } else { "Tun" })
            .field("name", &self.name().unwrap_or_default())
            .field("index", &self.index())
            .finish()
    }
}
