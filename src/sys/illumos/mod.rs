//! illumos: the tun driver's STREAMS device. The data stream of a unit carries its packets; for
//! each IP version a second stream of the unit, with IP pushed on it, is linked under a
//! multiplexor, which makes the IP interface. The links last while the multiplexors are open, so
//! the interface goes away with the device, and with the process. Each address lives on a logical
//! interface of its own; routes go through the routing socket.

mod sys;

use std::ffi::CStr;
use std::io::{Error, ErrorKind, Result};
use std::mem::zeroed;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use xtun_wire::{Framing, Prefix, Takes};
use ipnet::IpNet;

use super::unix::transport::{Each, Facts, Gathered, Sink, Source};
use super::unix::{Queue, control_socket, copy_name, index_of, read_name, set_nonblocking};
use crate::device::{Address, Offload, Options};

const NO_PERSIST: &str = "the driver frees a unit when its device is closed, and the interface stops working";

/// A tun device.
pub struct Tun {
    interface: Interface,
    /// The multiplexors this device linked IP's streams under, one per IP version: closing them
    /// unlinks the streams and so removes the IP interface. Before `queue`, so that the interface
    /// goes while its unit is still there.
    links: Vec<OwnedFd>,
    queue: Arc<Queue>,
}

impl Facts for Tun {
    fn takes(&self) -> Takes {
        Takes {
            framing: Framing { prefix: Prefix::None, ethernet: false },
            tcp: false,
            udp: false,
            udp_max_segments: 0,
            max_frame: usize::MAX,
        }
    }
}

impl super::Tunnel for Tun {
    type Source = Source<Tun, Each>;
    type Sink = Sink<Tun, Gathered>;

    fn create(options: &Options) -> Result<Tun> {
        if options.queues != 1 {
            return Err(Error::new(ErrorKind::Unsupported, "a tun device has one queue"));
        }
        if options.packet_information {
            return Err(Error::new(ErrorKind::Unsupported, "illumos's tun devices carry bare IP packets"));
        }
        if options.persist == Some(true) {
            return Err(Error::new(ErrorKind::Unsupported, NO_PERSIST));
        }
        let requested = options.name.as_deref().map(unit_of).transpose()?;
        let (data, unit, links) = open(requested, options.reuse)?;
        Tun::wrap(data, unit, links)
    }

    fn queues(&self) -> usize {
        1
    }

    fn source(self: &Arc<Tun>, queue: usize, frames: usize) -> Result<Self::Source> {
        Source::new(self.clone(), self.queue(queue)?, Each, frames)
    }

    fn sink(self: &Arc<Tun>, queue: usize) -> Result<Self::Sink> {
        Ok(Sink::new(self.clone(), self.queue(queue)?, Gathered::default()))
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn offload(&self) -> Offload {
        Offload::default()
    }

    fn set_persist(&self, persist: bool) -> Result<()> {
        if persist {
            return Err(Error::new(ErrorKind::Unsupported, NO_PERSIST));
        }
        Ok(())
    }
}

impl super::Descriptors for Tun {
    fn queue_fd(&self, queue: usize) -> Result<BorrowedFd<'_>> {
        let fd = self.queue(queue)?.raw_fd();
        // SAFETY: the queue lives as long as the device.
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    /// The data stream, for something else to use. IP's streams stay linked under their
    /// multiplexors, which this process keeps open from now on: the interface stays while the
    /// process runs.
    fn into_fd(self) -> std::result::Result<OwnedFd, Tun> {
        let Tun { interface, links, queue } = self;
        match Arc::try_unwrap(queue) {
            Ok(queue) => {
                for link in links {
                    std::mem::forget(link);
                }
                Ok(queue.into_fd())
            }
            Err(queue) => Err(Tun { interface, links, queue }),
        }
    }
}

impl super::Adopt for Tun {
    /// Wraps the data stream of a unit that something else made; its IP interface is left to
    /// whoever linked it.
    fn adopt(fd: OwnedFd, ethernet: bool) -> Result<Tun> {
        if ethernet {
            return Err(Error::new(ErrorKind::InvalidInput, "a tun device carries IP packets, not Ethernet frames"));
        }
        let unit = match stream_ioctl(&fd, sys::TUNGETPPA, None) {
            Ok(unit) => unit,
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "the tun driver does not tell a descriptor's unit: TUNGETPPA came after its version 1.3.3",
                ));
            }
            Err(error) => return Err(error),
        };
        Tun::wrap(fd, unit as u32, Vec::new())
    }
}

impl Tun {
    fn wrap(data: OwnedFd, unit: u32, links: Vec<OwnedFd>) -> Result<Tun> {
        // SAFETY: I_SRDOPT takes the read mode as its argument.
        if unsafe { libc::ioctl(data.as_raw_fd(), sys::I_SRDOPT, sys::RMSGD) } < 0 {
            return Err(Error::last_os_error());
        }
        set_nonblocking(data.as_raw_fd())?;
        let interface = Interface::new(format!("{}{unit}", sys::TUN_PREFIX))?;
        Ok(Tun { interface, links, queue: Arc::new(Queue::new(data)) })
    }

    fn queue(&self, queue: usize) -> Result<&Arc<Queue>> {
        if queue != 0 {
            return Err(Error::new(ErrorKind::InvalidInput, format!("the device has one queue, there is no queue {queue}")));
        }
        Ok(&self.queue)
    }
}

/// The interface behind a device.
pub struct Interface {
    index: u32,
    name: String,
    /// Whether the interface is up. illumos has a flag for each logical interface and none for
    /// the interface, and brings up only logical interfaces with an address: each address comes
    /// up or goes down with the interface.
    up: AtomicBool,
}

impl Interface {
    /// The interface called `name`, up if its first logical interface is.
    fn new(name: String) -> Result<Interface> {
        let up = flags(libc::AF_INET, &name)? & sys::IFF_UP != 0;
        Ok(Interface { index: index_of(&name)?, name, up: AtomicBool::new(up) })
    }

    pub fn name(&self) -> Result<String> {
        Ok(self.name.clone())
    }

    pub fn set_name(&self, _name: &str) -> Result<()> {
        Err(Error::new(ErrorKind::Unsupported, "a tun interface on illumos is called after its unit"))
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn mtu(&self) -> Result<u32> {
        let mut request = lifreq(&self.name)?;
        ioctl(libc::AF_INET, sys::SIOCGLIFMTU, &mut request)?;
        // SAFETY: SIOCGLIFMTU filled in the MTU.
        Ok(unsafe { request.lifr_lifru.lifru_mtu })
    }

    /// Sets the MTU of both IP versions; IPv6 takes no less than 1280.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        if mtu > sys::MAX_MTU {
            return Err(Error::new(ErrorKind::InvalidInput, format!("illumos's tun driver carries packets of up to {} bytes", sys::MAX_MTU)));
        }
        for (family, mtu) in [(libc::AF_INET, mtu), (libc::AF_INET6, mtu.max(sys::MIN_MTU_V6))] {
            let mut request = lifreq(&self.name)?;
            request.lifr_lifru.lifru_mtu = mtu;
            ioctl(family, sys::SIOCSLIFMTU, &mut request)?;
        }
        Ok(())
    }

    pub fn is_up(&self) -> Result<bool> {
        Ok(self.up.load(Ordering::Relaxed))
    }

    /// Brings every logical interface with an address up or down.
    pub fn set_up(&self, up: bool) -> Result<()> {
        for entry in self.entries()? {
            if !entry.net.addr().is_unspecified() {
                set_flag(entry.family, &entry.logical, sys::IFF_UP, up)?;
            }
        }
        self.up.store(up, Ordering::Relaxed);
        Ok(())
    }

    /// Up, with the unit's data stream there for IP to send to.
    pub fn is_running(&self) -> Result<bool> {
        Ok(self.is_up()? && flags(libc::AF_INET, &self.name)? & sys::IFF_RUNNING != 0)
    }

    /// The logical interfaces of both IP versions with their addresses, those that are down and
    /// those without an address included.
    fn entries(&self) -> Result<Vec<Entry>> {
        let mut found = Vec::new();
        for family in [libc::AF_INET, libc::AF_INET6] {
            let socket = control_socket(family)?;
            let mut number = sys::lifnum { lifn_family: family as libc::sa_family_t, lifn_flags: sys::LIFC_EVERY, lifn_count: 0 };
            // SAFETY: SIOCGLIFNUM reads and writes a `lifnum`.
            if unsafe { libc::ioctl(socket.as_raw_fd(), sys::SIOCGLIFNUM, &mut number) } < 0 {
                return Err(Error::last_os_error());
            }
            // Room for a few more, which may come meanwhile.
            let room = number.lifn_count as usize + 4;
            // SAFETY: plain old data.
            let mut requests: Vec<sys::lifreq> = (0..room).map(|_| unsafe { zeroed() }).collect();
            let mut list = sys::lifconf {
                lifc_family: family as libc::sa_family_t,
                lifc_flags: sys::LIFC_EVERY,
                lifc_len: (room * size_of::<sys::lifreq>()) as libc::c_int,
                lifc_buf: requests.as_mut_ptr(),
            };
            // SAFETY: SIOCGLIFCONF fills in up to `lifc_len` bytes of `lifreq`s and says how many.
            if unsafe { libc::ioctl(socket.as_raw_fd(), sys::SIOCGLIFCONF, &mut list) } < 0 {
                return Err(Error::last_os_error());
            }
            let listed = list.lifc_len as usize / size_of::<sys::lifreq>();
            for request in &requests[..listed] {
                let logical = read_name(&request.lifr_name);
                let ours = logical == self.name || logical.strip_prefix(&self.name).is_some_and(|rest| rest.starts_with(':'));
                if !ours {
                    continue;
                }
                let mut mask = lifreq(&logical)?;
                ioctl(family, sys::SIOCGLIFNETMASK, &mut mask)?;
                // SAFETY: both hold socket addresses of `family`.
                let net = unsafe {
                    net_of((&raw const request.lifr_lifru.lifru_addr).cast(), (&raw const mask.lifr_lifru.lifru_addr).cast())
                };
                if let Some(net) = net {
                    found.push(Entry { logical, family, net });
                }
            }
        }
        Ok(found)
    }

    pub fn addresses(&self) -> Result<Vec<IpNet>> {
        Ok(self.entries()?.into_iter().map(|entry| entry.net).filter(|net| !net.addr().is_unspecified()).collect())
    }

    /// The first address of a version goes on the interface itself, the others on logical
    /// interfaces of their own; each comes up if the interface is up. With `prefix_route` its
    /// subnet is reached through the interface.
    pub fn add_address(&self, address: Address, prefix_route: bool) -> Result<()> {
        let net = address.net;
        let family = if net.addr().is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let mut request = lifreq(&self.name)?;
        let first = self.entries()?.iter().any(|entry| entry.logical == self.name && entry.family == family && entry.net.addr().is_unspecified());
        request.lifr_lifru.lifru_addr = storage(net.addr());
        let logical = if first {
            ioctl(family, sys::SIOCSLIFADDR, &mut request)?;
            self.name.clone()
        } else {
            // The system names the new logical interface in the request.
            ioctl(family, sys::SIOCLIFADDIF, &mut request)?;
            read_name(&request.lifr_name)
        };
        let mut request = lifreq(&logical)?;
        request.lifr_lifru.lifru_addr = storage(net.netmask());
        ioctl(family, sys::SIOCSLIFNETMASK, &mut request)?;
        // A point-to-point interface comes up only with a far end: the address itself stands in
        // when there is none, as OpenVPN has it on Solaris, and its subnet gets a route.
        let mut request = lifreq(&logical)?;
        request.lifr_lifru.lifru_addr = storage(address.peer.unwrap_or(net.addr()));
        ioctl(family, sys::SIOCSLIFDSTADDR, &mut request)?;
        if self.is_up()? {
            set_flag(family, &logical, sys::IFF_UP, true)?;
        }
        // The route to the subnet goes through the address itself, so that it goes with it.
        if address.peer.is_none() && net.prefix_len() < net.max_prefix_len() && prefix_route {
            tolerate(self.route_message(sys::RTM_ADD, net.trunc(), net.addr(), false), libc::EEXIST)?;
        }
        Ok(())
    }

    /// Removes the logical interface that holds the address; the interface itself only loses it.
    /// The route to the subnet goes first, while the address it goes through is still there,
    /// unless another address of the subnet still needs it.
    pub fn remove_address(&self, net: IpNet) -> Result<()> {
        let family = if net.addr().is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
        let entries = self.entries()?;
        let Some(entry) = entries.iter().find(|entry| entry.net.addr() == net.addr()) else {
            return Err(Error::new(ErrorKind::NotFound, format!("the interface has no address {}", net.addr())));
        };
        let subnet = net.trunc();
        let shared = entries.iter().any(|other| other.net.addr() != net.addr() && !other.net.addr().is_unspecified() && other.net.trunc() == subnet);
        if net.prefix_len() < net.max_prefix_len() && !shared {
            tolerate(self.route_message(sys::RTM_DELETE, subnet, net.addr(), false), libc::ESRCH)?;
        }
        let mut request = lifreq(&entry.logical)?;
        if entry.logical == self.name {
            let unspecified = if family == libc::AF_INET { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };
            request.lifr_lifru.lifru_addr = storage(unspecified);
            ioctl(family, sys::SIOCSLIFADDR, &mut request)?;
        } else {
            request.lifr_lifru.lifru_addr = storage(net.addr());
            ioctl(family, sys::SIOCLIFREMOVEIF, &mut request)?;
        }
        Ok(())
    }

    pub fn broadcast(&self) -> Result<Option<Ipv4Addr>> {
        Err(Error::new(ErrorKind::Unsupported, "a point-to-point interface has no broadcast address"))
    }

    pub fn set_broadcast(&self, _broadcast: Ipv4Addr) -> Result<()> {
        Err(Error::new(ErrorKind::Unsupported, "a point-to-point interface has no broadcast address"))
    }

    pub fn mac_address(&self) -> Result<[u8; 6]> {
        Err(Error::new(ErrorKind::InvalidInput, "a layer 3 interface has no hardware address"))
    }

    pub fn set_mac_address(&self, _mac: [u8; 6]) -> Result<()> {
        Err(Error::new(ErrorKind::InvalidInput, "a layer 3 interface has no hardware address"))
    }

    pub fn add_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        self.route(sys::RTM_ADD, net, via)
    }

    pub fn remove_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        self.route(sys::RTM_DELETE, net, via)
    }

    /// Adds or deletes the route that sends `net` through the gateway `via`, or through the
    /// interface itself.
    fn route(&self, kind: u8, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        match via {
            Some(gateway) => self.route_message(kind, net, gateway, true),
            None => {
                let own = self.addresses()?.into_iter().map(|own| own.addr()).find(|own| own.is_ipv4() == net.addr().is_ipv4());
                let own = own.ok_or_else(|| Error::new(ErrorKind::NotFound, "the interface has no address of that IP version to route through"))?;
                self.route_message(kind, net, own, false)
            }
        }
    }

    /// Sends a routing message for `net` and `gateway`. A gateway `beyond` the link is another
    /// host; a route through the interface itself has one of the interface's own addresses
    /// for its gateway, without `RTF_GATEWAY`, as illumos takes it.
    fn route_message(&self, kind: u8, net: IpNet, gateway: IpAddr, beyond: bool) -> Result<()> {
        let mut flags = sys::RTF_UP | sys::RTF_STATIC | if beyond { sys::RTF_GATEWAY } else { 0 };
        if gateway.is_ipv4() != net.addr().is_ipv4() {
            return Err(Error::new(ErrorKind::InvalidInput, "the gateway is of the other IP version"));
        }
        let host = net.prefix_len() == net.max_prefix_len();
        let mut addrs = sys::RTA_DST | sys::RTA_GATEWAY | sys::RTA_IFP;
        let mut body = sockaddr(net.addr());
        body.extend_from_slice(&sockaddr(gateway));
        if host {
            flags |= sys::RTF_HOST;
        } else {
            addrs |= sys::RTA_NETMASK;
            body.extend_from_slice(&sockaddr(net.netmask()));
        }
        // A `sockaddr_dl` naming the interface by its index.
        let mut link = [0u8; size_of::<libc::sockaddr_dl>()];
        link[..2].copy_from_slice(&(libc::AF_LINK as u16).to_ne_bytes());
        link[2..4].copy_from_slice(&(self.index as u16).to_ne_bytes());
        body.extend_from_slice(&link);
        // SAFETY: plain old data.
        let mut header: sys::rt_msghdr = unsafe { zeroed() };
        let length = size_of::<sys::rt_msghdr>() + body.len();
        header.rtm_msglen = length as u16;
        header.rtm_version = sys::RTM_VERSION;
        header.rtm_type = kind;
        header.rtm_index = self.index as u16;
        header.rtm_flags = flags;
        header.rtm_addrs = addrs;
        header.rtm_seq = 1;
        let mut message = Vec::with_capacity(length);
        // SAFETY: the header is plain old data of its size.
        message.extend_from_slice(unsafe {
            std::slice::from_raw_parts((&raw const header).cast::<u8>(), size_of::<sys::rt_msghdr>())
        });
        message.extend_from_slice(&body);
        // SAFETY: plain socket creation; the descriptor is owned right away.
        let socket = unsafe { libc::socket(libc::AF_ROUTE, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if socket < 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: `socket` is new and owned by nobody else.
        let socket = unsafe { OwnedFd::from_raw_fd(socket) };
        // SAFETY: the message is readable for its length.
        if unsafe { libc::write(socket.as_raw_fd(), message.as_ptr().cast(), message.len()) } < 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

/// One address of the interface, or of one of its logical interfaces.
struct Entry {
    logical: String,
    family: libc::c_int,
    net: IpNet,
}

/// The unit of a tun interface's name.
fn unit_of(name: &str) -> Result<u32> {
    name.strip_prefix(sys::TUN_PREFIX)
        .filter(|unit| !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|unit| unit.parse::<u32>().ok())
        .filter(|unit| *unit < sys::UNITS)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("the interface is called tun and a unit below {}", sys::UNITS)))
}

/// Opens the data stream of a new unit and links IP under it for both versions. A unit whose name
/// an interface still has, left by something that linked IP for good and went away, is passed
/// over; asked for by name, it is taken back with `reuse`.
fn open(requested: Option<u32>, reuse: bool) -> Result<(OwnedFd, u32, Vec<OwnedFd>)> {
    let units: Vec<u32> = match requested {
        Some(unit) => vec![unit],
        None => (0..sys::UNITS).collect(),
    };
    for unit in units {
        let data = open_node(sys::TUN_DEVICE)?;
        let mut asked = unit as libc::c_int;
        match stream_ioctl(&data, sys::TUNNEWPPA, Some(&mut asked)) {
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) && requested.is_none() => continue,
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                return Err(Error::new(ErrorKind::AlreadyExists, format!("tun{unit} is in use")));
            }
            Err(error) => return Err(error),
        }
        let name = format!("{}{unit}", sys::TUN_PREFIX);
        match link_both(&name, unit) {
            Ok(links) => return Ok((data, unit, links)),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => match requested {
                None => continue,
                Some(_) if !reuse => {
                    return Err(Error::new(ErrorKind::AlreadyExists, format!("an interface is called {name}")));
                }
                Some(_) => {
                    unlink_left(&name)?;
                    return Ok((data, unit, link_both(&name, unit)?));
                }
            },
            Err(error) => return Err(error),
        }
    }
    Err(Error::new(ErrorKind::NotFound, format!("all {} tun units are in use", sys::UNITS)))
}

fn link_both(name: &str, unit: u32) -> Result<Vec<OwnedFd>> {
    Ok(vec![link(name, unit, libc::AF_INET)?, link(name, unit, libc::AF_INET6)?])
}

/// Links a stream of `unit`, with IP pushed on it and named `name`, under a new multiplexor for
/// `family`, as `ipadm` plumbs an interface, and returns the multiplexor.
fn link(name: &str, unit: u32, family: libc::c_int) -> Result<OwnedFd> {
    let ip = open_node(sys::TUN_DEVICE)?;
    push(&ip, c"ip")?;
    let mut request = lifreq(name)?;
    request.lifr_ppa = unit;
    request.lifr_lifru.lifru_flags = if family == libc::AF_INET { sys::IFF_IPV4 } else { sys::IFF_IPV6 | sys::IFF_NOLINKLOCAL };
    // SAFETY: SIOCSLIFNAME reads and writes a `lifreq`.
    if unsafe { libc::ioctl(ip.as_raw_fd(), sys::SIOCSLIFNAME, &mut request) } < 0 {
        return Err(Error::last_os_error());
    }
    let mux = multiplexor(family)?;
    // SAFETY: I_LINK takes the descriptor to link as its argument.
    if unsafe { libc::ioctl(mux.as_raw_fd(), sys::I_LINK, ip.as_raw_fd()) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(mux)
}

/// A UDP stream with the arp module on it, which IP's streams are linked under: with the module
/// IP keeps track of the links itself.
fn multiplexor(family: libc::c_int) -> Result<OwnedFd> {
    let mux = open_node(if family == libc::AF_INET { "/dev/udp" } else { "/dev/udp6" })?;
    // Modules that autopush put on come off first, until there are none.
    // SAFETY: I_POP takes no argument.
    while unsafe { libc::ioctl(mux.as_raw_fd(), sys::I_POP, 0) } == 0 {}
    let error = Error::last_os_error();
    if error.raw_os_error() != Some(libc::EINVAL) {
        return Err(error);
    }
    push(&mux, c"arp")?;
    Ok(mux)
}

/// Unlinks the IP streams of an interface that something linked for good and left behind.
fn unlink_left(name: &str) -> Result<()> {
    for family in [libc::AF_INET, libc::AF_INET6] {
        let mut request = lifreq(name)?;
        match ioctl(family, sys::SIOCGLIFMUXID, &mut request) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => continue,
            Err(error) => return Err(error),
        }
        // SAFETY: SIOCGLIFMUXID filled in the link ids.
        let id = unsafe { request.lifr_lifru.lif_muxid[0] };
        let mux = multiplexor(family)?;
        // SAFETY: I_PUNLINK takes the link id as its argument.
        if unsafe { libc::ioctl(mux.as_raw_fd(), sys::I_PUNLINK, id) } < 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

fn push(stream: &OwnedFd, module: &CStr) -> Result<()> {
    // SAFETY: I_PUSH takes a module name.
    if unsafe { libc::ioctl(stream.as_raw_fd(), sys::I_PUSH, module.as_ptr()) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// An ioctl of the tun driver, carried down the stream; returns what the driver answers.
fn stream_ioctl(stream: &OwnedFd, command: libc::c_int, argument: Option<&mut libc::c_int>) -> Result<libc::c_int> {
    let (length, data) = match argument {
        Some(value) => (size_of::<libc::c_int>() as libc::c_int, std::ptr::from_mut(value).cast()),
        None => (0, std::ptr::null_mut()),
    };
    let mut request = sys::strioctl { ic_cmd: command, ic_timout: 0, ic_len: length, ic_dp: data };
    // SAFETY: I_STR reads the request, which points at the argument for its length.
    let answer = unsafe { libc::ioctl(stream.as_raw_fd(), sys::I_STR, &mut request) };
    if answer < 0 {
        return Err(Error::last_os_error());
    }
    Ok(answer)
}

/// Opens a STREAMS device, closed on exec.
fn open_node(path: &str) -> Result<OwnedFd> {
    let path = std::ffi::CString::new(path).expect("a path without NUL");
    // SAFETY: a plain open of a NUL-terminated path.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `fd` is new and owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn lifreq(name: &str) -> Result<sys::lifreq> {
    // SAFETY: plain old data.
    let mut request: sys::lifreq = unsafe { zeroed() };
    copy_name(name, &mut request.lifr_name)?;
    Ok(request)
}

/// An interface ioctl through a socket of `family`.
fn ioctl(family: libc::c_int, request: libc::c_int, argument: &mut sys::lifreq) -> Result<()> {
    let socket = control_socket(family)?;
    // SAFETY: each request reads and writes a `lifreq`.
    if unsafe { libc::ioctl(socket.as_raw_fd(), request, std::ptr::from_mut(argument)) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn flags(family: libc::c_int, name: &str) -> Result<u64> {
    let mut request = lifreq(name)?;
    ioctl(family, sys::SIOCGLIFFLAGS, &mut request)?;
    // SAFETY: SIOCGLIFFLAGS filled in the flags.
    Ok(unsafe { request.lifr_lifru.lifru_flags })
}

fn set_flag(family: libc::c_int, name: &str, flag: u64, on: bool) -> Result<()> {
    let current = flags(family, name)?;
    let wanted = if on { current | flag } else { current & !flag };
    if wanted == current {
        return Ok(());
    }
    let mut request = lifreq(name)?;
    request.lifr_lifru.lifru_flags = wanted;
    ioctl(family, sys::SIOCSLIFFLAGS, &mut request)
}

/// `result`, with the error `code` counting as success.
fn tolerate(result: Result<()>, code: i32) -> Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(code) => Ok(()),
        other => other,
    }
}

/// A socket address in a `sockaddr_storage`, as the logical interface requests take it.
fn storage(ip: IpAddr) -> libc::sockaddr_storage {
    // SAFETY: plain old data.
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let bytes = sockaddr(ip);
    // SAFETY: the storage is larger than any socket address.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), (&raw mut storage).cast::<u8>(), bytes.len()) };
    storage
}

/// The bytes of a `sockaddr_in` or `sockaddr_in6`, which have no length field on illumos.
fn sockaddr(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => {
            // SAFETY: plain old data.
            let mut address: libc::sockaddr_in = unsafe { zeroed() };
            address.sin_family = libc::AF_INET as libc::sa_family_t;
            address.sin_addr.s_addr = u32::from(ip).to_be();
            // SAFETY: plain old data of its size.
            unsafe { std::slice::from_raw_parts((&raw const address).cast::<u8>(), size_of::<libc::sockaddr_in>()) }.to_vec()
        }
        IpAddr::V6(ip) => {
            // SAFETY: plain old data.
            let mut address: libc::sockaddr_in6 = unsafe { zeroed() };
            address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            address.sin6_addr.s6_addr = ip.octets();
            // SAFETY: plain old data of its size.
            unsafe { std::slice::from_raw_parts((&raw const address).cast::<u8>(), size_of::<libc::sockaddr_in6>()) }.to_vec()
        }
    }
}

/// An address with the prefix its mask gives.
///
/// # Safety
///
/// `address` and `mask` must point to socket addresses of the address's stated family.
unsafe fn net_of(address: *const libc::sockaddr, mask: *const libc::sockaddr) -> Option<IpNet> {
    // SAFETY: as the caller says.
    unsafe {
        match i32::from((*address).sa_family) {
            libc::AF_INET => {
                let ip = Ipv4Addr::from(u32::from_be((*address.cast::<libc::sockaddr_in>()).sin_addr.s_addr));
                let prefix = u32::from_be((*mask.cast::<libc::sockaddr_in>()).sin_addr.s_addr).count_ones();
                IpNet::new(IpAddr::V4(ip), prefix as u8).ok()
            }
            libc::AF_INET6 => {
                let ip = Ipv6Addr::from((*address.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr);
                let prefix = u128::from_be_bytes((*mask.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr).count_ones();
                IpNet::new(IpAddr::V6(ip), prefix as u8).ok()
            }
            _ => None,
        }
    }
}
