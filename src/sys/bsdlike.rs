//! The interface behind a device on the systems descended from BSD: the Apple systems. It is
//! configured with interface ioctls and the routing socket, which these systems share; each
//! brings only its layouts and request numbers.

use std::io::{Error, ErrorKind, Result};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use ipnet::IpNet;

use super::darwin::sys as os;
use super::unix::{control_socket, copy_name, index_of};
use crate::device::Address;

#[cfg(target_os = "macos")]
pub(crate) const IOC_VOID: libc::c_ulong = 0x2000_0000;
pub(crate) const IOC_OUT: libc::c_ulong = 0x4000_0000;
pub(crate) const IOC_IN: libc::c_ulong = 0x8000_0000;
pub(crate) const IOC_INOUT: libc::c_ulong = IOC_IN | IOC_OUT;
const IOCPARM_MASK: libc::c_ulong = 0x1fff;

/// An ioctl request number, as `_IOC` of `sys/ioccom.h` makes it on every one of these systems.
pub(crate) const fn ioc(direction: libc::c_ulong, group: u8, number: u8, size: usize) -> libc::c_ulong {
    direction | ((size as libc::c_ulong & IOCPARM_MASK) << 16) | ((group as libc::c_ulong) << 8) | number as libc::c_ulong
}

/// The interface behind a device.
pub struct Interface {
    index: u32,
    /// The interface carries Ethernet frames; one that carries IP packets is point to point.
    ethernet: bool,
    /// Interfaces of the Apple systems keep their names.
    name: String,
}

impl Interface {
    /// The interface called `name`.
    pub(crate) fn new(name: &str, ethernet: bool) -> Result<Interface> {
        Ok(Interface { index: index_of(name)?, ethernet, name: name.to_owned() })
    }

    pub fn name(&self) -> Result<String> {
        Ok(self.name.clone())
    }

    pub fn set_name(&self, _name: &str) -> Result<()> {
        Err(Error::new(ErrorKind::Unsupported, "interfaces on Apple systems keep their names"))
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    fn request(&self) -> Result<os::ifreq> {
        request(&self.name()?)
    }

    pub fn mtu(&self) -> Result<u32> {
        let mut request = self.request()?;
        ioctl(libc::AF_INET, os::SIOCGIFMTU, &mut request)?;
        // SAFETY: SIOCGIFMTU filled in the MTU.
        Ok(unsafe { request.ifr_ifru.ifru_mtu } as u32)
    }

    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        let mut request = self.request()?;
        request.ifr_ifru.ifru_mtu = libc::c_int::try_from(mtu).map_err(|_| Error::new(ErrorKind::InvalidInput, "the MTU is too large"))?;
        ioctl(libc::AF_INET, os::SIOCSIFMTU, &mut request)
    }

    fn flags(&self) -> Result<libc::c_int> {
        let mut request = self.request()?;
        ioctl(libc::AF_INET, os::SIOCGIFFLAGS, &mut request)?;
        // SAFETY: SIOCGIFFLAGS filled in the flags.
        Ok(libc::c_int::from(unsafe { request.ifr_ifru.ifru_flags }))
    }

    pub fn is_up(&self) -> Result<bool> {
        Ok(self.flags()? & libc::IFF_UP != 0)
    }

    pub fn is_running(&self) -> Result<bool> {
        let up_and_running = libc::IFF_UP | libc::IFF_RUNNING;
        Ok(self.flags()? & up_and_running == up_and_running)
    }

    pub fn set_up(&self, up: bool) -> Result<()> {
        let mut request = self.request()?;
        ioctl(libc::AF_INET, os::SIOCGIFFLAGS, &mut request)?;
        // SAFETY: SIOCGIFFLAGS filled in the flags.
        unsafe {
            let up_flag = libc::IFF_UP as libc::c_short;
            if up {
                request.ifr_ifru.ifru_flags |= up_flag;
            } else {
                request.ifr_ifru.ifru_flags &= !up_flag;
            }
        }
        ioctl(libc::AF_INET, os::SIOCSIFFLAGS, &mut request)
    }

    pub fn addresses(&self) -> Result<Vec<IpNet>> {
        addresses_of(&self.name()?)
    }

    /// Adds an address. With `prefix_route` its subnet is reached through the interface. The
    /// Apple systems add IPv6 addresses without checking the link for duplicates, and IPv4
    /// addresses are not checked, so the address can be used at once.
    pub fn add_address(&self, address: Address, prefix_route: bool) -> Result<()> {
        let name = self.name()?;
        let net = address.net;
        match net {
            IpNet::V4(v4) => {
                // SAFETY: plain old data.
                let mut request: os::ifaliasreq = unsafe { zeroed() };
                copy_name(&name, &mut request.ifra_name)?;
                request.ifra_addr = sockaddr_v4(v4.addr());
                // The far end of a point-to-point link: the address itself stands in when there
                // is none, as the systems require one. An Ethernet interface's broadcast address.
                request.ifra_broadaddr = sockaddr_v4(match (address.peer, self.ethernet) {
                    (Some(IpAddr::V6(_)), _) => unreachable!("the peer has the address's IP version"),
                    (Some(IpAddr::V4(peer)), _) => peer,
                    (None, false) => v4.addr(),
                    (None, true) => v4.broadcast(),
                });
                request.ifra_mask = sockaddr_v4(v4.netmask());
                ioctl(libc::AF_INET, os::SIOCAIFADDR, &mut request)?;
            }
            IpNet::V6(v6) => {
                // SAFETY: plain old data.
                let mut request: os::in6_aliasreq = unsafe { zeroed() };
                copy_name(&name, &mut request.ifra_name)?;
                request.ifra_addr = sockaddr_v6(v6.addr());
                if let Some(IpAddr::V6(peer)) = address.peer {
                    request.ifra_dstaddr = sockaddr_v6(peer);
                }
                request.ifra_prefixmask = sockaddr_v6(v6.netmask());
                request.ifra_flags = os::IN6_IFF_NODAD;
                request.ifra_lifetime.ia6t_vltime = os::ND6_INFINITE_LIFETIME;
                request.ifra_lifetime.ia6t_pltime = os::ND6_INFINITE_LIFETIME;
                ioctl(libc::AF_INET6, os::SIOCAIFADDR_IN6, &mut request)?;
            }
        }
        if address.peer.is_some() || net.prefix_len() == net.max_prefix_len() {
            return Ok(());
        }
        // An Ethernet interface gets the route to its subnet from the system; a point-to-point
        // interface does not.
        match (self.ethernet, prefix_route) {
            (false, true) => tolerate(route(RTM_ADD, self.index, net.trunc(), None), libc::EEXIST),
            (true, false) => tolerate(route(RTM_DELETE, self.index, net.trunc(), None), libc::ESRCH),
            _ => Ok(()),
        }
    }

    pub fn remove_address(&self, net: IpNet) -> Result<()> {
        let name = self.name()?;
        match net.addr() {
            IpAddr::V4(address) => {
                let mut request = request(&name)?;
                request.ifr_ifru.ifru_addr = sockaddr_v4(address);
                ioctl(libc::AF_INET, os::SIOCDIFADDR, &mut request)?;
            }
            IpAddr::V6(address) => {
                // SAFETY: plain old data.
                let mut request: os::in6_ifreq = unsafe { zeroed() };
                copy_name(&name, &mut request.ifr_name)?;
                request.ifr_ifru.ifru_addr = sockaddr_v6(address);
                ioctl(libc::AF_INET6, os::SIOCDIFADDR_IN6, &mut request)?;
            }
        }
        // The route to the subnet, unless the address was added without one or another address
        // of the subnet still needs it.
        let subnet = net.trunc();
        if !self.ethernet && net.prefix_len() < net.max_prefix_len() && !self.addresses()?.iter().any(|other| other.trunc() == subnet) {
            tolerate(route(RTM_DELETE, self.index, subnet, None), libc::ESRCH)?;
        }
        Ok(())
    }

    fn broadcast_interface(&self) -> Result<()> {
        if !self.ethernet {
            return Err(Error::new(ErrorKind::Unsupported, "a point-to-point interface has no broadcast address"));
        }
        Ok(())
    }

    pub fn broadcast(&self) -> Result<Option<Ipv4Addr>> {
        self.broadcast_interface()?;
        let mut request = self.request()?;
        match ioctl(libc::AF_INET, os::SIOCGIFBRDADDR, &mut request) {
            // SAFETY: SIOCGIFBRDADDR filled in an IPv4 socket address.
            Ok(()) => Ok(Some(unsafe { ipv4_of(&request.ifr_ifru.ifru_addr) })),
            Err(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn set_broadcast(&self, broadcast: Ipv4Addr) -> Result<()> {
        self.broadcast_interface()?;
        let mut request = self.request()?;
        request.ifr_ifru.ifru_addr = sockaddr_v4(broadcast);
        ioctl(libc::AF_INET, os::SIOCSIFBRDADDR, &mut request)
    }

    fn ethernet_interface(&self) -> Result<()> {
        if !self.ethernet {
            return Err(Error::new(ErrorKind::InvalidInput, "a layer 3 interface has no hardware address"));
        }
        Ok(())
    }

    pub fn mac_address(&self) -> Result<[u8; 6]> {
        self.ethernet_interface()?;
        link_address(&self.name()?)
    }

    pub fn set_mac_address(&self, mac: [u8; 6]) -> Result<()> {
        self.ethernet_interface()?;
        set_link_address(&self.name()?, mac)
    }

    pub fn add_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        route(RTM_ADD, self.index, net, via)
    }

    pub fn remove_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        route(RTM_DELETE, self.index, net, via)
    }
}

/// An `ifreq` naming the interface `name`.
pub(crate) fn request(name: &str) -> Result<os::ifreq> {
    // SAFETY: plain old data.
    let mut request: os::ifreq = unsafe { zeroed() };
    copy_name(name, &mut request.ifr_name)?;
    Ok(request)
}

pub(crate) fn sockaddr_v4(ip: Ipv4Addr) -> libc::sockaddr {
    // SAFETY: plain old data.
    let mut address: libc::sockaddr_in = unsafe { zeroed() };
    address.sin_len = size_of::<libc::sockaddr_in>() as u8;
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_addr.s_addr = u32::from(ip).to_be();
    // SAFETY: a `sockaddr_in` is as large as a `sockaddr`.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(address) }
}

pub(crate) fn sockaddr_v6(ip: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: plain old data.
    let mut address: libc::sockaddr_in6 = unsafe { zeroed() };
    address.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
    address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    address.sin6_addr.s6_addr = ip.octets();
    address
}

/// # Safety
///
/// `address` must hold an IPv4 socket address.
unsafe fn ipv4_of(address: &libc::sockaddr) -> Ipv4Addr {
    // SAFETY: the caller says it is a `sockaddr_in`, which is as large as a `sockaddr`.
    let address = unsafe { &*(address as *const libc::sockaddr).cast::<libc::sockaddr_in>() };
    Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))
}

/// An interface ioctl through a socket of `family`.
pub(crate) fn ioctl<T>(family: libc::c_int, request: libc::c_ulong, argument: &mut T) -> Result<()> {
    let socket = control_socket(family)?;
    // SAFETY: each request is paired with the structure it reads and writes.
    if unsafe { libc::ioctl(socket.as_raw_fd(), request, argument as *mut T) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// `result`, with the error `code` counting as success.
pub(crate) fn tolerate(result: Result<()>, code: i32) -> Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(code) => Ok(()),
        other => other,
    }
}

/// Walks the system's interface addresses of `name`.
fn interface_addresses<T>(name: &str, mut visit: impl FnMut(&libc::ifaddrs) -> Option<T>) -> Result<Vec<T>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills in a list that `freeifaddrs` releases below.
    if unsafe { libc::getifaddrs(&mut list) } < 0 {
        return Err(Error::last_os_error());
    }
    let mut found = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: entries of the list stay valid until it is released.
        let current = unsafe { &*entry };
        entry = current.ifa_next;
        // SAFETY: `ifa_name` is a NUL-terminated string.
        let entry_name = unsafe { std::ffi::CStr::from_ptr(current.ifa_name) };
        if entry_name.to_bytes() != name.as_bytes() || current.ifa_addr.is_null() {
            continue;
        }
        if let Some(value) = visit(current) {
            found.push(value);
        }
    }
    // SAFETY: `list` came from `getifaddrs`.
    unsafe { libc::freeifaddrs(list) };
    Ok(found)
}

/// The IP addresses of `name` with the prefixes of their subnets, link-local ones left out.
fn addresses_of(name: &str) -> Result<Vec<IpNet>> {
    interface_addresses(name, |current| {
        // SAFETY: the address and mask point to socket addresses of their stated family.
        let net = unsafe {
            match i32::from((*current.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let address = &*current.ifa_addr.cast::<libc::sockaddr_in>();
                    let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
                    let prefix = if current.ifa_netmask.is_null() {
                        32
                    } else {
                        u32::from_be((*current.ifa_netmask.cast::<libc::sockaddr_in>()).sin_addr.s_addr).count_ones()
                    };
                    IpNet::new(IpAddr::V4(ip), prefix as u8).ok()
                }
                libc::AF_INET6 => {
                    let address = &*current.ifa_addr.cast::<libc::sockaddr_in6>();
                    let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
                    let prefix = if current.ifa_netmask.is_null() {
                        128
                    } else {
                        u128::from_be_bytes((*current.ifa_netmask.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr)
                            .count_ones()
                    };
                    IpNet::new(IpAddr::V6(ip), prefix as u8).ok()
                }
                _ => None,
            }
        };
        net.filter(|net| !matches!(net.addr(), IpAddr::V6(ip) if ip.is_unicast_link_local()))
    })
}

/// The hardware addresses of `name`, from its link layer entries: each a `sockaddr_dl`, which on
/// every system has the name length at byte 5, the address length at byte 6 and the name and
/// then the address from byte 8.
fn link_addresses(name: &str) -> Result<Vec<[u8; 6]>> {
    interface_addresses(name, |current| {
        // SAFETY: the address points to a socket address of its stated family, and a link
        // layer address holds as many bytes as its lengths say.
        unsafe {
            if i32::from((*current.ifa_addr).sa_family) != libc::AF_LINK {
                return None;
            }
            let base = current.ifa_addr.cast::<u8>();
            let (name_len, address_len) = (usize::from(*base.add(5)), *base.add(6));
            if address_len != 6 {
                return None;
            }
            let data = base.add(8 + name_len);
            Some(<[u8; 6]>::try_from(std::slice::from_raw_parts(data, 6)).expect("six bytes"))
        }
    })
}

/// The hardware address of `name`: its link layer entry.
fn link_address(name: &str) -> Result<[u8; 6]> {
    link_addresses(name)?.into_iter().next().ok_or_else(|| Error::new(ErrorKind::NotFound, "the interface has no hardware address"))
}

fn set_link_address(name: &str, mac: [u8; 6]) -> Result<()> {
    let mut request = request(name)?;
    // SAFETY: plain old data.
    let mut address: libc::sockaddr = unsafe { zeroed() };
    address.sa_len = 6;
    address.sa_family = libc::AF_LINK as libc::sa_family_t;
    for (slot, byte) in address.sa_data.iter_mut().zip(mac) {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_addr = address;
    ioctl(libc::AF_INET, os::SIOCSIFLLADDR, &mut request)
}

/// The header of a routing message, as the Apple systems lay it out.
mod header {
    pub const VERSION: u8 = 5;
    /// Socket addresses in a message start at multiples of this.
    pub const ALIGN: usize = 4;
    /// The length of a `sockaddr_dl` without its variable part.
    pub const SOCKADDR_DL_LEN: usize = 20;

    #[repr(C)]
    pub struct rt_msghdr {
        pub rtm_msglen: u16,
        pub rtm_version: u8,
        pub rtm_type: u8,
        pub rtm_index: u16,
        pub rtm_flags: libc::c_int,
        pub rtm_addrs: libc::c_int,
        pub rtm_pid: libc::pid_t,
        pub rtm_seq: libc::c_int,
        pub rtm_errno: libc::c_int,
        pub rtm_use: libc::c_int,
        pub rtm_inits: u32,
        pub rtm_rmx: [u32; 14],
    }

    const _: () = assert!(size_of::<rt_msghdr>() == 92);
}

// The socket addresses behind the header start aligned.
const _: () = assert!(size_of::<header::rt_msghdr>().is_multiple_of(header::ALIGN));

const RTM_ADD: u8 = 1;
const RTM_DELETE: u8 = 2;
const RTF_UP: libc::c_int = 0x1;
const RTF_GATEWAY: libc::c_int = 0x2;
const RTF_HOST: libc::c_int = 0x4;
const RTF_STATIC: libc::c_int = 0x800;
const RTA_DST: libc::c_int = 0x1;
const RTA_GATEWAY: libc::c_int = 0x2;
const RTA_NETMASK: libc::c_int = 0x4;

/// Adds or deletes the route that sends `net` to the interface `index`, or through the gateway
/// `via`.
fn route(kind: u8, index: u32, net: IpNet, via: Option<IpAddr>) -> Result<()> {
    let host = net.prefix_len() == net.max_prefix_len();
    let mut body = Vec::new();
    let mut addresses = RTA_DST | RTA_GATEWAY;
    push_ip(&mut body, net.addr());
    match via {
        Some(via) => push_ip(&mut body, via),
        None => push_link(&mut body, index),
    }
    if !host {
        addresses |= RTA_NETMASK;
        push_ip(&mut body, net.netmask());
    }
    let flags = RTF_UP | RTF_STATIC | if via.is_some() { RTF_GATEWAY } else { 0 } | if host { RTF_HOST } else { 0 };
    routing_message(kind, index, flags, addresses, &body)
}

/// Sends the routing socket a message of `kind` whose socket addresses, the ones `addresses`
/// lists, are in `body`.
fn routing_message(kind: u8, index: u32, flags: libc::c_int, addresses: libc::c_int, body: &[u8]) -> Result<()> {
    let header_len = size_of::<header::rt_msghdr>();
    // SAFETY: plain old data.
    let mut header: header::rt_msghdr = unsafe { zeroed() };
    header.rtm_msglen = u16::try_from(header_len + body.len()).expect("a short message");
    header.rtm_version = header::VERSION;
    header.rtm_type = kind;
    header.rtm_index = index as u16;
    header.rtm_flags = flags;
    header.rtm_addrs = addresses;
    header.rtm_seq = 1;
    // SAFETY: the header is plain old data of its size.
    let mut message = unsafe { std::slice::from_raw_parts((&raw const header).cast::<u8>(), header_len) }.to_vec();
    message.extend_from_slice(body);
    // SAFETY: plain socket creation.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `fd` is new and owned by nobody else.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: the message is readable for its whole length.
    if unsafe { libc::write(socket.as_raw_fd(), message.as_ptr().cast(), message.len()) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn push_ip(body: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => push_sockaddr(body, &sockaddr_v4(ip)),
        IpAddr::V6(ip) => push_sockaddr(body, &sockaddr_v6(ip)),
    }
}

/// Appends a socket address padded to the alignment that routing messages want. The header that
/// goes in front is a multiple of it long.
fn push_sockaddr<T>(body: &mut Vec<u8>, address: &T) {
    // SAFETY: socket addresses are plain old data.
    let bytes = unsafe { std::slice::from_raw_parts((address as *const T).cast::<u8>(), size_of::<T>()) };
    body.extend_from_slice(bytes);
    body.resize(body.len().next_multiple_of(header::ALIGN), 0);
}

/// Appends the link layer address of the interface `index`, which names it as the gateway.
fn push_link(body: &mut Vec<u8>, index: u32) {
    let mut link = [0u8; header::SOCKADDR_DL_LEN];
    link[0] = header::SOCKADDR_DL_LEN as u8;
    link[1] = libc::AF_LINK as u8;
    link[2..4].copy_from_slice(&(index as u16).to_ne_bytes());
    body.extend_from_slice(&link);
    body.resize(body.len().next_multiple_of(header::ALIGN), 0);
}
