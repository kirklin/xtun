//! The interface behind a device on the systems descended from BSD: the Apple systems, FreeBSD,
//! NetBSD and OpenBSD. It is configured with interface ioctls and the routing socket, which
//! these systems share; each brings only its layouts and request numbers.

use std::io::{Error, ErrorKind, Result};
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
use std::time::{Duration, Instant};

use ipnet::IpNet;

#[cfg(target_vendor = "apple")]
use super::darwin::sys as os;
#[cfg(not(target_vendor = "apple"))]
use super::tuntap::os;
#[cfg(not(target_vendor = "apple"))]
use super::unix::read_name;
#[cfg(target_vendor = "apple")]
use super::unix::set_cloexec;
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
    #[cfg(target_vendor = "apple")]
    name: String,
}

impl Interface {
    /// The interface called `name`.
    pub(crate) fn new(name: &str, ethernet: bool) -> Result<Interface> {
        Ok(Interface {
            index: index_of(name)?,
            ethernet,
            #[cfg(target_vendor = "apple")]
            name: name.to_owned(),
        })
    }

    #[cfg(target_vendor = "apple")]
    pub fn name(&self) -> Result<String> {
        Ok(self.name.clone())
    }

    /// The name as it is now: FreeBSD renames interfaces.
    #[cfg(not(target_vendor = "apple"))]
    pub fn name(&self) -> Result<String> {
        name_of(self.index)
    }

    #[cfg(target_os = "freebsd")]
    pub fn set_name(&self, name: &str) -> Result<()> {
        let mut new_name = [0 as libc::c_char; libc::IFNAMSIZ];
        copy_name(name, &mut new_name)?;
        let mut request = self.request()?;
        request.ifr_ifru.ifru_data = new_name.as_mut_ptr();
        ioctl(libc::AF_INET, os::SIOCSIFNAME, &mut request)
    }

    #[cfg(not(target_os = "freebsd"))]
    pub fn set_name(&self, _name: &str) -> Result<()> {
        let system = if cfg!(target_vendor = "apple") { "Apple systems" } else { "this system" };
        Err(Error::new(ErrorKind::Unsupported, format!("interfaces on {system} keep their names")))
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
        ioctl(libc::AF_INET, os::SIOCSIFFLAGS, &mut request)?;
        // An interface that comes up has its addresses checked again.
        if up { self.settle() } else { Ok(()) }
    }

    /// FreeBSD and the Apple systems add IPv6 addresses without checking the link for
    /// duplicates, and IPv4 addresses are not checked.
    #[cfg(not(any(target_os = "netbsd", target_os = "openbsd")))]
    pub(crate) fn settle(&self) -> Result<()> {
        Ok(())
    }

    /// NetBSD and OpenBSD check every new IPv6 address for duplicates on the link before it may
    /// be used, about a second, and NetBSD sends ARP probes for a new IPv4 address of an
    /// Ethernet interface, for four to seven seconds; neither has a way to skip a check. Waits
    /// until the interface's addresses are checked, so that they can be used once a change returns.
    #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
    pub(crate) fn settle(&self) -> Result<()> {
        let name = self.name()?;
        let addresses = addresses_of(&name)?.into_iter().map(|net| net.addr());
        let mut checking = still_checked(&name, addresses)?;
        if checking.is_empty() {
            return Ok(());
        }
        let deadline = Instant::now() + longest_check(&name, &checking)?;
        // The system checks only while the interface is up and running, and again once it is.
        while !checking.is_empty() && self.is_running()? {
            if Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    format!("the system has not finished checking the link for another {}", checking[0]),
                ));
            }
            std::thread::sleep(CHECK_POLL);
            checking = still_checked(&name, checking)?;
        }
        Ok(())
    }

    pub fn addresses(&self) -> Result<Vec<IpNet>> {
        addresses_of(&self.name()?)
    }

    /// Adds an address and returns once it can be used.
    pub fn add_address(&self, address: Address, prefix_route: bool) -> Result<()> {
        self.insert_address(address, prefix_route)?;
        self.settle()
    }

    /// Adds an address without waiting for its check. With `prefix_route` its subnet is reached
    /// through the interface.
    pub(crate) fn insert_address(&self, address: Address, prefix_route: bool) -> Result<()> {
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
                // NetBSD refuses the flag and OpenBSD does not have it: their checks are waited for.
                #[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
                {
                    request.ifra_flags = os::IN6_IFF_NODAD;
                }
                request.ifra_lifetime.ia6t_vltime = os::ND6_INFINITE_LIFETIME;
                request.ifra_lifetime.ia6t_pltime = os::ND6_INFINITE_LIFETIME;
                ioctl(libc::AF_INET6, os::SIOCAIFADDR_IN6, &mut request)?;
            }
        }
        if address.peer.is_some() || net.prefix_len() == net.max_prefix_len() {
            return Ok(());
        }
        // An Ethernet interface gets the route to its subnet from the system, and so does a
        // point-to-point interface for an IPv6 address; a point-to-point interface does not for
        // an IPv4 address.
        match (self.ethernet, prefix_route) {
            (false, true) => tolerate(route(RTM_ADD, self.index, net.trunc(), None), libc::EEXIST),
            (true, false) => tolerate(route(RTM_DELETE, self.index, net.trunc(), None), libc::ESRCH),
            (false, false) if net.addr().is_ipv6() => tolerate(route(RTM_DELETE, self.index, net.trunc(), None), libc::ESRCH),
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

    #[cfg(not(target_os = "freebsd"))]
    pub fn set_broadcast(&self, broadcast: Ipv4Addr) -> Result<()> {
        self.broadcast_interface()?;
        let mut request = self.request()?;
        request.ifr_ifru.ifru_addr = sockaddr_v4(broadcast);
        ioctl(libc::AF_INET, os::SIOCSIFBRDADDR, &mut request)
    }

    /// FreeBSD sets a broadcast address only together with its address: the first IPv4 address
    /// is added again with it, which replaces the address.
    #[cfg(target_os = "freebsd")]
    pub fn set_broadcast(&self, broadcast: Ipv4Addr) -> Result<()> {
        self.broadcast_interface()?;
        let Some(IpNet::V4(v4)) = self.addresses()?.into_iter().find(|net| net.addr().is_ipv4()) else {
            return Err(Error::new(ErrorKind::NotFound, "the interface has no IPv4 address"));
        };
        let subnet = IpNet::V4(v4.trunc());
        let routed = v4.prefix_len() == 32 || has_route(subnet)?;
        // SAFETY: plain old data.
        let mut request: os::ifaliasreq = unsafe { zeroed() };
        copy_name(&self.name()?, &mut request.ifra_name)?;
        request.ifra_addr = sockaddr_v4(v4.addr());
        request.ifra_broadaddr = sockaddr_v4(broadcast);
        request.ifra_mask = sockaddr_v4(v4.netmask());
        ioctl(libc::AF_INET, os::SIOCAIFADDR, &mut request)?;
        // The address came back with the route to its subnet, which an address added without one
        // did not have.
        if !routed {
            tolerate(route(RTM_DELETE, self.index, subnet, None), libc::ESRCH)?;
        }
        Ok(())
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

/// The name of the interface `index`.
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn name_of(index: u32) -> Result<String> {
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: `name` holds the longest name and its NUL.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(Error::last_os_error());
    }
    Ok(read_name(&name))
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
    // SAFETY: the caller says it is a `sockaddr_in`, which is as large as a `sockaddr`; it is
    // read where it lies, which a `sockaddr_in` need not be aligned for.
    let address = unsafe { std::ptr::read_unaligned((address as *const libc::sockaddr).cast::<libc::sockaddr_in>()) };
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
#[cfg(not(target_os = "netbsd"))]
fn link_address(name: &str) -> Result<[u8; 6]> {
    link_addresses(name)?.into_iter().next().ok_or_else(|| Error::new(ErrorKind::NotFound, "the interface has no hardware address"))
}

/// NetBSD keeps every link layer address an interface was given, and marks the one in use.
#[cfg(target_os = "netbsd")]
fn link_address(name: &str) -> Result<[u8; 6]> {
    Ok(active_link_address(name)?.0)
}

#[cfg(not(target_os = "netbsd"))]
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

/// NetBSD adds the link layer address and makes it the one in use; the one used before goes,
/// unless the interface came with it.
#[cfg(target_os = "netbsd")]
fn set_link_address(name: &str, mac: [u8; 6]) -> Result<()> {
    let (previous, came_with) = active_link_address(name)?;
    if previous == mac {
        return Ok(());
    }
    let mut request = link_request(name, mac)?;
    request.flags = os::IFLR_ACTIVE;
    ioctl(libc::AF_LINK, os::SIOCALIFADDR, &mut request)?;
    if !came_with {
        ioctl(libc::AF_LINK, os::SIOCDLIFADDR, &mut link_request(name, previous)?)?;
    }
    Ok(())
}

/// The link layer address of `name` in use, and whether the interface came with it.
#[cfg(target_os = "netbsd")]
fn active_link_address(name: &str) -> Result<([u8; 6], bool)> {
    for mac in link_addresses(name)? {
        let mut request = link_request(name, mac)?;
        request.flags = os::IFLR_PREFIX;
        request.prefixlen = 48;
        ioctl(libc::AF_LINK, os::SIOCGLIFADDR, &mut request)?;
        if request.flags & os::IFLR_ACTIVE != 0 {
            return Ok((mac, request.flags & os::IFLR_FACTORY != 0));
        }
    }
    Err(Error::new(ErrorKind::NotFound, "the interface has no hardware address in use"))
}

/// A request about the link layer address `mac` of `name`, which goes through a link layer
/// socket: an IPv4 socket takes the same requests for IPv4 addresses.
#[cfg(target_os = "netbsd")]
fn link_request(name: &str, mac: [u8; 6]) -> Result<os::if_laddrreq> {
    // SAFETY: plain old data.
    let mut request: os::if_laddrreq = unsafe { zeroed() };
    copy_name(name, &mut request.iflr_name)?;
    // A `sockaddr_dl` without a name: its address follows the eight bytes of its header.
    let mut link = [0u8; 14];
    link[0] = link.len() as u8;
    link[1] = libc::AF_LINK as u8;
    link[6] = 6;
    link[8..].copy_from_slice(&mac);
    // SAFETY: the storage holds at least 128 bytes.
    unsafe { std::ptr::copy_nonoverlapping(link.as_ptr(), request.addr.as_mut_ptr().cast::<u8>(), link.len()) };
    Ok(request)
}

/// How often a check for duplicates is looked at: the systems' timers tick every 10 ms.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
const CHECK_POLL: Duration = Duration::from_millis(10);

/// Where the system is with checking an address for duplicates on the link.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
enum Check {
    /// Over, or not done for this address: it can be used.
    Over,
    Running,
    /// Another host has the address.
    Duplicate,
    /// The address is gone.
    Gone,
}

/// Those of `addresses` that the system is still checking for duplicates on the link. Fails
/// with [`ErrorKind::AddrInUse`] for one that another host has.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn still_checked(name: &str, addresses: impl IntoIterator<Item = IpAddr>) -> Result<Vec<IpAddr>> {
    let mut checking = Vec::new();
    for address in addresses {
        match check_of(name, address)? {
            Check::Running => checking.push(address),
            Check::Duplicate => {
                return Err(Error::new(ErrorKind::AddrInUse, format!("another host on the link has {address}")));
            }
            Check::Over | Check::Gone => {}
        }
    }
    Ok(checking)
}

/// The check of `address` of `name`, from the address's flags. An address of a link that is
/// down is checked once the link is back.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn check_of(name: &str, address: IpAddr) -> Result<Check> {
    let (flags, running, duplicate, detached) = match address {
        IpAddr::V6(address) => {
            // SAFETY: plain old data.
            let mut request: os::in6_ifreq = unsafe { zeroed() };
            copy_name(name, &mut request.ifr_name)?;
            request.ifr_ifru.ifru_addr = sockaddr_v6(address);
            let flags = match ioctl(libc::AF_INET6, os::SIOCGIFAFLAG_IN6, &mut request) {
                // SAFETY: SIOCGIFAFLAG_IN6 filled in the flags.
                Ok(()) => unsafe { request.ifr_ifru.ifru_flags6 },
                Err(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) => return Ok(Check::Gone),
                Err(error) => return Err(error),
            };
            (flags, os::IN6_IFF_TENTATIVE, os::IN6_IFF_DUPLICATED, os::IN6_IFF_DETACHED)
        }
        #[cfg(target_os = "netbsd")]
        IpAddr::V4(address) => {
            let mut request = request(name)?;
            request.ifr_ifru.ifru_addr = sockaddr_v4(address);
            let flags = match ioctl(libc::AF_INET, os::SIOCGIFAFLAG_IN, &mut request) {
                // SAFETY: SIOCGIFAFLAG_IN filled in the flags.
                Ok(()) => unsafe { request.ifr_ifru.ifru_addrflags },
                Err(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) => return Ok(Check::Gone),
                Err(error) => return Err(error),
            };
            let running = os::IN_IFF_TENTATIVE | os::IN_IFF_TRYTENTATIVE;
            (flags, running, os::IN_IFF_DUPLICATED, os::IN_IFF_DETACHED)
        }
        // OpenBSD does not check IPv4 addresses.
        #[cfg(target_os = "openbsd")]
        IpAddr::V4(_) => return Ok(Check::Over),
    };
    Ok(if flags & duplicate != 0 {
        Check::Duplicate
    } else if flags & running != 0 && flags & detached == 0 {
        Check::Running
    } else {
        Check::Over
    })
}

/// The longest the checks of `addresses` take on `name`, and once more the longest wait between
/// two probes, for timers that run late.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn longest_check(name: &str, addresses: &[IpAddr]) -> Result<Duration> {
    let mut longest = Duration::ZERO;
    if addresses.iter().any(IpAddr::is_ipv6) {
        // Up to a second before the first neighbor solicitation, and the retransmission time
        // after each.
        let probes = probe_count(os::IPV6CTL_DAD_COUNT, libc::PF_INET6, libc::IPPROTO_IPV6)?;
        let retransmission = retransmission_time(name)?;
        longest = longest.max(Duration::from_secs(1) + retransmission * (probes + 1));
    }
    #[cfg(target_os = "netbsd")]
    if addresses.iter().any(IpAddr::is_ipv4) {
        let probes = probe_count(os::IPCTL_DAD_COUNT, libc::PF_INET, libc::IPPROTO_IP)?;
        let seconds = os::PROBE_WAIT + u64::from(probes.saturating_sub(1)) * os::PROBE_MAX + os::ANNOUNCE_WAIT + os::PROBE_MAX;
        longest = longest.max(Duration::from_secs(seconds));
    }
    Ok(longest)
}

/// How many probes a check sends: the `dad_count` setting of `protocol`'s `family`.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn probe_count(setting: libc::c_int, family: libc::c_int, protocol: libc::c_int) -> Result<u32> {
    let mib = [libc::CTL_NET, family, protocol, setting];
    let mut probes: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>();
    // SAFETY: `probes` and `length` are writable, and nothing is written to the system.
    let status = unsafe {
        libc::sysctl(mib.as_ptr(), mib.len() as libc::c_uint, (&raw mut probes).cast(), &mut length, std::ptr::null_mut(), 0)
    };
    if status < 0 {
        return Err(Error::last_os_error());
    }
    Ok(probes.max(0) as u32)
}

/// The time between the probes of a check for duplicates on `name`, which the interface's
/// neighbor discovery settings hold.
#[cfg(target_os = "netbsd")]
fn retransmission_time(name: &str) -> Result<Duration> {
    // SAFETY: plain old data.
    let mut request: os::in6_ndireq = unsafe { zeroed() };
    copy_name(name, &mut request.ifname)?;
    ioctl(libc::AF_INET6, os::SIOCGIFINFO_IN6, &mut request)?;
    Ok(Duration::from_millis(u64::from(request.ndi.retrans)))
}

/// OpenBSD waits the same time between the probes on every interface.
#[cfg(target_os = "openbsd")]
fn retransmission_time(_name: &str) -> Result<Duration> {
    Ok(Duration::from_millis(os::RETRANS_TIMER))
}

/// The header of a routing message, as each system lays it out.
#[cfg(target_vendor = "apple")]
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

#[cfg(target_os = "freebsd")]
mod header {
    pub const VERSION: u8 = 5;
    pub const ALIGN: usize = size_of::<libc::c_long>();
    pub const SOCKADDR_DL_LEN: usize = 54;

    #[repr(C)]
    pub struct rt_msghdr {
        pub rtm_msglen: u16,
        pub rtm_version: u8,
        pub rtm_type: u8,
        pub rtm_index: u16,
        pub rtm_spare1: u16,
        pub rtm_flags: libc::c_int,
        pub rtm_addrs: libc::c_int,
        pub rtm_pid: libc::pid_t,
        pub rtm_seq: libc::c_int,
        pub rtm_errno: libc::c_int,
        pub rtm_fmask: libc::c_int,
        pub rtm_inits: libc::c_ulong,
        pub rtm_rmx: [libc::c_ulong; 14],
    }

    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(size_of::<rt_msghdr>() == 152);
}

#[cfg(target_os = "netbsd")]
mod header {
    pub const VERSION: u8 = 4;
    pub const ALIGN: usize = size_of::<u64>();
    pub const SOCKADDR_DL_LEN: usize = 32;

    #[repr(C, align(8))]
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
        pub rtm_inits: libc::c_int,
        pub rtm_rmx: [u64; 10],
    }

    const _: () = assert!(size_of::<rt_msghdr>() == 120);
}

#[cfg(target_os = "openbsd")]
mod header {
    pub const VERSION: u8 = 5;
    pub const ALIGN: usize = size_of::<libc::c_long>();
    pub const SOCKADDR_DL_LEN: usize = 32;

    #[repr(C)]
    pub struct rt_msghdr {
        pub rtm_msglen: u16,
        pub rtm_version: u8,
        pub rtm_type: u8,
        pub rtm_hdrlen: u16,
        pub rtm_index: u16,
        pub rtm_tableid: u16,
        pub rtm_priority: u8,
        pub rtm_mpls: u8,
        pub rtm_addrs: libc::c_int,
        pub rtm_flags: libc::c_int,
        pub rtm_fmask: libc::c_int,
        pub rtm_pid: libc::pid_t,
        pub rtm_seq: libc::c_int,
        pub rtm_errno: libc::c_int,
        pub rtm_inits: libc::c_uint,
        pub rtm_rmx: [u64; 7],
    }

    const _: () = assert!(size_of::<rt_msghdr>() == 96);
}

// The socket addresses behind the header start aligned.
const _: () = assert!(size_of::<header::rt_msghdr>().is_multiple_of(header::ALIGN));

const RTM_ADD: u8 = 1;
const RTM_DELETE: u8 = 2;
#[cfg(target_os = "freebsd")]
const RTM_GET: u8 = 4;
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
    push_scoped(&mut body, net.addr(), index);
    match via {
        Some(via) => push_scoped(&mut body, via, index),
        None => push_link(&mut body, index),
    }
    if !host {
        addresses |= RTA_NETMASK;
        push_ip(&mut body, net.netmask());
    }
    let flags = RTF_UP | RTF_STATIC | if via.is_some() { RTF_GATEWAY } else { 0 } | if host { RTF_HOST } else { 0 };
    routing_message(kind, index, flags, addresses, &body)
}

/// Whether the routing table has a route to exactly the subnet `net`.
#[cfg(target_os = "freebsd")]
fn has_route(net: IpNet) -> Result<bool> {
    let mut body = Vec::new();
    push_ip(&mut body, net.addr());
    push_ip(&mut body, net.netmask());
    // With a netmask the system looks for the subnet itself, and fails with `ESRCH` without it.
    match routing_message(RTM_GET, 0, RTF_UP, RTA_DST | RTA_NETMASK, &body) {
        Ok(()) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(false),
        Err(error) => Err(error),
    }
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
    #[cfg(target_os = "openbsd")]
    {
        header.rtm_hdrlen = header_len as u16;
    }
    // SAFETY: the header is plain old data of its size.
    let mut message = unsafe { std::slice::from_raw_parts((&raw const header).cast::<u8>(), header_len) }.to_vec();
    message.extend_from_slice(body);
    // Closed on exec: the Apple systems take no flag for it when the socket is made.
    #[cfg(not(target_vendor = "apple"))]
    let kind = libc::SOCK_RAW | libc::SOCK_CLOEXEC;
    #[cfg(target_vendor = "apple")]
    let kind = libc::SOCK_RAW;
    // SAFETY: plain socket creation.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, kind, 0) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `fd` is new and owned by nobody else.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    #[cfg(target_vendor = "apple")]
    set_cloexec(socket.as_raw_fd())?;
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

/// Appends `ip`, an address on the link of the interface `index` if it is link-local. The KAME
/// stacks of the BSDs and the Apple systems take the interface of such an address in its third
/// and fourth bytes, as their own `route` writes it, and some in its scope as well.
fn push_scoped(body: &mut Vec<u8>, ip: IpAddr, index: u32) {
    match ip {
        IpAddr::V6(v6) if v6.is_unicast_link_local() || (v6.is_multicast() && v6.octets()[1] & 0x0f == 2) => {
            let mut octets = v6.octets();
            octets[2..4].copy_from_slice(&(index as u16).to_be_bytes());
            let mut address = sockaddr_v6(Ipv6Addr::from(octets));
            address.sin6_scope_id = index;
            push_sockaddr(body, &address);
        }
        other => push_ip(body, other),
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
