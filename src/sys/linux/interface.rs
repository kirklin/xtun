//! A Linux interface by its index, configured over rtnetlink like any other.

use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use ipnet::IpNet;
use netlink_packet_route::link::LinkFlags;

use super::netlink::Netlink;
use crate::device::Address;
use crate::sys::unix::{copy_name, read_name};

/// The interface behind a device.
pub struct Interface {
    /// Zero for a descriptor that was adopted without the system telling its interface.
    index: u32,
}

impl Interface {
    pub(super) fn new(index: u32) -> Interface {
        Interface { index }
    }

    /// The interface index, unless the descriptor was adopted without one.
    fn known(&self) -> Result<u32> {
        if self.index == 0 {
            return Err(Error::new(ErrorKind::Unsupported, "the interface of the adopted descriptor is unknown"));
        }
        Ok(self.index)
    }

    pub fn name(&self) -> Result<String> {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: `name` holds the longest name and its NUL.
        if unsafe { libc::if_indextoname(self.known()?, name.as_mut_ptr()) }.is_null() {
            return Err(Error::last_os_error());
        }
        Ok(read_name(&name))
    }

    pub fn set_name(&self, name: &str) -> Result<()> {
        copy_name(name, &mut [0; libc::IF_NAMESIZE])?;
        Netlink::new()?.set_name(self.known()?, name)
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn mtu(&self) -> Result<u32> {
        Netlink::new()?.mtu(self.known()?)
    }

    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        Netlink::new()?.set_mtu(self.known()?, mtu)
    }

    pub fn is_up(&self) -> Result<bool> {
        Ok(Netlink::new()?.flags(self.known()?)?.contains(LinkFlags::Up))
    }

    pub fn set_up(&self, up: bool) -> Result<()> {
        Netlink::new()?.set_up(self.known()?, up)
    }

    pub fn is_running(&self) -> Result<bool> {
        Ok(Netlink::new()?.flags(self.known()?)?.contains(LinkFlags::Up | LinkFlags::Running))
    }

    pub fn addresses(&self) -> Result<Vec<IpNet>> {
        Netlink::new()?.addresses(self.known()?)
    }

    pub fn add_address(&self, address: Address, prefix_route: bool) -> Result<()> {
        Netlink::new()?.add_address(self.known()?, address, prefix_route)
    }

    pub fn remove_address(&self, net: IpNet) -> Result<()> {
        Netlink::new()?.remove_address(self.known()?, net)
    }

    pub fn broadcast(&self) -> Result<Option<Ipv4Addr>> {
        let mut request = self.request()?;
        match ioctl(libc::SIOCGIFBRDADDR, &mut request) {
            // SAFETY: SIOCGIFBRDADDR filled in an IPv4 socket address.
            Ok(()) => Ok(Some(unsafe { ipv4_of(&request.ifr_ifru.ifru_broadaddr) })),
            Err(error) if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn set_broadcast(&self, broadcast: Ipv4Addr) -> Result<()> {
        let mut request = self.request()?;
        request.ifr_ifru.ifru_broadaddr = sockaddr_v4(broadcast);
        ioctl(libc::SIOCSIFBRDADDR, &mut request)
    }

    pub fn mac_address(&self) -> Result<[u8; 6]> {
        Netlink::new()?.mac_address(self.known()?)
    }

    pub fn set_mac_address(&self, mac: [u8; 6]) -> Result<()> {
        Netlink::new()?.set_mac_address(self.known()?, mac)
    }

    pub fn add_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        Netlink::new()?.add_route(self.known()?, net, via)
    }

    pub fn remove_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        Netlink::new()?.remove_route(self.known()?, net, via)
    }

    pub fn tx_queue_len(&self) -> Result<u32> {
        Netlink::new()?.tx_queue_len(self.known()?)
    }

    pub fn set_tx_queue_len(&self, packets: u32) -> Result<()> {
        Netlink::new()?.set_tx_queue_len(self.known()?, packets)
    }

    /// An `ifreq` naming the interface, for the ioctls that netlink does not cover.
    fn request(&self) -> Result<libc::ifreq> {
        // SAFETY: `ifreq` is plain old data.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        copy_name(&self.name()?, &mut request.ifr_name)?;
        Ok(request)
    }
}

fn ioctl(request: libc::c_ulong, argument: &mut libc::ifreq) -> Result<()> {
    // SAFETY: plain socket creation; the descriptor is owned right away.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return Err(Error::last_os_error());
    }
    // SAFETY: `socket` is new and owned by nobody else.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: each request is paired with an `ifreq` it reads and writes.
    if unsafe { libc::ioctl(socket.as_raw_fd(), request as _, argument as *mut libc::ifreq) } < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn sockaddr_v4(ip: Ipv4Addr) -> libc::sockaddr {
    // SAFETY: plain old data.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as libc::sa_family_t;
    address.sin_addr.s_addr = u32::from(ip).to_be();
    // SAFETY: a `sockaddr_in` is as large as a `sockaddr`.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(address) }
}

/// # Safety
///
/// `address` must hold an IPv4 socket address.
unsafe fn ipv4_of(address: &libc::sockaddr) -> Ipv4Addr {
    // SAFETY: the caller says it is a `sockaddr_in`, which is no larger than a `sockaddr`.
    let address = unsafe { &*(address as *const libc::sockaddr).cast::<libc::sockaddr_in>() };
    Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))
}
