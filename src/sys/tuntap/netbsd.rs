//! NetBSD's layouts and requests for tun and tap devices and their interfaces.

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_short, c_uint, c_ulong, sockaddr, sockaddr_in6};

use crate::sys::bsdlike::{IOC_IN, IOC_INOUT, IOC_OUT, ioc};

pub const TAP_CLONER: &str = "/dev/tap";
pub const TUN_PREFIX: &str = "tun";
pub const TAP_PREFIX: &str = "tap";

/// `struct ifreq`, whose union holds a `struct sockaddr_storage`.
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [c_char; libc::IFNAMSIZ],
    pub ifr_ifru: ifreq_ifru,
}

#[repr(C)]
pub union ifreq_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_flags: c_short,
    pub ifru_mtu: c_int,
    pub ifru_addrflags: c_int,
    pub ifru_data: *mut c_char,
    ifru_space: [u64; 16],
}

#[repr(C)]
pub struct ifaliasreq {
    pub ifra_name: [c_char; libc::IFNAMSIZ],
    pub ifra_addr: sockaddr,
    pub ifra_broadaddr: sockaddr,
    pub ifra_mask: sockaddr,
}

#[repr(C)]
pub struct in6_addrlifetime {
    pub ia6t_expire: libc::time_t,
    pub ia6t_preferred: libc::time_t,
    pub ia6t_vltime: u32,
    pub ia6t_pltime: u32,
}

#[repr(C)]
pub struct in6_aliasreq {
    pub ifra_name: [c_char; libc::IFNAMSIZ],
    pub ifra_addr: sockaddr_in6,
    pub ifra_dstaddr: sockaddr_in6,
    pub ifra_prefixmask: sockaddr_in6,
    pub ifra_flags: c_int,
    pub ifra_lifetime: in6_addrlifetime,
}

#[repr(C)]
pub struct in6_ifreq {
    pub ifr_name: [c_char; libc::IFNAMSIZ],
    pub ifr_ifru: in6_ifreq_ifru,
}

#[repr(C)]
pub union in6_ifreq_ifru {
    pub ifru_addr: sockaddr_in6,
    pub ifru_flags6: c_int,
    ifru_icmp6stat: [u64; 34],
}

/// The neighbor discovery settings of an interface.
#[repr(C)]
pub struct in6_ndireq {
    pub ifname: [c_char; libc::IFNAMSIZ],
    pub ndi: nd_ifinfo,
}

#[repr(C)]
pub struct nd_ifinfo {
    pub chlim: u8,
    pub basereachable: u32,
    /// Milliseconds between the probes of a check for duplicates.
    pub retrans: u32,
    pub flags: u32,
}

/// Adds a link layer address to an interface, and with `IFLR_ACTIVE` makes it the one in use.
#[repr(C)]
pub struct if_laddrreq {
    pub iflr_name: [c_char; libc::IFNAMSIZ],
    pub flags: c_uint,
    pub prefixlen: c_uint,
    /// A `struct sockaddr_storage`.
    pub addr: [u64; 16],
    dstaddr: [u64; 16],
}

pub const IFLR_PREFIX: c_uint = 0x8000;
pub const IFLR_ACTIVE: c_uint = 0x4000;
pub const IFLR_FACTORY: c_uint = 0x2000;

pub const SIOCSIFFLAGS: c_ulong = ioc(IOC_IN, b'i', 16, size_of::<ifreq>());
pub const SIOCGIFFLAGS: c_ulong = ioc(IOC_INOUT, b'i', 17, size_of::<ifreq>());
pub const SIOCSIFBRDADDR: c_ulong = ioc(IOC_IN, b'i', 19, size_of::<ifreq>());
pub const SIOCGIFBRDADDR: c_ulong = ioc(IOC_INOUT, b'i', 35, size_of::<ifreq>());
pub const SIOCDIFADDR: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<ifreq>());
pub const SIOCAIFADDR: c_ulong = ioc(IOC_IN, b'i', 26, size_of::<ifaliasreq>());
pub const SIOCALIFADDR: c_ulong = ioc(IOC_IN, b'i', 28, size_of::<if_laddrreq>());
pub const SIOCGLIFADDR: c_ulong = ioc(IOC_INOUT, b'i', 29, size_of::<if_laddrreq>());
pub const SIOCDLIFADDR: c_ulong = ioc(IOC_IN, b'i', 30, size_of::<if_laddrreq>());
pub const SIOCGIFAFLAG_IN: c_ulong = ioc(IOC_INOUT, b'i', 39, size_of::<ifreq>());
pub const SIOCIFDESTROY: c_ulong = ioc(IOC_IN, b'i', 121, size_of::<ifreq>());
pub const SIOCIFCREATE: c_ulong = ioc(IOC_IN, b'i', 122, size_of::<ifreq>());
pub const SIOCGIFMTU: c_ulong = ioc(IOC_INOUT, b'i', 126, size_of::<ifreq>());
pub const SIOCSIFMTU: c_ulong = ioc(IOC_IN, b'i', 127, size_of::<ifreq>());
pub const SIOCDIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<in6_ifreq>());
pub const SIOCGIFAFLAG_IN6: c_ulong = ioc(IOC_INOUT, b'i', 73, size_of::<in6_ifreq>());
pub const SIOCAIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 107, size_of::<in6_aliasreq>());
pub const SIOCGIFINFO_IN6: c_ulong = ioc(IOC_INOUT, b'i', 113, size_of::<in6_ndireq>());

/// Packets of a tun device carry their address family in front.
pub const TUNSIFHEAD: c_ulong = ioc(IOC_IN, b't', 66, size_of::<c_int>());
/// The kind of link of a tun interface that is down: point to point or broadcast, and multicast.
pub const TUNSIFMODE: c_ulong = ioc(IOC_IN, b't', 88, size_of::<c_int>());
/// The name of the interface of a tap device.
pub const TAPGIFNAME: c_ulong = ioc(IOC_OUT, b'e', 0, size_of::<ifreq>());

pub const IN6_IFF_TENTATIVE: c_int = 0x02;
pub const IN6_IFF_DUPLICATED: c_int = 0x04;
pub const IN6_IFF_DETACHED: c_int = 0x08;
pub const ND6_INFINITE_LIFETIME: u32 = u32::MAX;
/// `net.inet6.ip6.dad_count`: how many probes a check for duplicates sends.
pub const IPV6CTL_DAD_COUNT: c_int = 16;

pub const IN_IFF_TENTATIVE: c_int = 0x01;
pub const IN_IFF_DUPLICATED: c_int = 0x02;
pub const IN_IFF_DETACHED: c_int = 0x04;
pub const IN_IFF_TRYTENTATIVE: c_int = 0x08;
/// `net.inet.ip.dad_count`: how many ARP probes a check of an IPv4 address sends.
pub const IPCTL_DAD_COUNT: c_int = 25;
/// Seconds of RFC 5227 that NetBSD's ARP probes keep: up to `PROBE_WAIT` before the first,
/// up to `PROBE_MAX` between two, and `ANNOUNCE_WAIT` after the last.
pub const PROBE_WAIT: u64 = 1;
pub const PROBE_MAX: u64 = 2;
pub const ANNOUNCE_WAIT: u64 = 2;

const _: () = assert!(size_of::<ifreq>() == 144);
const _: () = assert!(size_of::<ifaliasreq>() == 64);
const _: () = assert!(size_of::<in6_aliasreq>() == 128);
const _: () = assert!(size_of::<in6_ifreq>() == 288);
const _: () = assert!(size_of::<in6_ndireq>() == 32);
const _: () = assert!(std::mem::offset_of!(in6_ndireq, ndi.retrans) == 24);
const _: () = assert!(size_of::<if_laddrreq>() == 280);

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers NetBSD 11's headers give.
    #[test]
    fn requests() {
        assert_eq!(SIOCGIFAFLAG_IN, 0xc090_6927);
        assert_eq!(SIOCALIFADDR, 0x8118_691c);
        assert_eq!(SIOCGLIFADDR, 0xc118_691d);
        assert_eq!(SIOCDLIFADDR, 0x8118_691e);
        assert_eq!(SIOCGIFAFLAG_IN6, 0xc120_6949);
        assert_eq!(SIOCAIFADDR_IN6, 0x8080_696b);
        assert_eq!(SIOCDIFADDR_IN6, 0x8120_6919);
        assert_eq!(SIOCGIFINFO_IN6, 0xc020_6971);
    }
}
