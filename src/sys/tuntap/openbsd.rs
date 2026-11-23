//! OpenBSD's layouts and requests for tun and tap devices and their interfaces.

#![allow(non_camel_case_types, non_upper_case_globals)]

use libc::{c_char, c_int, c_short, c_ulong, sockaddr, sockaddr_in6};

use crate::sys::bsdlike::{IOC_IN, IOC_INOUT, IOC_OUT, ioc};

pub const TUN_PREFIX: &str = "tun";
pub const TAP_PREFIX: &str = "tap";

#[repr(C)]
pub struct ifreq {
    pub ifr_name: [c_char; libc::IFNAMSIZ],
    pub ifr_ifru: ifreq_ifru,
}

#[repr(C)]
pub union ifreq_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_flags: c_short,
    /// `ifru_metric`, which carries the MTU too.
    pub ifru_mtu: c_int,
    pub ifru_data: *mut c_char,
    ifru_media: u64,
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

pub const SIOCSIFFLAGS: c_ulong = ioc(IOC_IN, b'i', 16, size_of::<ifreq>());
pub const SIOCGIFFLAGS: c_ulong = ioc(IOC_INOUT, b'i', 17, size_of::<ifreq>());
pub const SIOCSIFBRDADDR: c_ulong = ioc(IOC_IN, b'i', 19, size_of::<ifreq>());
pub const SIOCGIFBRDADDR: c_ulong = ioc(IOC_INOUT, b'i', 35, size_of::<ifreq>());
pub const SIOCDIFADDR: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<ifreq>());
pub const SIOCAIFADDR: c_ulong = ioc(IOC_IN, b'i', 26, size_of::<ifaliasreq>());
pub const SIOCSIFLLADDR: c_ulong = ioc(IOC_IN, b'i', 31, size_of::<ifreq>());
pub const SIOCIFDESTROY: c_ulong = ioc(IOC_IN, b'i', 121, size_of::<ifreq>());
pub const SIOCIFCREATE: c_ulong = ioc(IOC_IN, b'i', 122, size_of::<ifreq>());
pub const SIOCGIFMTU: c_ulong = ioc(IOC_INOUT, b'i', 126, size_of::<ifreq>());
pub const SIOCSIFMTU: c_ulong = ioc(IOC_IN, b'i', 127, size_of::<ifreq>());
pub const SIOCDIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<in6_ifreq>());
pub const SIOCAIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 26, size_of::<in6_aliasreq>());
pub const SIOCGIFAFLAG_IN6: c_ulong = ioc(IOC_INOUT, b'i', 73, size_of::<in6_ifreq>());

/// `struct tun_capabilities`: the offloads a reader takes, which turns on `tun_hdr`.
#[repr(C)]
pub struct tun_capabilities {
    pub tun_if_capabilities: u32,
}

pub const TUNSCAP: c_ulong = ioc(IOC_IN, b't', 196, size_of::<tun_capabilities>());
pub const TUNGCAP: c_ulong = ioc(IOC_OUT, b't', 196, size_of::<tun_capabilities>());

pub const IFCAP_CSUM_TCPv4: u32 = 0x0000_0002;
pub const IFCAP_CSUM_UDPv4: u32 = 0x0000_0004;
pub const IFCAP_CSUM_TCPv6: u32 = 0x0000_0080;
pub const IFCAP_CSUM_UDPv6: u32 = 0x0000_0100;
pub const IFCAP_TSOv4: u32 = 0x0000_1000;
pub const IFCAP_TSOv6: u32 = 0x0000_2000;

pub const IN6_IFF_TENTATIVE: c_int = 0x02;
pub const IN6_IFF_DUPLICATED: c_int = 0x04;
pub const IN6_IFF_DETACHED: c_int = 0x08;
pub const ND6_INFINITE_LIFETIME: u32 = u32::MAX;
/// `net.inet6.ip6.dad_count`: how many probes a check for duplicates sends.
pub const IPV6CTL_DAD_COUNT: c_int = 16;
/// Milliseconds before each probe of a check for duplicates and after the last: `RETRANS_TIMER`,
/// which OpenBSD uses on every interface.
pub const RETRANS_TIMER: u64 = 1000;

const _: () = assert!(size_of::<ifreq>() == 32);
const _: () = assert!(size_of::<tun_capabilities>() == 4);
const _: () = assert!(size_of::<ifaliasreq>() == 64);
const _: () = assert!(size_of::<in6_aliasreq>() == 128);
const _: () = assert!(size_of::<in6_ifreq>() == 288);

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers OpenBSD 7.8's headers give.
    #[test]
    fn requests() {
        assert_eq!(SIOCGIFAFLAG_IN6, 0xc120_6949);
        assert_eq!(SIOCAIFADDR_IN6, 0x8080_691a);
        assert_eq!(SIOCDIFADDR_IN6, 0x8120_6919);
        assert_eq!(TUNSCAP, 0x8004_74c4);
        assert_eq!(TUNGCAP, 0x4004_74c4);
    }
}
