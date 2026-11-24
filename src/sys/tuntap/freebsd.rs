//! FreeBSD's layouts and requests for tun and tap devices and their interfaces.

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_short, c_ulong, sockaddr, sockaddr_in6};

use crate::sys::bsdlike::{IOC_IN, IOC_INOUT, IOC_OUT, ioc};

/// Opening it creates the next free interface of its kind.
pub const TUN_CLONER: &str = "/dev/tun";
pub const TAP_CLONER: &str = "/dev/tap";
/// Interface names start with these.
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
    /// The low 16 bits of the flags; the high ones follow, and stay as SIOCGIFFLAGS left them.
    pub ifru_flags: c_short,
    pub ifru_mtu: c_int,
    pub ifru_data: *mut c_char,
    /// The requested and the current capabilities.
    pub ifru_cap: [c_int; 2],
    ifru_size: [u64; 2],
}

/// `struct in_aliasreq`, which SIOCAIFADDR takes for IPv4.
#[repr(C)]
pub struct ifaliasreq {
    pub ifra_name: [c_char; libc::IFNAMSIZ],
    pub ifra_addr: sockaddr,
    pub ifra_broadaddr: sockaddr,
    pub ifra_mask: sockaddr,
    pub ifra_vhid: c_int,
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
    pub ifra_vhid: c_int,
}

/// `struct in6_ifreq`, whose union is as large as its largest member, `struct icmp6_ifstat`.
#[repr(C)]
pub struct in6_ifreq {
    pub ifr_name: [c_char; libc::IFNAMSIZ],
    pub ifr_ifru: in6_ifreq_ifru,
}

#[repr(C)]
pub union in6_ifreq_ifru {
    pub ifru_addr: sockaddr_in6,
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
    pub linkmtu: u32,
    pub maxmtu: u32,
    pub basereachable: u32,
    pub reachable: u32,
    pub retrans: u32,
    pub flags: u32,
    pub recalctm: c_int,
    pub chlim: u8,
    pub initialized: u8,
    pub randomseed0: [u8; 8],
    pub randomseed1: [u8; 8],
    pub randomid: [u8; 8],
}

pub const SIOCSIFFLAGS: c_ulong = ioc(IOC_IN, b'i', 16, size_of::<ifreq>());
pub const SIOCGIFFLAGS: c_ulong = ioc(IOC_INOUT, b'i', 17, size_of::<ifreq>());
pub const SIOCGIFBRDADDR: c_ulong = ioc(IOC_INOUT, b'i', 35, size_of::<ifreq>());
pub const SIOCDIFADDR: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<ifreq>());
pub const SIOCSIFCAP: c_ulong = ioc(IOC_IN, b'i', 30, size_of::<ifreq>());
pub const SIOCGIFCAP: c_ulong = ioc(IOC_INOUT, b'i', 31, size_of::<ifreq>());
pub const SIOCSIFNAME: c_ulong = ioc(IOC_IN, b'i', 40, size_of::<ifreq>());
pub const SIOCAIFADDR: c_ulong = ioc(IOC_IN, b'i', 43, size_of::<ifaliasreq>());
pub const SIOCGIFMTU: c_ulong = ioc(IOC_INOUT, b'i', 51, size_of::<ifreq>());
pub const SIOCSIFMTU: c_ulong = ioc(IOC_IN, b'i', 52, size_of::<ifreq>());
pub const SIOCSIFLLADDR: c_ulong = ioc(IOC_IN, b'i', 60, size_of::<ifreq>());
pub const SIOCIFDESTROY: c_ulong = ioc(IOC_IN, b'i', 121, size_of::<ifreq>());
pub const SIOCDIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<in6_ifreq>());
pub const SIOCAIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 27, size_of::<in6_aliasreq>());
pub const SIOCSIFINFO_FLAGS: c_ulong = ioc(IOC_INOUT, b'i', 87, size_of::<in6_ndireq>());
pub const SIOCGIFINFO_IN6: c_ulong = ioc(IOC_INOUT, b'i', 108, size_of::<in6_ndireq>());

/// Packets of a tun device carry their address family in front.
pub const TUNSIFHEAD: c_ulong = ioc(IOC_IN, b't', 96, size_of::<c_int>());
/// The name of the interface of a tun or tap device.
pub const TUNGIFNAME: c_ulong = ioc(IOC_OUT, b't', 93, size_of::<ifreq>());
/// The interface goes away with the last close of its device (FreeBSD 15).
pub const TUNSTRANSIENT: c_ulong = ioc(IOC_IN, b't', 98, size_of::<c_int>());
/// The length of the virtio header in front of the frames of a tap device.
pub const TAPSVNETHDR: c_ulong = ioc(IOC_IN, b't', 91, size_of::<c_int>());
pub const TAPGVNETHDR: c_ulong = ioc(IOC_OUT, b't', 94, size_of::<c_int>());

pub const IN6_IFF_NODAD: c_int = 0x20;
pub const ND6_INFINITE_LIFETIME: u32 = u32::MAX;
/// No address of the interface is checked for duplicates on the link.
pub const ND6_IFF_NO_DAD: u32 = 0x100;

pub const IFCAP_RXCSUM: c_int = 1 << 0;
pub const IFCAP_TXCSUM: c_int = 1 << 1;
pub const IFCAP_TSO4: c_int = 1 << 8;
pub const IFCAP_TSO6: c_int = 1 << 9;
pub const IFCAP_RXCSUM_IPV6: c_int = 1 << 21;
pub const IFCAP_TXCSUM_IPV6: c_int = 1 << 22;

/// What is turned on of what a tap device with a virtio header offers: checksums left to
/// either side and TCP segments in both directions. The system's own joining of the frames it
/// is written, `IFCAP_LRO`, stays off. The driver sets the state of that joining up anew
/// whenever the interface is initialised, as it is when an address is added, and takes no
/// account of a write that is under way: the write then reads the half made state and the
/// kernel faults. The writer joins packets itself, and the system takes the segments as they
/// are.
pub const OFFLOAD_CAPABILITIES: c_int = IFCAP_RXCSUM | IFCAP_TXCSUM | IFCAP_RXCSUM_IPV6 | IFCAP_TXCSUM_IPV6 | IFCAP_TSO4 | IFCAP_TSO6;

/// The virtio header that FreeBSD takes: without the count of merged buffers.
pub const VNET_LEN: c_int = 10;

const _: () = assert!(size_of::<ifreq>() == 32);
const _: () = assert!(size_of::<in6_ifreq>() == 288);
const _: () = assert!(size_of::<in6_ndireq>() == 72);
const _: () = assert!(std::mem::offset_of!(in6_ndireq, ndi.flags) == 36);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<ifaliasreq>() == 68 && size_of::<in6_aliasreq>() == 136);

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers FreeBSD 15's headers give.
    #[test]
    fn requests() {
        assert_eq!(SIOCGIFINFO_IN6, 0xc048_696c);
        assert_eq!(SIOCSIFINFO_FLAGS, 0xc048_6957);
    }
}
