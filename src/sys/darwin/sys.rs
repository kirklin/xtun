//! Kernel interfaces of the Apple systems that the `libc` crate does not carry for all of them.

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_uint, c_ulong, c_void, iovec, size_t, sockaddr, sockaddr_in6, socklen_t, ssize_t};

pub const AF_SYSTEM: c_int = 32;
pub const PF_SYSTEM: c_int = AF_SYSTEM;
pub const AF_SYS_CONTROL: u16 = 2;
pub const SYSPROTO_CONTROL: c_int = 2;
pub const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
pub const UTUN_OPT_IFNAME: c_int = 2;
pub const UTUN_OPT_MAX_PENDING_PACKETS: c_int = 16;
pub const IN6_IFF_NODAD: c_int = 0x0020;
pub const ND6_INFINITE_LIFETIME: u32 = u32::MAX;

#[repr(C)]
pub struct ctl_info {
    pub ctl_id: u32,
    pub ctl_name: [c_char; 96],
}

#[repr(C)]
pub struct sockaddr_ctl {
    pub sc_len: u8,
    pub sc_family: u8,
    pub ss_sysaddr: u16,
    pub sc_id: u32,
    pub sc_unit: u32,
    pub sc_reserved: [u32; 5],
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

/// `struct in6_ifreq`, whose union is as large as its largest member, `struct icmp6_ifstat`.
#[repr(C)]
pub struct in6_ifreq {
    pub ifr_name: [c_char; libc::IFNAMSIZ],
    pub ifr_ifru: in6_ifreq_ifru,
}

#[repr(C)]
pub union in6_ifreq_ifru {
    pub ifru_addr: sockaddr_in6,
    pub ifru_icmp6stat: [u64; 34],
}

/// `struct ifreq` for the members used here: flags and MTU.
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [c_char; libc::IFNAMSIZ],
    pub ifr_ifru: ifreq_ifru,
}

#[repr(C)]
pub union ifreq_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_flags: libc::c_short,
    pub ifru_mtu: c_int,
}

#[repr(C)]
pub struct msghdr_x {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: c_int,
    pub msg_control: *mut c_void,
    pub msg_controllen: socklen_t,
    pub msg_flags: c_int,
    pub msg_datalen: size_t,
}

use crate::sys::bsdlike::{IOC_IN, IOC_INOUT, ioc};

pub const CTLIOCGINFO: c_ulong = ioc(IOC_INOUT, b'N', 3, size_of::<ctl_info>());
pub const SIOCSIFFLAGS: c_ulong = ioc(IOC_IN, b'i', 16, size_of::<ifreq>());
pub const SIOCGIFFLAGS: c_ulong = ioc(IOC_INOUT, b'i', 17, size_of::<ifreq>());
pub const SIOCSIFBRDADDR: c_ulong = ioc(IOC_IN, b'i', 19, size_of::<ifreq>());
pub const SIOCDIFADDR: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<ifreq>());
pub const SIOCAIFADDR: c_ulong = ioc(IOC_IN, b'i', 26, size_of::<ifaliasreq>());
pub const SIOCGIFBRDADDR: c_ulong = ioc(IOC_INOUT, b'i', 35, size_of::<ifreq>());
pub const SIOCGIFMTU: c_ulong = ioc(IOC_INOUT, b'i', 51, size_of::<ifreq>());
pub const SIOCSIFMTU: c_ulong = ioc(IOC_IN, b'i', 52, size_of::<ifreq>());
pub const SIOCSIFLLADDR: c_ulong = ioc(IOC_IN, b'i', 60, size_of::<ifreq>());
pub const SIOCDIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 25, size_of::<in6_ifreq>());
pub const SIOCAIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 26, size_of::<in6_aliasreq>());

#[cfg(target_os = "macos")]
pub use feth::*;

/// What the layer 2 devices of macOS are made of: pairs of cloned `feth` interfaces, and BPF.
#[cfg(target_os = "macos")]
mod feth {
    use libc::{c_char, c_uint, c_ulong, c_void, size_t};

    use super::ifreq;
    use crate::sys::bsdlike::{IOC_IN, IOC_INOUT, IOC_OUT, IOC_VOID, ioc};

    pub const SIOCIFCREATE: c_ulong = ioc(IOC_INOUT, b'i', 120, size_of::<ifreq>());
    pub const SIOCIFDESTROY: c_ulong = ioc(IOC_IN, b'i', 121, size_of::<ifreq>());
    pub const SIOCSDRVSPEC: c_ulong = ioc(IOC_IN, b'i', 123, size_of::<ifdrv>());
    pub const SIOCGDRVSPEC: c_ulong = ioc(IOC_INOUT, b'i', 123, size_of::<ifdrv>());

    pub const BIOCGBLEN: c_ulong = ioc(IOC_OUT, b'B', 102, size_of::<c_uint>());
    pub const BIOCSBLEN: c_ulong = ioc(IOC_INOUT, b'B', 102, size_of::<c_uint>());
    pub const BIOCPROMISC: c_ulong = ioc(IOC_VOID, b'B', 105, 0);
    pub const BIOCSETIF: c_ulong = ioc(IOC_IN, b'B', 108, size_of::<ifreq>());
    pub const BIOCIMMEDIATE: c_ulong = ioc(IOC_IN, b'B', 112, size_of::<c_uint>());
    pub const BIOCSHDRCMPLT: c_ulong = ioc(IOC_IN, b'B', 117, size_of::<c_uint>());
    pub const BIOCSSEESENT: c_ulong = ioc(IOC_IN, b'B', 119, size_of::<c_uint>());

    /// `struct bpf_hdr` of a 64-bit process: a 32-bit time stamp, the captured and the original
    /// length, and the length of the header with its padding.
    #[repr(C)]
    pub struct bpf_hdr {
        pub bh_tstamp: [i32; 2],
        pub bh_caplen: u32,
        pub bh_datalen: u32,
        pub bh_hdrlen: u16,
    }

    /// Records in a BPF buffer start at multiples of this.
    pub const BPF_ALIGNMENT: usize = 4;

    /// The argument of the driver-specific ioctls.
    #[repr(C, packed(4))]
    pub struct ifdrv {
        pub ifd_name: [c_char; libc::IFNAMSIZ],
        pub ifd_cmd: c_ulong,
        pub ifd_len: size_t,
        pub ifd_data: *mut c_void,
    }

    /// The data of the `feth` driver's ioctls.
    #[repr(C)]
    pub struct if_fake_request {
        pub iffr_reserved: [u64; 4],
        pub iffr_peer_name: [c_char; 128],
    }

    /// Pairs a `feth` interface with another, or reads its pair.
    pub const IF_FAKE_S_CMD_SET_PEER: c_ulong = 1;
    pub const IF_FAKE_G_CMD_GET_PEER: c_ulong = 1;

    /// An interface's neighbor discovery settings, as SIOCGIFINFO_IN6 reads them.
    #[repr(C)]
    pub struct in6_ondireq {
        pub ifname: [c_char; libc::IFNAMSIZ],
        pub ndi: ondireq_info,
    }

    #[repr(C)]
    pub struct ondireq_info {
        pub linkmtu: u32,
        pub maxmtu: u32,
        pub basereachable: u32,
        pub reachable: u32,
        pub retrans: u32,
        pub flags: u32,
        pub recalctm: libc::c_int,
        pub chlim: u8,
        pub receivedra: u8,
        pub collision_count: u8,
    }

    /// What SIOCSIFINFO_FLAGS takes; of its settings only the flags count.
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
        pub recalctm: libc::c_int,
        pub chlim: u8,
        pub receivedra: u8,
        pub randomseed0: [u8; 8],
        pub randomseed1: [u8; 8],
        pub randomid: [u8; 8],
    }

    /// The interface checks new IPv6 addresses for duplicates before they may be used.
    pub const ND6_IFF_DAD: u32 = 0x200;

    pub const SIOCGIFINFO_IN6: c_ulong = ioc(IOC_INOUT, b'i', 76, size_of::<in6_ondireq>());
    pub const SIOCSIFINFO_FLAGS: c_ulong = ioc(IOC_INOUT, b'i', 87, size_of::<in6_ndireq>());
    /// Attaches IPv6 to an interface.
    pub const SIOCPROTOATTACH_IN6: c_ulong = ioc(IOC_INOUT, b'i', 110, size_of::<super::in6_aliasreq>());
    /// Gives an interface its link-local address.
    pub const SIOCLL_START: c_ulong = ioc(IOC_INOUT, b'i', 130, size_of::<super::in6_aliasreq>());
}

unsafe extern "C" {
    pub fn recvmsg_x(s: c_int, msgp: *const msghdr_x, cnt: c_uint, flags: c_int) -> ssize_t;
    pub fn sendmsg_x(s: c_int, msgp: *const msghdr_x, cnt: c_uint, flags: c_int) -> ssize_t;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_match_the_headers() {
        assert_eq!(size_of::<ctl_info>(), 100);
        assert_eq!(CTLIOCGINFO, 0xc064_4e03);
        assert_eq!(size_of::<ifreq>(), 32);
        assert_eq!(SIOCSIFMTU, 0x8020_6934);
        assert_eq!(SIOCAIFADDR, 0x8040_691a);
        assert_eq!(size_of::<in6_aliasreq>(), 128);
        assert_eq!(size_of::<in6_ifreq>(), 288);
        assert_eq!(size_of::<msghdr_x>(), 56);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn interface_and_bpf_requests_match_the_headers() {
        assert_eq!(SIOCIFCREATE, 0xc020_6978);
        assert_eq!(SIOCIFDESTROY, 0x8020_6979);
        assert_eq!((SIOCSDRVSPEC, SIOCGDRVSPEC), (0x8028_697b, 0xc028_697b));
        assert_eq!(SIOCSIFLLADDR, 0x8020_693c);
        assert_eq!((SIOCGIFBRDADDR, SIOCSIFBRDADDR), (0xc020_6923, 0x8020_6913));
        assert_eq!((BIOCSBLEN, BIOCGBLEN), (0xc004_4266, 0x4004_4266));
        assert_eq!(BIOCSETIF, 0x8020_426c);
        assert_eq!((BIOCIMMEDIATE, BIOCSHDRCMPLT, BIOCSSEESENT), (0x8004_4270, 0x8004_4275, 0x8004_4277));
        assert_eq!(BIOCPROMISC, 0x2000_4269);
        assert_eq!(size_of::<bpf_hdr>(), 20);
        assert_eq!(size_of::<ifdrv>(), 40);
        assert_eq!(size_of::<if_fake_request>(), 160);
        assert_eq!((size_of::<in6_ondireq>(), size_of::<in6_ndireq>()), (48, 72));
        assert_eq!((SIOCGIFINFO_IN6, SIOCSIFINFO_FLAGS), (0xc030_694c, 0xc048_6957));
        assert_eq!((SIOCPROTOATTACH_IN6, SIOCLL_START), (0xc080_696e, 0xc080_6982));
    }
}
