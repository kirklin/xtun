//! illumos's layouts and requests for the tun driver, STREAMS, logical interfaces and the
//! routing socket.

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_uint};

/// The tun driver's cloning device.
pub const TUN_DEVICE: &str = "/dev/tun";
pub const TUN_PREFIX: &str = "tun";
/// The driver hands out units 0 to 19 (`TUNMAXPPA`).
pub const UNITS: u32 = 20;
/// The largest packet the driver tells IP its link carries (`dl_max_sdu`).
pub const MAX_MTU: u32 = 1500;
/// The smallest MTU IPv6 takes.
pub const MIN_MTU_V6: u32 = 1280;

/// Makes the data stream the control stream of a new unit, the one asked for or, given -1, the
/// first free one, and returns the unit.
pub const TUNNEWPPA: c_int = ((b'T' as c_int) << 16) | 0x0001;
/// The unit of a control stream.
pub const TUNGETPPA: c_int = ((b'T' as c_int) << 16) | 0x0003;

pub const I_PUSH: c_int = 0x5302;
pub const I_POP: c_int = 0x5303;
pub const I_SRDOPT: c_int = 0x5306;
pub const I_STR: c_int = 0x5308;
/// Links a stream under a multiplexor until the multiplexor is closed.
pub const I_LINK: c_int = 0x530c;
/// Undoes a link made for good, with `I_PLINK`.
pub const I_PUNLINK: c_int = 0x5317;
/// Reads take one message each and drop what does not fit.
pub const RMSGD: c_int = 0x0001;

/// An ioctl carried down a stream as a message.
#[repr(C)]
pub struct strioctl {
    pub ic_cmd: c_int,
    pub ic_timout: c_int,
    pub ic_len: c_int,
    pub ic_dp: *mut c_char,
}

/// `struct lifreq`: a request about one logical interface.
#[repr(C)]
pub struct lifreq {
    pub lifr_name: [c_char; LIFNAMSIZ],
    /// `lifru_ppa` for SIOCSLIFNAME.
    pub lifr_ppa: c_uint,
    pub lifr_type: c_uint,
    pub lifr_lifru: lifreq_lifru,
}

#[repr(C)]
pub union lifreq_lifru {
    pub lifru_addr: libc::sockaddr_storage,
    pub lifru_flags: u64,
    pub lifru_mtu: c_uint,
    /// The ids of the links of IP's stream and of ARP's.
    pub lif_muxid: [c_int; 2],
    space: [u64; 42],
}

pub const LIFNAMSIZ: usize = 32;

/// How many logical interfaces `SIOCGLIFCONF` would list.
#[repr(C)]
pub struct lifnum {
    pub lifn_family: libc::sa_family_t,
    pub lifn_flags: c_int,
    pub lifn_count: c_int,
}

/// Room for `SIOCGLIFCONF` to list logical interfaces in, one `lifreq` each.
#[repr(C)]
pub struct lifconf {
    pub lifc_family: libc::sa_family_t,
    pub lifc_flags: c_int,
    pub lifc_len: c_int,
    pub lifc_buf: *mut lifreq,
}

/// Every logical interface: those that do not send, temporary ones, those of every zone and
/// those under IPMP. Without `LIFC_ENABLED`, those that are down are listed too, which
/// `getifaddrs` leaves out.
pub const LIFC_EVERY: c_int = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES | LIFC_UNDER_IPMP;
const LIFC_NOXMIT: c_int = 0x01;
const LIFC_TEMPORARY: c_int = 0x04;
const LIFC_ALLZONES: c_int = 0x08;
const LIFC_UNDER_IPMP: c_int = 0x10;

const IOC_IN: u32 = 0x8000_0000;
const IOC_INOUT: u32 = 0xc000_0000;

/// An ioctl request number as `_IOW` and `_IOWR` make it: illumos keeps the low byte of the size.
const fn ioc(direction: u32, group: u8, number: u8, size: usize) -> c_int {
    (direction | ((size as u32 & 0xff) << 16) | ((group as u32) << 8) | number as u32) as c_int
}

const LIFREQ: usize = size_of::<lifreq>();
pub const SIOCLIFREMOVEIF: c_int = ioc(IOC_IN, b'i', 110, LIFREQ);
pub const SIOCLIFADDIF: c_int = ioc(IOC_INOUT, b'i', 111, LIFREQ);
pub const SIOCSLIFADDR: c_int = ioc(IOC_IN, b'i', 112, LIFREQ);
pub const SIOCSLIFDSTADDR: c_int = ioc(IOC_IN, b'i', 114, LIFREQ);
pub const SIOCSLIFFLAGS: c_int = ioc(IOC_IN, b'i', 116, LIFREQ);
pub const SIOCGLIFFLAGS: c_int = ioc(IOC_INOUT, b'i', 117, LIFREQ);
pub const SIOCSLIFMTU: c_int = ioc(IOC_IN, b'i', 121, LIFREQ);
pub const SIOCGLIFMTU: c_int = ioc(IOC_INOUT, b'i', 122, LIFREQ);
pub const SIOCGLIFNETMASK: c_int = ioc(IOC_INOUT, b'i', 125, LIFREQ);
pub const SIOCSLIFNETMASK: c_int = ioc(IOC_IN, b'i', 126, LIFREQ);
pub const SIOCSLIFNAME: c_int = ioc(IOC_INOUT, b'i', 129, LIFREQ);
pub const SIOCGLIFNUM: c_int = ioc(IOC_INOUT, b'i', 130, size_of::<lifnum>());
/// Made with `_IOWRN` and a size of 16, which is not that of `struct lifconf`.
pub const SIOCGLIFCONF: c_int = ioc(IOC_INOUT, b'i', 165, 16);
pub const SIOCGLIFMUXID: c_int = ioc(IOC_INOUT, b'i', 131, LIFREQ);

pub const IFF_UP: u64 = 0x1;
pub const IFF_RUNNING: u64 = 0x40;
pub const IFF_IPV4: u64 = 0x0100_0000;
pub const IFF_IPV6: u64 = 0x0200_0000;
/// No link-local address on the IPv6 interface, as `ipadm` plumbs it.
pub const IFF_NOLINKLOCAL: u64 = 0x200_0000_0000;

/// `struct rt_msghdr`.
#[repr(C)]
pub struct rt_msghdr {
    pub rtm_msglen: u16,
    pub rtm_version: u8,
    pub rtm_type: u8,
    pub rtm_index: u16,
    pub rtm_flags: c_int,
    pub rtm_addrs: c_int,
    pub rtm_pid: libc::pid_t,
    pub rtm_seq: c_int,
    pub rtm_errno: c_int,
    pub rtm_use: c_int,
    pub rtm_inits: c_uint,
    pub rtm_rmx: [u32; 10],
}

pub const RTM_VERSION: u8 = 3;
pub const RTM_ADD: u8 = 1;
pub const RTM_DELETE: u8 = 2;
pub const RTA_DST: c_int = 0x1;
pub const RTA_GATEWAY: c_int = 0x2;
pub const RTA_NETMASK: c_int = 0x4;
pub const RTA_IFP: c_int = 0x10;
pub const RTF_UP: c_int = 0x1;
pub const RTF_GATEWAY: c_int = 0x2;
pub const RTF_HOST: c_int = 0x4;
pub const RTF_STATIC: c_int = 0x800;

const _: () = assert!(size_of::<strioctl>() == 24);
const _: () = assert!(size_of::<lifnum>() == 12 && size_of::<lifconf>() == 24);
const _: () = assert!(std::mem::offset_of!(lifconf, lifc_buf) == 16);
const _: () = assert!(size_of::<lifreq>() == 376);
const _: () = assert!(std::mem::offset_of!(lifreq, lifr_lifru) == 40);
const _: () = assert!(size_of::<rt_msghdr>() == 76);
const _: () = assert!(size_of::<libc::sockaddr_in6>() == 32 && size_of::<libc::sockaddr_dl>() == 252);

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers OmniOS r151060's headers give.
    #[test]
    fn requests() {
        let expected = [
            (SIOCLIFREMOVEIF, 0x8078_696e_u32),
            (SIOCLIFADDIF, 0xc078_696f),
            (SIOCSLIFADDR, 0x8078_6970),
            (SIOCGLIFNETMASK, 0xc078_697d),
            (SIOCGLIFNUM, 0xc00c_6982),
            (SIOCGLIFCONF, 0xc010_69a5),
            (SIOCSLIFDSTADDR, 0x8078_6972),
            (SIOCSLIFFLAGS, 0x8078_6974),
            (SIOCGLIFFLAGS, 0xc078_6975),
            (SIOCSLIFMTU, 0x8078_6979),
            (SIOCGLIFMTU, 0xc078_697a),
            (SIOCSLIFNETMASK, 0x8078_697e),
            (SIOCSLIFNAME, 0xc078_6981),
            (SIOCGLIFMUXID, 0xc078_6983),
        ];
        for (request, number) in expected {
            assert_eq!(request as u32, number);
        }
    }
}
