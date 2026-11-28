//! OpenBSD's `struct tun_hdr`, in front of every packet of a tun or tap device once `TUNSCAP`
//! turned it on: which checksums are left to the reader, a VLAN tag taken off the frame and, for a
//! TCP segment, the size to cut it into. Its fields are in the machine's byte order. A TCP
//! segment's checksum field holds the pseudo header without the length, which a read adds, as the
//! cut expects it there. On a write the system fills in the checksum field itself.

use std::io;

use crate::cut::segment_header_len;
use crate::packet::{
    CWR, Checksum, Gso, GsoKind, Head, TCP, TCP_CHECKSUM, Transport, UDP, UDP_CHECKSUM, adjust_partial, invalid, link_len_head,
    read_u16, transport_of, write_u16,
};
use crate::vnet;

pub(crate) const LEN: usize = 8;

const VTAG: u16 = 1 << 4;
const MSS: u16 = 1 << 5;
const IPV4_CSUM: u16 = 1 << 8;
const TCP_CSUM: u16 = 1 << 9;
const UDP_CSUM: u16 = 1 << 10;
const ICMP_CSUM: u16 = 1 << 11;
/// The flags that leave something of the transport header to the reader.
const TRANSPORT: u16 = TCP_CSUM | UDP_CSUM | ICMP_CSUM | MSS;

const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const ICMP_CHECKSUM: usize = 2;

/// The checksum field's place from the transport header on, for the protocols OpenBSD offloads.
fn checksum_offset(protocol: u8) -> Option<usize> {
    match protocol {
        TCP => Some(TCP_CHECKSUM),
        UDP => Some(UDP_CHECKSUM),
        ICMP | ICMPV6 => Some(ICMP_CHECKSUM),
        _ => None,
    }
}

/// The flags that may leave something of a packet of `protocol` to the reader.
fn flags_of(protocol: u8) -> u16 {
    match protocol {
        TCP => TCP_CSUM | MSS,
        UDP => UDP_CSUM,
        ICMP | ICMPV6 => ICMP_CSUM,
        _ => 0,
    }
}

/// The VLAN tag that header `head` says the system took off the frame behind it.
pub(crate) fn vlan_tag(head: &[u8]) -> Option<u16> {
    let flags = u16::from_ne_bytes([head[0], head[1]]);
    (flags & VTAG != 0).then(|| u16::from_ne_bytes([head[4], head[5]]))
}

/// What a packet read behind header `head` is: its checksum state and, for a segment, how to cut
/// it. `link` says where its IP header starts, if it carries IP. A missing IPv4 header checksum
/// and a segment's checksum field are put right in `data`.
pub(crate) fn describe(head: &[u8], data: &mut [u8], link: Option<usize>) -> io::Result<(Checksum, Option<Gso>)> {
    let flags = u16::from_ne_bytes([head[0], head[1]]);
    let mss = u16::from_ne_bytes([head[6], head[7]]);
    if flags & (IPV4_CSUM | TRANSPORT) == 0 {
        return Ok((Checksum::Unverified, None));
    }
    let link = link.ok_or_else(|| invalid("a packet with offloads has to carry IPv4 or IPv6"))?;
    let (v6, transport, protocol) = transport_of(data, link)?;
    if flags & IPV4_CSUM != 0 && !v6 {
        let header = data.get_mut(link..transport).ok_or_else(|| invalid("the IPv4 header is cut off"))?;
        crate::packet::ipv4_header_checksum(header);
    }
    if flags & TRANSPORT == 0 {
        return Ok((Checksum::Unverified, None));
    }
    let offset = checksum_offset(protocol).ok_or_else(|| invalid("a checksum is left for a protocol without one"))?;
    if flags & TRANSPORT & !flags_of(protocol) != 0 {
        return Err(invalid("a checksum is left for another protocol than the packet's"));
    }
    if transport + offset + 2 > data.len() {
        return Err(invalid("the checksum field lies outside the packet"));
    }
    let start = u16::try_from(transport).map_err(|_| invalid("the transport header starts past 64 KiB"))?;
    let checksum = Checksum::Partial { start, offset: offset as u16 };
    if flags & MSS == 0 {
        return Ok((checksum, None));
    }
    if protocol != TCP {
        return Err(invalid("a segment to cut is not TCP"));
    }
    let at = transport + offset;
    let field = read_u16(data, at);
    write_u16(data, at, adjust_partial(field, 0, data.len() - transport));
    let ecn = data.get(transport + 13).is_some_and(|flags| flags & CWR != 0);
    let kind = if v6 { GsoKind::Tcp6 { ecn } } else { GsoKind::Tcp4 { ecn } };
    let gso = Gso { kind, segment_size: mss, header_len: 0 };
    let header_len = segment_header_len(data, link, checksum, gso)?;
    Ok((checksum, Some(Gso { header_len, ..gso })))
}

/// Whether a `tun_hdr` can carry what `packet` leaves to the system: a checksum at the transport
/// header's own field and, for a segment, TCP right after the IP header. Other packets are cut
/// and completed here.
pub(crate) fn describes(head: Head<'_>, checksum: Checksum, gso: Option<Gso>, ethernet: bool) -> bool {
    let Checksum::Partial { start, offset } = checksum else {
        return gso.is_none();
    };
    let Some(link) = (if ethernet { link_len_head(head) } else { Some(0) }) else {
        return false;
    };
    let (start, offset) = (usize::from(start), usize::from(offset));
    match gso {
        None => transport_of(head.bytes, link)
            .is_ok_and(|(_, transport, protocol)| start == transport && checksum_offset(protocol) == Some(offset)),
        Some(gso) => {
            matches!(gso.kind, GsoKind::Tcp4 { .. } | GsoKind::Tcp6 { .. })
                && Transport::read_head(head, link).is_some_and(|info| info.tcp && start == info.transport && offset == TCP_CHECKSUM)
        }
    }
}

/// The `tun_hdr` for a write that a virtio header describes, one that [`describes`] passed.
pub(crate) fn encode(header: &vnet::Header, out: &mut [u8]) {
    let mut flags = 0u16;
    if header.flags & vnet::NEEDS_CSUM != 0 {
        flags |= match usize::from(header.csum_offset) {
            TCP_CHECKSUM => TCP_CSUM,
            UDP_CHECKSUM => UDP_CSUM,
            _ => ICMP_CSUM,
        };
    }
    let mss = match header.gso_type & !vnet::GSO_ECN {
        vnet::GSO_TCPV4 | vnet::GSO_TCPV6 => {
            flags |= MSS;
            header.gso_size
        }
        _ => 0,
    };
    out[..2].copy_from_slice(&flags.to_ne_bytes());
    out[2..6].fill(0);
    out[6..8].copy_from_slice(&mss.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::build::{Flow, payload};

    fn head(flags: u16, mss: u16) -> [u8; LEN] {
        let mut head = [0u8; LEN];
        head[..2].copy_from_slice(&flags.to_ne_bytes());
        head[6..].copy_from_slice(&mss.to_ne_bytes());
        head
    }

    #[test]
    fn a_segment_gets_the_length_into_its_pseudo_header() {
        for v6 in [false, true] {
            let flow = Flow::tcp(v6);
            let mut segment = flow.packet(1, &payload(1, 3000));
            let ip_len = if v6 { 40 } else { 20 };
            let at = ip_len + TCP_CHECKSUM;
            // OpenBSD's field for a segment: the pseudo header with a length of zero.
            let length = segment.len() - ip_len;
            let with_length = read_u16(&segment, at);
            write_u16(&mut segment, at, adjust_partial(with_length, length, 0));
            let (checksum, gso) = describe(&head(TCP_CSUM | MSS, 1400), &mut segment, Some(0)).unwrap();
            assert_eq!(checksum, Checksum::Partial { start: ip_len as u16, offset: TCP_CHECKSUM as u16 });
            assert_eq!(read_u16(&segment, at), with_length);
            let gso = gso.unwrap();
            assert_eq!((gso.segment_size, usize::from(gso.header_len)), (1400, ip_len + 32));
            assert!(matches!(gso.kind, GsoKind::Tcp6 { .. }) == v6);
        }
    }

    #[test]
    fn checksums_alone_and_nothing() {
        let mut packet = Flow::udp(false).packet(1, &payload(2, 100));
        let (checksum, gso) = describe(&head(UDP_CSUM, 0), &mut packet, Some(0)).unwrap();
        assert_eq!((checksum, gso), (Checksum::Partial { start: 20, offset: UDP_CHECKSUM as u16 }, None));
        assert_eq!(describe(&head(0, 0), &mut packet, None).unwrap(), (Checksum::Unverified, None));
        assert!(describe(&head(TCP_CSUM | MSS, 1400), &mut packet, Some(0)).is_err(), "a UDP packet is no TCP segment");
    }

    #[test]
    fn an_ipv4_header_shorter_than_its_fixed_part_is_refused() {
        let mut packet = Flow::udp(false).packet(1, &payload(2, 100));
        for words in 0..5 {
            packet[0] = 0x40 | words;
            assert!(describe(&head(IPV4_CSUM, 0), &mut packet, Some(0)).is_err(), "a header of {words} words");
            assert!(describe(&head(UDP_CSUM, 0), &mut packet, Some(0)).is_err(), "a header of {words} words");
        }
    }

    #[test]
    fn walks_past_ipv6_extension_headers() {
        let mut packet = vec![0u8; 40 + 8 + 20];
        packet[0] = 0x60;
        packet[6] = 0;
        packet[40] = TCP;
        packet[40 + 8 + 12] = 5 << 4;
        assert_eq!(transport_of(&packet, 0).unwrap(), (true, 48, TCP));
    }

    /// An IPv6 TCP packet behind a hop-by-hop options header of 16 bytes and a fragment header that
    /// holds the whole packet, whose checksum is left to the reader.
    fn behind_extension_headers(fragment: u16) -> Vec<u8> {
        let flow = Flow::tcp(true);
        let plain = flow.packet(1, &payload(4, 100));
        let mut packet = plain[..40].to_vec();
        packet[6] = 0;
        // An option of a type to skip, with twelve bytes of data.
        packet.extend_from_slice(&[44, 1, 0x1e, 12]);
        packet.extend_from_slice(&[0xaa; 12]);
        packet.extend_from_slice(&[TCP, 0]);
        packet.extend_from_slice(&fragment.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 7]);
        packet.extend_from_slice(&plain[40..]);
        let length = (packet.len() - 40) as u16;
        packet[4..6].copy_from_slice(&length.to_be_bytes());
        packet
    }

    #[test]
    fn walks_past_a_long_header_in_front_of_a_fragment_header() {
        let mut packet = behind_extension_headers(0);
        assert_eq!(transport_of(&packet, 0).unwrap(), (true, 64, TCP));
        let (checksum, gso) = describe(&head(TCP_CSUM, 0), &mut packet, Some(0)).unwrap();
        assert_eq!((checksum, gso), (Checksum::Partial { start: 64, offset: TCP_CHECKSUM as u16 }, None));
    }

    #[test]
    fn a_fragment_has_no_checksum_to_complete() {
        // The first fragment of several, and one further on.
        for fragment in [1, 8 << 3] {
            let mut packet = behind_extension_headers(fragment);
            assert!(describe(&head(TCP_CSUM, 0), &mut packet, Some(0)).is_err(), "fragment field {fragment:#x}");
        }
        let mut packet = Flow::udp(false).packet(1, &payload(2, 100));
        packet[6] |= 0x20;
        assert!(describe(&head(UDP_CSUM, 0), &mut packet, Some(0)).is_err(), "an IPv4 fragment");
    }

    #[test]
    fn a_checksum_left_for_another_protocol_is_refused() {
        let mut udp = Flow::udp(false).packet(1, &payload(2, 100));
        assert!(describe(&head(TCP_CSUM, 0), &mut udp, Some(0)).is_err());
        let mut tcp = Flow::tcp(false).packet(1, &payload(2, 100));
        assert!(describe(&head(UDP_CSUM, 0), &mut tcp, Some(0)).is_err());
        assert!(describe(&head(TCP_CSUM, 0), &mut tcp, Some(0)).is_ok());
    }

    #[test]
    fn says_what_it_can_carry() {
        let tcp = Flow::tcp(false).packet(1, &payload(3, 3000));
        let partial = Checksum::Partial { start: 20, offset: TCP_CHECKSUM as u16 };
        let segment = Gso { kind: GsoKind::Tcp4 { ecn: false }, segment_size: 1400, header_len: 0 };
        let carries = |data: &[u8], checksum, gso| describes(Head::whole(data), checksum, gso, false);
        assert!(carries(&tcp, Checksum::Unverified, None));
        assert!(carries(&tcp, partial, None));
        assert!(carries(&tcp, partial, Some(segment)));
        assert!(!carries(&tcp, Checksum::Partial { start: 20, offset: 4 }, None));
        let short = Head { bytes: &tcp[..40], len: tcp.len() };
        assert!(!describes(short, partial, Some(segment), false), "a segment whose headers go on past its head");
        let udp = Flow::udp(false).packet(1, &payload(4, 3000));
        let udp_partial = Checksum::Partial { start: 20, offset: UDP_CHECKSUM as u16 };
        let udp_segment = Gso { kind: GsoKind::Udp, segment_size: 1400, header_len: 0 };
        assert!(carries(&udp, udp_partial, None));
        assert!(!carries(&udp, udp_partial, Some(udp_segment)));
    }

    #[test]
    fn reads_the_vlan_tag() {
        let mut tagged = head(VTAG | TCP_CSUM, 0);
        tagged[4..6].copy_from_slice(&0x2007u16.to_ne_bytes());
        assert_eq!(vlan_tag(&tagged), Some(0x2007));
        assert_eq!(vlan_tag(&head(TCP_CSUM, 0)), None);
    }

    #[test]
    fn encodes_what_the_virtio_header_says() {
        let mut out = [0u8; LEN];
        let header = vnet::Header { flags: vnet::NEEDS_CSUM, gso_type: vnet::GSO_TCPV6, gso_size: 1428, csum_offset: 16, ..Default::default() };
        encode(&header, &mut out);
        assert_eq!(out, head(TCP_CSUM | MSS, 1428));
        encode(&vnet::Header { flags: vnet::NEEDS_CSUM, csum_offset: 6, ..Default::default() }, &mut out);
        assert_eq!(out, head(UDP_CSUM, 0));
        encode(&vnet::Header::default(), &mut out);
        assert_eq!(out, [0; LEN]);
    }
}
