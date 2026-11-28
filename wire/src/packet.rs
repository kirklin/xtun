use std::io;
use std::ops::Range;

use crate::checksum::Sum;

/// How far the transport checksum of a packet is done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checksum {
    /// The checksum field at `start + offset` holds the folded sum of the pseudo header only;
    /// the sum of the bytes from `start` on still has to be added. The Linux kernel hands over
    /// packets it made itself this way, and finishes packets written this way itself.
    Partial {
        /// Where the summed range starts: the transport header.
        start: u16,
        /// Where the checksum field is, from `start`: 16 for TCP, 6 for UDP.
        offset: u16,
    },
    /// The checksums are complete and known to be right. Written to a Linux device, the kernel
    /// does not check them again.
    Valid,
    /// The checksums are complete as far as anyone knows, but nobody has checked them. They are
    /// checked before a packet is joined with others.
    Unverified,
}

/// A TCP or UDP segment larger than the MTU. It stands for packets carrying `segment_size` bytes
/// of payload each, the last one possibly fewer, every packet with a copy of the first
/// `header_len` bytes whose lengths, sequence numbers and checksums are adjusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gso {
    /// The transport protocol and IP version.
    pub kind: GsoKind,
    /// The payload of every packet but the last.
    pub segment_size: u16,
    /// The IP and transport headers that every packet repeats.
    pub header_len: u16,
}

/// What a [`Gso`] segment carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GsoKind {
    /// TCP over IPv4. With `ecn` only the first packet keeps the CWR flag.
    Tcp4 {
        /// Whether the segment carries explicit congestion notification.
        ecn: bool,
    },
    /// TCP over IPv6.
    Tcp6 {
        /// Whether the segment carries explicit congestion notification.
        ecn: bool,
    },
    /// UDP over either IP version. Every packet is a datagram of its own.
    Udp,
}

/// A packet to write: its bytes, how far its checksum is done, and whether it is a segment
/// that still has to be cut.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    /// The IP packet, starting with the IP header.
    pub data: &'a [u8],
    /// How far the transport checksum is done.
    pub checksum: Checksum,
    /// Set for a segment larger than the MTU, which needs a [`Checksum::Partial`].
    pub gso: Option<Gso>,
}

impl<'a> Packet<'a> {
    /// A packet whose checksums have not been checked.
    pub fn new(data: &'a [u8]) -> Packet<'a> {
        Packet { data, checksum: Checksum::Unverified, gso: None }
    }

    /// Says how far the checksum is done.
    pub fn with_checksum(self, checksum: Checksum) -> Packet<'a> {
        Packet { checksum, ..self }
    }

    /// Marks the packet as a segment that still has to be cut.
    pub fn with_gso(self, gso: Gso) -> Packet<'a> {
        Packet { gso: Some(gso), ..self }
    }
}

/// A packet to write whose bytes come in pieces, the way a stack keeps what it sends: the
/// headers it made for the packet and the payload where it lies. Nothing is joined before the
/// write.
#[derive(Debug)]
pub struct Pieces<'a, B = &'a [u8]> {
    /// The first bytes of the packet. Packets are joined into a segment only when their link
    /// layer, IP and transport headers lie here.
    pub head: &'a [u8],
    /// The bytes that follow the head, in order. Empty pieces are passed over.
    pub body: &'a [B],
    /// How far the transport checksum is done.
    pub checksum: Checksum,
    /// Set for a segment larger than the MTU, which needs a [`Checksum::Partial`].
    pub gso: Option<Gso>,
}

impl<'a, B> Pieces<'a, B> {
    /// A packet whose checksums have not been checked.
    pub fn new(head: &'a [u8], body: &'a [B]) -> Pieces<'a, B> {
        Pieces { head, body, checksum: Checksum::Unverified, gso: None }
    }

    /// Says how far the checksum is done.
    pub fn with_checksum(self, checksum: Checksum) -> Pieces<'a, B> {
        Pieces { checksum, ..self }
    }

    /// Marks the packet as a segment that still has to be cut.
    pub fn with_gso(self, gso: Gso) -> Pieces<'a, B> {
        Pieces { gso: Some(gso), ..self }
    }
}

impl<B> Clone for Pieces<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B> Copy for Pieces<'_, B> {}

/// A packet to write as a [`crate::Plan`] takes it: a head and the pieces that follow it.
/// [`Packet`] and [`Pieces`] are the two kinds.
pub trait Parts {
    /// The first bytes of the packet, where its headers are read.
    fn head(&self) -> &[u8];

    /// How many pieces follow the head.
    fn pieces(&self) -> usize;

    /// Piece `index` of those that follow the head.
    fn piece(&self, index: usize) -> &[u8];

    /// How far the transport checksum is done.
    fn checksum(&self) -> Checksum;

    /// Set for a segment larger than the MTU.
    fn gso(&self) -> Option<Gso>;
}

impl Parts for Packet<'_> {
    #[inline]
    fn head(&self) -> &[u8] {
        self.data
    }

    #[inline]
    fn pieces(&self) -> usize {
        0
    }

    #[inline]
    fn piece(&self, _index: usize) -> &[u8] {
        &[]
    }

    #[inline]
    fn checksum(&self) -> Checksum {
        self.checksum
    }

    #[inline]
    fn gso(&self) -> Option<Gso> {
        self.gso
    }
}

impl<B: AsRef<[u8]>> Parts for Pieces<'_, B> {
    #[inline]
    fn head(&self) -> &[u8] {
        self.head
    }

    #[inline]
    fn pieces(&self) -> usize {
        self.body.len()
    }

    #[inline]
    fn piece(&self, index: usize) -> &[u8] {
        self.body[index].as_ref()
    }

    #[inline]
    fn checksum(&self) -> Checksum {
        self.checksum
    }

    #[inline]
    fn gso(&self) -> Option<Gso> {
        self.gso
    }
}

/// How many bytes `packet` has in all.
pub(crate) fn total(packet: &impl Parts) -> usize {
    packet.head().len() + (0..packet.pieces()).map(|index| packet.piece(index).len()).sum::<usize>()
}

/// The first byte of `packet`, wherever it lies.
pub(crate) fn first_byte(packet: &impl Parts) -> Option<u8> {
    packet.head().first().copied().or_else(|| (0..packet.pieces()).find_map(|index| packet.piece(index).first().copied()))
}

/// Hands `each` the bytes of `packet` from `range.start` up to `range.end`, or to the packet's
/// end if that comes first, as the stretches they lie in, in order. No stretch is empty.
#[inline]
pub(crate) fn each_in<'a, P: Parts>(packet: &'a P, range: Range<usize>, mut each: impl FnMut(&'a [u8])) {
    let head = packet.head();
    if range.start < head.len() && range.start < range.end {
        each(&head[range.start..range.end.min(head.len())]);
    }
    let mut at = head.len();
    for index in 0..packet.pieces() {
        if at >= range.end {
            break;
        }
        let bytes = packet.piece(index);
        let (from, to) = (range.start.saturating_sub(at).min(bytes.len()), (range.end - at).min(bytes.len()));
        if from < to {
            each(&bytes[from..to]);
        }
        at += bytes.len();
    }
}

/// Adds the bytes of `packet` in `range` to `sum`.
pub(crate) fn sum_in(packet: &impl Parts, range: Range<usize>, sum: Sum) -> Sum {
    let mut sum = sum;
    each_in(packet, range, |bytes| sum = sum.bytes(bytes));
    sum
}

/// The first bytes of a packet, where its headers lie, and how long the packet is in all.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Head<'a> {
    pub bytes: &'a [u8],
    pub len: usize,
}

impl<'a> Head<'a> {
    /// A packet that lies in one stretch.
    pub fn whole(data: &'a [u8]) -> Head<'a> {
        Head { bytes: data, len: data.len() }
    }

    /// The head of `packet`.
    pub fn of(packet: &'a impl Parts) -> Head<'a> {
        Head { bytes: packet.head(), len: total(packet) }
    }
}

pub(crate) const TCP: u8 = 6;
pub(crate) const UDP: u8 = 17;
pub(crate) const TCP_CHECKSUM: usize = 16;
pub(crate) const UDP_CHECKSUM: usize = 6;
pub(crate) const FIN: u8 = 0x01;
pub(crate) const PSH: u8 = 0x08;
pub(crate) const ACK: u8 = 0x10;
pub(crate) const CWR: u8 = 0x80;

/// A TCP or UDP packet with nothing between the IP header and the transport header: no IPv4
/// fragment, no IPv6 extension header. Lengths agree with each other and with the buffer. On a
/// layer 2 device the IP header follows the link layer header.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Transport {
    pub v6: bool,
    pub tcp: bool,
    /// Where the IP header starts: the length of the link layer header.
    pub link: usize,
    /// Where the transport header starts.
    pub transport: usize,
    /// The link layer, IP and transport headers.
    pub header_len: usize,
}

impl Transport {
    /// Reads a packet that lies in one stretch.
    #[cfg(test)]
    pub fn read(p: &[u8], link: usize) -> Option<Transport> {
        Transport::read_head(Head::whole(p), link)
    }

    /// Reads a packet whose IP header starts at `link` from its head. A packet whose headers
    /// go on past its head counts as none that can be read.
    pub fn read_head(head: Head<'_>, link: usize) -> Option<Transport> {
        let p = head.bytes;
        let ip = p.get(link..)?;
        let ip_total = head.len - link;
        let (v6, ip_len, protocol) = match ip.first()? >> 4 {
            4 => {
                if ip.len() < 20 {
                    return None;
                }
                let ip_len = usize::from(ip[0] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
                let fragment = ip[6] & 0x3f != 0 || ip[7] != 0;
                if ip_len < 20 || total != ip_total || fragment {
                    return None;
                }
                (false, ip_len, ip[9])
            }
            6 => {
                if ip.len() < 40 || 40 + usize::from(u16::from_be_bytes([ip[4], ip[5]])) != ip_total {
                    return None;
                }
                (true, 40, ip[6])
            }
            _ => return None,
        };
        let transport = link + ip_len;
        let header_len = match protocol {
            TCP => {
                let offset = usize::from(*p.get(transport + 12)? >> 4) * 4;
                if offset < 20 {
                    return None;
                }
                transport + offset
            }
            UDP => {
                let length = u16::from_be_bytes([*p.get(transport + 4)?, *p.get(transport + 5)?]);
                if usize::from(length) != head.len.checked_sub(transport)? {
                    return None;
                }
                transport + 8
            }
            _ => return None,
        };
        (header_len <= p.len()).then_some(Transport { v6, tcp: protocol == TCP, link, transport, header_len })
    }

    pub fn protocol(&self) -> u8 {
        if self.tcp { TCP } else { UDP }
    }

    pub fn checksum_offset(&self) -> usize {
        if self.tcp { TCP_CHECKSUM } else { UDP_CHECKSUM }
    }

    /// The pseudo header for `length` bytes from the transport header on.
    pub fn pseudo(&self, p: &[u8], length: usize) -> Sum {
        pseudo(&p[self.link..], self.v6, self.protocol(), length)
    }

    /// Whether the transport checksum of a complete packet is right. An IPv4 UDP packet without
    /// a checksum counts as right.
    #[cfg(test)]
    pub fn verify(&self, p: &[u8]) -> bool {
        self.verify_parts(&Packet::new(p), p.len())
    }

    /// Whether the packet whose head is `head` has a transport checksum: an IPv4 UDP datagram
    /// may go without one.
    pub fn summed(&self, head: &[u8]) -> bool {
        self.tcp || self.v6 || head[self.transport + 6..self.transport + 8] != [0, 0]
    }

    /// Whether the IPv4 header checksum of the packet whose head is `head` is right; an IPv6
    /// header has none.
    pub fn verify_ip_header(&self, head: &[u8]) -> bool {
        self.v6 || Sum::ZERO.bytes(&head[self.link..self.transport]).fold() == 0xffff
    }

    /// Whether the transport checksum of a complete packet of `total` bytes is right. An IPv4
    /// UDP packet without a checksum counts as right.
    pub fn verify_parts(&self, packet: &impl Parts, total: usize) -> bool {
        let head = packet.head();
        if !self.tcp && !self.v6 && head[self.transport + 6..self.transport + 8] == [0, 0] {
            return true;
        }
        sum_in(packet, self.transport..total, self.pseudo(head, total - self.transport)).fold() == 0xffff
    }
}

/// Where the transport header of the IP packet at `link` starts, past any IPv6 extension
/// headers, and its protocol, for an IPv6 packet if the first says so. A fragment that is not
/// the whole packet is refused: its transport checksum covers bytes that lie in other fragments.
pub(crate) fn transport_of(data: &[u8], link: usize) -> io::Result<(bool, usize, u8)> {
    let ip = data.get(link..).ok_or_else(|| invalid("the packet ends before its IP header"))?;
    match ip.first().map(|byte| byte >> 4) {
        Some(4) if ip.len() >= 20 => {
            let header = usize::from(ip[0] & 0x0f) * 4;
            if header < 20 {
                return Err(invalid("the IPv4 header length is out of range"));
            }
            if ip[6] & 0x3f != 0 || ip[7] != 0 {
                return Err(invalid("the packet is a fragment"));
            }
            Ok((false, link + header, ip[9]))
        }
        Some(6) if ip.len() >= 40 => {
            let (mut at, mut next) = (link + 40, ip[6]);
            // Hop-by-hop options, routing, fragment and destination options headers.
            while matches!(next, 0 | 43 | 44 | 60) {
                let header = data.get(at..at + 8).ok_or_else(|| invalid("an IPv6 extension header is cut off"))?;
                let length = if next == 44 {
                    // The offset of the fragment and the flag that more follow.
                    if u16::from_be_bytes([header[2], header[3]]) & 0xfff9 != 0 {
                        return Err(invalid("the packet is a fragment"));
                    }
                    8
                } else {
                    (usize::from(header[1]) + 1) * 8
                };
                next = header[0];
                at += length;
            }
            Ok((true, at, next))
        }
        _ => Err(invalid("the packet is neither IPv4 nor IPv6")),
    }
}

/// The pseudo header of the IP header that starts `ip`.
pub(crate) fn pseudo(ip: &[u8], v6: bool, protocol: u8, length: usize) -> Sum {
    if v6 {
        crate::checksum::pseudo_v6(&ip[8..24], &ip[24..40], protocol, length as u32)
    } else {
        crate::checksum::pseudo_v4(&ip[12..16], &ip[16..20], protocol, length as u16)
    }
}

/// Where the IP header starts in an Ethernet frame: after the addresses, any VLAN tags and the
/// type. `None` for a frame that does not carry IPv4 or IPv6.
pub(crate) fn link_len(frame: &[u8]) -> Option<usize> {
    link_len_head(Head::whole(frame))
}

/// [`link_len`] for a frame whose link layer header lies in its head.
pub(crate) fn link_len_head(head: Head<'_>) -> Option<usize> {
    let frame = head.bytes;
    let mut at = 12;
    loop {
        let kind = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
        match kind {
            0x8100 | 0x88a8 | 0x9100 => at += 4,
            0x0800 | 0x86dd if head.len > at + 2 => return Some(at + 2),
            _ => return None,
        }
    }
}

/// Recomputes an IPv4 header checksum in place.
pub(crate) fn ipv4_header_checksum(header: &mut [u8]) {
    header[10..12].fill(0);
    let value = Sum::ZERO.bytes(header).checksum();
    header[10..12].copy_from_slice(&value.to_be_bytes());
}

/// Turns the folded pseudo header sum for `old` transport bytes into the one for `new`.
pub(crate) fn adjust_partial(field: u16, old: usize, new: usize) -> u16 {
    Sum::ZERO.word(field).word(!(old as u16)).word(new as u16).fold()
}

/// The value of the checksum field at `offset` in a transport header, whose summed range comes
/// to `sum`: only UDP's field is at 6 among the protocols whose checksums are completed.
pub(crate) fn field_value(sum: Sum, offset: usize) -> u16 {
    if offset == UDP_CHECKSUM { sum.udp_checksum() } else { sum.checksum() }
}

/// Finishes a partial checksum: adds the bytes from `start` on, the field included.
pub(crate) fn complete(p: &mut [u8], start: usize, offset: usize) {
    let value = field_value(Sum::ZERO.bytes(&p[start..]), offset);
    p[start + offset..start + offset + 2].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn read_u16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

pub(crate) fn write_u16(p: &mut [u8], at: usize, value: u16) {
    p[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

pub(crate) fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.to_owned())
}

#[cfg(test)]
pub(crate) mod build {
    //! Packets for tests, with every length and checksum right.

    use super::*;

    pub struct Flow {
        pub v6: bool,
        pub tcp: bool,
        pub src: [u8; 16],
        pub dst: [u8; 16],
        pub src_port: u16,
        pub dst_port: u16,
        pub ttl: u8,
        pub tos: u8,
        pub ack: u32,
        pub flags: u8,
        pub options: Vec<u8>,
        pub id: u16,
        pub flow_label: u32,
    }

    impl Flow {
        pub fn tcp(v6: bool) -> Flow {
            Flow {
                v6,
                tcp: true,
                src: core::array::from_fn(|i| 0x20 + i as u8),
                dst: core::array::from_fn(|i| 0x40 + i as u8),
                src_port: 40_000,
                dst_port: 443,
                ttl: 64,
                tos: 0,
                ack: 0x0101_0101,
                flags: ACK,
                options: vec![1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2],
                id: 0x1234,
                flow_label: 0x12345,
            }
        }

        pub fn udp(v6: bool) -> Flow {
            Flow { tcp: false, options: Vec::new(), flags: 0, ..Flow::tcp(v6) }
        }

        /// One packet with `payload`, sequence number `seq` for TCP.
        pub fn packet(&self, seq: u32, payload: &[u8]) -> Vec<u8> {
            let transport = if self.tcp { 20 + self.options.len() } else { 8 };
            let ip_len = if self.v6 { 40 } else { 20 };
            let total = ip_len + transport + payload.len();
            let mut p = vec![0u8; total];
            if self.v6 {
                let first = (6u32 << 28) | (u32::from(self.tos) << 20) | self.flow_label;
                p[0..4].copy_from_slice(&first.to_be_bytes());
                write_u16(&mut p, 4, (total - 40) as u16);
                p[6] = if self.tcp { TCP } else { UDP };
                p[7] = self.ttl;
                p[8..24].copy_from_slice(&self.src);
                p[24..40].copy_from_slice(&self.dst);
            } else {
                p[0] = 0x45;
                p[1] = self.tos;
                write_u16(&mut p, 2, total as u16);
                write_u16(&mut p, 4, self.id);
                p[6] = 0x40;
                p[8] = self.ttl;
                p[9] = if self.tcp { TCP } else { UDP };
                p[12..16].copy_from_slice(&self.src[..4]);
                p[16..20].copy_from_slice(&self.dst[..4]);
                ipv4_header_checksum(&mut p[..20]);
            }
            let t = ip_len;
            write_u16(&mut p, t, self.src_port);
            write_u16(&mut p, t + 2, self.dst_port);
            if self.tcp {
                p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
                p[t + 8..t + 12].copy_from_slice(&self.ack.to_be_bytes());
                p[t + 12] = ((transport / 4) as u8) << 4;
                p[t + 13] = self.flags;
                write_u16(&mut p, t + 14, 65_000);
                p[t + 20..t + transport].copy_from_slice(&self.options);
            } else {
                write_u16(&mut p, t + 4, (transport + payload.len()) as u16);
            }
            p[ip_len + transport..].copy_from_slice(payload);
            let info = Transport::read(&p, 0).expect("a well formed packet");
            let offset = info.checksum_offset();
            let value = field_value(info.pseudo(&p, total - ip_len).bytes(&p[ip_len..]), offset);
            write_u16(&mut p, ip_len + offset, value);
            p
        }
    }

    /// Bytes that differ from packet to packet and from offset to offset.
    pub fn payload(seed: u32, len: usize) -> Vec<u8> {
        (0..len as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 11) as u8).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::build::{Flow, payload};
    use super::*;

    #[test]
    fn reads_transport_headers() {
        for v6 in [false, true] {
            let tcp = Flow::tcp(v6).packet(7, &payload(1, 100));
            let info = Transport::read(&tcp, 0).unwrap();
            assert_eq!((info.v6, info.tcp, info.transport, info.header_len), (v6, true, if v6 { 40 } else { 20 }, info.transport + 32));
            assert!(info.verify(&tcp));
            let udp = Flow::udp(v6).packet(0, &payload(2, 33));
            let info = Transport::read(&udp, 0).unwrap();
            assert_eq!((info.tcp, info.header_len), (false, info.transport + 8));
            assert!(info.verify(&udp));
        }
    }

    #[test]
    fn reads_behind_an_ethernet_header() {
        for (tags, kind) in [(&[][..], [0x08, 0x00]), (&[0x81, 0x00, 0x00, 0x05][..], [0x86, 0xdd])] {
            let v6 = kind == [0x86, 0xdd];
            let packet = Flow::tcp(v6).packet(7, &payload(1, 100));
            let mut frame = vec![2u8; 12];
            frame.extend_from_slice(tags);
            frame.extend_from_slice(&kind);
            let link = frame.len();
            frame.extend_from_slice(&packet);
            assert_eq!(link_len(&frame), Some(link));
            let info = Transport::read(&frame, link).unwrap();
            assert_eq!((info.link, info.transport, info.header_len - info.transport), (link, link + if v6 { 40 } else { 20 }, 32));
            assert!(info.verify(&frame));
        }
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(link_len(&arp), None);
        assert_eq!(link_len(&[0u8; 13]), None);
    }

    #[test]
    fn rejects_what_cannot_be_joined() {
        let mut fragment = Flow::tcp(false).packet(1, &payload(1, 64));
        fragment[6] |= 0x20;
        assert!(Transport::read(&fragment, 0).is_none());
        let mut short = Flow::tcp(false).packet(1, &payload(1, 64));
        short.pop();
        assert!(Transport::read(&short, 0).is_none());
        let mut extension = Flow::tcp(true).packet(1, &payload(1, 64));
        extension[6] = 0;
        assert!(Transport::read(&extension, 0).is_none());
        let mut corrupt = Flow::udp(true).packet(1, &payload(1, 64));
        corrupt[60] ^= 1;
        assert!(!Transport::read(&corrupt, 0).unwrap().verify(&corrupt));
        let mut unsummed = Flow::udp(false).packet(1, &payload(1, 64));
        unsummed[26..28].fill(0);
        assert!(Transport::read(&unsummed, 0).unwrap().verify(&unsummed));
    }

    #[test]
    fn an_ipv4_header_whose_sum_is_all_ones_gets_a_zero_checksum() {
        let mut header = [0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        let id = !Sum::ZERO.bytes(&header).fold();
        header[4..6].copy_from_slice(&id.to_be_bytes());
        ipv4_header_checksum(&mut header);
        assert_eq!(header[10..12], [0, 0], "a header is never all zeros, so its checksum is never 0xffff");
        assert_eq!(Sum::ZERO.bytes(&header).fold(), 0xffff);
    }

    #[test]
    fn adjusting_a_partial_sum_for_another_length() {
        let p = Flow::tcp(false).packet(1, &payload(3, 500));
        let info = Transport::read(&p, 0).unwrap();
        let long = info.pseudo(&p, 64_000).fold();
        assert_eq!(adjust_partial(long, 64_000, 1_460), info.pseudo(&p, 1_460).fold());
    }
}
