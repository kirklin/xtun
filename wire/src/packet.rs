use std::io;

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
    /// Reads a packet whose IP header starts at `link`.
    pub fn read(p: &[u8], link: usize) -> Option<Transport> {
        let ip = p.get(link..)?;
        let (v6, ip_len, protocol) = match ip.first()? >> 4 {
            4 => {
                if ip.len() < 20 {
                    return None;
                }
                let ip_len = usize::from(ip[0] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
                let fragment = ip[6] & 0x3f != 0 || ip[7] != 0;
                if ip_len < 20 || total != ip.len() || fragment {
                    return None;
                }
                (false, ip_len, ip[9])
            }
            6 => {
                if ip.len() < 40 || 40 + usize::from(u16::from_be_bytes([ip[4], ip[5]])) != ip.len() {
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
                if usize::from(length) != p.len() - transport {
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
    pub fn verify(&self, p: &[u8]) -> bool {
        if !self.tcp && !self.v6 && p[self.transport + 6..self.transport + 8] == [0, 0] {
            return true;
        }
        self.pseudo(p, p.len() - self.transport).bytes(&p[self.transport..]).fold() == 0xffff
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
    let mut at = 12;
    loop {
        let kind = u16::from_be_bytes([*frame.get(at)?, *frame.get(at + 1)?]);
        match kind {
            0x8100 | 0x88a8 | 0x9100 => at += 4,
            0x0800 | 0x86dd if frame.len() > at + 2 => return Some(at + 2),
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

/// Finishes a partial checksum: adds the bytes from `start` on, the field included.
pub(crate) fn complete(p: &mut [u8], start: usize, offset: usize) {
    let value = Sum::ZERO.bytes(&p[start..]).checksum();
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
            let value = info.pseudo(&p, total - ip_len).bytes(&p[ip_len..]).checksum();
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
    fn adjusting_a_partial_sum_for_another_length() {
        let p = Flow::tcp(false).packet(1, &payload(3, 500));
        let info = Transport::read(&p, 0).unwrap();
        let long = info.pseudo(&p, 64_000).fold();
        assert_eq!(adjust_partial(long, 64_000, 1_460), info.pseudo(&p, 1_460).fold());
    }
}
