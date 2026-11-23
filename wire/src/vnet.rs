//! The `virtio_net_hdr` that a Linux TUN device puts in front of every packet once it is opened
//! with `IFF_VNET_HDR`. Its fields are in the machine's byte order. On OpenBSD it only says what
//! a write leaves to the system, for the `tun_hdr` that carries it.

use crate::cut::segment_header_len;
use crate::packet::{Checksum, Gso, GsoKind, Transport, invalid};

pub(crate) const NEEDS_CSUM: u8 = 1;
pub(crate) const DATA_VALID: u8 = 2;
pub(crate) const GSO_NONE: u8 = 0;
pub(crate) const GSO_TCPV4: u8 = 1;
pub(crate) const GSO_TCPV6: u8 = 4;
pub(crate) const GSO_UDP_L4: u8 = 5;
pub(crate) const GSO_ECN: u8 = 0x80;

/// The size of `struct virtio_net_hdr`, the part of the header this library reads and writes.
/// A device configured with a larger header gets zeros in the rest.
pub(crate) const LEN: usize = 10;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Header {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl Header {
    pub fn read(b: &[u8]) -> Header {
        let field = |at: usize| u16::from_ne_bytes([b[at], b[at + 1]]);
        Header {
            flags: b[0],
            gso_type: b[1],
            hdr_len: field(2),
            gso_size: field(4),
            csum_start: field(6),
            csum_offset: field(8),
        }
    }

    pub fn write(&self, b: &mut [u8]) {
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
    }

    /// The header for a packet that is written unchanged.
    pub fn for_packet(checksum: Checksum, gso: Option<Gso>) -> Header {
        let mut header = Header::default();
        if let Checksum::Partial { start, offset } = checksum {
            header.flags = NEEDS_CSUM;
            header.csum_start = start;
            header.csum_offset = offset;
            header.hdr_len = start + offset + 2;
        }
        if let Some(gso) = gso {
            header.gso_type = match gso.kind {
                GsoKind::Tcp4 { ecn } => GSO_TCPV4 | if ecn { GSO_ECN } else { 0 },
                GsoKind::Tcp6 { ecn } => GSO_TCPV6 | if ecn { GSO_ECN } else { 0 },
                GsoKind::Udp => GSO_UDP_L4,
            };
            header.gso_size = gso.segment_size;
            header.hdr_len = gso.header_len;
        }
        header
    }

    /// What a frame read with this header is: its checksum state and, for a segment, how to cut
    /// it. `link` says where the IP header starts, if the frame carries IP. Frames the kernel
    /// would never produce are refused.
    pub fn describe(&self, data: &[u8], link: Option<usize>) -> Result<(Checksum, Option<Gso>), std::io::Error> {
        let checksum = if self.flags & NEEDS_CSUM != 0 {
            if usize::from(self.csum_start) + usize::from(self.csum_offset) + 2 > data.len() {
                return Err(invalid("the checksum field lies outside the frame"));
            }
            Checksum::Partial { start: self.csum_start, offset: self.csum_offset }
        } else if self.flags & DATA_VALID != 0 {
            Checksum::Valid
        } else {
            Checksum::Unverified
        };
        let ecn = self.gso_type & GSO_ECN != 0;
        let kind = match self.gso_type & !GSO_ECN {
            GSO_NONE => return Ok((checksum, None)),
            GSO_TCPV4 => GsoKind::Tcp4 { ecn },
            GSO_TCPV6 => GsoKind::Tcp6 { ecn },
            GSO_UDP_L4 if !ecn => GsoKind::Udp,
            _ => return Err(invalid("the frame has a segmentation type that was not negotiated")),
        };
        let link = link.ok_or_else(|| invalid("a segment has to carry IPv4 or IPv6"))?;
        let gso = Gso { kind, segment_size: self.gso_size, header_len: 0 };
        let header_len = segment_header_len(data, link, checksum, gso)?;
        Ok((checksum, Some(Gso { header_len, ..gso })))
    }
}

/// The header for a run of packets joined into one segment, or for one packet whose checksum is
/// handed to the kernel.
pub(crate) fn for_joined(info: &Transport, count: usize, segment_size: usize) -> Header {
    let gso_type = match (count > 1, info.tcp, info.v6) {
        (false, _, _) => GSO_NONE,
        (true, true, false) => GSO_TCPV4,
        (true, true, true) => GSO_TCPV6,
        (true, false, _) => GSO_UDP_L4,
    };
    Header {
        flags: NEEDS_CSUM,
        gso_type,
        hdr_len: info.header_len as u16,
        gso_size: if count > 1 { segment_size as u16 } else { 0 },
        csum_start: info.transport as u16,
        csum_offset: info.checksum_offset() as u16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::build::{Flow, payload};

    #[test]
    fn round_trips() {
        let header = Header { flags: 1, gso_type: 4, hdr_len: 72, gso_size: 1428, csum_start: 40, csum_offset: 16 };
        let mut bytes = [0u8; LEN];
        header.write(&mut bytes);
        assert_eq!(Header::read(&bytes), header);
    }

    #[test]
    fn describes_segments_from_the_packet() {
        let p = Flow::tcp(true).packet(1, &payload(1, 3000));
        let header = Header { flags: NEEDS_CSUM, gso_type: GSO_TCPV6, hdr_len: 9999, gso_size: 1428, csum_start: 40, csum_offset: 16 };
        let (checksum, gso) = header.describe(&p, Some(0)).unwrap();
        assert_eq!(checksum, Checksum::Partial { start: 40, offset: 16 });
        assert_eq!(gso, Some(Gso { kind: GsoKind::Tcp6 { ecn: false }, segment_size: 1428, header_len: 72 }));
        assert!(Header { gso_type: GSO_TCPV4, ..header }.describe(&p, Some(0)).is_err());
        assert!(Header { flags: 0, ..header }.describe(&p, Some(0)).is_err());
        assert!(Header { gso_type: 3, ..header }.describe(&p, Some(0)).is_err());
        assert!(header.describe(&p, None).is_err(), "a segment that is not IP");
        assert_eq!(Header { flags: DATA_VALID, gso_type: 0, ..header }.describe(&p, None).unwrap(), (Checksum::Valid, None));
    }

    #[test]
    fn describes_segments_behind_an_ethernet_header() {
        let mut frame = vec![2u8; 12];
        frame.extend_from_slice(&[0x86, 0xdd]);
        frame.extend_from_slice(&Flow::tcp(true).packet(1, &payload(1, 3000)));
        let header = Header { flags: NEEDS_CSUM, gso_type: GSO_TCPV6, hdr_len: 0, gso_size: 1428, csum_start: 54, csum_offset: 16 };
        let (_, gso) = header.describe(&frame, Some(14)).unwrap();
        assert_eq!(gso.map(|gso| gso.header_len), Some(86));
        assert!(Header { csum_start: 40, ..header }.describe(&frame, Some(14)).is_err());
    }
}
