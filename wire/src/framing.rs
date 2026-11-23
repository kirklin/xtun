//! What a device puts in front of every frame, and what that says about the frame: read off a
//! frame that came from the device, and written in front of a frame that goes to it.

use crate::packet::{Checksum, Gso, link_len};
use crate::{tunhdr, vnet};

/// The longest prefix a device may use: a virtio header of 64 bytes.
pub const MAX_PREFIX: usize = 64;

/// The size of `struct virtio_net_hdr`, the shortest virtio header and the part of a longer one
/// that is read and written.
pub const VIRTIO_HEADER: usize = vnet::LEN;

/// The numbers a system gives the two IP versions as address families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Family {
    /// `AF_INET`.
    pub inet: u32,
    /// `AF_INET6`.
    pub inet6: u32,
}

impl Family {
    fn bytes(self, v6: bool) -> [u8; 4] {
        (if v6 { self.inet6 } else { self.inet }).to_be_bytes()
    }
}

/// What lies in front of every frame of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    /// Nothing: the frame as it is.
    None,
    /// The address family as a big-endian 32-bit number: the tun devices of the BSDs and the
    /// Apple systems.
    Family(Family),
    /// A `virtio_net_hdr` of this many bytes, 10 to [`MAX_PREFIX`]: Linux, and FreeBSD's tap
    /// devices.
    Virtio(usize),
    /// OpenBSD's `tun_hdr`, followed by the address family on a tun device.
    TunHdr {
        /// The address family numbers, where the address family follows.
        family: Option<Family>,
    },
}

impl Prefix {
    /// How many bytes the prefix has.
    pub fn len(self) -> usize {
        match self {
            Prefix::None => 0,
            Prefix::Family(_) => 4,
            Prefix::Virtio(len) => len,
            Prefix::TunHdr { family } => tunhdr::LEN + if family.is_some() { 4 } else { 0 },
        }
    }

    /// Whether there is no prefix.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Writes the prefix that says what `header` says, for an IPv6 packet if `v6`, to `out`,
    /// which is zeroed and as long as the prefix.
    pub(crate) fn write(self, header: &vnet::Header, v6: bool, out: &mut [u8]) {
        match self {
            Prefix::None => {}
            Prefix::Family(family) => out.copy_from_slice(&family.bytes(v6)),
            Prefix::Virtio(_) => header.write(out),
            Prefix::TunHdr { family } => {
                tunhdr::encode(header, out);
                if let Some(family) = family {
                    out[tunhdr::LEN..].copy_from_slice(&family.bytes(v6));
                }
            }
        }
    }

    /// The prefix of a frame that leaves nothing to the device, for an IPv6 packet if `v6`: the
    /// bytes and how many of them count.
    pub fn plain(self, v6: bool) -> ([u8; MAX_PREFIX], usize) {
        let mut bytes = [0u8; MAX_PREFIX];
        let len = self.len();
        self.write(&vnet::Header::default(), v6, &mut bytes[..len]);
        (bytes, len)
    }
}

/// How the frames of a device are laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framing {
    /// What lies in front of every frame.
    pub prefix: Prefix,
    /// Whether frames start with an Ethernet header. Off, frames start with the IP header, or
    /// are not looked into at all.
    pub ethernet: bool,
}

/// A frame as it was read: where it lies in what the device handed over, and what it claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// Where the frame starts, behind the prefix.
    pub start: usize,
    /// How long the frame is.
    pub len: usize,
    /// Where the IP header starts in the frame.
    pub link: usize,
    /// How far the transport checksum is done.
    pub checksum: Checksum,
    /// Set for a segment that stands for several packets.
    pub gso: Option<Gso>,
}

impl Framing {
    /// Reads what the device handed over in `raw`: its prefix and the frame behind it. `None`
    /// for something the device never agreed to hand over. A VLAN tag that an OpenBSD device
    /// took off the frame goes back in, and fields the device left unfinished for the cut are
    /// put right in place.
    pub fn decode(&self, raw: &mut [u8]) -> Option<Decoded> {
        let head = self.prefix.len();
        if raw.len() <= head {
            return None;
        }
        match self.prefix {
            Prefix::None | Prefix::Family(_) => {
                Some(Decoded { start: head, len: raw.len() - head, link: 0, checksum: Checksum::Unverified, gso: None })
            }
            Prefix::Virtio(_) => {
                let (header, data) = raw.split_at(head);
                let link = if self.ethernet { link_len(data) } else { Some(0) };
                let (checksum, gso) = vnet::Header::read(header).describe(data, link).ok()?;
                Some(Decoded { start: head, len: data.len(), link: link.unwrap_or(0), checksum, gso })
            }
            Prefix::TunHdr { .. } => {
                let mut header = [0u8; tunhdr::LEN];
                header.copy_from_slice(&raw[..tunhdr::LEN]);
                let mut start = head;
                if self.ethernet
                    && let Some(tag) = tunhdr::vlan_tag(&header)
                {
                    if raw.len() - start < 14 {
                        return None;
                    }
                    // The tag goes back between the addresses and the type, where the system
                    // took it; the header in front, which has been read, gives the room.
                    raw.copy_within(start..start + 12, start - 4);
                    start -= 4;
                    raw[start + 12..start + 14].copy_from_slice(&0x8100u16.to_be_bytes());
                    raw[start + 14..start + 16].copy_from_slice(&tag.to_be_bytes());
                }
                let data = &mut raw[start..];
                let link = if self.ethernet { link_len(data) } else { Some(0) };
                let (checksum, gso) = tunhdr::describe(&header, data, link).ok()?;
                Some(Decoded { start, len: data.len(), link: link.unwrap_or(0), checksum, gso })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GsoKind;
    use crate::packet::build::{Flow, payload};
    use crate::packet::{Transport, adjust_partial, pseudo, read_u16, write_u16};

    const BSD: Family = Family { inet: 2, inet6: 24 };

    #[test]
    fn bare_frames_and_frames_behind_an_address_family() {
        let packet = Flow::udp(true).packet(0, &payload(1, 50));
        let mut raw = packet.clone();
        let bare = Framing { prefix: Prefix::None, ethernet: false };
        assert_eq!(bare.decode(&mut raw), Some(Decoded { start: 0, len: packet.len(), link: 0, checksum: Checksum::Unverified, gso: None }));
        assert_eq!(bare.decode(&mut []), None);
        let family = Framing { prefix: Prefix::Family(BSD), ethernet: false };
        let mut raw = [&24u32.to_be_bytes()[..], &packet].concat();
        assert_eq!(family.decode(&mut raw).map(|decoded| (decoded.start, decoded.len)), Some((4, packet.len())));
        assert_eq!(family.decode(&mut [0, 0, 0, 24]), None, "a family without a packet");
        assert_eq!(Prefix::Family(BSD).plain(true), ({
            let mut bytes = [0u8; MAX_PREFIX];
            bytes[3] = 24;
            bytes
        }, 4));
        assert_eq!(Prefix::Family(BSD).plain(false).0[..4], [0, 0, 0, 2]);
    }

    #[test]
    fn a_virtio_header_says_what_the_frame_is() {
        let mut segment = Flow::tcp(false).packet(1, &payload(1, 3000));
        let info = Transport::read(&segment, 0).unwrap();
        let partial = pseudo(&segment, false, 6, segment.len() - 20).fold();
        write_u16(&mut segment, 36, partial);
        let header = vnet::Header { flags: vnet::NEEDS_CSUM, gso_type: vnet::GSO_TCPV4, hdr_len: 0, gso_size: 1400, csum_start: 20, csum_offset: 16 };
        // A device whose header is longer than the part that is read.
        let framing = Framing { prefix: Prefix::Virtio(12), ethernet: false };
        let mut raw = vec![0u8; 12];
        header.write(&mut raw[..vnet::LEN]);
        raw.extend_from_slice(&segment);
        let decoded = framing.decode(&mut raw).unwrap();
        assert_eq!((decoded.start, decoded.len, decoded.link), (12, segment.len(), 0));
        assert_eq!(decoded.checksum, Checksum::Partial { start: 20, offset: 16 });
        assert_eq!(decoded.gso, Some(Gso { kind: GsoKind::Tcp4 { ecn: false }, segment_size: 1400, header_len: info.header_len as u16 }));
        assert_eq!(framing.decode(&mut raw[..12]), None, "a header without a frame");
        raw[1] = 3;
        assert_eq!(framing.decode(&mut raw), None, "a segmentation type that was never agreed");
    }

    #[test]
    fn a_tun_hdr_gives_back_the_vlan_tag_and_the_segment() {
        let packet = Flow::tcp(true).packet(1, &payload(2, 3000));
        let at = 40 + 16;
        // OpenBSD's field for a segment: the pseudo header with a length of zero.
        let mut segment = packet.clone();
        let length = segment.len() - 40;
        let with_length = pseudo(&segment, true, 6, length).fold();
        write_u16(&mut segment, at, adjust_partial(with_length, length, 0));
        // `TUN_H_VTAG`, `TUN_H_MSS` and `TUN_H_TCP_CSUM`, the tag and the segment size.
        let mut head = [0u8; tunhdr::LEN];
        head[..2].copy_from_slice(&(1u16 << 4 | 1 << 5 | 1 << 9).to_ne_bytes());
        head[4..6].copy_from_slice(&0x2007u16.to_ne_bytes());
        head[6..8].copy_from_slice(&1400u16.to_ne_bytes());
        let mut frame = vec![7u8; 12];
        frame.extend_from_slice(&[0x86, 0xdd]);
        frame.extend_from_slice(&segment);
        let mut raw = [&head[..], &frame].concat();
        let framing = Framing { prefix: Prefix::TunHdr { family: None }, ethernet: true };
        let decoded = framing.decode(&mut raw).unwrap();
        assert_eq!((decoded.start, decoded.len, decoded.link), (4, frame.len() + 4, 18));
        let tagged = &raw[decoded.start..];
        assert_eq!(tagged[..12], [7u8; 12]);
        assert_eq!(tagged[12..18], [0x81, 0x00, 0x20, 0x07, 0x86, 0xdd]);
        assert_eq!(read_u16(tagged, 18 + at), with_length, "the length is back in the pseudo header");
        assert_eq!(decoded.checksum, Checksum::Partial { start: 58, offset: 16 });
        assert_eq!(decoded.gso.map(|gso| (gso.segment_size, gso.header_len)), Some((1400, 18 + 72)));

        // A tun device: the address family follows the header, and there is no tag to give back.
        let mut raw = [&[0u8; 8][..], &24u32.to_be_bytes(), &packet].concat();
        let framing = Framing { prefix: Prefix::TunHdr { family: Some(BSD) }, ethernet: false };
        let decoded = framing.decode(&mut raw).unwrap();
        assert_eq!((decoded.start, decoded.len, decoded.checksum, decoded.gso), (12, packet.len(), Checksum::Unverified, None));
        let mut short = [&head[..], &[0u8; 10]].concat();
        assert_eq!(Framing { prefix: Prefix::TunHdr { family: None }, ethernet: true }.decode(&mut short), None);
    }
}
