//! Cutting a segment of up to 64 KiB into the packets it stands for.
//!
//! A frame read from a device is cut where it lies. Packet `i` of a segment needs the headers
//! right in front of its payload, and those bytes are the end of packet `i - 1`, which has been
//! handed out already: the headers are copied there from a saved template, adjusted, and the
//! packet is handed out as a slice of the original buffer. No payload byte moves.

use std::io::{self, IoSliceMut};
use std::ops::Range;

use crate::checksum::Sum;
use crate::packet::{
    CWR, Checksum, FIN, Gso, GsoKind, Head, PSH, Packet, Parts, TCP_CHECKSUM, UDP_CHECKSUM, adjust_partial, complete, each_in,
    invalid, ipv4_header_checksum, link_len, read_u16, sum_in, write_u16,
};

/// The longest headers a segment can repeat: IPv6 with extension headers and TCP options.
pub(crate) const MAX_HEADER: usize = 256;

/// Checks that a segment whose IP header starts at `link` can be cut as `gso` says, and returns
/// the length of the headers every packet repeats. The length is taken from the packet: the
/// kernel's `hdr_len` is only a hint.
pub(crate) fn segment_header_len(data: &[u8], link: usize, checksum: Checksum, gso: Gso) -> io::Result<u16> {
    segment_header_len_head(Head::whole(data), link, checksum, gso)
}

/// [`segment_header_len`] for a segment of which `head` holds the first bytes, the first
/// [`MAX_HEADER`] at least unless the segment is shorter.
pub(crate) fn segment_header_len_head(head: Head<'_>, link: usize, checksum: Checksum, gso: Gso) -> io::Result<u16> {
    let Checksum::Partial { start, offset } = checksum else {
        return Err(invalid("a segment to cut needs a partial checksum"));
    };
    let data = head.bytes;
    let start = usize::from(start);
    let version = data.get(link).map(|byte| byte >> 4);
    let (tcp, v6) = match gso.kind {
        GsoKind::Tcp4 { .. } => (true, false),
        GsoKind::Tcp6 { .. } => (true, true),
        GsoKind::Udp => (false, version == Some(6)),
    };
    if version != Some(if v6 { 6 } else { 4 }) {
        return Err(invalid("the segment's IP version does not match its type"));
    }
    let ip = &data[link..];
    if v6 {
        if start < link + 40 || ip.len() < 40 || 40 + usize::from(u16::from_be_bytes([ip[4], ip[5]])) != head.len - link {
            return Err(invalid("the IPv6 segment's lengths do not add up"));
        }
    } else if ip.len() < 20 || start < link + 20 || link + usize::from(ip[0] & 0x0f) * 4 != start {
        return Err(invalid("the IPv4 segment's header length does not match"));
    }
    let transport = if tcp {
        if usize::from(offset) != TCP_CHECKSUM || data.len() < start + 20 {
            return Err(invalid("the TCP segment is shorter than its header"));
        }
        let length = usize::from(data[start + 12] >> 4) * 4;
        if length < 20 {
            return Err(invalid("the TCP header length is out of range"));
        }
        length
    } else {
        if usize::from(offset) != UDP_CHECKSUM {
            return Err(invalid("the UDP checksum offset is wrong"));
        }
        8
    };
    let header_len = start + transport;
    if gso.segment_size == 0 || header_len >= head.len || header_len > MAX_HEADER {
        return Err(invalid("the segment has no payload, a zero segment size or headers that are too long"));
    }
    Ok(header_len as u16)
}

/// How to cut one segment. Built only from a segment whose layout has been checked.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cut {
    pub header_len: usize,
    /// Where the IP header starts.
    pub link: usize,
    /// Where the transport header starts.
    pub transport: usize,
    /// Where the transport checksum field is.
    pub checksum_at: usize,
    pub v6: bool,
    pub tcp: bool,
    pub size: usize,
    pub len: usize,
    pub count: usize,
    first_seq: u32,
    first_id: u16,
    /// The folded pseudo header sum for the whole segment.
    partial: u16,
}

impl Cut {
    /// `gso.header_len` must have come from [`segment_header_len`] with the same `link`.
    pub fn new(data: &[u8], link: usize, checksum: Checksum, gso: Gso) -> Cut {
        Cut::of(Head::whole(data), link, checksum, gso)
    }

    /// [`Cut::new`] for a segment that may come in pieces; `gso.header_len` must have come from
    /// [`segment_header_len_head`] with the same head and `link`.
    pub fn of(head: Head<'_>, link: usize, checksum: Checksum, gso: Gso) -> Cut {
        let data = head.bytes;
        let Checksum::Partial { start, offset } = checksum else {
            unreachable!("a checked segment has a partial checksum")
        };
        let (transport, header_len, size) = (usize::from(start), usize::from(gso.header_len), usize::from(gso.segment_size));
        let checksum_at = transport + usize::from(offset);
        let tcp = !matches!(gso.kind, GsoKind::Udp);
        Cut {
            header_len,
            link,
            transport,
            checksum_at,
            v6: data[link] >> 4 == 6,
            tcp,
            size,
            len: head.len,
            count: (head.len - header_len).div_ceil(size),
            first_seq: if tcp { u32::from_be_bytes(data[transport + 4..transport + 8].try_into().expect("four bytes")) } else { 0 },
            first_id: read_u16(data, link + 4),
            partial: read_u16(data, checksum_at),
        }
    }

    pub fn payload(&self, index: usize) -> Range<usize> {
        let start = self.header_len + index * self.size;
        start..(start + self.size).min(self.len)
    }

    /// Adjusts `header`, a copy of the segment's headers, for packet `index` with `payload`
    /// bytes. The checksum field gets the partial sum for that packet.
    pub fn patch(&self, header: &mut [u8], index: usize, payload: usize) {
        self.adjust(header, index, payload, index + 1 == self.count);
    }

    /// Adjusts `header`, a copy of the segment's headers, to lead the packets from `index` on
    /// as a segment of their own.
    pub fn patch_rest(&self, header: &mut [u8], index: usize) {
        self.adjust(header, index, self.len - self.payload(index).start, true);
    }

    /// Writes the lengths, the identification or sequence number and the partial checksum of
    /// headers that lead `payload` bytes from packet `index` on. FIN and PSH stay only on
    /// headers that lead the last packet.
    fn adjust(&self, header: &mut [u8], index: usize, payload: usize, last: bool) {
        let transport_len = self.header_len - self.transport + payload;
        let ip = self.link;
        if self.v6 {
            write_u16(header, ip + 4, (self.header_len - ip - 40 + payload) as u16);
        } else {
            write_u16(header, ip + 2, (self.header_len - ip + payload) as u16);
            write_u16(header, ip + 4, self.first_id.wrapping_add(index as u16));
            ipv4_header_checksum(&mut header[ip..self.transport]);
        }
        let t = self.transport;
        if self.tcp {
            let seq = self.first_seq.wrapping_add((index * self.size) as u32);
            header[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
            if index > 0 {
                header[t + 13] &= !CWR;
            }
            if !last {
                header[t + 13] &= !(FIN | PSH);
            }
        } else {
            write_u16(header, t + 4, transport_len as u16);
        }
        write_u16(header, self.checksum_at, adjust_partial(self.partial, self.len - self.transport, transport_len));
    }

    /// The checksum state of every packet cut from the segment.
    pub fn checksum(&self) -> Checksum {
        Checksum::Partial { start: self.transport as u16, offset: (self.checksum_at - self.transport) as u16 }
    }

    /// Appends the headers of packet `index` of the segment `whole` to `out`, with a complete
    /// checksum, and returns the range of its payload in the segment.
    pub fn copy_header(&self, index: usize, whole: &impl Parts, out: &mut Vec<u8>) -> Range<usize> {
        let payload = self.payload(index);
        let at = out.len();
        each_in(whole, 0..self.header_len, |bytes| out.extend_from_slice(bytes));
        let header = &mut out[at..];
        self.patch(header, index, payload.len());
        let value = sum_in(whole, payload.clone(), Sum::ZERO.bytes(&header[self.transport..])).checksum();
        write_u16(header, self.checksum_at, value);
        payload
    }
}

/// Copies the bytes of `packet`, which has a partial checksum and `total` bytes, into `out` up
/// to the checksum field, completes the checksum there, and returns the range of the rest of the
/// packet.
pub(crate) fn complete_into(packet: &impl Parts, total: usize, start: usize, offset: usize, out: &mut Vec<u8>) -> Range<usize> {
    let split = start + offset + 2;
    let at = out.len();
    each_in(packet, 0..split, |bytes| out.extend_from_slice(bytes));
    let header = &mut out[at..];
    let value = sum_in(packet, split..total, Sum::ZERO.bytes(&header[start..])).checksum();
    write_u16(header, start + offset, value);
    split..total
}

/// What is left of a frame after [`take_first`] took its first packet: the bytes from `skip` on,
/// a frame of their own that is still a segment if `gso` says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rest {
    /// Where the frame left over starts in the frame that was given.
    pub skip: usize,
    /// Set while the frame left over stands for several packets.
    pub gso: Option<Gso>,
}

/// Copies the first packet of `frame` into `out`, cut from its segment and with a complete
/// checksum, and returns its length and what is left of the frame, which stays in place as a
/// frame of its own with the same checksum state. Nothing changes when the packet does not fit.
/// `link`, `checksum` and `gso` must describe the frame as a checked [`Frame`] would.
pub fn take_first(
    frame: &mut [u8],
    link: usize,
    checksum: Checksum,
    gso: Option<Gso>,
    out: &mut [IoSliceMut<'_>],
) -> io::Result<(usize, Option<Rest>)> {
    let Some(gso) = gso else {
        let length = frame.len();
        if length > capacity(out) {
            return Err(too_small(length));
        }
        if let Checksum::Partial { start, offset } = checksum {
            complete(frame, usize::from(start), usize::from(offset));
        }
        scatter(frame, out);
        return Ok((length, None));
    };
    let cut = Cut::new(frame, link, checksum, gso);
    let first = cut.payload(0);
    let length = first.end;
    if length > capacity(out) {
        return Err(too_small(length));
    }
    let mut template = [0u8; MAX_HEADER];
    template[..cut.header_len].copy_from_slice(&frame[..cut.header_len]);
    cut.patch(&mut frame[..cut.header_len], 0, first.len());
    complete(&mut frame[..length], cut.transport, cut.checksum_at - cut.transport);
    scatter(&frame[..length], out);
    if cut.count == 1 {
        return Ok((length, None));
    }
    let skip = first.end - cut.header_len;
    let header = &mut frame[skip..first.end];
    header.copy_from_slice(&template[..cut.header_len]);
    if cut.count == 2 {
        cut.patch(header, 1, cut.len - first.end);
        return Ok((length, Some(Rest { skip, gso: None })));
    }
    cut.patch_rest(header, 1);
    Ok((length, Some(Rest { skip, gso: Some(gso) })))
}

/// Copies `data` into `out`, the buffers in order.
fn scatter(data: &[u8], out: &mut [IoSliceMut<'_>]) {
    let mut rest = data;
    for buffer in out {
        if rest.is_empty() {
            break;
        }
        let take = rest.len().min(buffer.len());
        buffer[..take].copy_from_slice(&rest[..take]);
        rest = &rest[take..];
    }
}

/// How many bytes `out` holds.
fn capacity(out: &[IoSliceMut<'_>]) -> usize {
    out.iter().map(|buffer| buffer.len()).sum()
}

fn too_small(length: usize) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("a packet of {length} bytes does not fit the buffer"))
}

/// One unit read from a device: an IP packet or, on a layer 2 device, an Ethernet frame; where
/// the device hands them over, also a TCP or UDP segment of up to 64 KiB that still has to be
/// cut to the MTU. The packets cut from a segment are frames too.
#[derive(Debug)]
pub struct Frame<'a> {
    data: &'a mut [u8],
    /// Where the IP header starts: 0 for an IP packet, after the Ethernet header for a frame.
    link: usize,
    checksum: Checksum,
    gso: Option<Gso>,
}

impl<'a> Frame<'a> {
    /// An IP packet from anywhere, to cut or complete it the same way. A segment needs a
    /// [`Checksum::Partial`] and a layout that matches `gso`; its header length is taken from the
    /// packet.
    pub fn new(data: &'a mut [u8], checksum: Checksum, gso: Option<Gso>) -> io::Result<Frame<'a>> {
        Frame::checked(data, 0, checksum, gso)
    }

    /// An Ethernet frame from anywhere, as [`Frame::new`] takes an IP packet. A segment has to
    /// carry IPv4 or IPv6, behind VLAN tags or not.
    pub fn new_ethernet(data: &'a mut [u8], checksum: Checksum, gso: Option<Gso>) -> io::Result<Frame<'a>> {
        let link = match (link_len(data), gso) {
            (Some(link), _) => link,
            (None, None) => 0,
            (None, Some(_)) => return Err(invalid("a segment has to carry IPv4 or IPv6")),
        };
        Frame::checked(data, link, checksum, gso)
    }

    fn checked(data: &'a mut [u8], link: usize, checksum: Checksum, gso: Option<Gso>) -> io::Result<Frame<'a>> {
        let gso = match gso {
            Some(gso) => Some(Gso { header_len: segment_header_len(data, link, checksum, gso)?, ..gso }),
            None => None,
        };
        if gso.is_none()
            && let Checksum::Partial { start, offset } = checksum
            && usize::from(start) + usize::from(offset) + 2 > data.len()
        {
            return Err(invalid("the checksum field lies outside the frame"));
        }
        Ok(Frame { data, link, checksum, gso })
    }

    /// A frame whose layout was checked when it was read: `link`, `checksum` and `gso` as
    /// [`crate::Framing::decode`] gave them for these bytes. With anything else, cutting the
    /// frame panics.
    pub fn trusted(data: &'a mut [u8], link: usize, checksum: Checksum, gso: Option<Gso>) -> Frame<'a> {
        Frame { data, link, checksum, gso }
    }

    /// The bytes: the IP packet, or the Ethernet frame on a layer 2 device.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// The bytes, for rewriting headers in place. Keep the lengths as they are.
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data
    }

    /// How far the transport checksum is done.
    pub fn checksum(&self) -> Checksum {
        self.checksum
    }

    /// Set when the frame is a segment that stands for several packets.
    pub fn gso(&self) -> Option<Gso> {
        self.gso
    }

    /// The frame as a packet to write: passing it on unchanged, or after its headers were
    /// rewritten in place, keeps a segment whole.
    pub fn packet(&self) -> Packet<'_> {
        Packet { data: self.data, checksum: self.checksum, gso: self.gso }
    }

    /// Completes a partial checksum. For a segment, complete the checksums of the packets that
    /// [`Frame::segments`] cuts instead.
    pub fn complete_checksum(&mut self) {
        if self.gso.is_none()
            && let Checksum::Partial { start, offset } = self.checksum
        {
            complete(self.data, usize::from(start), usize::from(offset));
            self.checksum = Checksum::Valid;
        }
    }

    /// The packets the frame stands for: the frame itself, or the packets cut from a segment.
    /// Cutting happens in the frame's buffer, so each packet has to be done with before the next
    /// one is taken.
    pub fn segments(&mut self) -> Segments<'_> {
        let cut = self.gso.map(|gso| {
            let cut = Cut::new(self.data, self.link, self.checksum, gso);
            let mut template = [0u8; MAX_HEADER];
            template[..cut.header_len].copy_from_slice(&self.data[..cut.header_len]);
            (cut, template)
        });
        Segments { data: self.data, link: self.link, checksum: self.checksum, cut, next: 0 }
    }
}

/// The packets of a [`Frame`], taken one after the other with [`Segments::next`].
pub struct Segments<'a> {
    data: &'a mut [u8],
    link: usize,
    checksum: Checksum,
    cut: Option<(Cut, [u8; MAX_HEADER])>,
    next: usize,
}

impl Segments<'_> {
    /// How many packets there are in all.
    pub fn count(&self) -> usize {
        self.cut.as_ref().map_or(1, |(cut, _)| cut.count)
    }

    /// The next packet, a frame that is no segment. It is valid until the next call: cutting the
    /// packet after it writes over its end.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Frame<'_>> {
        let Segments { data, link, checksum, cut, next } = self;
        let Some((cut, template)) = cut else {
            if *next > 0 {
                return None;
            }
            *next = 1;
            return Some(Frame { data, link: *link, checksum: *checksum, gso: None });
        };
        if *next >= cut.count {
            return None;
        }
        let index = *next;
        *next += 1;
        let payload = cut.payload(index);
        let start = payload.start - cut.header_len;
        let header = &mut data[start..payload.start];
        if index > 0 {
            header.copy_from_slice(&template[..cut.header_len]);
        }
        cut.patch(header, index, payload.len());
        Some(Frame { data: &mut data[start..payload.end], link: *link, checksum: cut.checksum(), gso: None })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::packet::build::{Flow, payload};
    use crate::packet::{ACK, Transport, pseudo};

    /// Builds a segment the way the kernel hands it over: headers for the whole payload, a
    /// partial checksum, and the packets it stands for, made one by one.
    pub(crate) fn segment(flow: &Flow, size: usize, payload: &[u8]) -> (Vec<u8>, Checksum, Gso, Vec<Vec<u8>>) {
        let mut whole = flow.packet(1000, payload);
        let info = Transport::read(&whole, 0).unwrap();
        let partial = pseudo(&whole, info.v6, info.protocol(), whole.len() - info.transport).fold();
        write_u16(&mut whole, info.transport + info.checksum_offset(), partial);
        let checksum = Checksum::Partial { start: info.transport as u16, offset: info.checksum_offset() as u16 };
        let kind = match (flow.tcp, flow.v6) {
            (true, false) => GsoKind::Tcp4 { ecn: false },
            (true, true) => GsoKind::Tcp6 { ecn: false },
            (false, _) => GsoKind::Udp,
        };
        let gso = Gso { kind, segment_size: size as u16, header_len: 0 };
        let header_len = segment_header_len(&whole, 0, checksum, gso).unwrap();
        let chunks: Vec<&[u8]> = payload.chunks(size).collect();
        let mut expected = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let mut each = Flow { id: flow.id.wrapping_add(index as u16), options: flow.options.clone(), ..*flow };
            if flow.tcp {
                if index > 0 {
                    each.flags &= !CWR;
                }
                if index + 1 < chunks.len() {
                    each.flags &= !(FIN | PSH);
                }
            }
            expected.push(each.packet(1000u32.wrapping_add((index * size) as u32), chunk));
        }
        (whole, checksum, Gso { header_len, ..gso }, expected)
    }

    fn cut_in_place(mut whole: Vec<u8>, checksum: Checksum, gso: Gso) -> Vec<Vec<u8>> {
        let mut frame = Frame::new(&mut whole, checksum, Some(gso)).unwrap();
        let mut segments = frame.segments();
        let mut out = Vec::new();
        while let Some(mut packet) = segments.next() {
            assert!(packet.gso().is_none());
            packet.complete_checksum();
            assert_eq!(packet.checksum(), Checksum::Valid);
            out.push(packet.data().to_vec());
        }
        out
    }

    /// Takes every packet off the front of `whole` one at a time, cutting the frame left over
    /// after the first packet with `segments` instead, to check that it is a frame of its own.
    fn take_one_by_one(mut whole: Vec<u8>, checksum: Checksum, gso: Gso, rest_by_segments: bool) -> Vec<Vec<u8>> {
        let mut left = Some(Rest { skip: 0, gso: Some(gso) });
        let mut at = 0;
        let mut out = Vec::new();
        while let Some(rest) = left {
            at += rest.skip;
            let frame = &mut whole[at..];
            let mut packet = vec![0u8; 2000];
            let mut too_small = [0u8; 10];
            let error = take_first(frame, 0, checksum, rest.gso, &mut [IoSliceMut::new(&mut too_small)]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "a packet that does not fit stays");
            let (head, tail) = packet.split_at_mut(100);
            let (length, next) = take_first(frame, 0, checksum, rest.gso, &mut [IoSliceMut::new(head), IoSliceMut::new(tail)]).unwrap();
            packet.truncate(length);
            out.push(packet);
            left = next;
            if rest_by_segments && let Some(rest) = left {
                let mut frame = Frame::trusted(&mut whole[at + rest.skip..], 0, checksum, rest.gso);
                let mut segments = frame.segments();
                while let Some(mut packet) = segments.next() {
                    packet.complete_checksum();
                    out.push(packet.data().to_vec());
                }
                break;
            }
        }
        out
    }

    #[test]
    fn packets_taken_one_at_a_time_are_the_packets_cut_in_place() {
        for v6 in [false, true] {
            for tcp in [true, false] {
                let mut flow = if tcp { Flow::tcp(v6) } else { Flow::udp(v6) };
                if tcp {
                    flow.flags = ACK | PSH | FIN | CWR;
                }
                for (size, length) in [(1400, 5000), (1400, 2000), (1400, 1400), (700, 4300)] {
                    let data = payload(11, length);
                    let (whole, checksum, gso, expected) = segment(&flow, size, &data);
                    let context = format!("v6 {v6} tcp {tcp} size {size} length {length}");
                    assert_eq!(take_one_by_one(whole.clone(), checksum, gso, false), expected, "{context}");
                    assert_eq!(take_one_by_one(whole, checksum, gso, true), expected, "{context}, rest cut in place");
                }
            }
        }
        let plain = Flow::udp(false).packet(3, &payload(1, 300));
        let mut buffer = plain.clone();
        let mut out = vec![0u8; 400];
        let taken = take_first(&mut buffer, 0, Checksum::Unverified, None, &mut [IoSliceMut::new(&mut out)]).unwrap();
        assert_eq!(taken, (plain.len(), None));
        assert_eq!(&out[..plain.len()], &plain[..]);
    }

    #[test]
    fn cuts_tcp_and_udp_like_the_kernel() {
        for v6 in [false, true] {
            for tcp in [true, false] {
                let mut flow = if tcp { Flow::tcp(v6) } else { Flow::udp(v6) };
                if tcp {
                    flow.flags = ACK | PSH | FIN | CWR;
                }
                let data = payload(7, 5000);
                let (whole, checksum, gso, expected) = segment(&flow, 1400, &data);
                assert_eq!(cut_in_place(whole.clone(), checksum, gso), expected, "v6 {v6} tcp {tcp}");
                let cut = Cut::new(&whole, 0, checksum, gso);
                let mut headers = Vec::new();
                let copied: Vec<Vec<u8>> = (0..cut.count)
                    .map(|index| {
                        let at = headers.len();
                        let body = cut.copy_header(index, &Packet::new(&whole), &mut headers);
                        [&headers[at..], &whole[body]].concat()
                    })
                    .collect();
                assert_eq!(copied, expected);
            }
        }
    }

    #[test]
    fn partial_checksums_of_the_cut_packets_complete_to_the_right_values() {
        let (whole, checksum, gso, expected) = segment(&Flow::tcp(false), 1000, &payload(3, 2500));
        let mut whole = whole;
        let mut frame = Frame::new(&mut whole, checksum, Some(gso)).unwrap();
        let mut segments = frame.segments();
        assert_eq!(segments.count(), 3);
        let mut index = 0;
        while let Some(packet) = segments.next() {
            let mut copy = packet.data().to_vec();
            let Checksum::Partial { start, offset } = packet.checksum() else { panic!("partial") };
            complete(&mut copy, usize::from(start), usize::from(offset));
            assert_eq!(copy, expected[index]);
            index += 1;
        }
    }

    #[test]
    fn frames_from_elsewhere_are_checked() {
        let (whole, checksum, gso, _) = segment(&Flow::tcp(false), 1000, &payload(5, 3000));
        let mut bytes = whole.clone();
        assert!(Frame::new(&mut bytes, Checksum::Valid, Some(gso)).is_err());
        assert!(Frame::new(&mut bytes, checksum, Some(Gso { segment_size: 0, ..gso })).is_err());
        assert!(Frame::new(&mut bytes, checksum, Some(Gso { kind: GsoKind::Tcp6 { ecn: false }, ..gso })).is_err());
        assert!(Frame::new(&mut bytes, Checksum::Partial { start: 20, offset: 4000 }, None).is_err());
        let mut no_header = whole.clone();
        no_header[0] = 0x40;
        assert!(Frame::new(&mut no_header, checksum, Some(gso)).is_err(), "an IPv4 header length of zero");
        let frame = Frame::new(&mut bytes, checksum, Some(Gso { header_len: 9999, ..gso })).unwrap();
        assert_eq!(frame.gso().unwrap().header_len, 52, "the header length comes from the packet");
    }

    #[test]
    fn a_frame_without_gso_is_its_own_packet() {
        let mut p = Flow::udp(true).packet(0, &payload(1, 100));
        let original = p.clone();
        let mut frame = Frame::new(&mut p, Checksum::Valid, None).unwrap();
        let mut segments = frame.segments();
        assert_eq!(segments.next().unwrap().data(), &original[..]);
        assert!(segments.next().is_none());
    }

    #[test]
    fn completing_into_a_copy() {
        let mut p = Flow::tcp(true).packet(5, &payload(9, 777));
        let expected = p.clone();
        let info = Transport::read(&p, 0).unwrap();
        let partial = info.pseudo(&p, p.len() - info.transport).fold();
        write_u16(&mut p, info.transport + 16, partial);
        let mut out = Vec::new();
        let rest = complete_into(&Packet::new(&p), p.len(), info.transport, 16, &mut out);
        assert_eq!([&out[..], &p[rest]].concat(), expected);
    }

    /// `packet` behind an Ethernet header and two VLAN tags.
    fn ethernet(packet: &[u8]) -> Vec<u8> {
        let mut frame = vec![9u8; 12];
        frame.extend_from_slice(&[0x88, 0xa8, 0x00, 0x01, 0x81, 0x00, 0x00, 0x02]);
        frame.extend_from_slice(if packet[0] >> 4 == 6 { &[0x86, 0xdd] } else { &[0x08, 0x00] });
        frame.extend_from_slice(packet);
        frame
    }

    #[test]
    fn cuts_ethernet_frames_like_ip_packets() {
        for v6 in [false, true] {
            for tcp in [true, false] {
                let flow = if tcp { Flow::tcp(v6) } else { Flow::udp(v6) };
                let (whole, checksum, gso, expected) = segment(&flow, 1000, &payload(3, 3500));
                let Checksum::Partial { start, offset } = checksum else { unreachable!() };
                let mut frame_bytes = ethernet(&whole);
                let link = frame_bytes.len() - whole.len();
                let checksum = Checksum::Partial { start: start + link as u16, offset };
                let gso = Gso { header_len: 0, ..gso };
                let mut frame = Frame::new_ethernet(&mut frame_bytes, checksum, Some(gso)).unwrap();
                let header_len = Transport::read(&whole, 0).unwrap().header_len;
                assert_eq!(usize::from(frame.gso().unwrap().header_len), link + header_len);
                let mut segments = frame.segments();
                let mut out = Vec::new();
                while let Some(mut packet) = segments.next() {
                    packet.complete_checksum();
                    out.push(packet.data().to_vec());
                }
                let expected: Vec<Vec<u8>> = expected.iter().map(|packet| ethernet(packet)).collect();
                assert_eq!(out, expected, "v6 {v6} tcp {tcp}");
            }
        }
        assert!(Frame::new_ethernet(&mut [0u8; 60], Checksum::Partial { start: 20, offset: 6 }, Some(Gso {
            kind: GsoKind::Udp,
            segment_size: 10,
            header_len: 0
        }))
        .is_err());
    }

    proptest! {
        #[test]
        fn any_segment_cuts_into_the_packets_it_stands_for(
            v6 in any::<bool>(), tcp in any::<bool>(), size in 8usize..2000, len in 1usize..20_000, seed in any::<u32>(),
            psh in any::<bool>(), id in any::<u16>(),
        ) {
            let mut flow = if tcp { Flow::tcp(v6) } else { Flow::udp(v6) };
            flow.id = id;
            if tcp && psh {
                flow.flags |= PSH;
            }
            let data = payload(seed, len);
            let total_limit = if v6 { 65_535 + 40 } else { 65_535 };
            prop_assume!(flow.packet(0, &data).len() <= total_limit);
            let (whole, checksum, gso, _) = segment(&flow, size, &data);
            let mut whole = whole;
            let seq0 = 1000u32;
            let cut = cut_in_place(whole.clone(), checksum, gso);
            prop_assert_eq!(cut.len(), len.div_ceil(size));
            let mut joined = Vec::new();
            for (index, packet) in cut.iter().enumerate() {
                let info = Transport::read(packet, 0).unwrap();
                prop_assert!(info.verify(packet));
                prop_assert!(packet.len() - info.header_len <= size);
                if tcp {
                    let seq = u32::from_be_bytes(packet[info.transport + 4..info.transport + 8].try_into().unwrap());
                    prop_assert_eq!(seq, seq0.wrapping_add((index * size) as u32));
                }
                joined.extend_from_slice(&packet[info.header_len..]);
            }
            prop_assert_eq!(joined, data);
            let mut frame = Frame::new(&mut whole, checksum, Some(gso)).unwrap();
            prop_assert_eq!(frame.segments().count(), len.div_ceil(size));
        }
    }
}
