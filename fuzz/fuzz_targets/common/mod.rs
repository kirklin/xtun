//! What the targets share: reading what a device hands over and writing what a writer plans,
//! end to end without a device.

#![allow(dead_code)]

use xtun_wire::checksum::Sum;
use xtun_wire::{Checksum, Frame, Framing, Gso, GsoKind, Parts, Plan, Prefix, Takes, VIRTIO_HEADER, Writes, gather};

/// `TUN_H_TCP_MSS` of OpenBSD's `tun_hdr`: the packet is a TCP segment to cut.
const TUN_H_TCP_MSS: u16 = 1 << 5;

/// The framing of a Linux tun device with offloads.
pub const VIRTIO: Framing = Framing { prefix: Prefix::Virtio(VIRTIO_HEADER), ethernet: false };

/// What a device with `framing` takes: TCP segments if `tcp`, UDP segments if `udp`.
pub fn takes(framing: Framing, tcp: bool, udp: bool) -> Takes {
    Takes { framing, tcp, udp, udp_max_segments: 64, max_frame: usize::MAX }
}

/// Reads what a device with `framing` handed over the way a reader does. Returns the packets it
/// stands for, each with a completed checksum, or `None` for something that is refused.
pub fn read(framing: Framing, bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut raw = bytes.to_vec();
    let decoded = framing.decode(&mut raw)?;
    let data = &mut raw[decoded.start..decoded.start + decoded.len];
    let mut frame = Frame::trusted(data, decoded.link, decoded.checksum, decoded.gso);
    let mut segments = frame.segments();
    let mut out = Vec::new();
    while let Some(mut packet) = segments.next() {
        packet.complete_checksum();
        out.push(packet.data().to_vec());
    }
    Some(out)
}

/// Plans `packets` for a device that takes `takes`, then reads every write back as the device
/// would. Returns `None` when planning refuses the batch.
pub fn plan_and_read<P: Parts>(takes: &Takes, packets: &[P]) -> Option<Vec<Vec<u8>>> {
    let mut plan = Plan::new();
    plan.plan_parts(takes, packets).ok()?;
    let writes = plan.writes(packets);
    let mut out = Vec::new();
    let mut write = Vec::new();
    for index in 0..writes.count() {
        gather(&writes, index, &mut write);
        handed_back(takes.framing, &mut write);
        out.extend(read(takes.framing, &write).expect("the writer plans only what the device accepts"));
    }
    Some(out)
}

/// Turns a write into what the device hands over for it. OpenBSD fills in the checksum field of
/// a TCP segment it takes itself, and hands one over with the pseudo header in that field
/// without the length, which a read adds.
fn handed_back(framing: Framing, write: &mut [u8]) {
    let Prefix::TunHdr { family } = framing.prefix else {
        return;
    };
    assert!(family.is_some() && !framing.ethernet, "the targets plan for OpenBSD's tun devices only");
    if u16::from_ne_bytes([write[0], write[1]]) & TUN_H_TCP_MSS == 0 {
        return;
    }
    // A segment the writer hands over has no IPv6 extension headers.
    let packet = &mut write[framing.prefix.len()..];
    let transport = if packet[0] >> 4 == 6 { 40 } else { usize::from(packet[0] & 0x0f) * 4 };
    let (at, length) = (transport + 16, packet.len() - transport);
    let field = u16::from_be_bytes([packet[at], packet[at + 1]]);
    let without = Sum::ZERO.word(field).word(!(length as u16)).fold();
    packet[at..at + 2].copy_from_slice(&without.to_be_bytes());
}

/// The checksum state and segmentation a caller could claim for a packet, from two bytes.
pub fn claim(selector: u8, size: u16, data: &[u8]) -> (Checksum, Option<Gso>) {
    let checksum = match selector % 4 {
        0 => Checksum::Unverified,
        1 => Checksum::Valid,
        _ => {
            let start = if data.first().is_some_and(|byte| byte >> 4 == 6) { 40 } else { 20 };
            let tcp = data.get(if start == 40 { 6 } else { 9 }) == Some(&6);
            Checksum::Partial { start, offset: if tcp { 16 } else { 6 } }
        }
    };
    let gso = (selector & 0x10 != 0).then_some(Gso {
        kind: match selector >> 5 & 3 {
            0 => GsoKind::Tcp4 { ecn: selector & 0x80 != 0 },
            1 => GsoKind::Tcp6 { ecn: false },
            _ => GsoKind::Udp,
        },
        segment_size: size,
        header_len: 0,
    });
    (checksum, gso)
}
