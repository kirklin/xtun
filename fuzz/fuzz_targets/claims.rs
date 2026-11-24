//! Any bytes as packets to write, with any checksum state and segmentation a caller could claim,
//! for every kind of device: the writer refuses a batch or plans it, never panics, and what it
//! plans is something the device accepts. The same packets in any pieces are refused or planned
//! alike, and reach the device as the same packets.

#![no_main]

mod common;

use common::{VIRTIO, plan_and_read, takes};
use xtun_wire::{Family, Framing, Packet, Pieces, Prefix};
use libfuzzer_sys::fuzz_target;

const BSD: Family = Family { inet: 2, inet6: 24 };

fuzz_target!(|input: Vec<(u8, u16, Vec<u8>)>| {
    // Each packet again as a head of any length and stretches of one length behind it, few
    // enough for one write.
    let split: Vec<(&[u8], Vec<&[u8]>)> = input
        .iter()
        .take(64)
        .map(|(selector, size, data)| {
            let (head, rest) = data.split_at(usize::from(*size).min(data.len()).min(80));
            (head, rest.chunks(rest.len() / 512 + 1 + usize::from(*selector)).collect())
        })
        .collect();
    let packets: Vec<Packet<'_>> = input
        .iter()
        .take(64)
        .map(|(selector, size, data)| {
            let (checksum, gso) = common::claim(*selector, *size, data);
            let packet = Packet::new(data).with_checksum(checksum);
            match gso {
                Some(gso) => packet.with_gso(gso),
                None => packet,
            }
        })
        .collect();
    let pieces: Vec<Pieces<'_>> = packets
        .iter()
        .zip(&split)
        .map(|(packet, (head, body))| Pieces { head, body, checksum: packet.checksum, gso: packet.gso })
        .collect();
    let bare = Framing { prefix: Prefix::None, ethernet: false };
    let family = Framing { prefix: Prefix::Family(BSD), ethernet: false };
    let tun_hdr = Framing { prefix: Prefix::TunHdr { family: Some(BSD) }, ethernet: false };
    // Linux with and without UDP segments, a device without offloads, a BSD tun device and an
    // OpenBSD tun device with offloads.
    for takes in [takes(VIRTIO, true, true), takes(VIRTIO, true, false), takes(bare, false, false), takes(family, false, false), takes(tun_hdr, true, false)] {
        // Empty packets make writes without a frame, which no device hands back.
        if packets.iter().any(|packet| packet.data.is_empty()) {
            let whole = xtun_wire::Plan::new().plan(&takes, &packets);
            assert_eq!(xtun_wire::Plan::new().plan_parts(&takes, &pieces).is_ok(), whole.is_ok());
            continue;
        }
        let (mut whole, mut cut) = (plan_and_read(&takes, &packets), plan_and_read(&takes, &pieces));
        // Which packets are joined depends on where their headers lie, and with it the order of
        // packets of different flows.
        for read in [&mut whole, &mut cut].into_iter().flatten() {
            read.sort();
        }
        assert_eq!(cut, whole);
    }
});
