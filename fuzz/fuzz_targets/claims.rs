//! Any bytes as packets to write, with any checksum state and segmentation a caller could claim,
//! for every kind of device: the writer refuses a batch or plans it, never panics, and what it
//! plans is something the device accepts.

#![no_main]

mod common;

use common::{VIRTIO, plan_and_read, takes};
use xtun_wire::{Family, Framing, Packet, Prefix};
use libfuzzer_sys::fuzz_target;

const BSD: Family = Family { inet: 2, inet6: 24 };

fuzz_target!(|input: Vec<(u8, u16, Vec<u8>)>| {
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
    let bare = Framing { prefix: Prefix::None, ethernet: false };
    let family = Framing { prefix: Prefix::Family(BSD), ethernet: false };
    let tun_hdr = Framing { prefix: Prefix::TunHdr { family: Some(BSD) }, ethernet: false };
    // Linux with and without UDP segments, a device without offloads, a BSD tun device and an
    // OpenBSD tun device with offloads.
    for takes in [takes(VIRTIO, true, true), takes(VIRTIO, true, false), takes(bare, false, false), takes(family, false, false), takes(tun_hdr, true, false)] {
        // Empty packets make writes without a frame, which no device hands back.
        if packets.iter().any(|packet| packet.data.is_empty()) {
            let _ = xtun_wire::Plan::new().plan(&takes, &packets);
            continue;
        }
        let _ = plan_and_read(&takes, &packets);
    }
});
