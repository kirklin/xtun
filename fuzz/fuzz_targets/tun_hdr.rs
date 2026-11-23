//! Any bytes as what an OpenBSD device hands over: a `tun_hdr` and a packet of a tun device, or a
//! frame of a tap device, whose VLAN tag the system may have taken off. It is refused or cut into
//! packets whose payloads add up to its own, never anything else.

#![no_main]

mod common;

use xtun_wire::{Framing, Prefix};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    for ethernet in [false, true] {
        let framing = Framing { prefix: Prefix::TunHdr { family: None }, ethernet };
        let Some(packets) = common::read(framing, bytes) else {
            continue;
        };
        assert!(!packets.is_empty());
        // A tag that goes back into a frame makes it four bytes longer.
        let longest = bytes.len() - 8 + if ethernet { 4 } else { 0 };
        let largest = packets.iter().map(Vec::len).max().unwrap_or(0);
        assert!(largest <= longest);
        if packets.len() == 1 && !ethernet {
            assert_eq!(packets[0].len(), bytes.len() - 8);
        }
    }
});
