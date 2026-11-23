//! Any bytes as a frame from a Linux device: a virtio header and a packet. A frame is refused or
//! cut into packets whose payloads add up to the frame's, never anything else.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let Some(packets) = common::read(common::VIRTIO, bytes) else {
        return;
    };
    assert!(!packets.is_empty());
    let frame = bytes.len() - 10;
    let largest = packets.iter().map(Vec::len).max().unwrap_or(0);
    assert!(largest <= frame);
    if packets.len() == 1 {
        assert_eq!(packets[0].len(), frame);
    }
});
