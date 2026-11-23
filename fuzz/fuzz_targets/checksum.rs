//! The checksum against RFC 1071 as written, over any bytes split anywhere.

#![no_main]

use xtun_wire::checksum::{Sum, copy};
use libfuzzer_sys::fuzz_target;

fn reference(data: &[u8]) -> u16 {
    let mut acc = 0u32;
    for pair in data.chunks(2) {
        acc += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

fuzz_target!(|input: (Vec<u8>, Vec<u16>, u8)| {
    let (data, cuts, skip) = input;
    let data = &data[usize::from(skip).min(data.len())..];
    let mut cuts: Vec<usize> = cuts.into_iter().map(|cut| usize::from(cut) % (data.len() + 1)).collect();
    cuts.sort_unstable();
    let mut sum = Sum::ZERO;
    let mut start = 0;
    for cut in cuts.into_iter().chain([data.len()]) {
        sum = sum.bytes(&data[start..cut]);
        start = cut;
    }
    let expected = reference(data);
    assert_eq!(sum.fold(), expected);
    let mut out = vec![0u8; data.len()];
    assert_eq!(copy(&mut out, data).fold(), expected);
    assert_eq!(out, data);
});
