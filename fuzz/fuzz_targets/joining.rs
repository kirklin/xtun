//! Batches of TCP and UDP packets from four flows, joined as the Linux writer joins them and
//! read back as the kernel would: every flow comes back packet for packet, byte for byte.

#![no_main]

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use xtun_wire::checksum::{Sum, pseudo_v4, pseudo_v6};
use xtun_wire::{Checksum, Packet};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Step {
    flow: u8,
    size: u16,
    flags: u8,
    gap: bool,
    corrupt: bool,
    claim: u8,
}

#[derive(Arbitrary, Debug)]
struct Input {
    steps: Vec<Step>,
    udp: bool,
}

struct Flow {
    v6: bool,
    tcp: bool,
    port: u16,
    seq: u32,
    id: u16,
}

fn build(flow: &Flow, flags: u8, payload: &[u8]) -> Vec<u8> {
    let transport = if flow.tcp { 32 } else { 8 } + payload.len();
    let mut p = if flow.v6 {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(transport as u16).to_be_bytes());
        p[6] = if flow.tcp { 6 } else { 17 };
        p[7] = 64;
        p[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());
        p[24..40].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        p
    } else {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + transport) as u16).to_be_bytes());
        p[4..6].copy_from_slice(&flow.id.to_be_bytes());
        p[6] = 0x40;
        p[8] = 64;
        p[9] = if flow.tcp { 6 } else { 17 };
        p[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        let value = Sum::ZERO.bytes(&p).checksum();
        p[10..12].copy_from_slice(&value.to_be_bytes());
        p
    };
    let start = p.len();
    p.extend_from_slice(&flow.port.to_be_bytes());
    p.extend_from_slice(&443u16.to_be_bytes());
    if flow.tcp {
        p.extend_from_slice(&flow.seq.to_be_bytes());
        p.extend_from_slice(&7u32.to_be_bytes());
        p.push(0x80);
        p.push(flags);
        p.extend_from_slice(&1000u16.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
    } else {
        p.extend_from_slice(&(transport as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
    }
    p.extend_from_slice(payload);
    let protocol = if flow.tcp { 6 } else { 17 };
    let pseudo = if flow.v6 {
        pseudo_v6(&p[8..24], &p[24..40], protocol, transport as u32)
    } else {
        pseudo_v4(&p[12..16], &p[16..20], protocol, transport as u16)
    };
    let field = start + if flow.tcp { 16 } else { 6 };
    let value = pseudo.bytes(&p[start..]).checksum();
    p[field..field + 2].copy_from_slice(&value.to_be_bytes());
    p
}

fn partial(complete: &[u8], tcp: bool) -> (Vec<u8>, Checksum) {
    let mut p = complete.to_vec();
    let v6 = p[0] >> 4 == 6;
    let start = if v6 { 40 } else { 20 };
    let offset = if tcp { 16 } else { 6 };
    let length = p.len() - start;
    let protocol = if tcp { 6 } else { 17 };
    let pseudo = if v6 {
        pseudo_v6(&p[8..24], &p[24..40], protocol, length as u32)
    } else {
        pseudo_v4(&p[12..16], &p[16..20], protocol, length as u16)
    };
    p[start + offset..start + offset + 2].copy_from_slice(&pseudo.fold().to_be_bytes());
    (p, Checksum::Partial { start: start as u16, offset: offset as u16 })
}

fuzz_target!(|input: Input| {
    let mut flows: Vec<Flow> = (0..4u16)
        .map(|index| Flow { v6: index % 2 == 1, tcp: index < 2, port: 1000 + index, seq: 1, id: 1 })
        .collect();
    let mut sent: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut given: Vec<(Vec<u8>, Checksum)> = Vec::new();
    for (index, step) in input.steps.iter().take(300).enumerate() {
        let which = usize::from(step.flow % 4);
        let flow = &mut flows[which];
        let size = usize::from(step.size % 1500);
        let payload: Vec<u8> = (0..size).map(|at| (at as u32).wrapping_mul(2_654_435_761).wrapping_add(index as u32) as u8).collect();
        let flags = if step.flags & 0x80 != 0 { step.flags & 0x3f } else if step.flags & 1 != 0 { 0x18 } else { 0x10 };
        let mut packet = build(flow, flags, &payload);
        flow.seq = flow.seq.wrapping_add(size as u32).wrapping_add(if step.gap { 1000 } else { 0 });
        flow.id = flow.id.wrapping_add(1);
        let (bytes, checksum) = if step.corrupt && size > 0 {
            let at = packet.len() - 1;
            packet[at] ^= 0x55;
            (packet.clone(), Checksum::Unverified)
        } else {
            match step.claim % 3 {
                0 => (packet.clone(), Checksum::Unverified),
                1 => (packet.clone(), Checksum::Valid),
                _ => partial(&packet, flow.tcp),
            }
        };
        sent.push((which, packet));
        given.push((bytes, checksum));
    }
    let packets: Vec<Packet<'_>> = given.iter().map(|(bytes, checksum)| Packet::new(bytes).with_checksum(*checksum)).collect();
    let takes = common::takes(common::VIRTIO, true, input.udp);
    let out = common::plan_and_read(&takes, &packets).expect("well formed packets are always planned");
    assert_eq!(out.len(), sent.len());
    for which in 0..4 {
        let port = (1000 + which as u16).to_be_bytes();
        let expected: Vec<&Vec<u8>> = sent.iter().filter(|(flow, _)| *flow == which).map(|(_, p)| p).collect();
        let got: Vec<&Vec<u8>> = out
            .iter()
            .filter(|p| {
                let start = if p[0] >> 4 == 6 { 40 } else { 20 };
                p[start..start + 2] == port
            })
            .collect();
        assert_eq!(got, expected);
    }
});
