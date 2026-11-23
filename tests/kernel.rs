//! The kernel as the reference for cutting and joining: segments go into one device and are
//! forwarded out of a second device without offloads, so the kernel cuts them itself.
//!
//! Device `xtuntest7` has offloads and the subnet 10.78.0.0/24; device `xtuntest8` has none and
//! the subnet 10.79.0.0/24. A packet from 10.78.0.5 to 10.79.0.5 written to the first comes out
//! of the second one hop later. Needs forwarding: `node scripts/linux.ts` turns it on.

#![cfg(target_os = "linux")]

mod common;

use std::net::IpAddr;
use std::time::Duration;

use common::Build;
use xtun::checksum::Sum;
use xtun::{Checksum, Frame, Gso, GsoKind, Packet, Reader, Tun, Writer};
use ipnet::IpNet;

fn net(text: &str) -> IpNet {
    text.parse().unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// The first device, with offloads if `offload`, and its writer, and the second device with its
/// reader.
fn devices(offload: bool) -> (Tun, Writer, Tun, Reader) {
    let (a, mut queues) =
        Tun::builder().name("xtuntest7").address(net("10.78.0.1/24")).address(net("fd78::1/64")).offload(offload).build().unwrap();
    let (_, writer) = queues.remove(0).split().unwrap();
    let (b, mut queues) = Tun::builder()
        .name("xtuntest8")
        .address(net("10.79.0.1/24"))
        .address(net("fd79::1/64"))
        .offload(false)
        .build()
        .unwrap();
    let (reader, _) = queues.remove(0).split().unwrap();
    (a, writer, b, reader)
}

/// A packet as it leaves after one hop: TTL or hop limit one lower.
fn forwarded(mut packet: Vec<u8>) -> Vec<u8> {
    if packet[0] >> 4 == 4 {
        packet[8] -= 1;
        packet[10..12].fill(0);
        let value = Sum::ZERO.bytes(&packet[..20]).checksum();
        packet[10..12].copy_from_slice(&value.to_be_bytes());
    } else {
        packet[7] -= 1;
    }
    packet
}

/// Reads `count` packets from the reader that carry `port` as their destination port.
async fn read(reader: &mut Reader, port: u16, count: usize) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while packets.len() < count {
        let mut batch = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .unwrap_or_else(|_| panic!("only {} of {count} packets came out", packets.len()))
            .unwrap();
        for frame in batch.frames() {
            let data = frame.data();
            let header = if data[0] >> 4 == 6 { 40 } else { 20 };
            if data.len() >= header + 4 && data[header + 2..header + 4] == port.to_be_bytes() {
                packets.push(data.to_vec());
            }
        }
    }
    assert_eq!(packets.len(), count);
    packets
}

/// Turns a complete packet into a segment: the checksum field holds the pseudo header sum.
fn partial(mut packet: Vec<u8>, tcp: bool) -> (Vec<u8>, Checksum) {
    let v6 = packet[0] >> 4 == 6;
    let start = if v6 { 40 } else { 20 };
    let offset = if tcp { 16 } else { 6 };
    let length = (packet.len() - start) as u32;
    let protocol = if tcp { 6 } else { 17 };
    let pseudo = if v6 {
        xtun::checksum::pseudo_v6(&packet[8..24], &packet[24..40], protocol, length)
    } else {
        xtun::checksum::pseudo_v4(&packet[12..16], &packet[16..20], protocol, length as u16)
    };
    packet[start + offset..start + offset + 2].copy_from_slice(&pseudo.fold().to_be_bytes());
    (packet, Checksum::Partial { start: start as u16, offset: offset as u16 })
}

/// Cuts a segment here, with complete checksums, as it would leave after one hop.
fn ours(mut segment: Vec<u8>, checksum: Checksum, gso: Gso) -> Vec<Vec<u8>> {
    let mut frame = Frame::new(&mut segment, checksum, Some(gso)).unwrap();
    let mut segments = frame.segments();
    let mut out = Vec::new();
    while let Some(mut packet) = segments.next() {
        packet.complete_checksum();
        out.push(forwarded(packet.data().to_vec()));
    }
    out
}

fn payload(seed: u32, len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

async fn send(writer: &mut Writer, packets: &[Packet<'_>]) {
    writer.send(packets).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces and forwards between them: run with scripts/linux.ts"]
async fn the_kernel_cuts_segments_as_we_do() {
    segments_come_out_cut(true, 20_000).await;
}

/// A device without offloads cannot be told to cut a segment: the writer cuts it before it
/// writes, into the packets the kernel would have made of it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces and forwards between them: run with scripts/linux.ts"]
async fn segments_for_a_device_without_offloads_are_cut_before_they_are_written() {
    segments_come_out_cut(false, 25_000).await;
}

/// Writes segments to a first device, with offloads if `offload`, and checks that the packets
/// forwarded out of the second device are the packets the segments are cut into here. A UDP
/// segment for a device that takes none is cut before it is written.
async fn segments_come_out_cut(offload: bool, first_port: u16) {
    let (a, mut writer, _b, mut reader) = devices(offload);
    assert_eq!(a.offload().tcp, offload);
    let mut port = first_port;
    for (src, dst) in [("10.78.0.5", "10.79.0.5"), ("fd78::5", "fd79::5")] {
        for tcp in [true, false] {
            // Every cut packet has to fit the second device's MTU of 1,500 bytes, or forwarding
            // drops it.
            for (size, segment) in [(10_000, 1_400), (4_321, 1_000), (60_000, 1_380), (3_000, 500)] {
                port += 1;
                let build = Build { src: ip(src), dst: ip(dst), src_port: 4_000, dst_port: port, ttl: 64, id: 0x4321 };
                let data = payload(port.into(), size);
                let whole = if tcp { build.tcp(77_777, 99, 0x18, &data) } else { build.udp(&data) };
                let (whole, checksum) = partial(whole, tcp);
                let kind = match (tcp, ip(src).is_ipv6()) {
                    (true, false) => GsoKind::Tcp4 { ecn: false },
                    (true, true) => GsoKind::Tcp6 { ecn: false },
                    (false, _) => GsoKind::Udp,
                };
                let gso = Gso { kind, segment_size: segment, header_len: 0 };
                let expected = ours(whole.clone(), checksum, gso);
                send(&mut writer, &[Packet::new(&whole).with_checksum(checksum).with_gso(gso)]).await;
                let got = read(&mut reader, port, expected.len()).await;
                assert_eq!(got, expected, "{src} tcp {tcp} size {size} segment {segment}");
            }
        }
    }
    assert_eq!(writer.stats().dropped, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces and forwards between them: run with scripts/linux.ts"]
async fn the_kernel_cuts_joined_runs_back_into_the_packets() {
    let (a, mut writer, _b, mut reader) = devices(true);
    let mut port = 30_000;
    for (src, dst) in [("10.78.0.5", "10.79.0.5"), ("fd78::5", "fd79::5")] {
        for tcp in [true, false] {
            port += 1;
            let mut build = Build { src: ip(src), dst: ip(dst), src_port: 5_000, dst_port: port, ttl: 64, id: 0x100 };
            let mut packets = Vec::new();
            let mut seq = 1_000_000u32;
            for index in 0..40 {
                let data = payload(index, if index == 39 { 700 } else { 1_300 });
                let flags = if index == 39 { 0x18 } else { 0x10 };
                packets.push(if tcp { build.tcp(seq, 5, flags, &data) } else { build.udp(&data) });
                seq = seq.wrapping_add(data.len() as u32);
                build.id = build.id.wrapping_add(1);
            }
            let views: Vec<Packet<'_>> = packets.iter().map(|p| Packet::new(p).with_checksum(Checksum::Valid)).collect();
            let before = writer.stats();
            send(&mut writer, &views).await;
            let writes = writer.stats().writes - before.writes;
            if tcp || a.offload().udp {
                assert_eq!(writes, 1, "{src} tcp {tcp}: forty packets of one flow go as one write");
            }
            let got = read(&mut reader, port, packets.len()).await;
            let expected: Vec<Vec<u8>> = packets.into_iter().map(forwarded).collect();
            assert_eq!(got, expected, "{src} tcp {tcp}");
        }
    }
    assert_eq!(writer.stats().dropped, 0);
}
