//! Shared by the device tests: a reflector that sends what the interface reads back in, so two
//! sockets of this machine talk through the device.
//!
//! The interface has address `local`. A client dials `peer`; the reflector turns its packets
//! into packets from `other` to `local`, which a listener on `local` accepts, and turns the
//! listener's answers to `other` into packets from `peer` back to the client. Both addresses
//! are in the interface's subnet, so their packets enter the device. On a layer 2 interface
//! the system knows both addresses as neighbors at one made-up hardware address, and the
//! reflector sends each frame back to the hardware address it came from.

#![allow(dead_code)]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use xtun::checksum::{Sum, pseudo_v4, pseudo_v6};
use xtun::{Checksum, Gso, Layer, OwnedFrame, Packet, Pieces, Reader, Writer, WriterStats};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// What reflectors have seen, summed over queues.
#[derive(Default, Debug)]
pub struct Counters {
    /// Frames that were segments of several packets.
    pub segments: AtomicU64,
    /// Packets handed to writers.
    pub packets: AtomicU64,
    /// Writes the writers made.
    pub writes: AtomicU64,
    /// Writes the system refused, whose packets were lost.
    pub refused: AtomicU64,
}

impl Counters {
    pub fn get(&self) -> (u64, u64, u64) {
        (self.segments.load(Ordering::Relaxed), self.packets.load(Ordering::Relaxed), self.writes.load(Ordering::Relaxed))
    }

    /// What the reflectors of the interface `name` did and what the transfer lost, for the line
    /// a test prints. `again` is how many segments TCP sent again meanwhile.
    pub fn summary(&self, name: &str, again: u64) -> String {
        let (segments, packets, writes) = self.get();
        let refused = self.refused.load(Ordering::Relaxed);
        format!("{segments} segments read, {packets} packets in {writes} writes, {refused} refused{}", lost(name, again))
    }

    /// Adds what a writer did between two readings of its statistics.
    fn wrote(&self, before: WriterStats, after: WriterStats) {
        self.packets.fetch_add(after.packets - before.packets, Ordering::Relaxed);
        self.writes.fetch_add(after.writes - before.writes, Ordering::Relaxed);
        self.refused.fetch_add(after.dropped - before.dropped, Ordering::Relaxed);
    }
}

/// Whether the system is Linux, which Android is too.
const LINUX: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// How many TCP segments the system has sent again so far, where any program can read that
/// count: on Linux. Zero elsewhere.
pub fn retransmitted() -> u64 {
    if !LINUX {
        return 0;
    }
    let counters = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let mut tcp = counters.lines().filter(|line| line.starts_with("Tcp:"));
    let (names, values) = (tcp.next().unwrap(), tcp.next().unwrap());
    let at = names.split_whitespace().position(|name| name == "RetransSegs").unwrap();
    values.split_whitespace().nth(at).unwrap().parse().unwrap()
}

/// What a transfer through the interface `name` lost, as far as a Linux system counts it: the
/// `again` segments that TCP sent again, the packets the interface dropped on their way to the
/// device, and the written packets it dropped.
fn lost(name: &str, again: u64) -> String {
    if !LINUX {
        return String::new();
    }
    let dropped = |way: &str| {
        let count = std::fs::read_to_string(format!("/sys/class/net/{name}/statistics/{way}_dropped")).unwrap();
        count.trim().parse::<u64>().unwrap()
    };
    format!("; {again} segments sent again, {} packets dropped on the way out and {} on the way in", dropped("tx"), dropped("rx"))
}

/// Checks that packets cut from segments were joined again: without joining every packet is a
/// write of its own. How many packets go into a write depends on how many come together. A
/// bare acknowledgement is joined with nothing. And once TCP has sent a segment again, as it
/// does when a machine that stalls keeps its packets too long, it goes on in small segments,
/// of which a packet or two come at a time: with `again` such segments the writes only have to
/// be fewer than the packets, and without any each has to carry more than two.
pub fn assert_joined(packets: u64, writes: u64, again: u64) {
    let least = if again == 0 { writes * 2 } else { writes };
    assert!(packets > least, "cut packets are joined again: {packets} packets in {writes} writes, {again} segments sent again");
}

/// An IP packet carrying TCP or UDP, every checksum complete.
pub struct Build {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl: u8,
    pub id: u16,
}

impl Build {
    fn ip(&self, protocol: u8, transport_len: usize) -> Vec<u8> {
        match (self.src, self.dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut p = vec![0u8; 20];
                p[0] = 0x45;
                p[2..4].copy_from_slice(&((20 + transport_len) as u16).to_be_bytes());
                p[4..6].copy_from_slice(&self.id.to_be_bytes());
                p[6] = 0x40;
                p[8] = self.ttl;
                p[9] = protocol;
                p[12..16].copy_from_slice(&src.octets());
                p[16..20].copy_from_slice(&dst.octets());
                let value = Sum::ZERO.bytes(&p).checksum();
                p[10..12].copy_from_slice(&value.to_be_bytes());
                p
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let mut p = vec![0u8; 40];
                p[0] = 0x60;
                p[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
                p[6] = protocol;
                p[7] = self.ttl;
                p[8..24].copy_from_slice(&src.octets());
                p[24..40].copy_from_slice(&dst.octets());
                p
            }
            _ => panic!("one IP version"),
        }
    }

    fn finish(&self, mut packet: Vec<u8>, start: usize, protocol: u8, field: usize) -> Vec<u8> {
        let length = packet.len() - start;
        let pseudo = match (self.src, self.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => pseudo_v4(&s.octets(), &d.octets(), protocol, length as u16),
            (IpAddr::V6(s), IpAddr::V6(d)) => pseudo_v6(&s.octets(), &d.octets(), protocol, length as u32),
            _ => unreachable!(),
        };
        let value = pseudo.bytes(&packet[start..]).checksum();
        packet[start + field..start + field + 2].copy_from_slice(&value.to_be_bytes());
        packet
    }

    pub fn udp(&self, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut packet = self.ip(17, udp_len);
        let start = packet.len();
        packet.extend_from_slice(&self.src_port.to_be_bytes());
        packet.extend_from_slice(&self.dst_port.to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        self.finish(packet, start, 17, 6)
    }

    /// A TCP packet with a timestamp option, as stacks send them.
    pub fn tcp(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let options = [1u8, 1, 8, 10, 0, 0, 0x12, 0x34, 0, 0, 0x56, 0x78];
        let tcp_len = 20 + options.len() + payload.len();
        let mut packet = self.ip(6, tcp_len);
        let start = packet.len();
        packet.extend_from_slice(&self.src_port.to_be_bytes());
        packet.extend_from_slice(&self.dst_port.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&ack.to_be_bytes());
        packet.push(((20 + options.len()) / 4) as u8 * 16);
        packet.push(flags);
        packet.extend_from_slice(&64_000u16.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&options);
        packet.extend_from_slice(payload);
        self.finish(packet, start, 6, 16)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Nat {
    pub local: IpAddr,
    pub peer: IpAddr,
    pub other: IpAddr,
    /// Bytes of link header in front of every packet: 14 for Ethernet frames.
    pub link: usize,
}

/// The hardware address that the neighbors of a layer 2 interface have.
pub const NEIGHBOR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

/// An Ethernet frame from `src` to `dst` around an IP packet.
pub fn ethernet(dst: [u8; 6], src: [u8; 6], packet: &[u8]) -> Vec<u8> {
    let kind: u16 = if packet[0] >> 4 == 6 { 0x86dd } else { 0x0800 };
    [&dst[..], &src[..], &kind.to_be_bytes(), packet].concat()
}

/// The IP packet in an Ethernet frame, if it carries one.
pub fn ip_packet(frame: &[u8]) -> Option<&[u8]> {
    let kind = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    matches!(kind, 0x0800 | 0x86dd).then(|| &frame[14..])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Frames go back as they were read, segments whole.
    Pass,
    /// Frames are cut into packets, which are copied out and written as a batch, the way a
    /// stack in the process would take them apart and send its own.
    Split,
    /// Packets are read one at a time, whole and with complete checksums, and the packets that
    /// are ready together are written as a batch.
    Packets,
    /// Frames are cut into packets as for [`Mode::Split`], and each packet is written in
    /// pieces: its headers, and its payload behind them in two stretches.
    Pieces,
    /// Frames are taken out of their batches and queued, segments whole, the way a stack keeps
    /// what it received; what takes them from the queue writes each in pieces.
    Kept,
    /// Frames longer than 512 bytes are taken out of their batches and the others stay, the way
    /// a stack keeps payload and reads the rest where it lies; all go back as they were read,
    /// in the order they came in.
    Mixed,
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// Rewrites the addresses of one packet in place and keeps its checksums right; a frame goes
/// back to where it came from. Returns false for a packet that is not for the reflector.
pub fn rewrite(frame: &mut [u8], checksum: Checksum, nat: &Nat) -> bool {
    if nat.link > 0 {
        if ip_packet(frame).is_none() {
            return false;
        }
        let (dst, src) = frame[..12].split_at_mut(6);
        dst.swap_with_slice(src);
    }
    let packet = &mut frame[nat.link..];
    let v6 = packet[0] >> 4 == 6;
    let (src_at, dst_at, len) = if v6 { (8, 24, 16) } else { (12, 16, 4) };
    let dst = &packet[dst_at..dst_at + len];
    let (new_src, new_dst) = if dst == octets(nat.peer) {
        (octets(nat.other), octets(nat.local))
    } else if dst == octets(nat.other) {
        (octets(nat.peer), octets(nat.local))
    } else {
        return false;
    };
    let old = Sum::ZERO.bytes(&packet[src_at..src_at + len]).bytes(&packet[dst_at..dst_at + len]);
    let new = Sum::ZERO.bytes(&new_src).bytes(&new_dst);
    packet[src_at..src_at + len].copy_from_slice(&new_src);
    packet[dst_at..dst_at + len].copy_from_slice(&new_dst);
    let ip_len = if v6 { 40 } else { usize::from(packet[0] & 0x0f) * 4 };
    if !v6 {
        packet[10..12].fill(0);
        let value = Sum::ZERO.bytes(&packet[..ip_len]).checksum();
        packet[10..12].copy_from_slice(&value.to_be_bytes());
    }
    let protocol = packet[if v6 { 6 } else { 9 }];
    let field = match protocol {
        6 => 16,
        17 => 6,
        58 => 2,
        _ => return true,
    };
    let at = ip_len + field;
    if at + 2 > packet.len() {
        return true;
    }
    let value = u16::from_be_bytes([packet[at], packet[at + 1]]);
    let updated = match checksum {
        // The field holds the pseudo header sum: move it from the old addresses to the new.
        Checksum::Partial { .. } => Sum::ZERO.word(value).word(!old.fold()).combine(new).fold(),
        _ if protocol == 17 && !v6 && value == 0 => 0,
        _ => !Sum::ZERO.word(!value).word(!old.fold()).combine(new).fold(),
    };
    packet[at..at + 2].copy_from_slice(&updated.to_be_bytes());
    true
}

/// Reflects packet by packet until reading or writing fails.
async fn reflect_packets<L: Layer>(mut reader: Reader<L>, mut writer: Writer<L>, nat: Nat, counters: Arc<Counters>) -> io::Result<()> {
    let mut pool: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 65_536]).collect();
    let mut lengths = Vec::new();
    loop {
        lengths.clear();
        lengths.push(reader.recv_packet(&mut pool[0]).await?);
        while lengths.len() < pool.len() {
            match reader.try_recv_packet(&mut pool[lengths.len()]) {
                Ok(length) => lengths.push(length),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        let kept: Vec<bool> =
            pool.iter_mut().zip(&lengths).map(|(buffer, length)| rewrite(&mut buffer[..*length], Checksum::Valid, &nat)).collect();
        let packets: Vec<Packet<'_>> = pool
            .iter()
            .zip(&lengths)
            .zip(&kept)
            .filter(|(_, kept)| **kept)
            .map(|((buffer, length), _)| Packet::new(&buffer[..*length]).with_checksum(Checksum::Valid))
            .collect();
        let before = writer.stats();
        writer.send(&packets).await?;
        counters.wrote(before, writer.stats());
    }
}

/// Where the headers of a frame end: behind the link layer, IP and TCP or UDP headers, or
/// behind the IP header for any other protocol.
fn headers(frame: &[u8], link: usize) -> usize {
    let packet = &frame[link..];
    let (ip_len, protocol) = if packet[0] >> 4 == 6 { (40, packet[6]) } else { (usize::from(packet[0] & 0x0f) * 4, packet[9]) };
    let transport = match protocol {
        6 => packet.get(ip_len + 12).map_or(0, |byte| usize::from(byte >> 4) * 4),
        17 => 8,
        _ => 0,
    };
    (link + ip_len + transport).min(frame.len())
}

/// A packet as its headers and its payload in two stretches.
fn in_pieces(packet: &[u8], link: usize) -> (&[u8], [&[u8]; 2]) {
    let (head, payload) = packet.split_at(headers(packet, link));
    let (first, second) = payload.split_at(payload.len() / 2);
    (head, [first, second])
}

/// Reflects frames that are taken out of their batches until reading or writing fails.
async fn reflect_kept<L: Layer>(mut reader: Reader<L>, mut writer: Writer<L>, nat: Nat, counters: Arc<Counters>) -> io::Result<()> {
    let (queue, mut queued) = tokio::sync::mpsc::channel::<Vec<OwnedFrame>>(4);
    let segments = &counters.segments;
    let reading = async move {
        loop {
            let mut batch = reader.recv().await?;
            let mut kept = Vec::with_capacity(batch.len());
            for frame in batch.frames() {
                if frame.gso().is_some() {
                    segments.fetch_add(1, Ordering::Relaxed);
                }
                // Windows adapters and the BPF device of a layer 2 interface on macOS hand over
                // frames that are copied when they are taken; everywhere else a frame has a
                // block to itself.
                let copied = cfg!(windows) || (cfg!(target_os = "macos") && nat.link > 0);
                match frame.block_len() {
                    Some(block) => assert!(!copied && block >= frame.data().len(), "a frame of {} bytes in a block of {block}", frame.data().len()),
                    None => assert!(copied, "a frame without a block of its own"),
                }
                kept.push(frame.into_owned());
            }
            assert!(batch.is_empty(), "every frame was taken out");
            drop(batch);
            if queue.send(kept).await.is_err() {
                return Ok::<(), io::Error>(());
            }
        }
    };
    let writing = async {
        while let Some(mut frames) = queued.recv().await {
            frames.retain_mut(|frame| {
                let checksum = frame.checksum();
                rewrite(frame.data_mut(), checksum, &nat)
            });
            let before = writer.stats();
            write_kept(&mut writer, frames, nat.link).await?;
            counters.wrote(before, writer.stats());
        }
        Ok::<(), io::Error>(())
    };
    tokio::try_join!(reading, writing).map(|_| ())
}

/// Writes frames that were kept, each in pieces that are `Bytes` of the frame.
#[cfg(feature = "bytes")]
async fn write_kept<L: Layer>(writer: &mut Writer<L>, frames: Vec<OwnedFrame>, link: usize) -> io::Result<()> {
    use bytes::Bytes;
    let kept: Vec<(Bytes, [Bytes; 2], Checksum, Option<xtun::Gso>)> = frames
        .into_iter()
        .map(|frame| {
            let (checksum, gso) = (frame.checksum(), frame.gso());
            let bytes = Bytes::from(frame);
            let (head, body) = in_pieces(&bytes, link);
            (bytes.slice_ref(head), body.map(|piece| bytes.slice_ref(piece)), checksum, gso)
        })
        .collect();
    let packets: Vec<Pieces<'_, Bytes>> =
        kept.iter().map(|(head, body, checksum, gso)| Pieces { head: &head[..], body: &body[..], checksum: *checksum, gso: *gso }).collect();
    writer.send_pieces(&packets).await
}

/// Writes frames that were kept, each in pieces of its bytes.
#[cfg(not(feature = "bytes"))]
async fn write_kept<L: Layer>(writer: &mut Writer<L>, frames: Vec<OwnedFrame>, link: usize) -> io::Result<()> {
    let pieces: Vec<(&[u8], [&[u8]; 2])> = frames.iter().map(|frame| in_pieces(frame.data(), link)).collect();
    let packets: Vec<Pieces<'_>> = frames
        .iter()
        .zip(&pieces)
        .map(|(frame, (head, body))| Pieces { head, body: &body[..], checksum: frame.checksum(), gso: frame.gso() })
        .collect();
    writer.send_pieces(&packets).await
}

/// A frame of a batch that a reflector holds: taken out, or its bytes where they lie.
enum Held<'a> {
    Kept(OwnedFrame),
    Left(&'a mut [u8], Checksum, Option<Gso>),
}

/// Reflects frames of which the long ones are taken out of their batches and the others stay,
/// until reading or writing fails.
async fn reflect_mixed<L: Layer>(mut reader: Reader<L>, mut writer: Writer<L>, nat: Nat, counters: Arc<Counters>) -> io::Result<()> {
    loop {
        let mut batch = reader.recv().await?;
        let (read, mut taken) = (batch.len(), 0);
        let mut held = Vec::with_capacity(read);
        for frame in batch.frames() {
            if frame.gso().is_some() {
                counters.segments.fetch_add(1, Ordering::Relaxed);
            }
            let checksum = frame.checksum();
            if frame.data().len() > 512 {
                taken += 1;
                let mut frame = frame.into_owned();
                if rewrite(frame.data_mut(), checksum, &nat) {
                    held.push(Held::Kept(frame));
                }
            } else {
                let (gso, data) = (frame.gso(), frame.into_data());
                if rewrite(data, checksum, &nat) {
                    held.push(Held::Left(data, checksum, gso));
                }
            }
        }
        let packets: Vec<Packet<'_>> = held
            .iter()
            .map(|frame| match frame {
                Held::Kept(frame) => frame.packet(),
                Held::Left(data, checksum, gso) => Packet { data, checksum: *checksum, gso: *gso },
            })
            .collect();
        let before = writer.stats();
        writer.send(&packets).await?;
        counters.wrote(before, writer.stats());
        drop(packets);
        drop(held);
        assert_eq!(batch.len(), read - taken, "the frames that were not taken out are still in the batch");
    }
}

/// Reflects until reading or writing fails.
pub async fn reflect<L: Layer>(mut reader: Reader<L>, mut writer: Writer<L>, nat: Nat, mode: Mode, counters: Arc<Counters>) -> io::Result<()> {
    if mode == Mode::Packets {
        return reflect_packets(reader, writer, nat, counters).await;
    }
    if mode == Mode::Kept {
        return reflect_kept(reader, writer, nat, counters).await;
    }
    if mode == Mode::Mixed {
        return reflect_mixed(reader, writer, nat, counters).await;
    }
    let mut pool: Vec<(Vec<u8>, Checksum)> = Vec::new();
    loop {
        let mut batch = reader.recv().await?;
        let before = writer.stats();
        match mode {
            Mode::Pass => {
                let mut frames: Vec<_> = batch.frames().collect();
                frames.retain_mut(|frame| {
                    let checksum = frame.checksum();
                    rewrite(frame.data_mut(), checksum, &nat)
                });
                let segments = frames.iter().filter(|frame| frame.gso().is_some()).count();
                counters.segments.fetch_add(segments as u64, Ordering::Relaxed);
                let packets: Vec<Packet<'_>> = frames.iter().map(|frame| frame.packet()).collect();
                writer.send(&packets).await?;
            }
            Mode::Split | Mode::Pieces => {
                let mut used = 0;
                for mut frame in batch.frames() {
                    if frame.gso().is_some() {
                        counters.segments.fetch_add(1, Ordering::Relaxed);
                    }
                    let mut segments = frame.segments();
                    while let Some(mut segment) = segments.next() {
                        let checksum = segment.checksum();
                        if !rewrite(segment.data_mut(), checksum, &nat) {
                            continue;
                        }
                        if used == pool.len() {
                            pool.push((Vec::new(), checksum));
                        }
                        let (buffer, state) = &mut pool[used];
                        buffer.clear();
                        buffer.extend_from_slice(segment.data());
                        *state = checksum;
                        used += 1;
                    }
                }
                if mode == Mode::Pieces {
                    let pieces: Vec<(&[u8], [&[u8]; 2])> = pool[..used].iter().map(|(buffer, _)| in_pieces(buffer, nat.link)).collect();
                    let packets: Vec<Pieces<'_>> = pool[..used]
                        .iter()
                        .zip(&pieces)
                        .map(|((_, checksum), (head, body))| Pieces::new(head, &body[..]).with_checksum(*checksum))
                        .collect();
                    writer.send_pieces(&packets).await?;
                } else {
                    let packets: Vec<Packet<'_>> =
                        pool[..used].iter().map(|(buffer, checksum)| Packet::new(buffer).with_checksum(*checksum)).collect();
                    writer.send(&packets).await?;
                }
            }
            Mode::Packets | Mode::Kept | Mode::Mixed => unreachable!("reflected by a function of its own"),
        }
        counters.wrote(before, writer.stats());
    }
}

/// Bytes that a receiver can check without keeping a copy.
pub fn pattern(offset: u64, out: &mut [u8]) {
    for (index, byte) in out.iter_mut().enumerate() {
        let at = offset + index as u64;
        *byte = (at.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8;
    }
}

/// Makes closing `stream` wait until the peer has acknowledged everything this side sent, its FIN
/// included, so that no segment of the connection is still on its way when the reflector stops.
/// A segment sent after the interface is gone takes the default route, and some systems then
/// keep a route to the address that outlives the test. Set while the connection is open: illumos
/// takes no socket options once a direction is shut down.
#[cfg(unix)]
fn linger(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    // The Apple systems count `SO_LINGER` in clock ticks and take seconds as `SO_LINGER_SEC`.
    #[cfg(target_vendor = "apple")]
    let option = libc::SO_LINGER_SEC;
    #[cfg(not(target_vendor = "apple"))]
    let option = libc::SO_LINGER;
    let linger = libc::linger { l_onoff: 1, l_linger: 30 };
    // SAFETY: the option reads a `linger`.
    let set = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw const linger).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(set, 0, "{}", io::Error::last_os_error());
}

/// [`linger`] for Windows sockets.
#[cfg(windows)]
fn linger(stream: &TcpStream) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{LINGER, SO_LINGER, SOL_SOCKET, WSAGetLastError, setsockopt};
    let linger = LINGER { l_onoff: 1, l_linger: 30 };
    // SAFETY: the option reads a `LINGER`.
    let set = unsafe {
        setsockopt(stream.as_raw_socket() as usize, SOL_SOCKET, SO_LINGER, (&raw const linger).cast(), size_of::<LINGER>() as i32)
    };
    // SAFETY: reads the calling thread's last socket error.
    assert_eq!(set, 0, "{}", io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
}

/// Closes `stream`, waiting as [`linger`] made it, on a thread of its own.
async fn close(stream: TcpStream) {
    let stream = stream.into_std().unwrap();
    stream.set_nonblocking(false).unwrap();
    tokio::task::spawn_blocking(move || drop(stream)).await.unwrap();
}

/// Sends `size` bytes of the pattern starting at `seed` and checks `size` bytes of the pattern
/// starting at `expect` coming back.
async fn exchange(stream: TcpStream, size: u64, seed: u64, expect: u64) {
    linger(&stream);
    let (mut read, mut write) = stream.into_split();
    let sending = tokio::spawn(async move {
        let mut buffer = vec![0u8; 256 * 1024];
        let mut sent = 0u64;
        while sent < size {
            let chunk = (size - sent).min(buffer.len() as u64) as usize;
            pattern(seed + sent, &mut buffer[..chunk]);
            write.write_all(&buffer[..chunk]).await.unwrap();
            sent += chunk as u64;
        }
        write.shutdown().await.unwrap();
        write
    });
    let mut buffer = vec![0u8; 256 * 1024];
    let mut wanted = vec![0u8; 256 * 1024];
    let mut received = 0u64;
    loop {
        let n = read.read(&mut buffer).await.unwrap();
        if n == 0 {
            break;
        }
        pattern(expect + received, &mut wanted[..n]);
        assert!(buffer[..n] == wanted[..n], "bytes after {received} differ");
        received += n as u64;
    }
    assert_eq!(received, size);
    let write = sending.await.unwrap();
    close(read.reunite(write).unwrap()).await;
}

/// Moves `size` bytes each way over `connections` connections through the reflector.
pub async fn transfer(nat: Nat, size: u64, connections: usize) {
    let listener = TcpListener::bind(SocketAddr::new(nat.local, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..connections {
            let (stream, from) = listener.accept().await.unwrap();
            assert_eq!(from.ip(), nat.other);
            tasks.push(tokio::spawn(exchange(stream, size, 1 << 40, 0)));
        }
        for task in tasks {
            task.await.unwrap();
        }
    });
    let mut clients = Vec::new();
    for _ in 0..connections {
        clients.push(tokio::spawn(async move {
            let stream = TcpStream::connect(SocketAddr::new(nat.peer, port)).await.unwrap();
            exchange(stream, size, 0, 1 << 40).await;
        }));
    }
    for client in clients {
        tokio::time::timeout(Duration::from_secs(120), client).await.expect("the transfer finishes").unwrap();
    }
    server.await.unwrap();
}

/// How many writers of one queue write at the same time in [`several_writers`].
const WRITERS: usize = 4;
/// How many datagrams each of them sends in a round, two with every call.
const EACH: u32 = 50;

/// The two datagrams of one call in a round of [`several_writers`], as the device takes them.
fn pair(wrap: &(impl Fn(&[u8]) -> Vec<u8> + ?Sized), round: u8, writer: usize, first: u32) -> [Vec<u8>; 2] {
    [first, first + 1].map(|number| wrap(&[&[round, writer as u8][..], &number.to_be_bytes()].concat()))
}

/// Reads the datagrams of one round of [`several_writers`]: those of each writer arrive in the
/// order it sent them, and none is missing.
fn arrive_in_order(socket: &std::net::UdpSocket, round: u8) {
    let mut next = [0u32; WRITERS];
    let mut datagram = [0u8; 16];
    for _ in 0..WRITERS as u32 * EACH {
        let (size, _) = socket.recv_from(&mut datagram).expect("every datagram arrives within the timeout");
        assert_eq!((size, datagram[0]), (6, round));
        let writer = usize::from(datagram[1]);
        let number = u32::from_be_bytes(datagram[2..6].try_into().unwrap());
        assert_eq!(number, next[writer], "the datagrams of writer {writer} arrive in the order it sent them");
        next[writer] += 1;
    }
}

/// Four writers of one queue, `writer` and three made of it, send datagrams to `socket` at the
/// same time: first each on a thread of its own with blocking calls, then each in a task of its
/// own. `wrap` puts a payload into a datagram for the socket, as the device takes it.
pub async fn several_writers<L: Layer>(writer: Writer<L>, socket: std::net::UdpSocket, wrap: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static) {
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut writers = vec![writer];
    for _ in 1..WRITERS {
        writers.push(writers[0].try_clone().unwrap());
    }
    std::thread::scope(|scope| {
        for (index, writer) in writers.iter_mut().enumerate() {
            let wrap = &wrap;
            scope.spawn(move || {
                for first in (0..EACH).step_by(2) {
                    let [one, two] = pair(wrap, 0, index, first);
                    writer.blocking_send(&[Packet::new(&one).with_checksum(Checksum::Valid), Packet::new(&two).with_checksum(Checksum::Valid)]).unwrap();
                }
            });
        }
        arrive_in_order(&socket, 0);
    });
    let wrap = Arc::new(wrap);
    let tasks: Vec<_> = writers
        .into_iter()
        .enumerate()
        .map(|(index, mut writer)| {
            let wrap = wrap.clone();
            tokio::spawn(async move {
                for first in (0..EACH).step_by(2) {
                    let [one, two] = pair(&*wrap, 1, index, first);
                    writer.send(&[Packet::new(&one).with_checksum(Checksum::Valid), Packet::new(&two).with_checksum(Checksum::Valid)]).await.unwrap();
                }
                writer
            })
        })
        .collect();
    tokio::task::block_in_place(|| arrive_in_order(&socket, 1));
    for task in tasks {
        let stats = task.await.unwrap().stats();
        assert_eq!((stats.packets, stats.dropped), (u64::from(EACH) * 2, 0), "every writer counts what it wrote itself");
    }
}

/// Stops tasks and waits until they are dropped, so their queues close.
pub async fn stop(tasks: Vec<JoinHandle<io::Result<()>>>) {
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}
