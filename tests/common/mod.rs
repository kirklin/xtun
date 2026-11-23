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
use xtun::{Checksum, Layer, Packet, Reader, Writer};
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
}

impl Counters {
    pub fn get(&self) -> (u64, u64, u64) {
        (self.segments.load(Ordering::Relaxed), self.packets.load(Ordering::Relaxed), self.writes.load(Ordering::Relaxed))
    }
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
        let after = writer.stats();
        counters.packets.fetch_add(after.packets - before.packets, Ordering::Relaxed);
        counters.writes.fetch_add(after.writes - before.writes, Ordering::Relaxed);
    }
}

/// Reflects until reading or writing fails.
pub async fn reflect<L: Layer>(mut reader: Reader<L>, mut writer: Writer<L>, nat: Nat, mode: Mode, counters: Arc<Counters>) -> io::Result<()> {
    if mode == Mode::Packets {
        return reflect_packets(reader, writer, nat, counters).await;
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
            Mode::Split => {
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
                let packets: Vec<Packet<'_>> =
                    pool[..used].iter().map(|(buffer, checksum)| Packet::new(buffer).with_checksum(*checksum)).collect();
                writer.send(&packets).await?;
            }
            Mode::Packets => unreachable!("reflected packet by packet"),
        }
        let after = writer.stats();
        counters.packets.fetch_add(after.packets - before.packets, Ordering::Relaxed);
        counters.writes.fetch_add(after.writes - before.writes, Ordering::Relaxed);
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
/// keep a route to the address that outlives the test.
fn linger(stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    let linger = libc::linger { l_onoff: 1, l_linger: 30 };
    // SAFETY: the option reads a `linger`.
    let set = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(set, 0, "{}", io::Error::last_os_error());
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

/// Stops tasks and waits until they are dropped, so their queues close.
pub async fn stop(tasks: Vec<JoinHandle<io::Result<()>>>) {
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}
