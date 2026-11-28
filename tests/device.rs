//! Tests on real interfaces. They need the privilege to create interfaces and are ignored by
//! default: `cargo test -- --ignored --test-threads=1` as root, or `node scripts/linux.ts`.

#![cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos"
))]

mod common;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use common::{Build, Counters, Mode, Nat, assert_joined, reflect, retransmitted, several_writers, stop, transfer};
use xtun::{Builder, Checksum, Packet, Queue, Reader, Tun, Writer};
use ipnet::IpNet;
use tokio::net::UdpSocket;

fn net(text: &str) -> IpNet {
    text.parse().unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// Whether the system is Linux, which Android is too.
const LINUX: bool = cfg!(any(target_os = "linux", target_os = "android"));
/// The kernel release of a Linux system as major and minor number.
fn linux_version() -> (u32, u32) {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut numbers = release.split(|c: char| !c.is_ascii_digit()).map(|part| part.parse::<u32>().unwrap());
    (numbers.next().unwrap(), numbers.next().unwrap())
}

/// Whether the library reads and writes through io_uring here: 64-bit Linux from 6.4 on has it,
/// and Android does not let applications use it.
fn uring_here() -> bool {
    cfg!(all(target_os = "linux", target_pointer_width = "64")) && linux_version() >= (6, 4)
}

/// A builder for a device named per test on Linux; macOS picks utun names itself.
fn builder(name: &str) -> Builder {
    let builder = Tun::builder();
    if LINUX { builder.name(name) } else { builder }
}

/// Both ends of the only queue of a device.
fn ends(mut queues: Vec<Queue>) -> (Reader, Writer) {
    assert_eq!(queues.len(), 1);
    queues.remove(0).split().unwrap()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn with_queues(builder: Builder, queues: usize) -> Builder {
    builder.queues(queues)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn with_queues(builder: Builder, queues: usize) -> Builder {
    assert_eq!(queues, 1, "only Linux has more than one queue");
    builder
}

#[cfg(target_os = "linux")]
fn uring(builder: Builder, on: bool) -> Builder {
    builder.uring(if on { xtun::Uring::Required } else { xtun::Uring::Off })
}

#[cfg(not(target_os = "linux"))]
fn uring(builder: Builder, on: bool) -> Builder {
    assert!(!on, "only Linux has io_uring");
    builder
}

fn exists(name: &str) -> bool {
    let name = std::ffi::CString::new(name).unwrap();
    // SAFETY: a NUL-terminated name.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn configures_the_interface() {
    let (device, queues) = builder("xtuntest0").mtu(1400).address(net("10.71.0.1/24")).address(net("fd71::1/64")).build().unwrap();
    let name = device.name().unwrap();
    assert!(exists(&name));
    assert!(device.index() > 0);
    assert_eq!(device.mtu().unwrap(), 1400);
    let addresses = device.addresses().unwrap();
    assert!(addresses.contains(&net("10.71.0.1/24")), "{addresses:?}");
    assert!(addresses.contains(&net("fd71::1/64")), "{addresses:?}");
    device.set_mtu(1500).unwrap();
    assert_eq!(device.mtu().unwrap(), 1500);
    device.add_address(net("10.71.1.1/24")).unwrap();
    assert!(device.addresses().unwrap().contains(&net("10.71.1.1/24")));
    assert_eq!(route_device("10.71.1.2"), name, "the subnet of an address is reached through the interface");
    device.remove_address(net("10.71.1.1/24")).unwrap();
    assert!(!device.addresses().unwrap().contains(&net("10.71.1.1/24")));
    assert_ne!(route_device("10.71.1.2"), name, "the route to the subnet goes with the address");
    drop(device);
    assert!(exists(&name), "a queue keeps the interface");
    drop(queues);
    assert!(!exists(&name), "the interface is gone with its last handle");
}

async fn udp_round_trip(offload: bool, on: bool) {
    let builder = builder("xtuntest1").address(net("10.72.0.1/24")).address(net("fd72::1/64")).offload(offload);
    let (_device, queues) = uring(builder, on).build().unwrap();
    let (mut reader, mut writer) = ends(queues);
    for (local, remote) in [("10.72.0.1", "10.72.0.2"), ("fd72::1", "fd72::2")] {
        let socket = UdpSocket::bind(SocketAddr::new(ip(local), 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        socket.send_to(b"hello through the device", SocketAddr::new(ip(remote), 9)).await.unwrap();
        let (data, checksum) = loop {
            let mut batch = tokio::time::timeout(Duration::from_secs(5), reader.recv()).await.unwrap().unwrap();
            let found = batch.frames().find_map(|frame| {
                let data = frame.data();
                let v6 = data[0] >> 4 == 6;
                let header = if v6 { 40 } else { 20 };
                let udp = data[if v6 { 6 } else { 9 }] == 17;
                (udp && data[header + 2..header + 4] == 9u16.to_be_bytes()).then(|| (data.to_vec(), frame.checksum()))
            });
            if let Some(found) = found {
                break found;
            }
        };
        let header = if data[0] >> 4 == 6 { 40 } else { 20 };
        assert_eq!(&data[header + 8..], b"hello through the device");
        if offload && cfg!(any(target_os = "linux", target_os = "android", target_os = "openbsd")) {
            assert!(matches!(checksum, Checksum::Partial { .. }), "{checksum:?}");
        }
        let reply = Build { src: ip(remote), dst: ip(local), src_port: 9, dst_port: port, ttl: 64, id: 1 }.udp(b"and back");
        writer.send(&[Packet::new(&reply).with_checksum(Checksum::Valid)]).await.unwrap();
        let mut buffer = [0u8; 64];
        let (size, from) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(&buffer[..size], b"and back");
        assert_eq!(from, SocketAddr::new(ip(remote), 9));
    }
    assert_eq!(writer.stats().dropped, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn udp_round_trip_plain() {
    udp_round_trip(false, false).await;
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "openbsd"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn udp_round_trip_offload() {
    udp_round_trip(true, false).await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn udp_round_trip_uring() {
    if !uring_here() {
        let refused = uring(builder("xtuntest1"), true).build().unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::Unsupported, "a kernel without io_uring for TUN devices makes no device that needs it: {refused}");
        return;
    }
    udp_round_trip(true, true).await;
    udp_round_trip(false, true).await;
}

/// A subnet that no device of this run had before, as its number. Android closes the TCP
/// connections of an address a moment after the address goes with its device, and those of the
/// next device with it when that device has the same address.
fn fresh_subnet() -> u8 {
    static NEXT: AtomicU8 = AtomicU8::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

async fn through_reflector(offload: bool, mode: Mode, v6: bool, queues: usize, on: bool) {
    let subnet = fresh_subnet();
    let host = |number: u8| if v6 { format!("fd73:{subnet:x}::{number}") } else { format!("10.73.{subnet}.{number}") };
    let address = format!("{}/{}", host(1), if v6 { 64 } else { 24 });
    let builder = with_queues(builder("xtuntest2").address(net(&address)).offload(offload), queues);
    let (device, handed) = uring(builder, on).build().unwrap();
    assert_eq!(handed.len(), queues);
    let nat = Nat { local: ip(&host(1)), peer: ip(&host(2)), other: ip(&host(3)), link: 0 };
    let counters = Arc::new(Counters::default());
    let mut tasks = Vec::new();
    for queue in handed {
        let (reader, writer) = queue.split().unwrap();
        tasks.push(tokio::spawn(reflect(reader, writer, nat, mode, counters.clone())));
    }
    let before = retransmitted();
    transfer(nat, 16 << 20, queues * 2).await;
    stop(tasks).await;
    let again = retransmitted() - before;
    let (segments, packets, writes) = counters.get();
    println!("offload {offload} {mode:?} v6 {v6} queues {queues}: {}", counters.summary(&device.name().unwrap(), again));
    if offload && cfg!(any(target_os = "linux", target_os = "android", target_os = "openbsd")) {
        if mode != Mode::Packets {
            assert!(segments > 0, "the kernel hands over segments");
        }
        if matches!(mode, Mode::Split | Mode::Packets | Mode::Pieces) {
            assert_joined(packets, writes, again);
        }
    } else {
        assert_eq!(segments, 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_one_packet_at_a_time() {
    for v6 in [false, true] {
        through_reflector(false, Mode::Packets, v6, 1, false).await;
        if LINUX {
            through_reflector(true, Mode::Packets, v6, 1, false).await;
        }
        if uring_here() {
            through_reflector(true, Mode::Packets, v6, 1, true).await;
        }
    }
}

/// Reads packets until one ends with `tail`, skipping what the system sends on its own.
fn blocking_packet(reader: &mut xtun::Reader, tail: &[u8]) -> Vec<u8> {
    let mut buffer = [0u8; 2048];
    loop {
        let length = reader.blocking_recv_packet(&mut buffer).unwrap();
        if buffer[..length].ends_with(tail) {
            return buffer[..length].to_vec();
        }
    }
}

/// Waits with `blocking_recv_packet` until it fails, skipping what the system sends on its own.
fn blocking_failure(reader: &mut xtun::Reader) -> io::Error {
    let mut buffer = [0u8; 2048];
    loop {
        if let Err(error) = reader.blocking_recv_packet(&mut buffer) {
            return error;
        }
    }
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn blocking_calls_need_no_runtime() {
    let (_device, queues) = builder("xtuntest7").address(net("10.78.0.1/24")).build().unwrap();
    let (mut reader, mut writer) = ends(queues);
    reader.set_timeout(Some(Duration::from_secs(5)));
    let socket = std::net::UdpSocket::bind("10.78.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let port = socket.local_addr().unwrap().port();
    socket.send_to(b"blocking", "10.78.0.2:9").unwrap();
    let request = blocking_packet(&mut reader, b"blocking");
    assert_eq!(&request[28..], b"blocking");
    let reply = Build { src: ip("10.78.0.2"), dst: ip("10.78.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 2 }.udp(b"in pieces");
    let (head, tail) = reply.split_at(20);
    writer.blocking_send_vectored(&[io::IoSlice::new(head), io::IoSlice::new(tail)]).unwrap();
    let mut answer = [0u8; 64];
    let (size, _) = socket.recv_from(&mut answer).unwrap();
    assert_eq!(&answer[..size], b"in pieces");
    // A packet in more pieces than one write takes is refused, as `send_pieces` refuses it.
    let back = Build { src: ip("10.78.0.2"), dst: ip("10.78.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 3 };
    let (too_many, most) = (back.udp(&[7; 1024 - 28]), back.udp(&[7; 1023 - 28]));
    let crumbs: Vec<io::IoSlice<'_>> = too_many.chunks(1).map(io::IoSlice::new).collect();
    let refused = writer.blocking_send_vectored(&crumbs).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{refused}");
    let crumbs: Vec<io::IoSlice<'_>> = most.chunks(1).map(io::IoSlice::new).collect();
    writer.blocking_send_vectored(&crumbs).unwrap();
    let (size, _) = socket.recv_from(&mut [0u8; 1024]).unwrap();
    assert_eq!((size, writer.stats().dropped), (most.len() - 28, 0), "1023 pieces are taken");

    reader.set_timeout(Some(Duration::from_millis(100)));
    let started = std::time::Instant::now();
    assert_eq!(blocking_failure(&mut reader).kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= Duration::from_millis(100));

    reader.set_timeout(None);
    let interrupt = xtun::Interrupt::new().unwrap();
    reader.set_interrupt(Some(interrupt.clone()));
    let trigger = interrupt.clone();
    let triggering = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        trigger.trigger().unwrap();
    });
    assert_eq!(blocking_failure(&mut reader).kind(), io::ErrorKind::Interrupted);
    triggering.join().unwrap();
    assert_eq!(blocking_failure(&mut reader).kind(), io::ErrorKind::Interrupted, "the interrupt stays triggered");
    interrupt.reset().unwrap();
    socket.send_to(b"after the reset", "10.78.0.2:9").unwrap();
    reader.set_timeout(Some(Duration::from_secs(5)));
    blocking_packet(&mut reader, b"after the reset");
}

#[cfg(feature = "async-io")]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn round_trip_on_async_io() {
    async_io::block_on(async {
        let (_device, queues) = builder("xtuntest8").address(net("10.79.0.1/24")).build().unwrap();
        let (mut reader, mut writer) = ends(queues);
        let socket = async_io::Async::<std::net::UdpSocket>::bind(SocketAddr::new(ip("10.79.0.1"), 0)).unwrap();
        let port = socket.get_ref().local_addr().unwrap().port();
        socket.send_to(b"on async-io", SocketAddr::new(ip("10.79.0.2"), 9)).await.unwrap();
        let mut buffer = [0u8; 2048];
        loop {
            let length = reader.recv_packet(&mut buffer).await.unwrap();
            if buffer[..length].ends_with(b"on async-io") {
                break;
            }
        }
        let reply = Build { src: ip("10.79.0.2"), dst: ip("10.79.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 3 }.udp(b"back");
        writer.send(&[Packet::new(&reply)]).await.unwrap();
        let mut answer = [0u8; 64];
        let (size, _) = socket.recv_from(&mut answer).await.unwrap();
        assert_eq!(&answer[..size], b"back");
    });
}

#[cfg(feature = "futures")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn streams_and_sinks() {
    use futures_util::{SinkExt, StreamExt};
    let (_device, queues) = builder("xtuntest9").address(net("10.82.0.1/24")).build().unwrap();
    let (reader, writer) = ends(queues);
    let (mut stream, mut sink) = (reader.into_stream(), writer.into_sink());
    let socket = UdpSocket::bind("10.82.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    for round in 0..3 {
        socket.send_to(format!("item {round}").as_bytes(), "10.82.0.2:9").await.unwrap();
    }
    let mut seen = 0;
    while seen < 3 {
        let packet = tokio::time::timeout(Duration::from_secs(5), stream.next()).await.unwrap().unwrap().unwrap();
        if packet.ends_with(format!("item {seen}").as_bytes()) {
            seen += 1;
        }
    }
    for round in 0..3u16 {
        let reply = Build { src: ip("10.82.0.2"), dst: ip("10.82.0.1"), src_port: 9, dst_port: port, ttl: 64, id: round }
            .udp(format!("reply {round}").as_bytes());
        sink.feed(reply).await.unwrap();
    }
    sink.flush().await.unwrap();
    let mut answer = [0u8; 64];
    for round in 0..3 {
        let (size, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut answer)).await.unwrap().unwrap();
        assert_eq!(&answer[..size], format!("reply {round}").as_bytes());
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_through_the_device() {
    for v6 in [false, true] {
        for mode in [Mode::Pass, Mode::Split, Mode::Pieces, Mode::Kept, Mode::Mixed] {
            through_reflector(false, mode, v6, 1, false).await;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "openbsd"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_through_the_device_with_offload() {
    let rings: &[bool] = if uring_here() { &[false, true] } else { &[false] };
    for &on in rings {
        for v6 in [false, true] {
            for mode in [Mode::Pass, Mode::Split, Mode::Pieces, Mode::Kept, Mode::Mixed] {
                through_reflector(true, mode, v6, 1, on).await;
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_through_four_queues() {
    through_reflector(true, Mode::Split, false, 4, false).await;
    through_reflector(true, Mode::Pass, true, 4, uring_here()).await;
    through_reflector(true, Mode::Kept, false, 4, uring_here()).await;
    through_reflector(true, Mode::Pieces, true, 4, false).await;
    through_reflector(true, Mode::Mixed, true, 4, uring_here()).await;
}

/// A program that makes an interface right after another went away gets one. FreeBSD frees the
/// unit of a TUN interface that goes before its device is gone, and a device that is going may
/// still be handed out for a moment.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn interfaces_are_made_one_right_after_another() {
    for round in 0..50u64 {
        // Each interface has a subnet of its own: the one before may still be there.
        let made = Tun::builder().address(net(&format!("10.73.{round}.1/24"))).build();
        let (device, queues) = made.unwrap_or_else(|error| panic!("interface {round}: {error}"));
        // As in a program whose tasks hold the queues: they go a moment after the device, and
        // the next interface may be made before or after.
        let later = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(round % 3));
            drop(queues);
        });
        drop(device);
        if round % 2 == 0 {
            later.join().unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn a_device_hands_out_its_queues_once() {
    let (device, mut queues) = builder("xtuntest3").address(net("10.74.0.1/24")).build().unwrap();
    assert_eq!(queues.len(), 1);
    let queue = queues.remove(0);
    assert_eq!(queue.index(), 0);
    assert!(device.queue_fd(0).is_ok() && device.queue_fd(1).is_err());
    let (reader, writer) = queue.split_with_capacity(8).unwrap();
    assert_eq!((reader.stats().frames, writer.stats().packets), (0, 0));
    let (_other, mut queues) = builder("xtuntest20").address(net("10.74.1.1/24")).build().unwrap();
    let refused = queues.remove(0).split_with_capacity(0).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "a batch holds at least one frame");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn a_queue_takes_packets_from_several_writers() {
    let (_device, queues) = builder("xtuntest21").address(net("10.97.0.1/24")).build().unwrap();
    let (_reader, writer) = ends(queues);
    let socket = std::net::UdpSocket::bind("10.97.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let from = Build { src: ip("10.97.0.2"), dst: ip("10.97.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 3 };
    several_writers(writer, socket, move |payload| from.udp(payload)).await;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn a_deleted_interface_ends_the_reader() {
    let rings: &[bool] = if uring_here() { &[false, true] } else { &[false] };
    for &on in rings {
        let (_device, queues) = uring(builder("xtuntest4").address(net("10.75.0.1/24")), on).build().unwrap();
        let (mut reader, _writer) = ends(queues);
        // The kernel may send a packet of its own before the interface goes; only the error counts.
        let waiting = tokio::spawn(async move {
            loop {
                if let Err(error) = reader.recv().await {
                    return error;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let status = std::process::Command::new("ip").args(["link", "del", "xtuntest4"]).status().unwrap();
        assert!(status.success());
        let error = tokio::time::timeout(Duration::from_secs(2), waiting).await.unwrap_or_else(|_| panic!("the reader wakes up, io_uring {on}")).unwrap();
        assert_eq!(error.raw_os_error(), Some(libc::EBADFD), "{error}");
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn large_packets_without_offload() {
    let (device, queues) = builder("xtuntest5").address(net("10.76.0.1/24")).offload(false).build().unwrap();
    device.set_mtu(9000).unwrap();
    let (mut reader, _writer) = ends(queues);
    let socket = UdpSocket::bind("10.76.0.1:0").await.unwrap();
    socket.send_to(&vec![7u8; 8000], "10.76.0.2:9").await.unwrap();
    loop {
        let mut batch = tokio::time::timeout(Duration::from_secs(5), reader.recv()).await.unwrap().unwrap();
        if let Some(len) = batch.frames().map(|frame| frame.data().len()).find(|len| *len > 1000) {
            assert_eq!(len, 8028);
            break;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn adopts_a_descriptor() {
    use std::os::fd::{FromRawFd, OwnedFd};
    let flags = [(libc::IFF_TUN | libc::IFF_NO_PI, false), (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR, true)];
    // The device that hands out interfaces, which Android keeps at a place of its own.
    let clone_device = if cfg!(target_os = "android") { c"/dev/tun" } else { c"/dev/net/tun" };
    for (flags, offload) in flags {
        // SAFETY: plain open and ioctl on a request filled in here.
        let fd = unsafe {
            let fd = libc::open(clone_device.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            assert!(fd >= 0);
            let mut request: libc::ifreq = std::mem::zeroed();
            for (slot, byte) in request.ifr_name.iter_mut().zip(b"xtuntest6") {
                *slot = *byte as libc::c_char;
            }
            request.ifr_ifru.ifru_flags = flags as libc::c_short;
            assert!(libc::ioctl(fd, libc::TUNSETIFF, &mut request) >= 0);
            OwnedFd::from_raw_fd(fd)
        };
        // SAFETY: duplicates a descriptor that is open.
        let duplicate = unsafe { OwnedFd::from_raw_fd(libc::dup(std::os::fd::AsRawFd::as_raw_fd(&fd))) };
        let refused = xtun::Tap::from_fd(duplicate).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "a TUN descriptor makes no TAP device: {refused}");
        let (device, queue) = Tun::from_fd(fd).unwrap();
        assert_eq!(device.name().unwrap(), "xtuntest6");
        assert_eq!(device.offload().tcp, offload);
        device.add_address(net("10.77.0.1/24")).unwrap();
        assert!(std::process::Command::new("ip").args(["link", "set", "xtuntest6", "up"]).status().unwrap().success());
        let (mut reader, _writer) = queue.split().unwrap();
        let socket = UdpSocket::bind("10.77.0.1:0").await.unwrap();
        socket.send_to(b"adopted", "10.77.0.2:9").await.unwrap();
        loop {
            let mut batch = tokio::time::timeout(Duration::from_secs(5), reader.recv()).await.unwrap().unwrap();
            if batch.frames().any(|frame| frame.data().ends_with(b"adopted")) {
                break;
            }
        }
    }
}

/// A descriptor whose interface lives in another network namespace is adopted without its
/// interface, which an interface of the same name here does not stand for.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn adopts_a_descriptor_of_another_namespace() {
    let (device, mut queues) = builder("xtuntest23").build().unwrap();
    let fd = device.into_fd(queues.remove(0)).unwrap();
    // This thread and what it starts move to a namespace of their own.
    // SAFETY: changes the namespace of this thread alone.
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
    run("ip", &["link", "add", "xtuntest23", "type", "dummy"]);
    let (adopted, queue) = Tun::from_fd(fd).unwrap();
    let refused = adopted.name().unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::Unsupported, "{refused}");
    assert!(adopted.set_mtu(1300).is_err());
    assert!(run("ip", &["link", "show", "xtuntest23"]).contains("mtu 1500"), "the interface here is left alone");
    drop((adopted, queue));
}

/// Runs a system tool and returns what it printed; it has to succeed.
fn run(program: &str, args: &[&str]) -> String {
    let output = std::process::Command::new(program).args(args).output().unwrap();
    assert!(output.status.success(), "{program} {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

/// The interface through which the system sends packets for `ip`.
fn route_device(ip: &str) -> String {
    if LINUX {
        let shown = run("ip", &["route", "get", ip]);
        shown.split_whitespace().skip_while(|word| *word != "dev").nth(1).unwrap_or_default().to_owned()
    } else {
        // Without the family, `route` takes an IPv6 address for a host name to look up.
        let family = if ip.contains(':') { "-inet6" } else { "-inet" };
        let shown = run("route", &["-n", "get", family, ip]);
        shown.lines().find_map(|line| line.trim().strip_prefix("interface: ")).unwrap_or_default().to_owned()
    }
}

/// Waits up to two seconds for `condition`, which the kernel may make true a moment later.
fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(2) {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Sends a datagram from `from` to port 9 of `to` and finds it in what the reader reads.
fn sent_through(reader: &mut xtun::Reader, from: &str, to: &str, text: &[u8]) -> Vec<u8> {
    let socket = std::net::UdpSocket::bind(SocketAddr::new(ip(from), 0)).unwrap();
    socket.send_to(text, SocketAddr::new(ip(to), 9)).unwrap();
    reader.set_timeout(Some(Duration::from_secs(5)));
    blocking_packet(reader, text)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn renames_and_brings_up_and_down() {
    let (device, _queues) = builder("xtuntest10").up(false).build().unwrap();
    assert!(!device.is_up().unwrap());
    assert!(!device.is_running().unwrap());
    device.set_name("xtuntest11").unwrap();
    assert_eq!(device.name().unwrap(), "xtuntest11");
    assert!(exists("xtuntest11") && !exists("xtuntest10"));
    device.set_up(true).unwrap();
    assert!(device.is_up().unwrap());
    assert!(eventually(|| device.is_running().unwrap()), "a TUN interface has a link while a queue is open");
    match device.set_name("xtuntest10") {
        // Linux renames an interface that is up from 6.2 on, and so does an older kernel that a
        // distribution has brought the change to.
        Ok(()) => assert_eq!(device.name().unwrap(), "xtuntest10"),
        Err(error) => {
            let version = linux_version();
            assert!(version < (6, 2), "Linux {}.{} renames interfaces that are up: {error}", version.0, version.1);
            assert_eq!(error.raw_os_error(), Some(libc::EBUSY), "{error}");
        }
    }
    device.set_up(false).unwrap();
    assert!(!device.is_up().unwrap());
    assert!(!device.is_running().unwrap());
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn brings_up_and_down() {
    // FreeBSD runs a tun interface once it has an address.
    let (device, _queues) = builder("xtuntest10").address(net("10.96.0.1/24")).up(false).build().unwrap();
    assert!(!device.is_up().unwrap());
    device.set_up(true).unwrap();
    assert!(device.is_up().unwrap());
    assert!(eventually(|| device.is_running().unwrap()));
    device.set_up(false).unwrap();
    assert!(!device.is_up().unwrap());
    // FreeBSD renames interfaces; the others keep their names.
    let renamed = device.set_name("xtun7");
    if cfg!(target_os = "freebsd") {
        renamed.unwrap();
        assert_eq!(device.name().unwrap(), "xtun7");
        assert!(exists("xtun7"));
    } else {
        assert_eq!(renamed.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
    if cfg!(target_vendor = "apple") {
        assert_eq!(device.set_persist(true).unwrap_err().kind(), io::ErrorKind::Unsupported, "a utun interface goes with its socket");
    }
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn point_to_point_addresses() {
    let (device, queues) = builder("xtuntest12").peer_address(net("10.83.0.1/32"), ip("10.83.0.2")).build().unwrap();
    device.add_peer_address(net("fd83::1/128"), ip("fd83::2")).unwrap();
    let addresses = device.addresses().unwrap();
    assert!(addresses.contains(&net("10.83.0.1/32")), "{addresses:?}");
    assert!(addresses.contains(&net("fd83::1/128")), "{addresses:?}");
    if LINUX {
        let shown = run("ip", &["addr", "show", "dev", "xtuntest12"]);
        assert!(shown.contains("peer 10.83.0.2/32") && shown.contains("peer fd83::2/128"), "{shown}");
    }
    let (mut reader, _writer) = ends(queues);
    let request = sent_through(&mut reader, "10.83.0.1", "10.83.0.2", b"to the far end");
    assert_eq!(&request[16..20], &[10, 83, 0, 2]);
    sent_through(&mut reader, "fd83::1", "fd83::2", b"to the far end over IPv6");
    assert!(device.add_peer_address(net("10.83.1.1/32"), ip("fd83::3")).is_err(), "the far end has the address's IP version");
    device.remove_address(net("10.83.0.1/32")).unwrap();
    assert!(!device.addresses().unwrap().contains(&net("10.83.0.1/32")));
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn broadcast_and_one_address_per_version() {
    let (device, _queues) = builder("xtuntest13").address(net("10.84.0.1/24")).address(net("fd84::1/64")).build().unwrap();
    if LINUX {
        assert_eq!(device.broadcast().unwrap(), Some("10.84.0.255".parse().unwrap()));
        device.set_broadcast("10.84.0.254".parse().unwrap()).unwrap();
        assert_eq!(device.broadcast().unwrap(), Some("10.84.0.254".parse().unwrap()));
    } else {
        assert_eq!(device.broadcast().unwrap_err().kind(), io::ErrorKind::Unsupported, "a utun interface is point to point");
    }
    device.add_address(net("10.84.1.1/24")).unwrap();
    device.set_address(net("10.84.2.1/24")).unwrap();
    let addresses = device.addresses().unwrap();
    let v4: Vec<_> = addresses.iter().filter(|net| net.addr().is_ipv4()).collect();
    assert_eq!(v4, [&net("10.84.2.1/24")], "{addresses:?}");
    assert!(addresses.contains(&net("fd84::1/64")), "the other IP version keeps its address: {addresses:?}");
    // The address stays and takes the other prefix.
    for (from, to) in [("10.84.2.1/24", "10.84.2.1/16"), ("fd84::1/64", "fd84::1/48"), ("10.84.2.1/16", "10.84.2.1/24")] {
        device.set_address(net(to)).unwrap_or_else(|error| panic!("{from} to {to}: {error}"));
        let addresses = device.addresses().unwrap();
        let same: Vec<_> = addresses.iter().filter(|net| net.addr() == self::net(to).addr()).collect();
        assert_eq!(same, [&net(to)], "{from} to {to}: {addresses:?}");
    }
    if LINUX {
        assert_eq!(device.broadcast().unwrap(), Some("10.84.2.255".parse().unwrap()));
        // A subnet of one or two addresses has none to broadcast to.
        device.set_address(net("10.84.3.1/31")).unwrap();
        assert_eq!(device.broadcast().unwrap(), None);
    }
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn routes_through_the_interface() {
    let (device, queues) = builder("xtuntest14").address(net("10.85.0.1/24")).address(net("fd85::1/64")).build().unwrap();
    let name = device.name().unwrap();
    let (mut reader, _writer) = ends(queues);
    device.add_route(net("10.86.0.0/16"), None).unwrap();
    device.add_route(net("10.87.0.0/16"), Some(ip("10.85.0.2"))).unwrap();
    device.add_route(net("fd86::/48"), None).unwrap();
    assert_eq!(route_device("10.86.1.1"), name);
    assert_eq!(route_device("10.87.1.1"), name);
    assert_eq!(route_device("fd86::1"), name);
    if LINUX {
        let shown = run("ip", &["route", "show", "10.87.0.0/16"]);
        assert!(shown.contains(&format!("via 10.85.0.2 dev {name}")), "{shown}");
    }
    let refused = device.add_route(net("10.86.0.0/16"), None).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists, "{refused}");
    sent_through(&mut reader, "10.85.0.1", "10.86.1.1", b"routed");
    sent_through(&mut reader, "10.85.0.1", "10.87.1.1", b"routed through a gateway");
    sent_through(&mut reader, "fd85::1", "fd86::1", b"routed over IPv6");
    device.remove_route(net("10.86.0.0/16"), None).unwrap();
    device.remove_route(net("10.87.0.0/16"), Some(ip("10.85.0.2"))).unwrap();
    device.remove_route(net("fd86::/48"), None).unwrap();
    assert_ne!(route_device("10.86.1.1"), name);
    assert_ne!(route_device("10.87.1.1"), name);
    assert!(device.remove_route(net("10.86.0.0/16"), None).is_err(), "the route is gone");

    device.set_prefix_routes(false);
    assert!(!device.prefix_routes());
    device.add_address(net("10.88.0.1/24")).unwrap();
    assert!(device.addresses().unwrap().contains(&net("10.88.0.1/24")));
    assert_ne!(route_device("10.88.0.2"), name, "an address without a prefix route leaves its subnet alone");
    device.set_prefix_routes(true);
    device.add_address(net("10.88.1.1/24")).unwrap();
    assert_eq!(route_device("10.88.1.2"), name);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn queue_length_persistence_and_exclusive_names() {
    let (device, queues) = builder("xtuntest15").tx_queue_len(2000).persist(true).build().unwrap();
    assert_eq!(device.tx_queue_len().unwrap(), 2000);
    device.set_tx_queue_len(100).unwrap();
    assert_eq!(device.tx_queue_len().unwrap(), 100);
    drop((device, queues));
    assert!(exists("xtuntest15"), "a persistent interface stays");
    let taken = builder("xtuntest15").reuse(false).build().unwrap_err();
    assert_eq!(taken.kind(), io::ErrorKind::ResourceBusy, "{taken}");
    let (device, queues) = builder("xtuntest15").build().unwrap();
    assert_eq!(device.tx_queue_len().unwrap(), 100, "the interface was taken over as it was");
    device.set_persist(false).unwrap();
    drop((device, queues));
    assert!(!exists("xtuntest15"));
    // A builder told that the interface does not persist takes the persistence off one it takes over.
    drop(builder("xtuntest15").persist(true).build().unwrap());
    drop(builder("xtuntest15").persist(false).build().unwrap());
    assert!(!exists("xtuntest15"));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn owner_group_and_more_queues() {
    let sysfs = |what: &str| std::fs::read_to_string(format!("/sys/class/net/xtuntest16/{what}")).unwrap().trim().to_owned();
    let (device, queues) = builder("xtuntest16").queues(2).owner(1234).group(5678).build().unwrap();
    assert_eq!(queues.iter().map(|queue| queue.index()).collect::<Vec<_>>(), [0, 1]);
    assert_eq!((sysfs("owner"), sysfs("group")), ("1234".to_owned(), "5678".to_owned()));
    device.set_owner(4321).unwrap();
    device.set_group(8765).unwrap();
    assert_eq!((sysfs("owner"), sysfs("group")), ("4321".to_owned(), "8765".to_owned()));
    let added = device.add_queue().unwrap();
    assert_eq!(added.index(), 2);
    let (_reader, _writer) = added.split().unwrap();
    assert!(device.queue_fd(2).is_ok() && device.queue_fd(3).is_err());
    let (single, _queues) = builder("xtuntest17").build().unwrap();
    assert_eq!(single.add_queue().unwrap_err().kind(), io::ErrorKind::Unsupported);
}

/// A packet tunnel provider finds the utun interface that the system opened for its process
/// among the process's descriptors. A process that made a utun interface itself has one too.
#[cfg(target_vendor = "apple")]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn finds_the_utun_interface_of_the_process() {
    let (device, queues) = builder("xtuntest20").address(net("10.92.0.1/24")).build().unwrap();
    let name = device.name().unwrap();
    let (found, queue) = Tun::from_packet_tunnel().unwrap();
    assert_eq!(found.name().unwrap(), name);
    drop((device, queues));
    assert!(exists(&name), "the duplicate of the descriptor keeps the interface");
    let (mut reader, _writer) = queue.split().unwrap();
    sent_through(&mut reader, "10.92.0.1", "10.92.0.2", b"through the duplicate");
}

/// The receive buffer of a utun socket and the packets its interface queues for the reader are
/// what the builder and the device say, the packets never more than fit the buffer.
#[cfg(target_vendor = "apple")]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn receive_buffer_and_pending_packets() {
    let (device, queues) = builder("xtuntest24").build().unwrap();
    assert!(device.receive_buffer().unwrap() >= 1 << 20);
    assert_eq!(device.max_pending_packets().unwrap(), 64);
    drop((device, queues));

    let tuned = |device: &Tun| (device.receive_buffer().unwrap(), device.max_pending_packets().unwrap());
    let (device, _queues) = builder("xtuntest24").receive_buffer(256 << 10).max_pending_packets(150).build().unwrap();
    assert_eq!(tuned(&device), (256 << 10, 150));
    // Larger packets fit fewer to the buffer, and the number the builder named is back with
    // the MTU that has room for it.
    device.set_mtu(2000).unwrap();
    assert_eq!(tuned(&device), (256 << 10, 114));
    device.set_mtu(1500).unwrap();
    assert_eq!(tuned(&device), (256 << 10, 150));
    // More packets than fit the buffer are cut down to what fits, until the buffer has room.
    device.set_max_pending_packets(1000).unwrap();
    assert_eq!(tuned(&device), (256 << 10, 152));
    device.set_receive_buffer(4 << 20).unwrap();
    assert_eq!(tuned(&device), (4 << 20, 1000));
    // What the system could not take is refused and changes nothing: the system would cut a
    // buffer above its limit down to the limit.
    assert_eq!(device.set_max_pending_packets(0).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert_eq!(device.set_receive_buffer(0).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    let above = i32::MAX as u32;
    assert!(device.set_receive_buffer(above).is_err(), "a buffer above the system's limit");
    assert_eq!(tuned(&device), (4 << 20, 1000));
    assert!(builder("xtuntest24").receive_buffer(above).build().is_err(), "a buffer above the system's limit");
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn hands_over_its_descriptor() {
    let (device, mut queues) = builder("xtuntest18").address(net("10.90.0.1/24")).build().unwrap();
    let name = device.name().unwrap();
    let queue = queues.remove(0);
    let handle = device.clone();
    let (device, queue) = device.into_fd(queue).unwrap_err();
    assert_eq!(queue.index(), 0);
    drop(handle);
    // The queue of another device is given back as it was: no queue of this device comes of it.
    let (other, mut others) = builder("xtuntest22").build().unwrap();
    let (device, foreign) = device.into_fd(others.remove(0)).unwrap_err();
    let fd = device.into_fd(queue).unwrap();
    drop((other, foreign));
    let (device, queue) = match Tun::from_fd(fd) {
        Ok(adopted) => adopted,
        // The tun driver OmniOS ships is older than the request that tells a descriptor's unit.
        Err(error) if cfg!(target_os = "illumos") && error.kind() == io::ErrorKind::Unsupported => return,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(device.name().unwrap(), name);
    let (mut reader, _writer) = queue.split().unwrap();
    sent_through(&mut reader, "10.90.0.1", "10.90.0.2", b"through the handed over descriptor");
    // NetBSD keeps the interface after the descriptor is closed, unless the device removes it.
    device.set_persist(false).unwrap();
}

#[cfg(not(target_os = "illumos"))]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn frames_with_packet_information() {
    let (device, queues) = builder("xtuntest19").address(net("10.91.0.1/24")).packet_information(true).build().unwrap();
    assert!(device.packet_information());
    assert!(!device.offload().tcp, "packet information rules out offloads");
    let (mut reader, mut writer) = ends(queues);
    // Linux puts flags and the Ethernet protocol in front, the Apple systems the address family.
    let information: [u8; 4] = if LINUX { [0, 0, 0x08, 0x00] } else { (libc::AF_INET as u32).to_be_bytes() };
    let socket = std::net::UdpSocket::bind("10.91.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let port = socket.local_addr().unwrap().port();
    socket.send_to(b"with information", "10.91.0.2:9").unwrap();
    reader.set_timeout(Some(Duration::from_secs(5)));
    let frame = blocking_packet(&mut reader, b"with information");
    assert_eq!(frame[..4], information);
    assert_eq!(frame[4] >> 4, 4);
    let reply = Build { src: ip("10.91.0.2"), dst: ip("10.91.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 4 }.udp(b"back with information");
    writer.blocking_send(&[Packet::new(&[&information[..], &reply].concat())]).unwrap();
    let mut answer = [0u8; 64];
    let (size, _) = socket.recv_from(&mut answer).unwrap();
    assert_eq!(&answer[..size], b"back with information");
}
