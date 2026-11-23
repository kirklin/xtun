//! Tests on real interfaces. They need the privilege to create interfaces and are ignored by
//! default: `cargo test -- --ignored --test-threads=1` as root, or `node scripts/linux.ts`.

#![cfg(any(target_os = "linux", target_os = "android"))]

mod common;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::{Build, Counters, Mode, Nat, reflect, stop, transfer};
use xtun::{Builder, Checksum, Packet, Queue, Reader, Tun, Writer};
use ipnet::IpNet;
use tokio::net::UdpSocket;

fn net(text: &str) -> IpNet {
    text.parse().unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A builder for a device named per test.
fn builder(name: &str) -> Builder {
    Tun::builder().name(name)
}

/// Both ends of the only queue of a device.
fn ends(mut queues: Vec<Queue>) -> (Reader, Writer) {
    assert_eq!(queues.len(), 1);
    queues.remove(0).split().unwrap()
}

fn with_queues(builder: Builder, queues: usize) -> Builder {
    builder.queues(queues)
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

async fn udp_round_trip(offload: bool) {
    let (_device, queues) = builder("xtuntest1").address(net("10.72.0.1/24")).address(net("fd72::1/64")).offload(offload).build().unwrap();
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
        if offload {
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
    udp_round_trip(false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn udp_round_trip_offload() {
    udp_round_trip(true).await;
}

async fn through_reflector(offload: bool, mode: Mode, v6: bool, queues: usize) {
    let (local, peer, other, subnet) = if v6 {
        ("fd73::1", "fd73::2", "fd73::3", "fd73::1/64")
    } else {
        ("10.73.0.1", "10.73.0.2", "10.73.0.3", "10.73.0.1/24")
    };
    let (_device, handed) = with_queues(builder("xtuntest2").address(net(subnet)).offload(offload), queues).build().unwrap();
    assert_eq!(handed.len(), queues);
    let nat = Nat { local: ip(local), peer: ip(peer), other: ip(other), link: 0 };
    let counters = Arc::new(Counters::default());
    let mut tasks = Vec::new();
    for queue in handed {
        let (reader, writer) = queue.split().unwrap();
        tasks.push(tokio::spawn(reflect(reader, writer, nat, mode, counters.clone())));
    }
    transfer(nat, 16 << 20, queues * 2).await;
    stop(tasks).await;
    let (segments, packets, writes) = counters.get();
    println!("offload {offload} {mode:?} v6 {v6} queues {queues}: {segments} segments read, {packets} packets in {writes} writes");
    if offload {
        if mode != Mode::Packets {
            assert!(segments > 0, "the kernel hands over segments");
        }
        if mode != Mode::Pass {
            // Without joining every packet is a write of its own. How many packets go into a
            // write depends on how many of them are bare acknowledgements, which nothing joins.
            assert!(packets > writes * 2, "cut packets are joined again: {packets} packets in {writes} writes");
        }
    } else {
        assert_eq!(segments, 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_one_packet_at_a_time() {
    for v6 in [false, true] {
        through_reflector(false, Mode::Packets, v6, 1).await;
        through_reflector(true, Mode::Packets, v6, 1).await;
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
        through_reflector(false, Mode::Pass, v6, 1).await;
        through_reflector(false, Mode::Split, v6, 1).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_through_the_device_with_offload() {
    for v6 in [false, true] {
        through_reflector(true, Mode::Pass, v6, 1).await;
        through_reflector(true, Mode::Split, v6, 1).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_through_four_queues() {
    through_reflector(true, Mode::Split, false, 4).await;
    through_reflector(true, Mode::Pass, true, 4).await;
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
async fn a_deleted_interface_ends_the_reader() {
    let (_device, queues) = builder("xtuntest4").address(net("10.75.0.1/24")).build().unwrap();
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
    let error = tokio::time::timeout(Duration::from_secs(2), waiting).await.expect("the reader wakes up").unwrap();
    assert_eq!(error.raw_os_error(), Some(libc::EBADFD), "{error}");
}

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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn adopts_a_descriptor() {
    use std::os::fd::{FromRawFd, OwnedFd};
    let flags = [(libc::IFF_TUN | libc::IFF_NO_PI, false), (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR, true)];
    for (flags, offload) in flags {
        // SAFETY: plain open and ioctl on a request filled in here.
        let fd = unsafe {
            let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
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

/// Runs a system tool and returns what it printed; it has to succeed.
fn run(program: &str, args: &[&str]) -> String {
    let output = std::process::Command::new(program).args(args).output().unwrap();
    assert!(output.status.success(), "{program} {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

/// The interface through which the system sends packets for `ip`.
fn route_device(ip: &str) -> String {
    let shown = run("ip", &["route", "get", ip]);
    shown.split_whitespace().skip_while(|word| *word != "dev").nth(1).unwrap_or_default().to_owned()
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
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut numbers = release.split(|c: char| !c.is_ascii_digit()).map(|part| part.parse::<u32>().unwrap());
    let version = (numbers.next().unwrap(), numbers.next().unwrap());
    match device.set_name("xtuntest10") {
        Ok(()) => {
            assert!(version >= (6, 2), "Linux {release} renamed an interface that is up");
            assert_eq!(device.name().unwrap(), "xtuntest10");
        }
        Err(error) => {
            assert!(version < (6, 2), "Linux {release} renames interfaces that are up: {error}");
            assert_eq!(error.raw_os_error(), Some(libc::EBUSY), "{error}");
        }
    }
    device.set_up(false).unwrap();
    assert!(!device.is_up().unwrap());
    assert!(!device.is_running().unwrap());
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn point_to_point_addresses() {
    let (device, queues) = builder("xtuntest12").peer_address(net("10.83.0.1/32"), ip("10.83.0.2")).build().unwrap();
    device.add_peer_address(net("fd83::1/128"), ip("fd83::2")).unwrap();
    let addresses = device.addresses().unwrap();
    assert!(addresses.contains(&net("10.83.0.1/32")), "{addresses:?}");
    assert!(addresses.contains(&net("fd83::1/128")), "{addresses:?}");
    let shown = run("ip", &["addr", "show", "dev", "xtuntest12"]);
    assert!(shown.contains("peer 10.83.0.2/32") && shown.contains("peer fd83::2/128"), "{shown}");
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
    assert_eq!(device.broadcast().unwrap(), Some("10.84.0.255".parse().unwrap()));
    device.set_broadcast("10.84.0.254".parse().unwrap()).unwrap();
    assert_eq!(device.broadcast().unwrap(), Some("10.84.0.254".parse().unwrap()));
    device.add_address(net("10.84.1.1/24")).unwrap();
    device.set_address(net("10.84.2.1/24")).unwrap();
    let addresses = device.addresses().unwrap();
    let v4: Vec<_> = addresses.iter().filter(|net| net.addr().is_ipv4()).collect();
    assert_eq!(v4, [&net("10.84.2.1/24")], "{addresses:?}");
    assert!(addresses.contains(&net("fd84::1/64")), "the other IP version keeps its address: {addresses:?}");
    assert_eq!(device.broadcast().unwrap(), Some("10.84.2.255".parse().unwrap()));
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
    let shown = run("ip", &["route", "show", "10.87.0.0/16"]);
    assert!(shown.contains(&format!("via 10.85.0.2 dev {name}")), "{shown}");
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
}

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
    let fd = device.into_fd(queue).unwrap();
    let (device, queue) = Tun::from_fd(fd).unwrap();
    assert_eq!(device.name().unwrap(), name);
    let (mut reader, _writer) = queue.split().unwrap();
    sent_through(&mut reader, "10.90.0.1", "10.90.0.2", b"through the handed over descriptor");
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn frames_with_packet_information() {
    let (device, queues) = builder("xtuntest19").address(net("10.91.0.1/24")).packet_information(true).build().unwrap();
    assert!(device.packet_information());
    assert!(!device.offload().tcp, "packet information rules out offloads");
    let (mut reader, mut writer) = ends(queues);
    // Flags and the Ethernet protocol.
    let information: [u8; 4] = [0, 0, 0x08, 0x00];
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
