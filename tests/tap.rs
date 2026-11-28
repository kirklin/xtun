//! Tests on real layer 2 interfaces: TAP interfaces on Linux and the BSDs, pairs of `feth`
//! interfaces on macOS. They need the privilege to create interfaces and are ignored by default:
//! `cargo test -- --ignored --test-threads=1` as root, or `node scripts/linux.ts`.

#![cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]

mod common;

use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use common::{Build, Counters, Mode, NEIGHBOR_MAC, Nat, assert_joined, ethernet, ip_packet, reflect, retransmitted, several_writers, stop, transfer};
use xtun::{Builder, Checksum, Ethernet, Packet, Queue, Reader, Tap, Writer};
use ipnet::IpNet;
use tokio::net::UdpSocket;

/// Whether the system is Linux, which Android is too.
const LINUX: bool = cfg!(any(target_os = "linux", target_os = "android"));

/// The hardware address of the system's side of every device.
const DEVICE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

fn net(text: &str) -> IpNet {
    text.parse().unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn exists(name: &str) -> bool {
    let name = std::ffi::CString::new(name).unwrap();
    // SAFETY: a NUL-terminated name.
    unsafe { libc::if_nametoindex(name.as_ptr()) != 0 }
}

/// A layer 2 device named per test on Linux; macOS numbers its `feth` interfaces itself.
fn builder(name: &str) -> Builder<Ethernet> {
    let builder = Tap::builder().mac_address(DEVICE_MAC);
    if LINUX { builder.name(name) } else { builder }
}

/// Both ends of the only queue of a device.
fn ends(mut queues: Vec<Queue<Ethernet>>) -> (Reader<Ethernet>, Writer<Ethernet>) {
    assert_eq!(queues.len(), 1);
    queues.remove(0).split().unwrap()
}

/// Makes the system know `addresses` as neighbors on the device at [`NEIGHBOR_MAC`], so that it
/// sends them frames without asking first.
fn neighbors(device: &Tap, addresses: &[&str]) {
    let name = device.name().unwrap();
    for address in addresses {
        let output = if LINUX {
            Command::new("ip")
                .args(["neigh", "replace", address, "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", &name])
                .output()
        } else if address.contains(':') {
            Command::new("ndp").args(["-s", address, "2:0:0:0:0:2"]).output()
        } else {
            Command::new("arp").args(["-s", address, "2:0:0:0:0:2"]).output()
        };
        let output = output.unwrap();
        assert!(
            output.status.success(),
            "adding the neighbor {address}: {}{}\nroutes:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            routes(),
        );
        // On macOS `ndp -s` looks the address up before it adds the entry, and the lookup leaves
        // an unresolved entry scoped to the interface beside the one that is added. The system
        // finds the scoped one first and asks the link for the address until it gives up.
        if cfg!(target_os = "macos") && address.contains(':') {
            let output = Command::new("route").args(["-n", "delete", "-inet6", "-ifscope", &name, address]).output().unwrap();
            assert!(
                output.status.success(),
                "removing the unresolved neighbor {address}: {}{}\nroutes:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                routes(),
            );
        }
    }
}

/// The system's IPv4 and IPv6 routes, neighbors included, for a failure message.
fn routes() -> String {
    let output = if LINUX {
        Command::new("sh").args(["-c", "ip route; ip -6 route; ip neigh"]).output()
    } else {
        Command::new("netstat").args(["-rn"]).output()
    };
    output.map_or_else(|error| error.to_string(), |output| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// What a frame carries, for a failure message: its EtherType, IP protocol, ICMPv6 type and
/// length, and for neighbor discovery who asks about which address.
fn summary(frame: &[u8]) -> String {
    let kind = u16::from_be_bytes([frame[12], frame[13]]);
    let protocol = match kind {
        0x0800 => frame.get(23).copied(),
        0x86dd => frame.get(20).copied(),
        _ => None,
    };
    let v6 = |at: usize| frame.get(at..at + 16).map(|bytes| std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()));
    let icmp6 = match (kind, protocol, frame.get(54)) {
        (0x86dd, Some(58), Some(&kind @ (135 | 136))) => {
            format!(" type {kind} from {} about {}", v6(22).map_or("?".into(), |ip| ip.to_string()), v6(62).map_or("?".into(), |ip| ip.to_string()))
        }
        (0x86dd, Some(58), Some(kind)) => format!(" type {kind}"),
        _ => String::new(),
    };
    format!("{kind:04x}/{}{icmp6} of {} bytes", protocol.map_or("-".to_owned(), |protocol| protocol.to_string()), frame.len())
}

/// What a command prints, or why it could not run, for a failure message.
fn shown(program: &str, args: &[&str]) -> String {
    Command::new(program).args(args).output().map_or_else(
        |error| error.to_string(),
        |output| format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)),
    )
}

/// The system's table of IPv6 neighbors, for a failure message.
fn neighbor_table() -> String {
    if LINUX { shown("ip", &["-6", "neigh"]) } else { shown("ndp", &["-an"]) }
}

/// How the system would send to `address`, by any interface and bound to the device's own, and
/// the state of the device's interface, for a failure message.
fn way_to(address: &str, name: &str) -> String {
    if LINUX {
        return format!("{}{}", shown("ip", &["route", "get", address]), shown("ip", &["addr", "show", "dev", name]));
    }
    let family = if address.contains(':') { "-inet6" } else { "-inet" };
    format!(
        "route get:\n{}route get, bound to {name}:\n{}{}",
        shown("route", &["-n", "get", family, address]),
        shown("route", &["-n", "get", family, "-ifscope", name, address]),
        shown("ifconfig", &[name]),
    )
}

async fn udp_round_trip(name: &str, offload: bool) {
    let (device, queues) = builder(name).offload(offload).address(net("10.92.0.1/24")).address(net("fd92::1/64")).build().unwrap();
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC);
    neighbors(&device, &["10.92.0.2", "fd92::2"]);
    let (mut reader, mut writer) = ends(queues);
    for (local, remote) in [("10.92.0.1", "10.92.0.2"), ("fd92::1", "fd92::2")] {
        let socket = UdpSocket::bind(SocketAddr::new(ip(local), 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        socket.send_to(b"hello through the frames", SocketAddr::new(ip(remote), 9)).await.unwrap();
        let mut others = Vec::new();
        let frame = loop {
            let mut batch = tokio::time::timeout(Duration::from_secs(5), reader.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "no frame from {local} to {remote} in 5 seconds; the frames before: {others:?}; neighbors:\n{}{}",
                        neighbor_table(),
                        way_to(remote, &device.name().unwrap()),
                    )
                })
                .unwrap();
            let mut found = None;
            for frame in batch.frames() {
                if frame.data().ends_with(b"hello through the frames") {
                    found = Some(frame.data().to_vec());
                    break;
                }
                others.push(summary(frame.data()));
            }
            if let Some(found) = found {
                break found;
            }
        };
        assert_eq!(frame[..6], NEIGHBOR_MAC, "the frame goes to the neighbor");
        assert_eq!(frame[6..12], DEVICE_MAC, "the frame comes from the device's address");
        let packet = ip_packet(&frame).expect("an IP packet");
        assert_eq!(packet[0] >> 4, if remote.contains(':') { 6 } else { 4 });
        let reply = Build { src: ip(remote), dst: ip(local), src_port: 9, dst_port: port, ttl: 64, id: 1 }.udp(b"and back");
        let reply = ethernet(DEVICE_MAC, NEIGHBOR_MAC, &reply);
        writer.send(&[Packet::new(&reply).with_checksum(Checksum::Valid)]).await.unwrap();
        let mut buffer = [0u8; 64];
        let (size, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(&buffer[..size], b"and back");
        assert_eq!(from, SocketAddr::new(ip(remote), 9));
    }
    assert_eq!(writer.stats().dropped, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn udp_round_trip_plain() {
    udp_round_trip("xtuntap0", false).await;
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "openbsd"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn udp_round_trip_offload() {
    udp_round_trip("xtuntap0", true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn a_queue_takes_frames_from_several_writers() {
    let (device, queues) = builder("xtuntap0").address(net("10.98.0.1/24")).build().unwrap();
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC);
    let (_reader, writer) = ends(queues);
    let socket = std::net::UdpSocket::bind("10.98.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let from = Build { src: ip("10.98.0.2"), dst: ip("10.98.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 3 };
    several_writers(writer, socket, move |payload| ethernet(DEVICE_MAC, NEIGHBOR_MAC, &from.udp(payload))).await;
}

async fn through_reflector(offload: bool, mode: Mode, v6: bool) {
    let (local, peer, other, subnet) = if v6 {
        ("fd93::1", "fd93::2", "fd93::3", "fd93::1/64")
    } else {
        ("10.93.0.1", "10.93.0.2", "10.93.0.3", "10.93.0.1/24")
    };
    let (device, queues) = builder("xtuntap1").offload(offload).address(net(subnet)).build().unwrap();
    neighbors(&device, &[peer, other]);
    let nat = Nat { local: ip(local), peer: ip(peer), other: ip(other), link: 14 };
    let counters = Arc::new(Counters::default());
    let (reader, writer) = ends(queues);
    let task = tokio::spawn(reflect(reader, writer, nat, mode, counters.clone()));
    let before = retransmitted();
    transfer(nat, 16 << 20, 2).await;
    stop(vec![task]).await;
    let again = retransmitted() - before;
    let (segments, packets, writes) = counters.get();
    println!("offload {offload} {mode:?} v6 {v6}: {}", counters.summary(&device.name().unwrap(), again));
    if offload && cfg!(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "openbsd")) {
        if mode != Mode::Packets {
            assert!(segments > 0, "the kernel hands over segments of Ethernet frames");
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
async fn tcp_through_frames() {
    for v6 in [false, true] {
        for mode in [Mode::Pass, Mode::Split, Mode::Packets, Mode::Pieces, Mode::Kept, Mode::Mixed] {
            through_reflector(false, mode, v6).await;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "openbsd"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn tcp_through_frames_with_offload() {
    for v6 in [false, true] {
        for mode in [Mode::Pass, Mode::Split, Mode::Packets, Mode::Pieces, Mode::Kept, Mode::Mixed] {
            through_reflector(true, mode, v6).await;
        }
    }
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn hardware_address_and_broadcast() {
    let (device, _queues) = builder("xtuntap2").address(net("10.94.0.1/24")).build().unwrap();
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC);
    let changed = [0x02, 0, 0, 0, 0x5e, 0x01];
    device.set_mac_address(changed).unwrap();
    assert_eq!(device.mac_address().unwrap(), changed);
    assert_eq!(device.broadcast().unwrap(), Some("10.94.0.255".parse().unwrap()));
    device.set_broadcast("10.94.0.254".parse().unwrap()).unwrap();
    assert_eq!(device.broadcast().unwrap(), Some("10.94.0.254".parse().unwrap()));
    assert!(device.addresses().unwrap().contains(&net("10.94.0.1/24")));
    assert!(!device.packet_information());
}

#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn a_persistent_device_stays_and_is_taken_over() {
    let (device, queues) = builder("xtuntap3").persist(true).address(net("10.95.0.1/24")).build().unwrap();
    let name = device.name().unwrap();
    drop((device, queues));
    assert!(exists(&name), "a persistent interface stays");
    let (device, queues) = Tap::builder().name(&name).build().unwrap();
    assert_eq!(device.name().unwrap(), name);
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC, "the interface was taken over as it was");
    drop((device, queues));
    assert!(exists(&name), "an interface that was taken over stays");
    let (device, queues) = Tap::builder().name(&name).build().unwrap();
    device.set_persist(false).unwrap();
    drop((device, queues));
    assert!(!exists(&name), "told it may go, the interface goes with the device");
}

/// A `feth` interface that was there without a second one gets a new one that carries what it
/// does: at its MTU, and up beside it when the builder leaves it up.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn a_feth_interface_that_was_there_gets_a_second_one_that_carries_its_frames() {
    let (name, second) = ("feth940", "feth941");
    let ifconfig = |args: &[&str]| {
        let output = Command::new("ifconfig").args(args).output().unwrap();
        assert!(output.status.success(), "ifconfig {args:?}: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap()
    };
    ifconfig(&[name, "create"]);
    ifconfig(&[name, "mtu", "2000", "up"]);
    let (device, queues) =
        Tap::builder().name(name).peer_name(second).mac_address(DEVICE_MAC).keep_up_state().address(net("10.99.0.1/24")).build().unwrap();
    assert!(device.is_up().unwrap(), "the interface is left up");
    assert_eq!(device.mtu().unwrap(), 2000, "the interface keeps its MTU");
    let state = ifconfig(&[second]);
    assert!(state.contains("<UP,") && state.contains("mtu 2000"), "the second interface: {state}");
    neighbors(&device, &["10.99.0.2"]);
    let (mut reader, mut writer) = ends(queues);
    let socket = std::net::UdpSocket::bind(SocketAddr::new(ip("10.99.0.1"), 0)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let port = socket.local_addr().unwrap().port();
    // What the system sends crosses the pair to the reader.
    socket.send_to(b"across the pair", SocketAddr::new(ip("10.99.0.2"), 9)).unwrap();
    reader.set_timeout(Some(Duration::from_secs(5)));
    let mut frame = [0u8; 2048];
    loop {
        let length = reader.blocking_recv_packet(&mut frame).unwrap();
        if frame[..length].ends_with(b"across the pair") {
            break;
        }
    }
    // A frame as large as the MTU of the first interface goes out through the second.
    let payload = vec![0x5a; 2000 - 28];
    let reply = Build { src: ip("10.99.0.2"), dst: ip("10.99.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 1 }.udp(&payload);
    writer.blocking_send(&[Packet::new(&ethernet(DEVICE_MAC, NEIGHBOR_MAC, &reply)).with_checksum(Checksum::Valid)]).unwrap();
    assert_eq!(writer.stats().dropped, 0);
    let mut received = vec![0u8; 4096];
    let (size, _) = socket.recv_from(&mut received).unwrap();
    assert_eq!(received[..size], payload[..]);
    device.set_persist(false).unwrap();
    drop((device, reader, writer));
    assert!(!exists(name) && !exists(second), "told they may go, both interfaces go with the device");
}

/// A read that takes everything the BPF device of a `feth` pair holds tells the reader that the
/// device is empty: it waits for the next frame without a read that finds nothing.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates interfaces: run as root with --ignored"]
async fn a_feth_reader_waits_without_a_read_that_finds_nothing() {
    const ROUNDS: u64 = 16;
    let (device, queues) = builder("xtuntap5").address(net("10.100.0.1/24")).build().unwrap();
    neighbors(&device, &["10.100.0.2"]);
    let (mut reader, _writer) = ends(queues);
    let socket = UdpSocket::bind(SocketAddr::new(ip("10.100.0.1"), 0)).await.unwrap();
    let mut batches = 0;
    for round in 0..ROUNDS {
        let text = format!("frame {round} for a reader that waits");
        // The reader waits first; the frame is sent while it does.
        let receiving = async {
            loop {
                let mut batch = reader.recv().await.unwrap();
                batches += 1;
                if batch.frames().any(|frame| frame.data().ends_with(text.as_bytes())) {
                    break;
                }
            }
        };
        let sending = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            socket.send_to(text.as_bytes(), SocketAddr::new(ip("10.100.0.2"), 9)).await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(receiving, sending) }).await.expect("the frame reaches the reader");
    }
    // A call per batch. The first read of all may find nothing, and so may one that follows a
    // frame of the system's own that came while another was read; a reader that looked again
    // after every batch would make a call more in every round.
    let calls = reader.stats().calls;
    assert!(calls <= batches + ROUNDS / 2, "{calls} calls for {batches} batches");
}

/// FreeBSD renames interfaces: a descriptor is known for what it is by its device.
#[cfg(target_os = "freebsd")]
#[test]
#[ignore = "creates interfaces: run as root with --ignored"]
fn a_renamed_device_is_handed_over_as_what_it_is() {
    let (device, mut queues) = builder("xtuntap4").build().unwrap();
    device.set_name("xtunrenamed").unwrap();
    let fd = device.into_fd(queues.remove(0)).unwrap();
    let (device, _queue) = Tap::from_fd(fd).unwrap();
    assert_eq!(device.name().unwrap(), "xtunrenamed");
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC);
    device.set_persist(false).unwrap();
    drop((device, _queue));
    assert!(!exists("xtunrenamed"));
}
