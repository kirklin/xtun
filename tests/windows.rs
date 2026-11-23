//! Tests on real Windows adapters: Wintun adapters for TUN devices, TAP-Windows adapters for TAP
//! devices. They need an administrator, `wintun.dll` at the path in `XTUN_WINTUN`, the
//! TAP-Windows6 driver in the driver store, and inbound traffic to the test subnets let through
//! the firewall, and are ignored by default: `node scripts/vm/windows.ts` sets all of that up.

#![cfg(windows)]

mod common;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Build, Counters, Mode, NEIGHBOR_MAC, Nat, ethernet, ip_packet, reflect, stop, transfer};
use xtun::{Builder, Checksum, Ethernet, Ip, Packet, Queue, Reader, Tap, Tun, Writer};
use ipnet::IpNet;
use tokio::net::UdpSocket;

/// The hardware address of the system's side of every TAP device.
const DEVICE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

fn net(text: &str) -> IpNet {
    text.parse().unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A Wintun device named `name`, with the `wintun.dll` the environment points at.
fn tun(name: &str) -> Builder<Ip> {
    let wintun = std::env::var_os("XTUN_WINTUN").expect("XTUN_WINTUN names wintun.dll");
    Tun::builder().name(name).wintun(wintun)
}

/// A TAP-Windows device named `name`, with a known hardware address.
fn tap(name: &str) -> Builder<Ethernet> {
    Tap::builder().name(name).mac_address(DEVICE_MAC)
}

/// Both ends of the only queue of a device.
fn ends<L: xtun::Layer>(mut queues: Vec<Queue<L>>) -> (Reader<L>, Writer<L>) {
    assert_eq!(queues.len(), 1);
    queues.remove(0).split().unwrap()
}

/// Whether Windows has an interface whose alias is `name`.
fn exists(name: &str) -> bool {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
    let wide: Vec<u16> = name.encode_utf16().collect();
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: the table is allocated by the call and freed below.
    assert_eq!(unsafe { GetIfTable2(&mut table) }, 0);
    // SAFETY: the table holds `NumEntries` rows.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
    let found = rows.iter().any(|row| row.Alias[..wide.len()] == wide[..] && row.Alias[wide.len()] == 0);
    // SAFETY: the table came from GetIfTable2.
    unsafe { FreeMibTable(table.cast()) };
    found
}

/// Runs a system tool and returns what it printed; it has to succeed.
fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    let said = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "{program} {args:?}: {said}");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Runs PowerShell and returns what it printed; it has to succeed.
fn powershell(script: &str) -> String {
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", script])
}

/// Waits up to five seconds for `condition`, which Windows may make true a moment later.
fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The index of the interface through which Windows sends packets for `address`.
fn route_index(address: &str) -> String {
    powershell(&format!("(Find-NetRoute -RemoteIPAddress '{address}' | Where-Object InterfaceIndex | Select-Object -First 1).InterfaceIndex"))
}

/// Reads packets until one ends with `tail`, skipping what the system sends on its own.
fn blocking_packet<L: xtun::Layer>(reader: &mut Reader<L>, tail: &[u8]) -> Vec<u8> {
    let mut buffer = [0u8; 2048];
    loop {
        let length = reader.blocking_recv_packet(&mut buffer).unwrap();
        if buffer[..length].ends_with(tail) {
            return buffer[..length].to_vec();
        }
    }
}

/// Waits with `blocking_recv_packet` until it fails, skipping what the system sends on its own.
fn blocking_failure<L: xtun::Layer>(reader: &mut Reader<L>) -> io::Error {
    let mut buffer = [0u8; 2048];
    loop {
        if let Err(error) = reader.blocking_recv_packet(&mut buffer) {
            return error;
        }
    }
}

/// Sends a datagram from `from` to port 9 of `to` and finds it in what the reader reads.
fn sent_through<L: xtun::Layer>(reader: &mut Reader<L>, from: &str, to: &str, text: &[u8]) -> Vec<u8> {
    let socket = std::net::UdpSocket::bind(SocketAddr::new(ip(from), 0)).unwrap();
    socket.send_to(text, SocketAddr::new(ip(to), 9)).unwrap();
    reader.set_timeout(Some(Duration::from_secs(5)));
    blocking_packet(reader, text)
}

/// Makes Windows know `addresses` as neighbors on the TAP device at [`NEIGHBOR_MAC`], so that it
/// sends them frames without asking first.
fn neighbors(device: &Tap, addresses: &[&str]) {
    let index = device.index().to_string();
    for address in addresses {
        let version = if address.contains(':') { "ipv6" } else { "ipv4" };
        run(
            "netsh",
            &["interface", version, "add", "neighbors", &format!("interface={index}"), &format!("address={address}"), "neighbor=02-00-00-00-00-02", "store=active"],
        );
    }
}

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn wintun_configures_the_interface() {
    let (device, queues) = tun("xtuntest0")
        .mtu(1400)
        .mtu_v6(1380)
        .metric(7)
        .address(net("10.171.0.1/24"))
        .address(net("fd71::1/64"))
        .build()
        .unwrap();
    assert_eq!(device.name().unwrap(), "xtuntest0");
    assert!(exists("xtuntest0"));
    assert!(device.index() > 0 && device.luid() != 0);
    assert_eq!((device.mtu().unwrap(), device.mtu_v6().unwrap(), device.metric().unwrap()), (1400, 1380, 7));
    let addresses = device.addresses().unwrap();
    assert!(addresses.contains(&net("10.171.0.1/24")) && addresses.contains(&net("fd71::1/64")), "{addresses:?}");
    let version = device.driver_version().unwrap();
    assert!(version.split('.').all(|part| part.parse::<u32>().is_ok()), "{version}");
    assert_eq!(device.offload(), xtun::Offload::default());
    assert!(!device.packet_information());
    assert_eq!(device.broadcast().unwrap_err().kind(), io::ErrorKind::Unsupported);

    device.set_mtu(1500).unwrap();
    assert_eq!((device.mtu().unwrap(), device.mtu_v6().unwrap()), (1500, 1500), "both IP versions take the MTU");
    device.set_mtu_v6(1300).unwrap();
    assert_eq!((device.mtu().unwrap(), device.mtu_v6().unwrap()), (1500, 1300));
    device.set_metric(25).unwrap();
    assert_eq!(device.metric().unwrap(), 25);
    device.add_address(net("10.171.1.1/24")).unwrap();
    assert!(device.addresses().unwrap().contains(&net("10.171.1.1/24")));
    device.remove_address(net("10.171.1.1/24")).unwrap();
    assert!(!device.addresses().unwrap().contains(&net("10.171.1.1/24")));

    let index = device.index();
    let servers = |family: &str| {
        powershell(&format!("(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily {family}).ServerAddresses -join ','"))
    };
    // Windows shows its own site-local servers for an interface that has none for IPv6.
    let unset = (servers("IPv4"), servers("IPv6"));
    assert_eq!(unset.0, "");
    device.set_dns_servers(&[ip("10.171.0.53"), ip("10.171.0.54"), ip("fd71::53")]).unwrap();
    assert_eq!(servers("IPv4"), "10.171.0.53,10.171.0.54");
    assert_eq!(servers("IPv6"), "fd71::53");
    device.set_dns_servers(&[]).unwrap();
    assert_eq!((servers("IPv4"), servers("IPv6")), unset, "an empty list clears both");

    drop(device);
    assert!(exists("xtuntest0"), "a queue keeps the adapter");
    drop(queues);
    assert!(!exists("xtuntest0"), "the adapter is gone with its last handle");
}

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn wintun_refuses_what_it_does_not_have() {
    let refused = tun("xtuntest1").persist(true).build().unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::Unsupported, "{refused}");
    assert!(!exists("xtuntest1"), "a device that could not be made leaves no adapter");
    let refused = tun("xtuntest1").ring_capacity(100_000).build().unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{refused}");
    let (device, mut queues) = tun("xtuntest1").build().unwrap();
    assert_eq!(device.set_persist(true).unwrap_err().kind(), io::ErrorKind::Unsupported);
    let taken = tun("xtuntest1").reuse(false).build().unwrap_err();
    assert_eq!(taken.kind(), io::ErrorKind::AlreadyExists, "{taken}");
    assert_eq!(queues.len(), 1);
    let queue = queues.remove(0);
    assert_eq!(queue.index(), 0);
    assert_eq!(queue.split_with_capacity(0).unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn wintun_renames_and_brings_up_and_down() {
    let (device, queues) = tun("xtuntest2").address(net("10.172.0.1/24")).up(false).build().unwrap();
    assert!(!device.is_up().unwrap());
    assert!(eventually(|| !device.is_running().unwrap()), "a Wintun adapter runs only with a session");
    device.set_up(true).unwrap();
    assert!(device.is_up().unwrap());
    assert!(eventually(|| device.is_running().unwrap()));
    let (mut reader, _writer) = ends(queues);
    sent_through(&mut reader, "10.172.0.1", "10.172.0.2", b"while up");
    device.set_name("xtuntest2-renamed").unwrap();
    assert_eq!(device.name().unwrap(), "xtuntest2-renamed");
    assert!(exists("xtuntest2-renamed"));
    assert!(!exists("xtuntest2"), "the old name is free");
    device.set_up(false).unwrap();
    assert!(!device.is_up().unwrap());
    assert!(eventually(|| !device.is_running().unwrap()));
    device.set_up(true).unwrap();
    sent_through(&mut reader, "10.172.0.1", "10.172.0.2", b"up again");
}

async fn udp_round_trip<L: xtun::Layer>(reader: &mut Reader<L>, writer: &mut Writer<L>, pairs: [(&str, &str); 2], link: usize) {
    for (local, remote) in pairs {
        let socket = UdpSocket::bind(SocketAddr::new(ip(local), 0)).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        socket.send_to(b"hello through the device", SocketAddr::new(ip(remote), 9)).await.unwrap();
        let frame = loop {
            let mut batch = tokio::time::timeout(Duration::from_secs(5), reader.recv())
                .await
                .unwrap_or_else(|_| panic!("nothing from {local} to {remote} in 5 seconds"))
                .unwrap();
            if let Some(found) = batch.frames().find(|frame| frame.data().ends_with(b"hello through the device")).map(|frame| frame.data().to_vec()) {
                break found;
            }
        };
        let packet = if link > 0 { ip_packet(&frame).expect("an IP packet") } else { &frame[..] };
        assert_eq!(packet[0] >> 4, if remote.contains(':') { 6 } else { 4 });
        let reply = Build { src: ip(remote), dst: ip(local), src_port: 9, dst_port: port, ttl: 64, id: 1 }.udp(b"and back");
        let reply = if link > 0 { ethernet(DEVICE_MAC, NEIGHBOR_MAC, &reply) } else { reply };
        writer.send(&[Packet::new(&reply).with_checksum(Checksum::Valid)]).await.unwrap();
        let mut buffer = [0u8; 64];
        let (size, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("no reply from {remote} in 5 seconds"))
            .unwrap();
        assert_eq!(&buffer[..size], b"and back");
        assert_eq!(from, SocketAddr::new(ip(remote), 9));
    }
    assert_eq!(writer.stats().dropped, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
async fn wintun_udp_round_trip() {
    let (_device, queues) = tun("xtuntest3").address(net("10.173.0.1/24")).address(net("fd73::1/64")).build().unwrap();
    let (mut reader, mut writer) = ends(queues);
    udp_round_trip(&mut reader, &mut writer, [("10.173.0.1", "10.173.0.2"), ("fd73::1", "fd73::2")], 0).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
async fn tap_udp_round_trip() {
    let (device, queues) = tap("xtuntap0").address(net("10.174.0.1/24")).address(net("fd74::1/64")).build().unwrap();
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC);
    neighbors(&device, &["10.174.0.2", "fd74::2"]);
    let (mut reader, mut writer) = ends(queues);
    udp_round_trip(&mut reader, &mut writer, [("10.174.0.1", "10.174.0.2"), ("fd74::1", "fd74::2")], 14).await;
}

/// Moves data both ways over two connections through a reflector on the device.
async fn through_reflector<L: xtun::Layer>(queues: Vec<Queue<L>>, nat: Nat, mode: Mode) {
    let counters = Arc::new(Counters::default());
    let (reader, writer) = ends(queues);
    let task = tokio::spawn(reflect(reader, writer, nat, mode, counters.clone()));
    transfer(nat, 16 << 20, 2).await;
    stop(vec![task]).await;
    let (segments, packets, writes) = counters.get();
    println!("{mode:?} {}: {segments} segments read, {packets} packets in {writes} writes", nat.local);
    assert_eq!(segments, 0, "Windows adapters hand over no segments");
}

/// The addresses of the reflector's subnet: the device's own, the one clients dial and the one
/// the server sees them come from.
fn subnet(v6: bool, number: u8) -> (IpNet, [IpAddr; 3]) {
    if v6 {
        let at = |host: u8| ip(&format!("fd{number:02x}::{host}"));
        (net(&format!("fd{number:02x}::1/64")), [at(1), at(2), at(3)])
    } else {
        let at = |host: u8| ip(&format!("10.{number}.0.{host}"));
        (net(&format!("10.{number}.0.1/24")), [at(1), at(2), at(3)])
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
async fn wintun_tcp_through_the_device() {
    for v6 in [false, true] {
        for mode in [Mode::Pass, Mode::Split, Mode::Packets] {
            let (address, [local, peer, other]) = subnet(v6, 175);
            let (_device, queues) = tun("xtuntest4").mtu(1500).address(address).build().unwrap();
            through_reflector(queues, Nat { local, peer, other, link: 0 }, mode).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
async fn tap_tcp_through_frames() {
    for v6 in [false, true] {
        for mode in [Mode::Pass, Mode::Split, Mode::Packets] {
            let (address, [local, peer, other]) = subnet(v6, 176);
            let (device, queues) = tap("xtuntap1").address(address).build().unwrap();
            neighbors(&device, &[&peer.to_string(), &other.to_string()]);
            through_reflector(queues, Nat { local, peer, other, link: 14 }, mode).await;
        }
    }
}

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn wintun_blocking_calls_need_no_runtime() {
    let (_device, queues) = tun("xtuntest5").address(net("10.177.0.1/24")).build().unwrap();
    let (mut reader, mut writer) = ends(queues);
    reader.set_timeout(Some(Duration::from_secs(5)));
    let socket = std::net::UdpSocket::bind("10.177.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let port = socket.local_addr().unwrap().port();
    socket.send_to(b"blocking", "10.177.0.2:9").unwrap();
    let request = blocking_packet(&mut reader, b"blocking");
    assert_eq!(&request[28..], b"blocking");
    let reply = Build { src: ip("10.177.0.2"), dst: ip("10.177.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 2 }.udp(b"in pieces");
    let (head, tail) = reply.split_at(20);
    writer.blocking_send_vectored(&[io::IoSlice::new(head), io::IoSlice::new(tail)]).unwrap();
    let mut answer = [0u8; 64];
    let (size, _) = socket.recv_from(&mut answer).unwrap();
    assert_eq!(&answer[..size], b"in pieces");

    reader.set_timeout(Some(Duration::from_millis(100)));
    let started = Instant::now();
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
    socket.send_to(b"after the reset", "10.177.0.2:9").unwrap();
    reader.set_timeout(Some(Duration::from_secs(5)));
    blocking_packet(&mut reader, b"after the reset");
}

#[cfg(feature = "async-io")]
#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn wintun_round_trip_on_async_io() {
    async_io::block_on(async {
        let (_device, queues) = tun("xtuntest6").address(net("10.178.0.1/24")).build().unwrap();
        let (mut reader, mut writer) = ends(queues);
        let socket = async_io::Async::<std::net::UdpSocket>::bind(SocketAddr::new(ip("10.178.0.1"), 0)).unwrap();
        let port = socket.get_ref().local_addr().unwrap().port();
        socket.send_to(b"on async-io", SocketAddr::new(ip("10.178.0.2"), 9)).await.unwrap();
        let mut buffer = [0u8; 2048];
        loop {
            let length = reader.recv_packet(&mut buffer).await.unwrap();
            if buffer[..length].ends_with(b"on async-io") {
                break;
            }
        }
        let reply = Build { src: ip("10.178.0.2"), dst: ip("10.178.0.1"), src_port: 9, dst_port: port, ttl: 64, id: 3 }.udp(b"back");
        writer.send(&[Packet::new(&reply)]).await.unwrap();
        let mut answer = [0u8; 64];
        let (size, _) = socket.recv_from(&mut answer).await.unwrap();
        assert_eq!(&answer[..size], b"back");
    });
}

#[cfg(feature = "futures")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
async fn wintun_streams_and_sinks() {
    use futures_util::{SinkExt, StreamExt};
    let (_device, queues) = tun("xtuntest7").address(net("10.179.0.1/24")).build().unwrap();
    let (reader, writer) = ends(queues);
    let (mut stream, mut sink) = (reader.into_stream(), writer.into_sink());
    let socket = UdpSocket::bind("10.179.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    for round in 0..3 {
        socket.send_to(format!("item {round}").as_bytes(), "10.179.0.2:9").await.unwrap();
    }
    let mut seen = 0;
    while seen < 3 {
        let packet = tokio::time::timeout(Duration::from_secs(5), stream.next()).await.unwrap().unwrap().unwrap();
        if packet.ends_with(format!("item {seen}").as_bytes()) {
            seen += 1;
        }
    }
    for round in 0..3u16 {
        let reply = Build { src: ip("10.179.0.2"), dst: ip("10.179.0.1"), src_port: 9, dst_port: port, ttl: 64, id: round }
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

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn wintun_routes_through_the_interface() {
    let (device, queues) = tun("xtuntest8").address(net("10.180.0.1/24")).address(net("fd80:1::1/64")).build().unwrap();
    let index = device.index().to_string();
    let (mut reader, _writer) = ends(queues);
    device.add_route(net("10.181.0.0/16"), None).unwrap();
    device.add_route(net("10.182.0.0/16"), Some(ip("10.180.0.2"))).unwrap();
    device.add_route(net("fd81::/48"), None).unwrap();
    assert_eq!(route_index("10.181.1.1"), index);
    assert_eq!(route_index("10.182.1.1"), index);
    assert_eq!(route_index("fd81::1"), index);
    let refused = device.add_route(net("10.181.0.0/16"), None).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::AlreadyExists, "{refused}");
    sent_through(&mut reader, "10.180.0.1", "10.181.1.1", b"routed");
    sent_through(&mut reader, "10.180.0.1", "10.182.1.1", b"routed through a gateway");
    sent_through(&mut reader, "fd80:1::1", "fd81::1", b"routed over IPv6");
    device.remove_route(net("10.181.0.0/16"), None).unwrap();
    device.remove_route(net("10.182.0.0/16"), Some(ip("10.180.0.2"))).unwrap();
    device.remove_route(net("fd81::/48"), None).unwrap();
    assert_ne!(route_index("10.181.1.1"), index);
    assert_ne!(route_index("10.182.1.1"), index);
    assert!(device.remove_route(net("10.181.0.0/16"), None).is_err(), "the route is gone");

    device.set_prefix_routes(false);
    assert!(!device.prefix_routes());
    device.add_address(net("10.183.0.1/24")).unwrap();
    assert!(device.addresses().unwrap().contains(&net("10.183.0.1/24")), "the address keeps its prefix");
    assert_ne!(route_index("10.183.0.2"), index, "an address without a prefix route leaves its subnet alone");
    device.set_prefix_routes(true);
    device.add_address(net("10.184.0.1/24")).unwrap();
    assert_eq!(route_index("10.184.0.2"), index);
    device.set_address(net("10.185.0.1/24")).unwrap();
    let v4: Vec<IpNet> = device.addresses().unwrap().into_iter().filter(|net| net.addr().is_ipv4()).collect();
    assert_eq!(v4, [net("10.185.0.1/24")]);
    assert!(device.addresses().unwrap().contains(&net("fd80:1::1/64")), "the other IP version keeps its address");
}

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn wintun_point_to_point_addresses() {
    let (device, queues) = tun("xtuntest9").peer_address(net("10.186.0.1/32"), ip("10.186.0.2")).build().unwrap();
    device.add_peer_address(net("fd86:1::1/128"), ip("fd86:1::2")).unwrap();
    let addresses = device.addresses().unwrap();
    assert!(addresses.contains(&net("10.186.0.1/32")) && addresses.contains(&net("fd86:1::1/128")), "{addresses:?}");
    let index = device.index().to_string();
    assert_eq!(route_index("10.186.0.2"), index);
    let (mut reader, _writer) = ends(queues);
    let request = sent_through(&mut reader, "10.186.0.1", "10.186.0.2", b"to the far end");
    assert_eq!(&request[16..20], &[10, 186, 0, 2]);
    sent_through(&mut reader, "fd86:1::1", "fd86:1::2", b"to the far end over IPv6");
    device.set_up(false).unwrap();
    device.set_up(true).unwrap();
    assert_eq!(route_index("10.186.0.2"), index, "the far end's route comes back with the link");
    sent_through(&mut reader, "10.186.0.1", "10.186.0.2", b"after the link came back");
    device.remove_address(net("10.186.0.1/32")).unwrap();
    assert!(!device.addresses().unwrap().contains(&net("10.186.0.1/32")));
    assert_ne!(route_index("10.186.0.2"), index, "the far end's route goes with its address");
}

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn tap_hardware_address_up_and_down() {
    let (device, queues) = tap("xtuntap2").address(net("10.187.0.1/24")).up(false).build().unwrap();
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC);
    assert_eq!(device.set_mac_address([2, 0, 0, 0, 0x5e, 1]).unwrap_err().kind(), io::ErrorKind::Unsupported);
    let version = device.driver_version().unwrap();
    assert!(version.starts_with("9."), "{version}");
    assert!(device.set_mtu(70_000).is_err(), "no TAP adapter carries that much");
    device.set_mtu(1400).unwrap();
    assert_eq!(device.mtu().unwrap(), 1400);
    assert!(!device.is_up().unwrap());
    assert!(eventually(|| !device.is_running().unwrap()), "the medium is disconnected");
    device.set_up(true).unwrap();
    assert!(device.is_up().unwrap());
    assert!(eventually(|| device.is_running().unwrap()), "the medium is connected");
    neighbors(&device, &["10.187.0.2"]);
    let (mut reader, _writer) = ends(queues);
    let frame = sent_through(&mut reader, "10.187.0.1", "10.187.0.2", b"through the medium");
    assert_eq!((frame[..6].to_vec(), frame[6..12].to_vec()), (NEIGHBOR_MAC.to_vec(), DEVICE_MAC.to_vec()));
    device.set_up(false).unwrap();
    assert!(eventually(|| !device.is_running().unwrap()));
}

#[test]
#[ignore = "creates adapters: run with scripts/vm/windows.ts"]
fn tap_a_persistent_device_stays_and_is_taken_over() {
    let (device, queues) = tap("xtuntap3").persist(true).address(net("10.188.0.1/24")).build().unwrap();
    drop((device, queues));
    assert!(exists("xtuntap3"), "a persistent adapter stays");
    let taken = tap("xtuntap3").reuse(false).build().unwrap_err();
    assert_eq!(taken.kind(), io::ErrorKind::AlreadyExists, "{taken}");
    let (device, queues) = Tap::builder().name("xtuntap3").build().unwrap();
    assert_eq!(device.mac_address().unwrap(), DEVICE_MAC, "the adapter was taken over as it was");
    drop((device, queues));
    assert!(exists("xtuntap3"), "an adapter that was taken over stays");
    let (device, queues) = Tap::builder().name("xtuntap3").build().unwrap();
    device.set_persist(false).unwrap();
    drop((device, queues));
    assert!(!exists("xtuntap3"), "told it may go, the adapter goes with the device");
}
