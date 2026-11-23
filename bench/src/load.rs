//! Traffic for the reflector where iperf3 is not installed, on plain threads and blocking
//! sockets.
//!
//!   load serve <address>                 TCP and UDP sinks on port 5300, a TCP source on 5301 and
//!                                        a UDP echo on 5302
//!   load up <address> <seconds> [gbit]   TCP to the sink, as fast as it goes or paced to that
//!                                        many Gbit/s, prints Gbit/s
//!   load down <address> <seconds>        TCP from the source, prints Gbit/s
//!   load udp <address> <seconds> <size>  four UDP senders, prints packets per second received
//!   load echo <address> <count>          a datagram to the echo every 10 ms, prints the round
//!                                        trip of each that came back, in milliseconds: a ping
//!                                        where the system's own counts whole milliseconds

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const SINK: u16 = 5300;
const SOURCE: u16 = 5301;
const ECHO: u16 = 5302;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let address = |index: usize| args[index].parse::<std::net::IpAddr>().expect("an address");
    let seconds = |index: usize| Duration::from_secs_f64(args[index].parse().expect("seconds"));
    match args[0].as_str() {
        "serve" => serve(address(1)),
        "up" => {
            let rate = args.get(3).map(|rate| rate.parse::<f64>().expect("a rate in Gbit/s"));
            println!("{:.3}", tcp(SocketAddr::new(address(1), SINK), seconds(2), true, rate));
        }
        "down" => println!("{:.3}", tcp(SocketAddr::new(address(1), SOURCE), seconds(2), false, None)),
        "udp" => println!("{:.0}", udp(address(1), seconds(2), args[3].parse().expect("a size"))),
        "echo" => {
            for time in echo(address(1), args[2].parse().expect("a count")) {
                println!("{time:.3}");
            }
        }
        other => panic!("unknown command {other}"),
    }
}

/// Runs until killed. The UDP sink answers a datagram of four zero bytes with the number of
/// datagrams it has received.
fn serve(address: std::net::IpAddr) {
    let sink = TcpListener::bind(SocketAddr::new(address, SINK)).expect("binding the TCP sink");
    std::thread::spawn(move || {
        for stream in sink.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buffer = vec![0u8; 256 * 1024];
                while matches!(stream.read(&mut buffer), Ok(n) if n > 0) {}
            });
        }
    });
    let source = TcpListener::bind(SocketAddr::new(address, SOURCE)).expect("binding the TCP source");
    std::thread::spawn(move || {
        for stream in source.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let buffer = vec![0x5au8; 256 * 1024];
                while stream.write_all(&buffer).is_ok() {}
            });
        }
    });
    let echo = UdpSocket::bind(SocketAddr::new(address, ECHO)).expect("binding the UDP echo");
    std::thread::spawn(move || {
        let mut buffer = [0u8; 64];
        loop {
            if let Ok((size, from)) = echo.recv_from(&mut buffer) {
                let _ = echo.send_to(&buffer[..size], from);
            }
        }
    });
    let socket = UdpSocket::bind(SocketAddr::new(address, SINK)).expect("binding the UDP sink");
    let mut received = 0u64;
    let mut buffer = vec![0u8; 65_536];
    loop {
        let Ok((size, from)) = socket.recv_from(&mut buffer) else { continue };
        if size == 4 && buffer[..4] == [0, 0, 0, 0] {
            let _ = socket.send_to(&received.to_be_bytes(), from);
            received = 0;
        } else {
            received += 1;
        }
    }
}

/// Writes to the sink, or reads from the source, for `duration`, and returns the Gbit/s moved.
/// With a `rate` in Gbit/s the writer holds back whenever it is ahead of that rate, in pieces
/// small enough to keep the flow even.
fn tcp(to: SocketAddr, duration: Duration, up: bool, rate: Option<f64>) -> f64 {
    let mut stream = TcpStream::connect(to).expect("connecting");
    let mut buffer = vec![0x5au8; if rate.is_some() { 16 * 1024 } else { 256 * 1024 }];
    let start = Instant::now();
    let mut bytes = 0u64;
    while start.elapsed() < duration {
        if let Some(rate) = rate
            && bytes as f64 * 8.0 > rate * 1e9 * start.elapsed().as_secs_f64()
        {
            std::thread::sleep(Duration::from_micros(50));
            continue;
        }
        let n = if up { stream.write(&buffer).expect("writing") } else { stream.read(&mut buffer).expect("reading") };
        bytes += n as u64;
    }
    bytes as f64 * 8.0 / start.elapsed().as_secs_f64() / 1e9
}

fn udp(address: std::net::IpAddr, duration: Duration, size: usize) -> f64 {
    let to = SocketAddr::new(address, SINK);
    let control = UdpSocket::bind(SocketAddr::new(local_for(address), 0)).expect("binding");
    control.set_read_timeout(Some(Duration::from_secs(2))).expect("a timeout");
    control.send_to(&[0, 0, 0, 0], to).expect("resetting the count");
    let mut reply = [0u8; 8];
    let _ = control.recv_from(&mut reply);
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let senders: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            let sent = sent.clone();
            std::thread::spawn(move || {
                let socket = UdpSocket::bind(SocketAddr::new(local_for(address), 0)).expect("binding");
                socket.connect(to).expect("connecting");
                let payload = vec![0x33u8; size];
                while !stop.load(Ordering::Relaxed) {
                    if socket.send(&payload).is_ok() {
                        sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    let start = Instant::now();
    std::thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);
    for sender in senders {
        sender.join().expect("a sender");
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::thread::sleep(Duration::from_millis(300));
    control.send_to(&[0, 0, 0, 0], to).expect("asking for the count");
    let (size, _) = control.recv_from(&mut reply).expect("the count");
    assert_eq!(size, 8);
    u64::from_be_bytes(reply) as f64 / elapsed
}

/// Sends `count` numbered datagrams to the echo, one every 10 ms, and returns the round trip of
/// each that came back within a second, in milliseconds.
fn echo(address: std::net::IpAddr, count: u32) -> Vec<f64> {
    let socket = UdpSocket::bind(SocketAddr::new(local_for(address), 0)).expect("binding");
    socket.connect(SocketAddr::new(address, ECHO)).expect("connecting");
    let mut times = Vec::new();
    let mut reply = [0u8; 64];
    for number in 0..count {
        let sent = Instant::now();
        socket.send(&number.to_be_bytes()).expect("sending");
        let deadline = sent + Duration::from_secs(1);
        // An answer to an earlier datagram that came late is passed over.
        while let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) {
            socket.set_read_timeout(Some(left)).expect("a timeout");
            match socket.recv(&mut reply) {
                Ok(4) if reply[..4] == number.to_be_bytes() => {
                    times.push(sent.elapsed().as_secs_f64() * 1e3);
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        std::thread::sleep(Duration::from_millis(10).saturating_sub(sent.elapsed()));
    }
    times
}

/// The interface address that reaches `address`: the reflector's subnet has its `.1`.
fn local_for(address: std::net::IpAddr) -> std::net::IpAddr {
    match address {
        std::net::IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            octets[3] = 1;
            std::net::IpAddr::V4(octets.into())
        }
        std::net::IpAddr::V6(ip) => {
            let mut segments = ip.segments();
            segments[7] = 1;
            std::net::IpAddr::V6(segments.into())
        }
    }
}
