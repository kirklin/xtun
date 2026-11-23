//! A reflector over either library, for measuring both the same way.
//!
//!   reflect xtun|tun-rs pass|split [--queues N] [--offload on|off] [--uring on|off] [--ring MiB]
//!
//! The interface `bench0` has 10.80.0.1/24 and fd80::1/64. Traffic to .2 is turned into traffic
//! from .3 to .1 and back, so a client dialling 10.80.0.2 reaches a server on 10.80.0.1 through
//! the reflector, as under a stack that rewrites addresses. In `pass` mode frames go back as they
//! were read; in `split` mode they are cut into packets and written as a batch of packets, as a
//! stack in the process would send its own.

mod nat;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nat::{Nat, rewrite};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Pass,
    Split,
}

struct Options {
    backend: String,
    mode: Mode,
    queues: usize,
    offload: bool,
    uring: bool,
    /// The capacity of each Wintun ring, in MiB; the library's own without it.
    #[cfg(windows)]
    ring: Option<u32>,
}

#[derive(Default)]
struct Counters {
    frames: AtomicU64,
    packets: AtomicU64,
}

fn options() -> Options {
    let mut args = std::env::args().skip(1);
    let backend = args.next().expect("a backend: xtun or tun-rs");
    let mode = match args.next().as_deref() {
        Some("pass") => Mode::Pass,
        Some("split") => Mode::Split,
        other => panic!("a mode: pass or split, not {other:?}"),
    };
    let mut options = Options {
        backend,
        mode,
        queues: 1,
        offload: cfg!(target_os = "linux"),
        uring: false,
        #[cfg(windows)]
        ring: None,
    };
    while let Some(flag) = args.next() {
        let value = args.next().expect("a value");
        match flag.as_str() {
            "--queues" => options.queues = value.parse().expect("a number"),
            "--offload" => options.offload = value == "on",
            "--uring" => options.uring = value == "on",
            #[cfg(windows)]
            "--ring" => options.ring = Some(value.parse().expect("a number of MiB")),
            other => panic!("unknown flag {other}"),
        }
    }
    options
}

fn nat() -> Nat {
    let ip = |text: &str| text.parse::<IpAddr>().unwrap();
    Nat { v4: [ip("10.80.0.1"), ip("10.80.0.2"), ip("10.80.0.3")], v6: [ip("fd80::1"), ip("fd80::2"), ip("fd80::3")] }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let options = options();
    let counters = Arc::new(Counters::default());
    let tasks = match options.backend.as_str() {
        "xtun" => xtun_backend::start(&options, counters.clone())?,
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        "tun-rs" => tunrs_backend::start(&options, counters.clone())?,
        other => panic!("unknown backend {other}"),
    };
    println!("ready");
    tokio::select! {
        _ = terminated() => {}
        result = futures_any(tasks) => {
            eprintln!("a reflector stopped: {result:?}");
        }
    }
    println!(
        "frames {} packets {}",
        counters.frames.load(Ordering::Relaxed),
        counters.packets.load(Ordering::Relaxed)
    );
    Ok(())
}

#[cfg(unix)]
async fn terminated() {
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a handler for SIGTERM");
    tokio::select! {
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

/// Without a signal that asks a program to stop, the reflector also stops when its standard
/// input ends, which lets a script end it from afar and have it close its device.
#[cfg(not(unix))]
async fn terminated() {
    let (ended, input_ended) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin(), &mut io::sink());
        let _ = ended.send(());
    });
    tokio::select! {
        _ = input_ended => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

async fn futures_any(tasks: Vec<tokio::task::JoinHandle<io::Result<()>>>) -> io::Result<()> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(tasks.len());
    for task in tasks {
        let sender = sender.clone();
        tokio::spawn(async move {
            let result = task.await.unwrap_or_else(|error| Err(io::Error::other(error)));
            let _ = sender.send(result).await;
        });
    }
    receiver.recv().await.unwrap_or(Ok(()))
}

mod xtun_backend {
    use super::*;
    use xtun::{Checksum, Packet, Reader, Tun, Writer};

    pub fn start(options: &Options, counters: Arc<Counters>) -> io::Result<Vec<tokio::task::JoinHandle<io::Result<()>>>> {
        let builder =
            Tun::builder().mtu(1500).address("10.80.0.1/24".parse().unwrap()).address("fd80::1/64".parse().unwrap()).offload(options.offload);
        #[cfg(target_os = "linux")]
        let builder = {
            let uring = if options.uring { xtun::Uring::Required } else { xtun::Uring::Off };
            builder.name("bench0").queues(options.queues).uring(uring)
        };
        #[cfg(windows)]
        let builder = match options.ring {
            Some(mib) => builder.name("bench0").ring_capacity(mib << 20),
            None => builder.name("bench0"),
        };
        let (device, queues) = builder.build()?;
        eprintln!("xtun on {}", device.name()?);
        let mut tasks = Vec::new();
        for queue in queues {
            let (reader, writer) = queue.split()?;
            tasks.push(tokio::spawn(reflect(reader, writer, options.mode, counters.clone())));
        }
        Ok(tasks)
    }

    async fn reflect(mut reader: Reader, mut writer: Writer, mode: Mode, counters: Arc<Counters>) -> io::Result<()> {
        let nat = nat();
        let mut pool: Vec<(Vec<u8>, Checksum)> = Vec::new();
        loop {
            let mut batch = reader.recv().await?;
            counters.frames.fetch_add(batch.len() as u64, Ordering::Relaxed);
            match mode {
                Mode::Pass => {
                    let mut frames: Vec<_> = batch.frames().collect();
                    frames.retain_mut(|frame| {
                        let partial = matches!(frame.checksum(), Checksum::Partial { .. });
                        rewrite(frame.data_mut(), partial, &nat)
                    });
                    let packets: Vec<Packet<'_>> = frames.iter().map(|frame| frame.packet()).collect();
                    counters.packets.fetch_add(packets.len() as u64, Ordering::Relaxed);
                    writer.send(&packets).await?;
                }
                Mode::Split => {
                    let mut used = 0;
                    for mut frame in batch.frames() {
                        let mut segments = frame.segments();
                        while let Some(mut segment) = segments.next() {
                            let checksum = segment.checksum();
                            if !rewrite(segment.data_mut(), matches!(checksum, Checksum::Partial { .. }), &nat) {
                                continue;
                            }
                            if used == pool.len() {
                                pool.push((Vec::with_capacity(2048), checksum));
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
                    counters.packets.fetch_add(packets.len() as u64, Ordering::Relaxed);
                    writer.send(&packets).await?;
                }
            }
        }
    }
}

/// tun-rs makes devices of its own on every system but Android and iOS, which hand an
/// application the device they made.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tunrs_backend {
    use super::*;

    pub fn start(options: &Options, counters: Arc<Counters>) -> io::Result<Vec<tokio::task::JoinHandle<io::Result<()>>>> {
        let mut builder = tun_rs::DeviceBuilder::new().mtu(1500).ipv4("10.80.0.1", 24, None).ipv6("fd80::1", 64);
        if cfg!(any(target_os = "linux", windows)) {
            builder = builder.name("bench0");
        }
        #[cfg(target_os = "linux")]
        {
            builder = builder.offload(options.offload).multi_queue(options.queues > 1);
        }
        #[cfg(windows)]
        if let Some(mib) = options.ring {
            builder = builder.ring_capacity(mib << 20);
        }
        let first = builder.build_async()?;
        eprintln!("tun-rs on {}", first.name()?);
        let mut devices = Vec::new();
        #[cfg(target_os = "linux")]
        for _ in 1..options.queues {
            devices.push(first.try_clone()?);
        }
        devices.insert(0, first);
        let offload = options.offload && cfg!(target_os = "linux");
        Ok(devices
            .into_iter()
            .map(|device| {
                let counters = counters.clone();
                let mode = options.mode;
                tokio::spawn(async move {
                    match (offload, mode) {
                        #[cfg(target_os = "linux")]
                        (true, Mode::Pass) => pass_offload(device, counters).await,
                        #[cfg(target_os = "linux")]
                        (true, Mode::Split) => split_offload(device, counters).await,
                        _ => plain(device, counters).await,
                    }
                })
            })
            .collect())
    }

    /// One packet at a time, the only way without offloads.
    async fn plain(device: tun_rs::AsyncDevice, counters: Arc<Counters>) -> io::Result<()> {
        let nat = nat();
        let mut buffer = vec![0u8; 65_536];
        loop {
            let size = device.recv(&mut buffer).await?;
            counters.frames.fetch_add(1, Ordering::Relaxed);
            if rewrite(&mut buffer[..size], false, &nat) {
                counters.packets.fetch_add(1, Ordering::Relaxed);
                device.send(&buffer[..size]).await?;
            }
        }
    }

    /// Frames with their virtio header, read and written back whole.
    #[cfg(target_os = "linux")]
    async fn pass_offload(device: tun_rs::AsyncDevice, counters: Arc<Counters>) -> io::Result<()> {
        let nat = nat();
        let mut frame = vec![0u8; tun_rs::VIRTIO_NET_HDR_LEN + 65_535];
        loop {
            let size = device.recv(&mut frame).await?;
            counters.frames.fetch_add(1, Ordering::Relaxed);
            let header = tun_rs::VirtioNetHdr::decode(&frame[..tun_rs::VIRTIO_NET_HDR_LEN])?;
            // `VIRTIO_NET_HDR_F_NEEDS_CSUM`: the checksum field holds the pseudo header sum.
            let partial = header.flags & 1 != 0;
            if rewrite(&mut frame[tun_rs::VIRTIO_NET_HDR_LEN..size], partial, &nat) {
                counters.packets.fetch_add(1, Ordering::Relaxed);
                device.send(&frame[..size]).await?;
            }
        }
    }

    /// Frames cut into packets by `recv_multiple` and joined again by `send_multiple`, with
    /// buffers large enough for joining.
    #[cfg(target_os = "linux")]
    async fn split_offload(device: tun_rs::AsyncDevice, counters: Arc<Counters>) -> io::Result<()> {
        let nat = nat();
        let offset = tun_rs::VIRTIO_NET_HDR_LEN;
        let slot = offset + 1500;
        let mut original = vec![0u8; offset + 65_535];
        let mut buffers: Vec<Vec<u8>> = (0..tun_rs::IDEAL_BATCH_SIZE)
            .map(|_| {
                let mut buffer = Vec::with_capacity(2 * offset + 65_535);
                buffer.resize(slot, 0);
                buffer
            })
            .collect();
        let mut sizes = vec![0usize; tun_rs::IDEAL_BATCH_SIZE];
        let mut table = tun_rs::GROTable::default();
        loop {
            let count = device.recv_multiple(&mut original, &mut buffers, &mut sizes, offset).await?;
            counters.frames.fetch_add(1, Ordering::Relaxed);
            let mut out = Vec::with_capacity(count);
            for (index, buffer) in buffers.iter_mut().enumerate().take(count) {
                buffer.truncate(offset + sizes[index]);
                if rewrite(&mut buffer[offset..], false, &nat) {
                    out.push(index);
                }
            }
            counters.packets.fetch_add(out.len() as u64, Ordering::Relaxed);
            let mut sending: Vec<&mut Vec<u8>> = Vec::with_capacity(out.len());
            let mut rest = buffers.iter_mut().enumerate();
            for want in &out {
                for (index, buffer) in rest.by_ref() {
                    if index == *want {
                        sending.push(buffer);
                        break;
                    }
                }
            }
            if !sending.is_empty() {
                device.send_multiple(&mut table, &mut sending, offset).await?;
            }
            for buffer in &mut buffers {
                buffer.resize(slot, 0);
            }
        }
    }
}
