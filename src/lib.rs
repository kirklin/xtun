//! Virtual network interfaces with batched packet I/O.
//!
//! A [`Tun`] interface carries IP packets, on Linux and Android; a [`Tap`] interface carries
//! Ethernet frames, on Linux. Building one gives a handle to configure the interface and its
//! [`Queue`]s; each queue splits, once, into a [`Reader`] and a [`Writer`]. Frames are read and
//! written a batch at a time or one packet at a time, asynchronously on Tokio or async-io, or
//! blocking the thread. The system hands over TCP and UDP segments of up to 64 KiB at once and
//! takes them back the same way; [`Frame::segments`] cuts such a segment into ordinary packets
//! inside the buffer it was read into, and the writer joins consecutive packets of a flow into
//! one segment before writing.
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! let (tun, mut queues) = xtun::Tun::builder().address("10.0.0.1/24".parse().unwrap()).build()?;
//! tun.set_mtu(1400)?;
//! let (mut reader, mut writer) = queues.remove(0).split()?;
//! loop {
//!     let mut batch = reader.recv().await?;
//!     let frames: Vec<_> = batch.frames().collect();
//!     let packets: Vec<_> = frames.iter().map(|frame| frame.packet()).collect();
//!     writer.send(&packets).await?;
//! }
//! # }
//! ```

mod device;
mod io;
mod layer;
#[cfg(feature = "futures")]
mod stream;
mod sys;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use device::Tap;
#[cfg(target_os = "linux")]
pub use device::Uring;
pub use device::{Builder, Device, Offload, Tun};
pub use xtun_wire::{Checksum, Frame, Gso, GsoKind, Packet, Segments, checksum};
pub use io::{Batch, Interrupt, Queue, Reader, ReaderStats, Writer, WriterStats};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use layer::Ethernet;
pub use layer::{Ip, Layer};
#[cfg(feature = "futures")]
pub use stream::{PacketSink, PacketStream};

/// Why an asynchronous call cannot wait.
#[cfg(all(unix, not(feature = "async-io")))]
pub(crate) const NO_RUNTIME: &str =
    "waiting asynchronously needs the tokio feature and a Tokio runtime, or the async-io feature";
