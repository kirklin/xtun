//! Virtual network interfaces with batched packet I/O.
//!
//! A [`Tun`] interface carries IP packets, on Linux, Android, the Apple systems, FreeBSD, NetBSD,
//! OpenBSD, illumos and Windows; a [`Tap`] interface carries Ethernet frames, on Linux, macOS,
//! the BSDs and Windows. Building one gives a handle to configure the interface and its
//! [`Queue`]s; each queue splits, once, into a [`Reader`] and a [`Writer`], and
//! [`Writer::try_clone`] gives one more writer of the queue to every thread that writes at the
//! same time. Frames are read and written a batch at a time or one packet at a time,
//! asynchronously on Tokio or async-io, or blocking the thread. On Linux and OpenBSD, and for TAP interfaces on FreeBSD, the system
//! hands over TCP segments of up to 64 KiB at once and takes them back the same way, and on
//! Linux UDP segments too; [`Frame::segments`] cuts such a segment into ordinary packets inside
//! the buffer it was read into, and the writer joins consecutive packets of a flow into one
//! segment before writing.
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
//!
//! The frames of a batch are lent until the batch is dropped. A program that keeps what it
//! reads takes a frame out of its batch with [`LentFrame::into_owned`], which copies nothing
//! where the reader has read the frame into a block of its own, and a program whose packets are
//! headers it made and payload that lies elsewhere writes them with [`Writer::send_pieces`]:
//!
//! ```no_run
//! # async fn example(reader: &mut xtun::Reader, writer: &mut xtun::Writer) -> std::io::Result<()> {
//! let mut kept = Vec::new();
//! let mut batch = reader.recv().await?;
//! for frame in batch.frames() {
//!     // A long frame is kept as it lies; a short one is cheaper to copy than to hold a block for.
//!     if frame.data().len() >= 4096 {
//!         kept.push(frame.into_owned());
//!     }
//! }
//! drop(batch);
//!
//! let packets: Vec<_> = kept
//!     .iter()
//!     .map(|frame| {
//!         let (head, payload) = frame.data().split_at(40);
//!         (head, [payload], frame.checksum(), frame.gso())
//!     })
//!     .collect();
//! let pieces: Vec<_> = packets
//!     .iter()
//!     .map(|(head, body, checksum, gso)| xtun::Pieces { head, body, checksum: *checksum, gso: *gso })
//!     .collect();
//! writer.send_pieces(&pieces).await
//! # }
//! ```

#[cfg_attr(not(unix), allow(dead_code))]
mod block;
mod device;
mod io;
mod layer;
#[cfg(feature = "futures")]
mod stream;
mod sys;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
pub use device::Tap;
#[cfg(target_os = "linux")]
pub use device::Uring;
#[cfg(windows)]
pub use device::WintunLevel;
pub use device::{Builder, Device, Offload, Tun};
pub use xtun_wire::{Checksum, Frame, Gso, GsoKind, Packet, Pieces, Segments, checksum};
pub use io::{Batch, Interrupt, LentFrame, OwnedFrame, Queue, Reader, ReaderStats, Writer, WriterStats};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
))]
pub use layer::Ethernet;
pub use layer::{Ip, Layer};
#[cfg(feature = "futures")]
pub use stream::{PacketSink, PacketStream};

/// Why an asynchronous call cannot wait.
#[cfg(all(unix, not(feature = "async-io")))]
pub(crate) const NO_RUNTIME: &str =
    "waiting asynchronously needs the tokio feature and a Tokio runtime with its I/O driver, or the async-io feature";
