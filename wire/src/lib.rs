//! The bytes of batched and offloaded packet I/O, without any device.
//!
//! A [`Framing`] says what a device puts in front of every frame and reads a frame that came
//! from it. A [`Frame`] is cut into the packets it stands for where it lies. A [`Plan`] turns a
//! batch of packets into the writes a device takes: runs of a flow joined into segments, what
//! the device can be told left to it, and the rest carried out before it is written. Nothing
//! here calls the system, so all of it runs, and is tested, on any machine.

pub mod checksum;
mod cut;
mod framing;
mod packet;
mod plan;
mod tunhdr;
mod vnet;

pub use cut::{Frame, Rest, Segments, take_first};
pub use framing::{Decoded, Family, Framing, MAX_PREFIX, Prefix, VIRTIO_HEADER};
pub use packet::{Checksum, Gso, GsoKind, Packet};
pub use plan::{Plan, Planned, Takes, Writes, gather};
