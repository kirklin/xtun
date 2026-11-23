//! The bytes of batched and offloaded packet I/O, without any device.
//!
//! The [`checksum`] of RFC 1071, which every packet that is cut or joined needs computed again.
//! Nothing here calls the system, so all of it runs, and is tested, on any machine.

pub mod checksum;
