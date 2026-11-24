//! Where io_uring is not used: Android, which does not let applications use it, and 32-bit
//! Linux. Queues are read and written a frame per call.

use std::io::Result;
use std::os::fd::RawFd;

use xtun_wire::Writes as List;

use crate::device::Options;
use crate::io::{Filled, ReaderStats, WriterStats};
use crate::sys::unix::transport::{Each, Found, Gathered, Read, Slots, Write};

pub(super) fn choose(options: &Options) -> Result<bool> {
    #[cfg(target_os = "linux")]
    if options.uring == crate::device::Uring::Required {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "io_uring is only used on 64-bit Linux"));
    }
    let _ = options;
    Ok(false)
}

pub(super) fn usable() -> bool {
    false
}

/// How a queue is read.
pub struct Reads(Each);

impl Reads {
    pub(super) fn new(_uring: bool, _frames: usize) -> Result<Reads> {
        Ok(Reads(Each))
    }
}

impl Read for Reads {
    fn read(&mut self, fd: RawFd, slots: &mut Slots, frames: usize, stats: &mut ReaderStats, frame: impl FnMut(Found<'_>)) -> Filled {
        self.0.read(fd, slots, frames, stats, frame)
    }
}

/// How a queue is written.
pub struct Writes(Gathered);

impl Writes {
    pub(super) fn new(_uring: bool) -> Result<Writes> {
        Ok(Writes(Gathered::default()))
    }
}

impl Write for Writes {
    fn write(&mut self, fd: RawFd, list: &impl List, stats: &mut WriterStats) -> Result<usize> {
        self.0.write(fd, list, stats)
    }
}
