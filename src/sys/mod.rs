//! What each system brings: its devices, the interface behind a device, and how the ends of a
//! queue move frames and wait.

use std::io;
use std::sync::Arc;

use crate::device::{Offload, Options, Up};
use crate::io::{Sink, Source};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::{Signal, interrupted};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::{Interface, Tunnel as Tun, Tunnel as Tap};

/// A device of one kind as a system has it: what creates the interface, opens its queues and
/// keeps both alive. The interface behind it is configured through [`Tunnel::interface`]; what
/// a kind of device does its own way overrides the methods that default to the interface.
pub trait Tunnel: Send + Sync + Sized + 'static {
    /// The reading end of a queue.
    type Source: Source + 'static;
    /// The writing end of a queue.
    type Sink: Sink + 'static;

    /// Creates the interface and opens its queues, without configuring it.
    fn create(options: &Options) -> io::Result<Self>;

    /// How many queues are open.
    fn queues(&self) -> usize;

    /// The reading end of queue `queue`, holding up to `frames` frames per batch. Called once
    /// for every queue.
    fn source(self: &Arc<Self>, queue: usize, frames: usize) -> io::Result<Self::Source>;

    /// The writing end of queue `queue`. Called once for every queue.
    fn sink(self: &Arc<Self>, queue: usize) -> io::Result<Self::Sink>;

    /// The interface behind the device.
    fn interface(&self) -> &Interface;

    /// What the device does with segments larger than the MTU.
    fn offload(&self) -> Offload;

    /// Whether frames carry the system's packet information in front.
    fn packet_information(&self) -> bool {
        false
    }

    /// Sets whether the interface stays after the device is gone.
    fn set_persist(&self, persist: bool) -> io::Result<()>;

    /// Configures a new interface as `options` say. Persistence comes last, so that an
    /// interface whose setup failed does not stay behind.
    fn configure(&self, options: &Options) -> io::Result<()> {
        if let Some(mtu) = options.mtu {
            self.set_mtu(mtu)?;
        }
        if let Some(mac) = options.mac_address {
            self.set_mac_address(mac)?;
        }
        self.prepare(options)?;
        for address in &options.addresses {
            self.interface()
                .add_address(*address, options.prefix_routes)
                .map_err(|error| io::Error::new(error.kind(), format!("adding {}: {error}", address.net)))?;
        }
        match options.up {
            Up::Yes => self.set_up(true)?,
            Up::No => self.set_up(false)?,
            Up::Unchanged => {}
        }
        if options.persist {
            self.set_persist(true)?;
        }
        Ok(())
    }

    /// What a kind of device configures besides, before addresses are added.
    fn prepare(&self, options: &Options) -> io::Result<()> {
        let _ = options;
        Ok(())
    }

    /// Renames the interface.
    fn set_name(&self, name: &str) -> io::Result<()> {
        self.interface().set_name(name)
    }

    /// Changes the MTU.
    fn set_mtu(&self, mtu: u32) -> io::Result<()> {
        self.interface().set_mtu(mtu)
    }

    /// Whether the interface is up.
    fn is_up(&self) -> io::Result<bool> {
        self.interface().is_up()
    }

    /// Brings the interface up or down.
    fn set_up(&self, up: bool) -> io::Result<()> {
        self.interface().set_up(up)
    }

    /// Whether the interface is up and its link is too.
    fn is_running(&self) -> io::Result<bool> {
        self.interface().is_running()
    }

    /// The hardware address of a layer 2 interface.
    fn mac_address(&self) -> io::Result<[u8; 6]> {
        self.interface().mac_address()
    }

    /// Changes the hardware address of a layer 2 interface.
    fn set_mac_address(&self, mac: [u8; 6]) -> io::Result<()> {
        self.interface().set_mac_address(mac)
    }
}

/// A device whose queues are descriptors.
#[cfg(unix)]
pub trait Descriptors: Tunnel {
    /// The descriptor of queue `queue`.
    fn queue_fd(&self, queue: usize) -> io::Result<std::os::fd::BorrowedFd<'_>>;

    /// The descriptor of a device with one queue; the device back if it has more.
    fn into_fd(self) -> Result<std::os::fd::OwnedFd, Self>;
}

/// A device that can be made of a descriptor that something else opened.
#[cfg(unix)]
pub trait Adopt: Tunnel {
    /// Wraps the descriptor of a device that carries Ethernet frames if `ethernet`, IP packets
    /// otherwise; fails for a descriptor of the other kind.
    fn adopt(fd: std::os::fd::OwnedFd, ethernet: bool) -> io::Result<Self>;
}
