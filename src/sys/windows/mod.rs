//! Windows: Wintun adapters carry IP packets, TAP-Windows adapters Ethernet frames; both are
//! configured through the IP Helper API.

mod config;
mod interface;
mod tap;
mod tap_io;
mod tunnel;
mod tunnel_io;
mod wait;
mod wintun;

use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;

pub use interface::Interface;
pub use tap::Tap;
pub use tunnel::Tun;
pub use wait::Signal;
pub(crate) use wait::interrupted;
use wintun::LogFunction;

use crate::device::{Options, Up};

/// What only Windows asks for.
#[derive(Clone, Debug)]
pub struct WindowsOptions {
    /// Where `wintun.dll` is.
    pub wintun: Option<PathBuf>,
    /// The size of each of Wintun's two rings.
    pub ring_capacity: u32,
    /// The adapter's GUID.
    pub guid: Option<u128>,
    /// The tunnel type shown for a Wintun adapter.
    pub tunnel_type: String,
    /// The MTU of IPv6.
    pub mtu_v6: Option<u32>,
    /// The interface metric of both IP versions.
    pub metric: Option<u32>,
    /// Whether the Wintun driver is removed once the device is dropped.
    pub delete_driver: bool,
    /// What receives Wintun's messages.
    pub logger: Option<LogFunction>,
}

impl Default for WindowsOptions {
    fn default() -> WindowsOptions {
        WindowsOptions {
            wintun: None,
            ring_capacity: 8 << 20,
            guid: None,
            tunnel_type: "xtun".to_owned(),
            mtu_v6: None,
            metric: None,
            delete_driver: false,
            logger: None,
        }
    }
}

/// Refuses what no Windows adapter has: more than one queue, and packet information.
fn check_options(options: &Options) -> Result<()> {
    if options.queues != 1 {
        return Err(Error::new(ErrorKind::Unsupported, "Windows adapters have one queue"));
    }
    if options.packet_information {
        return Err(Error::new(ErrorKind::InvalidInput, "Windows adapters carry no packet information"));
    }
    Ok(())
}

fn check_queue(queue: usize) -> Result<()> {
    if queue != 0 {
        return Err(Error::new(ErrorKind::InvalidInput, format!("the device has one queue, there is no queue {queue}")));
    }
    Ok(())
}

/// Configures a new adapter of either kind as `options` say, once the IP stack has picked it
/// up. A hardware address is not among the steps: an adapter that takes one takes it when it is
/// created. Persistence comes last, so that an adapter whose setup failed does not stay behind.
fn configure<T: super::Tunnel>(tunnel: &T, options: &Options) -> Result<()> {
    let interface = tunnel.interface();
    interface.settle(options.addresses.iter().any(|address| address.net.addr().is_ipv6()) || options.windows.mtu_v6.is_some())?;
    if let Some(mtu) = options.mtu {
        tunnel.set_mtu(mtu)?;
    }
    if let Some(mtu) = options.windows.mtu_v6 {
        interface.set_mtu_v6(mtu)?;
    }
    if let Some(metric) = options.windows.metric {
        interface.set_metric(metric)?;
    }
    for address in &options.addresses {
        interface
            .add_address(*address, options.prefix_routes)
            .map_err(|error| Error::new(error.kind(), format!("adding {}: {error}", address.net)))?;
    }
    match options.up {
        Up::Yes => tunnel.set_up(true)?,
        Up::No => tunnel.set_up(false)?,
        Up::Unchanged => {}
    }
    if let Some(persist) = options.persist {
        tunnel.set_persist(persist)?;
    }
    Ok(())
}
