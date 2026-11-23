//! The two kinds of device, told apart by type: what only one of them has exists only on it.

use crate::sys;

mod sealed {
    pub trait Sealed {}
}

/// What a device carries: [`Ip`] packets or [`Ethernet`] frames.
pub trait Layer: sealed::Sealed + Send + Sync + Sized + 'static {
    /// The system's device of this kind.
    #[doc(hidden)]
    type Tunnel: sys::Tunnel;

    /// Whether frames start with an Ethernet header.
    #[doc(hidden)]
    const ETHERNET: bool;
}

/// IP packets: the layer of a TUN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ip {}

impl sealed::Sealed for Ip {}

impl Layer for Ip {
    type Tunnel = sys::Tun;

    const ETHERNET: bool = false;
}

/// Ethernet frames: the layer of a TAP interface.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ethernet {}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl sealed::Sealed for Ethernet {}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Layer for Ethernet {
    type Tunnel = sys::Tap;

    const ETHERNET: bool = true;
}
