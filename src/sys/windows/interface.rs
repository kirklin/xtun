//! A Windows interface by its LUID, configured through the IP Helper API like any other.

use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::Duration;

use ipnet::IpNet;
use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_IF_ADMIN_STATUS_UP, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::config;
use crate::device::Address;

/// How long to wait for the IP stack to pick up a new adapter.
const INTERFACE_TIMEOUT: Duration = Duration::from_secs(5);

const ERROR_OBJECT_ALREADY_EXISTS: i32 = windows_sys::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS as i32;
const ERROR_NOT_FOUND: i32 = windows_sys::Win32::Foundation::ERROR_NOT_FOUND as i32;

/// The interface behind a device.
pub struct Interface {
    luid: NET_LUID_LH,
    index: u32,
    /// Addresses added without a route to their subnet, which Windows has as host addresses,
    /// with the prefixes they were given.
    host_only: Mutex<Vec<IpNet>>,
    /// The far ends of point-to-point addresses, by address, which have routes of their own.
    peers: Mutex<Vec<(IpAddr, IpAddr)>>,
}

impl Interface {
    pub(super) fn new(luid: NET_LUID_LH) -> Result<Interface> {
        let mut index = 0;
        // SAFETY: both pointers are valid.
        config::check(unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) })?;
        Ok(Interface { luid, index, host_only: Mutex::new(Vec::new()), peers: Mutex::new(Vec::new()) })
    }

    /// Waits for the IP stack to pick up a new adapter: IPv4 always, IPv6 when `v6` says that
    /// it is needed.
    pub(super) fn settle(&self, v6: bool) -> Result<()> {
        config::ip_interface(&self.luid, AF_INET, INTERFACE_TIMEOUT)?
            .ok_or_else(|| Error::new(ErrorKind::TimedOut, "the IPv4 stack did not pick up the adapter"))?;
        if v6 {
            config::ip_interface(&self.luid, AF_INET6, INTERFACE_TIMEOUT)?
                .ok_or_else(|| Error::new(ErrorKind::Unsupported, "IPv6 is not enabled on the adapter"))?;
        }
        Ok(())
    }

    pub fn name(&self) -> Result<String> {
        config::alias(&self.luid)
    }

    pub fn set_name(&self, name: &str) -> Result<()> {
        config::rename(&self.luid, name)
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn luid(&self) -> u64 {
        // SAFETY: both members of the union are the same 64 bits.
        unsafe { self.luid.Value }
    }

    pub fn mtu(&self) -> Result<u32> {
        Ok(config::existing_interface(&self.luid, AF_INET)?.NlMtu)
    }

    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        config::set_mtu(&self.luid, mtu)
    }

    pub fn mtu_v6(&self) -> Result<u32> {
        Ok(config::existing_interface(&self.luid, AF_INET6)?.NlMtu)
    }

    pub fn set_mtu_v6(&self, mtu: u32) -> Result<()> {
        if mtu < config::IPV6_MINIMUM_MTU {
            return Err(Error::new(ErrorKind::InvalidInput, "IPv6 needs an MTU of at least 1280"));
        }
        let mut row = config::existing_interface(&self.luid, AF_INET6)?;
        row.NlMtu = mtu;
        config::set_ip_interface(row)
    }

    pub fn metric(&self) -> Result<u32> {
        Ok(config::existing_interface(&self.luid, AF_INET)?.Metric)
    }

    pub fn set_metric(&self, metric: u32) -> Result<()> {
        config::set_metric(&self.luid, metric)
    }

    pub fn set_dns_servers(&self, servers: &[IpAddr]) -> Result<()> {
        config::set_dns_servers(&self.luid, self.index, servers)
    }

    /// Whether the interface is enabled.
    pub fn is_up(&self) -> Result<bool> {
        Ok(config::link(&self.luid)?.AdminStatus == NET_IF_ADMIN_STATUS_UP)
    }

    /// The IP Helper API brings no interface up or down: each kind of adapter has its own way.
    pub fn set_up(&self, _up: bool) -> Result<()> {
        Err(Error::new(ErrorKind::Unsupported, "an interface on Windows comes up and goes down through its adapter"))
    }

    /// Whether the interface is operational: for Wintun, while a session runs.
    pub fn is_running(&self) -> Result<bool> {
        Ok(config::link(&self.luid)?.OperStatus == IfOperStatusUp)
    }

    /// The far ends of point-to-point addresses lose their routes with the link: once the link
    /// is up again, they get them back.
    pub(super) fn restore_peers(&self) -> Result<()> {
        for (_, peer) in self.peers.lock().expect("peers").iter() {
            tolerate(config::add_route(&self.luid, IpNet::from(*peer), None), ERROR_OBJECT_ALREADY_EXISTS)?;
        }
        Ok(())
    }

    pub fn addresses(&self) -> Result<Vec<IpNet>> {
        let host_only = self.host_only.lock().expect("host addresses");
        let nets = config::addresses(&self.luid)?;
        Ok(nets
            .into_iter()
            .map(|net| {
                let given = host_only.iter().find(|given| given.addr() == net.addr() && net.prefix_len() == net.max_prefix_len());
                given.copied().unwrap_or(net)
            })
            .collect())
    }

    /// Adds an address. Without a prefix route, Windows gets it as a host address, so that its
    /// subnet has no route; a peer gets a route of its own.
    pub fn add_address(&self, address: Address, prefix_route: bool) -> Result<()> {
        let net = address.net;
        let host = net.prefix_len() < net.max_prefix_len() && !prefix_route;
        let added = if host { IpNet::from(net.addr()) } else { net };
        config::add_address(&self.luid, added)?;
        if host {
            self.host_only.lock().expect("host addresses").push(net);
        }
        if let Some(peer) = address.peer {
            tolerate(config::add_route(&self.luid, IpNet::from(peer), None), ERROR_OBJECT_ALREADY_EXISTS)?;
            self.peers.lock().expect("peers").push((net.addr(), peer));
        }
        Ok(())
    }

    pub fn remove_address(&self, net: IpNet) -> Result<()> {
        let mut host_only = self.host_only.lock().expect("host addresses");
        let host = host_only.iter().position(|given| *given == net);
        let removed = if host.is_some() { IpNet::from(net.addr()) } else { net };
        config::remove_address(&self.luid, removed)?;
        if let Some(position) = host {
            host_only.remove(position);
        }
        drop(host_only);
        let mut peers = self.peers.lock().expect("peers");
        if let Some(position) = peers.iter().position(|(address, _)| *address == net.addr()) {
            let (_, peer) = peers.remove(position);
            tolerate(config::remove_route(&self.luid, IpNet::from(peer), None), ERROR_NOT_FOUND)?;
        }
        Ok(())
    }

    pub fn broadcast(&self) -> Result<Option<Ipv4Addr>> {
        Err(no_broadcast())
    }

    pub fn set_broadcast(&self, _broadcast: Ipv4Addr) -> Result<()> {
        Err(no_broadcast())
    }

    /// The hardware address Windows lists for the interface. A layer 3 interface has none.
    pub fn mac_address(&self) -> Result<[u8; 6]> {
        let link = config::link(&self.luid)?;
        if link.PhysicalAddressLength != 6 {
            return Err(no_hardware_address());
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&link.PhysicalAddress[..6]);
        Ok(mac)
    }

    /// Only an adapter that carries Ethernet frames takes a hardware address, in its own way.
    pub fn set_mac_address(&self, _mac: [u8; 6]) -> Result<()> {
        Err(no_hardware_address())
    }

    pub fn add_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        config::add_route(&self.luid, net, via).map_err(|error| match error.raw_os_error() {
            Some(ERROR_OBJECT_ALREADY_EXISTS) => Error::new(ErrorKind::AlreadyExists, format!("the route to {net} exists")),
            _ => error,
        })
    }

    pub fn remove_route(&self, net: IpNet, via: Option<IpAddr>) -> Result<()> {
        config::remove_route(&self.luid, net, via)
    }
}

/// `result`, with the error `code` counting as success.
fn tolerate(result: Result<()>, code: i32) -> Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(code) => Ok(()),
        other => other,
    }
}

fn no_broadcast() -> Error {
    Error::new(ErrorKind::Unsupported, "Windows keeps no broadcast address for an interface")
}

fn no_hardware_address() -> Error {
    Error::new(ErrorKind::InvalidInput, "a layer 3 interface has no hardware address")
}
