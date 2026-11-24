//! The calls of the IP Helper API that configure an interface by its LUID: its name, state, MTU,
//! metric, addresses, routes and name servers.

use std::io::{Error, ErrorKind, Result};
use std::mem::zeroed;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CR_NO_SUCH_DEVNODE};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeMibTable, GetIfEntry2, GetIfTable2, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::core::GUID;

use super::wintun::wide;

pub(super) fn check(code: WIN32_ERROR) -> Result<()> {
    if code == 0 { Ok(()) } else { Err(Error::from_raw_os_error(code as i32)) }
}

/// The interface's name, its alias.
pub(super) fn alias(luid: &NET_LUID_LH) -> Result<String> {
    let mut name = [0u16; 257];
    // SAFETY: `name` holds the longest alias and its NUL.
    check(unsafe { ConvertInterfaceLuidToAlias(luid, name.as_mut_ptr(), name.len()) })?;
    let length = name.iter().position(|unit| *unit == 0).unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..length]))
}

/// The name and the LUID of every interface, without what is left of adapters that are gone.
fn interfaces() -> Result<Vec<(String, NET_LUID_LH)>> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: the table is allocated by the call and freed below.
    check(unsafe { GetIfTable2(&mut table) })?;
    // SAFETY: the table holds `NumEntries` rows.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
    let found = rows
        .iter()
        .filter(|row| !leftover(&row.InterfaceGuid))
        .map(|row| {
            let length = row.Alias.iter().position(|unit| *unit == 0).unwrap_or(row.Alias.len());
            (String::from_utf16_lossy(&row.Alias[..length]), row.InterfaceLuid)
        })
        .collect();
    // SAFETY: the table came from GetIfTable2.
    unsafe { FreeMibTable(table.cast()) };
    Ok(found)
}

/// Where Windows lists the network connections, by the GUID of their interface.
pub(super) const CONNECTIONS: &str = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// The GUID as Windows writes it in the registry and in device paths.
pub(super) fn guid_text(guid: &GUID) -> String {
    let d4 = guid.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1, guid.data2, guid.data3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    )
}

/// Whether the interface with `guid` is what is left of an adapter that is gone. Windows 11
/// keeps the interface of an adapter that ran for more than a minute after it removed the
/// adapter: down, without addresses, and under the adapter's name, until another adapter takes
/// its place. Its network connection still names the adapter's device, which is no more.
fn leftover(guid: &GUID) -> bool {
    let path = wide(format!(r"{CONNECTIONS}\{}\Connection", guid_text(guid)).as_ref());
    let mut device = [0u16; 512];
    let mut size = size_of_val(&device) as u32;
    // SAFETY: both strings are NUL-terminated and `device` is writable for `size` bytes; a string
    // read this way ends with a NUL.
    let read = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            wide("PnPInstanceId".as_ref()).as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            device.as_mut_ptr().cast(),
            &mut size,
        )
    };
    // An interface without an adapter of its own, as the loopback interface, has no device.
    if read != 0 {
        return false;
    }
    let mut node = 0u32;
    // SAFETY: `device` is NUL-terminated and `node` is writable.
    unsafe { CM_Locate_DevNodeW(&mut node, device.as_ptr(), CM_LOCATE_DEVNODE_NORMAL) == CR_NO_SUCH_DEVNODE }
}

/// Whether Windows takes two interface names for the same: it disregards case.
fn same_name(one: &str, other: &str) -> bool {
    one.to_lowercase() == other.to_lowercase()
}

/// The interface of any kind whose whole name is `name`, if there is one.
pub(super) fn luid_of(name: &str) -> Result<Option<NET_LUID_LH>> {
    Ok(interfaces()?.into_iter().find(|(alias, _)| same_name(alias, name)).map(|(_, luid)| luid))
}

/// The first of `prefix0`, `prefix1` and so on that no interface is called.
pub(super) fn free_name(prefix: &str) -> Result<String> {
    let taken = interfaces()?;
    let free = |name: &String| !taken.iter().any(|(alias, _)| same_name(alias, name));
    Ok((0..).map(|unit| format!("{prefix}{unit}")).find(free).expect("a free name"))
}

pub(super) fn guid(luid: &NET_LUID_LH) -> Result<GUID> {
    // SAFETY: plain old data.
    let mut guid: GUID = unsafe { zeroed() };
    // SAFETY: both pointers are valid.
    check(unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) })?;
    Ok(guid)
}

type SetConnectionName = unsafe extern "system" fn(guid: *const GUID, name: *const u16) -> WIN32_ERROR;
type SetInterfaceDnsSettings = unsafe extern "system" fn(interface: GUID, settings: *const DNS_INTERFACE_SETTINGS) -> WIN32_ERROR;
type FlushResolverCache = unsafe extern "system" fn() -> i32;

/// A function of a system library, looked up once; the library stays loaded.
fn system_function(library: &str, name: &[u8]) -> Option<unsafe extern "system" fn() -> isize> {
    // SAFETY: the name is NUL-terminated; only the system directory is searched.
    let module = unsafe { LoadLibraryExW(wide(library.as_ref()).as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return None;
    }
    // SAFETY: `name` is NUL-terminated and the module is loaded.
    unsafe { GetProcAddress(module, name.as_ptr()) }
}

/// Renames the interface, as the network connections folder does.
pub(super) fn rename(luid: &NET_LUID_LH, name: &str) -> Result<()> {
    static FUNCTION: OnceLock<Option<SetConnectionName>> = OnceLock::new();
    let function = FUNCTION.get_or_init(|| {
        system_function("nci.dll", b"NciSetConnectionName\0").map(|function| {
            // SAFETY: the function has this signature in every Windows that has it.
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, SetConnectionName>(function) }
        })
    });
    let function = function.ok_or_else(|| Error::new(ErrorKind::Unsupported, "this Windows cannot rename connections"))?;
    if name.is_empty() || name.encode_utf16().count() >= 256 {
        return Err(Error::new(ErrorKind::InvalidInput, "an interface name has 1 to 255 characters"));
    }
    let guid = guid(luid)?;
    // SAFETY: the GUID and the NUL-terminated name live through the call.
    check(unsafe { function(&guid, wide(name.as_ref()).as_ptr()) })
}

/// The interface as a link: its state and its hardware address.
pub(super) fn link(luid: &NET_LUID_LH) -> Result<MIB_IF_ROW2> {
    // SAFETY: plain old data.
    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceLuid = *luid;
    // SAFETY: the row names the interface.
    check(unsafe { GetIfEntry2(&mut row) })?;
    Ok(row)
}

/// Waits up to `timeout` for the interface to be there: Windows makes the interface of a new
/// adapter a moment after the adapter.
pub(super) fn await_link(luid: &NET_LUID_LH, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        match link(luid) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound && start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error),
        }
    }
}

/// How long to wait for Windows to take away the interface of a removed adapter.
const REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Waits for the interface of an adapter that was removed to be gone: Windows takes it away a
/// moment after the adapter, or keeps no more of it than its place in the list of interfaces.
/// Once it is gone, its name is free for the next adapter. Returns whether it is gone.
pub(super) fn await_gone(luid: &NET_LUID_LH) -> bool {
    let start = Instant::now();
    while link(luid).is_ok_and(|row| !leftover(&row.InterfaceGuid)) {
        if start.elapsed() >= REMOVAL_TIMEOUT {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

/// The IP interface of one family, waiting up to `timeout` for it to appear.
pub(super) fn ip_interface(luid: &NET_LUID_LH, family: ADDRESS_FAMILY, timeout: Duration) -> Result<Option<MIB_IPINTERFACE_ROW>> {
    let start = Instant::now();
    loop {
        // SAFETY: plain old data, initialized by the call.
        let mut row: MIB_IPINTERFACE_ROW = unsafe { zeroed() };
        // SAFETY: `row` is writable.
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid = *luid;
        // SAFETY: the row names the interface.
        match unsafe { GetIpInterfaceEntry(&mut row) } {
            0 => return Ok(Some(row)),
            ERROR_NOT_FOUND if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(20)),
            ERROR_NOT_FOUND => return Ok(None),
            code => return Err(Error::from_raw_os_error(code as i32)),
        }
    }
}

/// The IP interface of one family, which must exist.
pub(super) fn existing_interface(luid: &NET_LUID_LH, family: ADDRESS_FAMILY) -> Result<MIB_IPINTERFACE_ROW> {
    ip_interface(luid, family, Duration::ZERO)?.ok_or_else(|| {
        let version = if family == AF_INET { "IPv4" } else { "IPv6" };
        Error::new(ErrorKind::NotFound, format!("{version} is not enabled on the adapter"))
    })
}

pub(super) fn set_ip_interface(mut row: MIB_IPINTERFACE_ROW) -> Result<()> {
    if row.Family == AF_INET {
        // The call refuses an IPv4 row that carries a site prefix.
        row.SitePrefixLength = 0;
    }
    // SAFETY: the row came from GetIpInterfaceEntry.
    check(unsafe { SetIpInterfaceEntry(&mut row) })
}

/// IPv6 needs links of at least this MTU.
pub(super) const IPV6_MINIMUM_MTU: u32 = 1280;

/// Sets the MTU of IPv4 and, when it is large enough, of IPv6; a version that is not enabled is
/// left out.
pub(super) fn set_mtu(luid: &NET_LUID_LH, mtu: u32) -> Result<()> {
    for family in [AF_INET, AF_INET6] {
        if family == AF_INET6 && mtu < IPV6_MINIMUM_MTU {
            continue;
        }
        if let Some(mut row) = ip_interface(luid, family, Duration::ZERO)? {
            row.NlMtu = mtu;
            set_ip_interface(row)?;
        }
    }
    Ok(())
}

/// Sets the interface metric of both IP versions; one that is not enabled is left out.
pub(super) fn set_metric(luid: &NET_LUID_LH, metric: u32) -> Result<()> {
    for family in [AF_INET, AF_INET6] {
        if let Some(mut row) = ip_interface(luid, family, Duration::ZERO)? {
            row.UseAutomaticMetric = false;
            row.Metric = metric;
            set_ip_interface(row)?;
        }
    }
    Ok(())
}

pub(super) fn addresses(luid: &NET_LUID_LH) -> Result<Vec<IpNet>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: the table is allocated by the call and freed below.
    check(unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) })?;
    // SAFETY: the table holds `NumEntries` rows.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
    let nets = rows
        .iter()
        // SAFETY: both are plain unions of the same value.
        .filter(|row| unsafe { row.InterfaceLuid.Value == luid.Value })
        .filter_map(|row| IpNet::new(from_sockaddr(&row.Address)?, row.OnLinkPrefixLength).ok())
        .filter(|net| !matches!(net.addr(), IpAddr::V6(ip) if ip.is_unicast_link_local()))
        .collect();
    // SAFETY: the table came from GetUnicastIpAddressTable.
    unsafe { FreeMibTable(table.cast()) };
    Ok(nets)
}

fn address_row(luid: &NET_LUID_LH, net: IpNet) -> MIB_UNICASTIPADDRESS_ROW {
    // SAFETY: plain old data, initialized by the call.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { zeroed() };
    // SAFETY: `row` is writable.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.Address = to_sockaddr(net.addr());
    row.OnLinkPrefixLength = net.prefix_len();
    row.DadState = IpDadStatePreferred;
    row
}

/// Adds an address; Windows routes its subnet through the interface.
pub(super) fn add_address(luid: &NET_LUID_LH, net: IpNet) -> Result<()> {
    let row = address_row(luid, net);
    // SAFETY: the row is complete.
    check(unsafe { CreateUnicastIpAddressEntry(&row) })
}

pub(super) fn remove_address(luid: &NET_LUID_LH, net: IpNet) -> Result<()> {
    let row = address_row(luid, net);
    // SAFETY: the row names the address.
    check(unsafe { DeleteUnicastIpAddressEntry(&row) })
}

fn route_row(luid: &NET_LUID_LH, net: IpNet, via: Option<IpAddr>) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: plain old data, initialized by the call.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
    // SAFETY: `row` is writable.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = *luid;
    row.DestinationPrefix.Prefix = to_sockaddr(net.addr());
    row.DestinationPrefix.PrefixLength = net.prefix_len();
    // A route without a gateway reaches its destination on the link.
    row.NextHop = to_sockaddr(via.unwrap_or(match net {
        IpNet::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpNet::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }));
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

pub(super) fn add_route(luid: &NET_LUID_LH, net: IpNet, via: Option<IpAddr>) -> Result<()> {
    let row = route_row(luid, net, via);
    // SAFETY: the row is complete.
    check(unsafe { CreateIpForwardEntry2(&row) })
}

pub(super) fn remove_route(luid: &NET_LUID_LH, net: IpNet, via: Option<IpAddr>) -> Result<()> {
    let row = route_row(luid, net, via);
    // SAFETY: the row names the route.
    check(unsafe { DeleteIpForwardEntry2(&row) })
}

/// Makes `servers` the interface's name servers, of each IP version its own, in order; no
/// servers of a version clears that version's.
pub(super) fn set_dns_servers(luid: &NET_LUID_LH, index: u32, servers: &[IpAddr]) -> Result<()> {
    static FUNCTION: OnceLock<Option<SetInterfaceDnsSettings>> = OnceLock::new();
    let function = FUNCTION.get_or_init(|| {
        system_function("iphlpapi.dll", b"SetInterfaceDnsSettings\0").map(|function| {
            // SAFETY: the function has this signature in every Windows that has it, from Windows
            // 10 2004 on.
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, SetInterfaceDnsSettings>(function) }
        })
    });
    for v6 in [false, true] {
        let list: Vec<IpAddr> = servers.iter().copied().filter(|server| server.is_ipv6() == v6).collect();
        match function {
            Some(function) => {
                let joined: Vec<String> = list.iter().map(IpAddr::to_string).collect();
                let mut text = wide(joined.join(",").as_ref());
                let settings = DNS_INTERFACE_SETTINGS {
                    Version: DNS_INTERFACE_SETTINGS_VERSION1,
                    Flags: u64::from(DNS_SETTING_NAMESERVER | if v6 { DNS_SETTING_IPV6 } else { 0 }),
                    NameServer: text.as_mut_ptr(),
                    ..DNS_INTERFACE_SETTINGS::default()
                };
                // SAFETY: the settings and the string they point to live through the call.
                check(unsafe { function(guid(luid)?, &settings) })?;
            }
            None => set_dns_servers_with_netsh(index, v6, &list)?,
        }
    }
    flush_resolver_cache();
    Ok(())
}

/// Sets the name servers of one IP version through `netsh`, on Windows before 10 2004.
fn set_dns_servers_with_netsh(index: u32, v6: bool, servers: &[IpAddr]) -> Result<()> {
    let version = if v6 { "ipv6" } else { "ipv4" };
    let name = format!("name={index}");
    let first = servers.first().map_or("none".to_owned(), IpAddr::to_string);
    netsh(&["interface", version, "set", "dnsservers", &name, "source=static", &format!("address={first}"), "register=none", "validate=no"])?;
    for (position, server) in servers.iter().enumerate().skip(1) {
        netsh(&["interface", version, "add", "dnsservers", &name, &format!("address={server}"), &format!("index={}", position + 1), "validate=no"])?;
    }
    Ok(())
}

fn netsh(args: &[&str]) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let mut directory = [0u16; 260];
    // SAFETY: the buffer is writable for its length.
    let length = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if length == 0 || length >= directory.len() {
        return Err(Error::last_os_error());
    }
    let program = std::path::PathBuf::from(String::from_utf16_lossy(&directory[..length])).join("netsh.exe");
    // No console window comes up.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new(program).args(args).creation_flags(CREATE_NO_WINDOW).output()?;
    if !output.status.success() {
        let said = String::from_utf8_lossy(&output.stdout);
        return Err(Error::other(format!("netsh {}: {}", args.join(" "), said.trim())));
    }
    Ok(())
}

/// Lets the resolver forget what it learnt through the old name servers.
fn flush_resolver_cache() {
    static FUNCTION: OnceLock<Option<FlushResolverCache>> = OnceLock::new();
    let function = FUNCTION.get_or_init(|| {
        system_function("dnsapi.dll", b"DnsFlushResolverCache\0").map(|function| {
            // SAFETY: the function takes nothing and returns a BOOL in every Windows that has it.
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, FlushResolverCache>(function) }
        })
    });
    if let Some(function) = function {
        // SAFETY: the function takes nothing. A cache that could not be flushed only answers
        // from old records until they expire.
        unsafe { function() };
    }
}

pub(super) fn to_sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: plain old data.
    let mut address: SOCKADDR_INET = unsafe { zeroed() };
    match ip {
        IpAddr::V4(ip) => {
            address.Ipv4.sin_family = AF_INET;
            address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            address.Ipv6.sin6_family = AF_INET6;
            address.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    address
}

fn from_sockaddr(address: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family says which member is set.
    unsafe {
        match address.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}
