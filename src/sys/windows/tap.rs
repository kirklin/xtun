//! TAP-Windows adapters (tap-windows6), for Ethernet frames. An adapter is made and removed with
//! the setup API, known by the GUID of its interface and opened as `\\.\Global\{GUID}.tap` for
//! overlapped reads and writes. The driver itself has to be installed.

use std::io::{Error, ErrorKind, Result};
use std::mem::zeroed;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DI_NEEDREBOOT, DI_NEEDRESTART, DICD_GENERATE_ID, DICS_FLAG_GLOBAL, DICS_PROPCHANGE, DIF_INSTALLDEVICE, DIF_INSTALLINTERFACES,
    DIF_PROPERTYCHANGE, DIF_REGISTER_COINSTALLERS, DIF_REGISTERDEVICE, DIF_REMOVE, DIGCF_PRESENT, DIREG_DRV, GUID_DEVCLASS_NET,
    HDEVINFO, MAX_CLASS_NAME_LEN, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_DEVINSTALL_PARAMS_W, SP_DRVINFO_DATA_V2_W,
    SP_DRVINFO_DETAIL_DATA_W, SP_PROPCHANGE_PARAMS, SPDIT_COMPATDRIVER, SPDRP_HARDWAREID, SetupDiBuildDriverInfoList,
    SetupDiCallClassInstaller, SetupDiClassNameFromGuidW, SetupDiCreateDeviceInfoList, SetupDiCreateDeviceInfoW,
    SetupDiDestroyDeviceInfoList, SetupDiDestroyDriverInfoList, SetupDiEnumDeviceInfo, SetupDiEnumDriverInfoW,
    SetupDiGetClassDevsW, SetupDiGetDeviceInstallParamsW, SetupDiGetDeviceRegistryPropertyW, SetupDiGetDriverInfoDetailW,
    SetupDiOpenDevRegKey, SetupDiSetClassInstallParamsW, SetupDiSetDeviceRegistryPropertyW, SetupDiSetSelectedDriverW,
};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_NO_MORE_ITEMS, GENERIC_READ, GENERIC_WRITE, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_OVERLAPPED, OPEN_EXISTING};
use windows_sys::Win32::System::IO::{DeviceIoControl, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    REG_SZ, RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use super::tap_io::{Sink, Source};
use super::wait::{Event, wait};
use super::wintun::wide;
use super::{Interface, check_options, check_queue, config};
use crate::device::{Offload, Options};

/// The hardware ids of the driver's adapters: the root-enumerated ones this library makes, and
/// those of older tools.
const HARDWARE_IDS: [&str; 2] = ["root\\tap0901", "tap0901"];
/// How long Windows may take to install an adapter or start it again.
const START_TIMEOUT: Duration = Duration::from_secs(20);

/// `CTL_CODE(FILE_DEVICE_UNKNOWN, function, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const fn control_code(function: u32) -> u32 {
    (0x22 << 16) | (function << 2)
}
const TAP_WIN_IOCTL_GET_MAC: u32 = control_code(1);
const TAP_WIN_IOCTL_GET_VERSION: u32 = control_code(2);
const TAP_WIN_IOCTL_GET_MTU: u32 = control_code(3);
const TAP_WIN_IOCTL_SET_MEDIA_STATUS: u32 = control_code(6);

/// A TAP-Windows adapter: its file, and the adapter, which goes with the device unless it
/// persists.
pub struct Tap {
    interface: Interface,
    /// Before `adapter`, so that the file is closed before the adapter is removed.
    file: OwnedHandle,
    adapter: Adapter,
    /// Whether the medium is connected.
    up: AtomicBool,
}

/// An adapter, known by the GUID of its interface. Dropped, it removes the adapter unless the
/// adapter persists.
struct Adapter {
    guid: String,
    luid: NET_LUID_LH,
    persist: AtomicBool,
}

impl Drop for Adapter {
    fn drop(&mut self) {
        if !self.persist.load(Ordering::Relaxed) {
            // Nothing is left to report a failure to; the adapter stays behind.
            if remove(&self.guid).is_ok() {
                config::await_gone(&self.luid);
            }
        }
    }
}

impl crate::sys::Tunnel for Tap {
    type Source = Source;
    type Sink = Sink;

    /// Opens the TAP adapter of the requested name, which `reuse` allows to take over, or makes
    /// one and names it, `tap0`, `tap1` and so on without a name. A hardware address is set
    /// before the file is opened, as Windows takes it only when the adapter starts.
    fn create(options: &Options) -> Result<Tap> {
        check_options(options)?;
        let name = match &options.name {
            Some(name) => name.clone(),
            None => config::free_name("tap")?,
        };
        if name.is_empty() || name.encode_utf16().count() >= 128 {
            return Err(Error::new(ErrorKind::InvalidInput, "an adapter name has 1 to 127 characters"));
        }
        let (adapter, luid) = if let Some(luid) = config::luid_of(&name)? {
            if !options.reuse {
                return Err(Error::new(ErrorKind::AlreadyExists, format!("an interface is called {name}")));
            }
            // An adapter that was there before stays, as a persistent interface does on Linux,
            // until the device is told it may go.
            (Adapter { guid: guid_text(&config::guid(&luid)?), luid, persist: AtomicBool::new(true) }, luid)
        } else {
            let (adapter, luid) = step("installing a TAP adapter", install())?;
            step("waiting for the TAP adapter's interface", config::await_link(&luid, START_TIMEOUT))?;
            step("waiting for Windows to list the TAP adapter", connection_listed(&adapter.guid))?;
            step("naming the TAP adapter", config::rename(&luid, &name))?;
            (adapter, luid)
        };
        if let Some(mac) = options.mac_address {
            step("writing the TAP adapter's hardware address", set_network_address(&adapter.guid, mac))?;
            step("restarting the TAP adapter", restart(&adapter.guid))?;
        }
        let file = open(&adapter.guid).map_err(|error| match error.kind() {
            ErrorKind::NotFound => Error::new(ErrorKind::InvalidInput, format!("{name} is not a TAP-Windows adapter")),
            _ => error,
        })?;
        let interface = Interface::new(luid)?;
        Ok(Tap { interface, file, adapter, up: AtomicBool::new(false) })
    }

    fn queues(&self) -> usize {
        1
    }

    fn source(self: &Arc<Tap>, queue: usize, frames: usize) -> Result<Source> {
        check_queue(queue)?;
        Source::new(self.clone(), frames)
    }

    fn sink(self: &Arc<Tap>, queue: usize) -> Result<Sink> {
        check_queue(queue)?;
        Sink::new(self.clone())
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn offload(&self) -> Offload {
        Offload::default()
    }

    fn set_persist(&self, persist: bool) -> Result<()> {
        self.adapter.persist.store(persist, Ordering::Relaxed);
        Ok(())
    }

    fn configure(&self, options: &Options) -> Result<()> {
        super::configure(self, options)
    }

    fn set_mtu(&self, mtu: u32) -> Result<()> {
        let most = self.frame_mtu()?;
        if mtu > most {
            return Err(Error::new(ErrorKind::InvalidInput, format!("the TAP adapter carries packets of up to {most} bytes")));
        }
        self.interface.set_mtu(mtu)
    }

    fn is_up(&self) -> Result<bool> {
        Ok(self.up.load(Ordering::Relaxed))
    }

    /// Connects the adapter's medium, or disconnects it: the adapter carries frames only while
    /// its medium is connected.
    fn set_up(&self, up: bool) -> Result<()> {
        let was_up = self.up.load(Ordering::Relaxed);
        let status = u32::from(up);
        self.control(TAP_WIN_IOCTL_SET_MEDIA_STATUS, &status.to_ne_bytes(), &mut [])?;
        self.up.store(up, Ordering::Relaxed);
        if up && !was_up {
            self.interface.restore_peers()?;
        }
        Ok(())
    }

    fn mac_address(&self) -> Result<[u8; 6]> {
        let mut mac = [0u8; 6];
        self.control(TAP_WIN_IOCTL_GET_MAC, &[], &mut mac)?;
        Ok(mac)
    }

    fn set_mac_address(&self, _mac: [u8; 6]) -> Result<()> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "a TAP adapter takes its hardware address when it starts, which the open device would not survive: give it to the builder",
        ))
    }

    /// The version of the driver: its major and minor number.
    fn driver_version(&self) -> Result<String> {
        let mut version = [0u8; 12];
        self.control(TAP_WIN_IOCTL_GET_VERSION, &[], &mut version)?;
        let number = |at: usize| u32::from_ne_bytes(version[at..at + 4].try_into().expect("four bytes"));
        Ok(format!("{}.{}", number(0), number(4)))
    }
}

impl Tap {
    pub(super) fn handle(&self) -> HANDLE {
        self.file.as_raw_handle()
    }

    /// The largest Ethernet payload the driver carries.
    pub(super) fn frame_mtu(&self) -> Result<u32> {
        let mut mtu = [0u8; 4];
        self.control(TAP_WIN_IOCTL_GET_MTU, &[], &mut mtu)?;
        Ok(u32::from_ne_bytes(mtu))
    }

    /// A request to the driver, which it answers at once.
    fn control(&self, code: u32, input: &[u8], output: &mut [u8]) -> Result<()> {
        let event = Event::new(true)?;
        // SAFETY: plain old data.
        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        overlapped.hEvent = event.handle();
        let mut returned = 0u32;
        // SAFETY: both buffers live through the request, which is waited for below.
        let done = unsafe {
            DeviceIoControl(
                self.handle(),
                code,
                input.as_ptr().cast(),
                input.len() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut returned,
                &mut overlapped,
            )
        };
        // SAFETY: reads the calling thread's last error.
        if done == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(Error::last_os_error());
        }
        // SAFETY: the request was started with this overlapped structure; waits for it.
        if unsafe { GetOverlappedResult(self.handle(), &overlapped, &mut returned, 1) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

/// `result`, with an error that says which step of making the adapter failed.
fn step<T>(what: &str, result: Result<T>) -> Result<T> {
    result.map_err(|error| Error::new(error.kind(), format!("{what}: {error}")))
}

/// The GUID as Windows writes it in the registry and in device paths.
fn guid_text(guid: &windows_sys::core::GUID) -> String {
    let d4 = guid.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1, guid.data2, guid.data3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    )
}

/// Opens the adapter's file for overlapped reads and writes, waiting for a new adapter to start.
fn open(guid: &str) -> Result<OwnedHandle> {
    let path = wide(format!(r"\\.\Global\{guid}.tap").as_ref());
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        // SAFETY: the path is NUL-terminated; the handle is owned right away.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            // SAFETY: a new handle that nobody else owns.
            return Ok(unsafe { OwnedHandle::from_raw_handle(handle) });
        }
        let error = Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND as i32) || Instant::now() >= deadline {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A set of device information, destroyed when dropped.
struct DeviceSet(HDEVINFO);

impl DeviceSet {
    /// An empty set for a new network adapter.
    fn new() -> Result<DeviceSet> {
        // SAFETY: plain creation of an empty set.
        let set = unsafe { SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, std::ptr::null_mut()) };
        if set == INVALID_HANDLE_VALUE as HDEVINFO {
            return Err(Error::last_os_error());
        }
        Ok(DeviceSet(set))
    }

    /// The network adapters that are present.
    fn present() -> Result<DeviceSet> {
        // SAFETY: plain query of the adapters.
        let set = unsafe { SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, std::ptr::null(), std::ptr::null_mut(), DIGCF_PRESENT) };
        if set == INVALID_HANDLE_VALUE as HDEVINFO {
            return Err(Error::last_os_error());
        }
        Ok(DeviceSet(set))
    }

    fn call(&self, function: u32, device: &SP_DEVINFO_DATA) -> Result<()> {
        // SAFETY: the set holds the device.
        check(unsafe { SetupDiCallClassInstaller(function, self.0, device) })
    }

    /// The device's driver key in the registry.
    fn driver_key(&self, device: &SP_DEVINFO_DATA, access: u32) -> Result<Key> {
        // SAFETY: the set holds the device.
        let key = unsafe { SetupDiOpenDevRegKey(self.0, device, DICS_FLAG_GLOBAL, 0, DIREG_DRV, access) };
        if std::ptr::eq(key, INVALID_HANDLE_VALUE) {
            return Err(Error::last_os_error());
        }
        Ok(Key(key))
    }

    /// The present TAP adapter whose interface has `guid`.
    fn find(&self, guid: &str) -> Result<SP_DEVINFO_DATA> {
        for index in 0.. {
            let mut device = device_data();
            // SAFETY: `device` is writable and says its size.
            if unsafe { SetupDiEnumDeviceInfo(self.0, index, &mut device) } == 0 {
                // SAFETY: reads the calling thread's last error.
                return match unsafe { GetLastError() } {
                    ERROR_NO_MORE_ITEMS => Err(Error::new(ErrorKind::NotFound, format!("no TAP adapter has the interface {guid}"))),
                    code => Err(Error::from_raw_os_error(code as i32)),
                };
            }
            if !self.is_tap(&device)? {
                continue;
            }
            let Ok(key) = self.driver_key(&device, KEY_QUERY_VALUE) else {
                continue;
            };
            if key.string("NetCfgInstanceId")?.is_some_and(|found| found.eq_ignore_ascii_case(guid)) {
                return Ok(device);
            }
        }
        unreachable!("the enumeration ends with ERROR_NO_MORE_ITEMS")
    }

    /// Whether the device has a hardware id of the TAP driver.
    fn is_tap(&self, device: &SP_DEVINFO_DATA) -> Result<bool> {
        let mut buffer = [0u16; 512];
        let mut needed = 0u32;
        // SAFETY: the buffer is writable for its size in bytes.
        let found = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                self.0,
                device,
                SPDRP_HARDWAREID,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                size_of_val(&buffer) as u32,
                &mut needed,
            )
        };
        if found == 0 {
            // A device without hardware ids, or with more than fit, is none of the driver's.
            return Ok(false);
        }
        let ids = String::from_utf16_lossy(&buffer[..(needed as usize / 2).min(buffer.len())]);
        Ok(ids.split('\0').any(|id| HARDWARE_IDS.iter().any(|ours| id.eq_ignore_ascii_case(ours))))
    }
}

impl Drop for DeviceSet {
    fn drop(&mut self) {
        // SAFETY: the set was created here and is destroyed once.
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

fn device_data() -> SP_DEVINFO_DATA {
    // SAFETY: plain old data.
    let mut device: SP_DEVINFO_DATA = unsafe { zeroed() };
    device.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
    device
}

/// Removes, when dropped, a device that is being installed, unless the installation finished.
struct Installing<'a> {
    set: &'a DeviceSet,
    device: SP_DEVINFO_DATA,
    done: bool,
}

impl Drop for Installing<'_> {
    fn drop(&mut self) {
        if !self.done {
            // The installation failed already; that error is the one to report.
            let _ = self.set.call(DIF_REMOVE, &self.device);
        }
    }
}

/// Makes a TAP adapter with the newest version of the driver that is installed, and waits for
/// Windows to give it an interface.
fn install() -> Result<(Adapter, NET_LUID_LH)> {
    let set = DeviceSet::new()?;
    let mut class = [0u16; MAX_CLASS_NAME_LEN as usize];
    // SAFETY: the buffer is writable for its length in characters.
    check(unsafe { SetupDiClassNameFromGuidW(&GUID_DEVCLASS_NET, class.as_mut_ptr(), class.len() as u32, std::ptr::null_mut()) })?;
    let mut device = device_data();
    // SAFETY: the class name is NUL-terminated and `device` says its size.
    check(unsafe {
        SetupDiCreateDeviceInfoW(
            set.0,
            class.as_ptr(),
            &GUID_DEVCLASS_NET,
            std::ptr::null(),
            std::ptr::null_mut(),
            DICD_GENERATE_ID,
            &mut device,
        )
    })?;
    // A list of strings that ends with an empty one.
    let mut ids: Vec<u16> = HARDWARE_IDS[0].encode_utf16().collect();
    ids.extend([0, 0]);
    // SAFETY: the list is readable for its size in bytes.
    check(unsafe {
        SetupDiSetDeviceRegistryPropertyW(set.0, &mut device, SPDRP_HARDWAREID, ids.as_ptr().cast(), (ids.len() * 2) as u32)
    })?;
    let _drivers = select_driver(&set, &mut device)?;
    set.call(DIF_REGISTERDEVICE, &device)?;
    let mut installing = Installing { set: &set, device, done: false };
    set.call(DIF_REGISTER_COINSTALLERS, &device)?;
    set.call(DIF_INSTALLINTERFACES, &device)?;
    set.call(DIF_INSTALLDEVICE, &device)?;
    // SAFETY: plain old data.
    let mut parameters: SP_DEVINSTALL_PARAMS_W = unsafe { zeroed() };
    parameters.cbSize = size_of::<SP_DEVINSTALL_PARAMS_W>() as u32;
    // SAFETY: `parameters` is writable and says its size.
    check(unsafe { SetupDiGetDeviceInstallParamsW(set.0, &device, &mut parameters) })?;
    if parameters.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) != 0 {
        return Err(Error::other("Windows has to restart to finish installing the TAP adapter"));
    }
    let key = set.driver_key(&device, KEY_QUERY_VALUE | KEY_NOTIFY)?;
    let (guid, luid) = key.interface()?;
    installing.done = true;
    Ok((Adapter { guid, luid, persist: AtomicBool::new(false) }, luid))
}

/// The list of the drivers that suit a device. The driver selected from it stays the device's
/// selected driver only while the list lives.
struct Drivers<'a> {
    set: &'a DeviceSet,
    device: SP_DEVINFO_DATA,
}

impl Drop for Drivers<'_> {
    fn drop(&mut self) {
        // SAFETY: the list was built for this device of the set.
        unsafe { SetupDiDestroyDriverInfoList(self.set.0, &self.device, SPDIT_COMPATDRIVER) };
    }
}

/// Selects, of the drivers that suit the device, the newest one that is the TAP driver. The
/// device installs with it while the list that comes back lives.
fn select_driver<'a>(set: &'a DeviceSet, device: &mut SP_DEVINFO_DATA) -> Result<Drivers<'a>> {
    // SAFETY: the set holds the device.
    check(unsafe { SetupDiBuildDriverInfoList(set.0, device, SPDIT_COMPATDRIVER) })?;
    let drivers = Drivers { set, device: *device };
    let mut chosen: Option<SP_DRVINFO_DATA_V2_W> = None;
    for index in 0.. {
        // SAFETY: plain old data.
        let mut driver: SP_DRVINFO_DATA_V2_W = unsafe { zeroed() };
        driver.cbSize = size_of::<SP_DRVINFO_DATA_V2_W>() as u32;
        // SAFETY: `driver` is writable and says its size.
        if unsafe { SetupDiEnumDriverInfoW(set.0, device, SPDIT_COMPATDRIVER, index, &mut driver) } == 0 {
            // SAFETY: reads the calling thread's last error.
            match unsafe { GetLastError() } {
                ERROR_NO_MORE_ITEMS => break,
                code => return Err(Error::from_raw_os_error(code as i32)),
            }
        }
        if chosen.is_some_and(|chosen| chosen.DriverVersion >= driver.DriverVersion) || !driver_is_tap(set, device, &driver)? {
            continue;
        }
        chosen = Some(driver);
    }
    let Some(mut driver) = chosen else {
        return Err(Error::new(ErrorKind::NotFound, "the TAP-Windows driver is not installed"));
    };
    // SAFETY: the driver came from the device's list.
    check(unsafe { SetupDiSetSelectedDriverW(set.0, device, &mut driver) })?;
    Ok(drivers)
}

/// Whether a driver of the device's list is the TAP driver, by its hardware id.
fn driver_is_tap(set: &DeviceSet, device: &SP_DEVINFO_DATA, driver: &SP_DRVINFO_DATA_V2_W) -> Result<bool> {
    // Room for the details and a long list of hardware ids, aligned as the structure.
    let mut buffer = vec![0u64; (size_of::<SP_DRVINFO_DETAIL_DATA_W>() + 4096) / 8];
    let detail = buffer.as_mut_ptr().cast::<SP_DRVINFO_DETAIL_DATA_W>();
    // SAFETY: the buffer is large enough for the structure, which says its fixed size.
    unsafe { (*detail).cbSize = size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32 };
    let mut needed = 0u32;
    // SAFETY: the buffer is writable for its size in bytes.
    let found = unsafe { SetupDiGetDriverInfoDetailW(set.0, device, driver, detail, (buffer.len() * 8) as u32, &mut needed) };
    // SAFETY: reads the calling thread's last error.
    if found == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(Error::last_os_error());
    }
    // SAFETY: the hardware id is a NUL-terminated string within the buffer.
    let id = unsafe {
        let start = std::ptr::addr_of!((*detail).HardwareID).cast::<u16>();
        let room = (buffer.len() * 8 - (start as usize - buffer.as_ptr() as usize)) / 2;
        let id = std::slice::from_raw_parts(start, room);
        String::from_utf16_lossy(&id[..id.iter().position(|unit| *unit == 0).unwrap_or(room)])
    };
    Ok(HARDWARE_IDS.iter().any(|ours| id.eq_ignore_ascii_case(ours)))
}

/// Where Windows lists the network connections, by the GUID of their interface.
const CONNECTIONS: &str = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// Waits until Windows lists a new adapter as a network connection, under a name of its own
/// choice, which it does a moment after it installed the adapter. Only a listed connection
/// takes another name.
fn connection_listed(guid: &str) -> Result<()> {
    let connections = Key::open(HKEY_LOCAL_MACHINE, CONNECTIONS, KEY_NOTIFY)?;
    let deadline = Instant::now() + START_TIMEOUT;
    let changed = Event::new(false)?;
    loop {
        // Watched first, so that a name written meanwhile is not missed.
        // SAFETY: the key and the event are open; the watch ends with the key.
        check_code(unsafe {
            RegNotifyChangeKeyValue(connections.0, 1, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, changed.handle(), 1)
        })?;
        match Key::open(connections.0, &format!(r"{guid}\Connection"), KEY_QUERY_VALUE) {
            Ok(connection) if connection.string("Name")?.is_some() => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        wait(Some(changed.handle()), None, Some(deadline), None)?;
    }
}

/// Removes the TAP adapter whose interface has `guid`.
fn remove(guid: &str) -> Result<()> {
    let set = DeviceSet::present()?;
    let device = set.find(guid)?;
    set.call(DIF_REMOVE, &device)
}

/// Writes the hardware address the adapter takes when it starts.
fn set_network_address(guid: &str, mac: [u8; 6]) -> Result<()> {
    let set = DeviceSet::present()?;
    let device = set.find(guid)?;
    let key = set.driver_key(&device, KEY_SET_VALUE)?;
    let text: String = mac.iter().map(|byte| format!("{byte:02X}")).collect();
    key.set_string("NetworkAddress", &text)
}

/// Stops the adapter and starts it again, so that it takes its settings anew.
fn restart(guid: &str) -> Result<()> {
    let set = DeviceSet::present()?;
    let device = set.find(guid)?;
    let parameters = SP_PROPCHANGE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_PROPERTYCHANGE,
        },
        StateChange: DICS_PROPCHANGE,
        Scope: DICS_FLAG_GLOBAL,
        HwProfile: 0,
    };
    // SAFETY: the parameters say their size and the set holds the device.
    check(unsafe {
        SetupDiSetClassInstallParamsW(set.0, &device, &parameters.ClassInstallHeader, size_of::<SP_PROPCHANGE_PARAMS>() as u32)
    })?;
    set.call(DIF_PROPERTYCHANGE, &device)
}

/// A registry key, closed when dropped.
struct Key(HKEY);

impl Key {
    /// Opens the key at `path` below `parent`.
    fn open(parent: HKEY, path: &str, access: u32) -> Result<Key> {
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: the path is NUL-terminated and `key` is writable.
        check_code(unsafe { RegOpenKeyExW(parent, wide(path.as_ref()).as_ptr(), 0, access, &mut key) })?;
        Ok(Key(key))
    }

    fn string(&self, name: &str) -> Result<Option<String>> {
        let name = wide(name.as_ref());
        let mut buffer = [0u16; 256];
        let mut size = size_of_val(&buffer) as u32;
        let mut kind = 0u32;
        // SAFETY: the buffer is writable for `size` bytes.
        let code = unsafe { RegQueryValueExW(self.0, name.as_ptr(), std::ptr::null(), &mut kind, buffer.as_mut_ptr().cast(), &mut size) };
        match code {
            0 if kind == REG_SZ => {
                let text = &buffer[..size as usize / 2];
                Ok(Some(String::from_utf16_lossy(text).trim_end_matches('\0').to_owned()))
            }
            0 => Err(Error::new(ErrorKind::InvalidData, "the registry value is not a string")),
            ERROR_FILE_NOT_FOUND => Ok(None),
            code => Err(Error::from_raw_os_error(code as i32)),
        }
    }

    fn number(&self, name: &str) -> Result<Option<u32>> {
        let name = wide(name.as_ref());
        let mut value = 0u32;
        let mut size = size_of::<u32>() as u32;
        let mut kind = 0u32;
        // SAFETY: `value` is writable for `size` bytes.
        let code = unsafe { RegQueryValueExW(self.0, name.as_ptr(), std::ptr::null(), &mut kind, (&raw mut value).cast(), &mut size) };
        match code {
            0 if kind == REG_DWORD => Ok(Some(value)),
            0 => Err(Error::new(ErrorKind::InvalidData, "the registry value is not a number")),
            ERROR_FILE_NOT_FOUND => Ok(None),
            code => Err(Error::from_raw_os_error(code as i32)),
        }
    }

    fn set_string(&self, name: &str, value: &str) -> Result<()> {
        let name = wide(name.as_ref());
        let value = wide(value.as_ref());
        // SAFETY: both strings are NUL-terminated; the value is readable for its size in bytes.
        let code = unsafe { RegSetValueExW(self.0, name.as_ptr(), 0, REG_SZ, value.as_ptr().cast(), (value.len() * 2) as u32) };
        check_code(code)
    }

    /// The interface of a new adapter, once Windows wrote it: its GUID and LUID.
    fn interface(&self) -> Result<(String, NET_LUID_LH)> {
        let deadline = Instant::now() + START_TIMEOUT;
        let changed = Event::new(false)?;
        loop {
            // Watched first, so that a value written meanwhile is not missed.
            // SAFETY: the key and the event are open; the watch ends with the key.
            check_code(unsafe {
                RegNotifyChangeKeyValue(self.0, 0, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, changed.handle(), 1)
            })?;
            if let (Some(guid), Some(kind), Some(index)) = (self.string("NetCfgInstanceId")?, self.number("*IfType")?, self.number("NetLuidIndex")?) {
                // `NET_LUID_LH`: 24 reserved bits, then the index in 24 bits and the type in 16.
                let luid = NET_LUID_LH { Value: (u64::from(kind & 0xffff) << 48) | (u64::from(index & 0xff_ffff) << 24) };
                return Ok((guid, luid));
            }
            wait(Some(changed.handle()), None, Some(deadline), None)
                .map_err(|error| Error::new(error.kind(), format!("waiting for the TAP adapter's interface: {error}")))?;
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened here and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn check(done: windows_sys::core::BOOL) -> Result<()> {
    if done == 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn check_code(code: WIN32_ERROR) -> Result<()> {
    if code != 0 {
        return Err(Error::from_raw_os_error(code as i32));
    }
    Ok(())
}
