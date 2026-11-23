//! The functions of `wintun.dll`, loaded at run time. Only the interface of `wintun.h` is used.

use std::ffi::c_void;
use std::io::{Error, ErrorKind, Result};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use windows_sys::Win32::Foundation::{FreeLibrary, HANDLE};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    LoadLibraryExW,
};
use windows_sys::core::{BOOL, GUID};

use crate::device::WintunLevel;

pub(crate) type Adapter = *mut c_void;
pub(crate) type Session = *mut c_void;

/// What Wintun calls with each message: its level, the time as a `FILETIME` and the text.
type Logger = unsafe extern "system" fn(level: i32, timestamp: u64, message: *const u16);

type CreateAdapter = unsafe extern "system" fn(name: *const u16, tunnel_type: *const u16, guid: *const GUID) -> Adapter;
type OpenAdapter = unsafe extern "system" fn(name: *const u16) -> Adapter;
type CloseAdapter = unsafe extern "system" fn(adapter: Adapter);
type DeleteDriver = unsafe extern "system" fn() -> BOOL;
type GetAdapterLuid = unsafe extern "system" fn(adapter: Adapter, luid: *mut NET_LUID_LH);
type GetRunningDriverVersion = unsafe extern "system" fn() -> u32;
type SetLogger = unsafe extern "system" fn(logger: Option<Logger>);
type StartSession = unsafe extern "system" fn(adapter: Adapter, capacity: u32) -> Session;
type EndSession = unsafe extern "system" fn(session: Session);
type GetReadWaitEvent = unsafe extern "system" fn(session: Session) -> HANDLE;
type ReceivePacket = unsafe extern "system" fn(session: Session, size: *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(session: Session, packet: *const u8);
type AllocateSendPacket = unsafe extern "system" fn(session: Session, size: u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(session: Session, packet: *const u8);

/// The functions of the library, which stays loaded for as long as the process runs: Wintun
/// does work of its own in the background after an adapter is opened or closed, and that work
/// must not lose its code.
pub(crate) struct Wintun {
    pub create_adapter: CreateAdapter,
    pub open_adapter: OpenAdapter,
    pub close_adapter: CloseAdapter,
    pub delete_driver: DeleteDriver,
    pub get_adapter_luid: GetAdapterLuid,
    pub get_running_driver_version: GetRunningDriverVersion,
    set_logger: SetLogger,
    pub start_session: StartSession,
    pub end_session: EndSession,
    pub get_read_wait_event: GetReadWaitEvent,
    pub receive_packet: ReceivePacket,
    pub release_receive_packet: ReleaseReceivePacket,
    pub allocate_send_packet: AllocateSendPacket,
    pub send_packet: SendPacket,
}

// SAFETY: the function pointers are valid in every thread, and the
// functions themselves are safe to call from any thread.
unsafe impl Send for Wintun {}
// SAFETY: as above.
unsafe impl Sync for Wintun {}

impl Wintun {
    /// Loads the library from `path`, or `wintun.dll` next to the program or in the system
    /// directory. The current directory and `PATH` are never searched.
    pub fn load(path: Option<&Path>) -> Result<Wintun> {
        let (name, flags) = match path {
            Some(path) => (wide(path.as_os_str()), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32),
            None => (wide("wintun.dll".as_ref()), LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32),
        };
        // SAFETY: `name` is a NUL-terminated wide string.
        let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), flags) };
        if module.is_null() {
            let error = Error::last_os_error();
            return Err(Error::new(error.kind(), format!("loading wintun.dll: {error}")));
        }
        let symbol = |name: &[u8]| {
            // SAFETY: `name` is NUL-terminated and `module` is loaded.
            unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or_else(|| {
                Error::new(ErrorKind::NotFound, format!("wintun.dll lacks {}", String::from_utf8_lossy(&name[..name.len() - 1])))
            })
        };
        macro_rules! load {
            ($name:literal, $type:ty) => {
                // SAFETY: the symbol has the signature that wintun.h declares for it.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $type>(symbol($name)?) }
            };
        }
        let loaded: Result<Wintun> = (|| {
            Ok(Wintun {
                create_adapter: load!(b"WintunCreateAdapter\0", CreateAdapter),
                open_adapter: load!(b"WintunOpenAdapter\0", OpenAdapter),
                close_adapter: load!(b"WintunCloseAdapter\0", CloseAdapter),
                delete_driver: load!(b"WintunDeleteDriver\0", DeleteDriver),
                get_adapter_luid: load!(b"WintunGetAdapterLUID\0", GetAdapterLuid),
                get_running_driver_version: load!(b"WintunGetRunningDriverVersion\0", GetRunningDriverVersion),
                set_logger: load!(b"WintunSetLogger\0", SetLogger),
                start_session: load!(b"WintunStartSession\0", StartSession),
                end_session: load!(b"WintunEndSession\0", EndSession),
                get_read_wait_event: load!(b"WintunGetReadWaitEvent\0", GetReadWaitEvent),
                receive_packet: load!(b"WintunReceivePacket\0", ReceivePacket),
                release_receive_packet: load!(b"WintunReleaseReceivePacket\0", ReleaseReceivePacket),
                allocate_send_packet: load!(b"WintunAllocateSendPacket\0", AllocateSendPacket),
                send_packet: load!(b"WintunSendPacket\0", SendPacket),
            })
        })();
        if loaded.is_err() {
            // SAFETY: the module was loaded above and nothing of it is in use.
            unsafe { FreeLibrary(module) };
        }
        loaded
    }

    /// Hands Wintun's messages to `logger`, or stops them with `None`. Wintun keeps one logger
    /// for the whole process.
    pub fn set_logger(&self, logger: Option<LogFunction>) {
        *LOGGER.lock().expect("logger") = logger;
        // SAFETY: `forward` stays valid for as long as the library is loaded.
        unsafe { (self.set_logger)(logger.map(|_| forward as Logger)) };
    }
}


/// What receives Wintun's messages.
pub(crate) type LogFunction = fn(WintunLevel, SystemTime, &str);

static LOGGER: Mutex<Option<LogFunction>> = Mutex::new(None);

/// Seconds from 1601, where a `FILETIME` starts, to 1970.
const FILETIME_TO_UNIX: u64 = 11_644_473_600;

unsafe extern "system" fn forward(level: i32, timestamp: u64, message: *const u16) {
    let Some(logger) = *LOGGER.lock().expect("logger") else {
        return;
    };
    let level = match level {
        0 => WintunLevel::Info,
        1 => WintunLevel::Warning,
        _ => WintunLevel::Error,
    };
    let ticks = Duration::from_nanos(timestamp.saturating_mul(100));
    let time = SystemTime::UNIX_EPOCH + ticks.saturating_sub(Duration::from_secs(FILETIME_TO_UNIX));
    // SAFETY: Wintun passes a NUL-terminated wide string that lives through the call.
    let length = (0..).take_while(|&at| unsafe { *message.add(at) } != 0).count();
    // SAFETY: the string has `length` units before its NUL.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(message, length) });
    logger(level, time, &text);
}

pub(crate) fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    text.encode_wide().chain(std::iter::once(0)).collect()
}
