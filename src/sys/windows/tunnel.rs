//! Wintun adapters, for IP packets. An adapter is up while a session runs on it; the session's
//! rings carry the packets.

use std::io::{Error, ErrorKind, Result};
use std::mem::zeroed;
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::core::GUID;

use super::tunnel_io::{Sink, Source};
use super::wait::{Event, set_event};
use super::wintun::{Wintun, wide};
use super::{Interface, check_options, check_queue, config};
use crate::device::{Offload, Options};

/// An open adapter. It is closed once the device and every session on it are gone; an adapter
/// created here is removed then.
struct Handle {
    wintun: Arc<Wintun>,
    adapter: super::wintun::Adapter,
    /// Whether the adapter was created here, so that closing it removes it.
    created: bool,
    delete_driver: bool,
    /// Whether a session runs on the adapter, which runs one at a time.
    session_runs: Mutex<bool>,
    /// Notified when the session has ended.
    session_ended: Condvar,
}

impl Handle {
    fn new(wintun: Arc<Wintun>, adapter: super::wintun::Adapter, created: bool, delete_driver: bool) -> Handle {
        Handle { wintun, adapter, created, delete_driver, session_runs: Mutex::new(false), session_ended: Condvar::new() }
    }
}

// SAFETY: adapter handles may be used from any thread; Wintun locks inside.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: plain old data.
        let mut luid: NET_LUID_LH = unsafe { zeroed() };
        // SAFETY: the adapter is open, `luid` is writable, and nothing uses the adapter any more.
        unsafe {
            (self.wintun.get_adapter_luid)(self.adapter, &mut luid);
            (self.wintun.close_adapter)(self.adapter);
        }
        if self.created {
            config::await_gone(&luid);
        }
        if self.delete_driver {
            // SAFETY: plain call. The driver stays while other adapters use it.
            unsafe { (self.wintun.delete_driver)() };
        }
    }
}

/// A running session: its rings carry the packets. It ends once the device and both ends of
/// its queue let go of it.
pub(super) struct Session {
    handle: Arc<Handle>,
    pub(super) session: super::wintun::Session,
    pub(super) read_event: HANDLE,
}

// SAFETY: session handles may be used from any thread; Wintun locks inside.
unsafe impl Send for Session {}
// SAFETY: as above.
unsafe impl Sync for Session {}

impl Session {
    /// Starts a session, once the one before it has ended: a session that nobody holds any
    /// more may still be ending in the thread that let go of it last.
    fn start(handle: &Arc<Handle>, capacity: u32) -> Result<Session> {
        let mut runs = handle.session_runs.lock().expect("session");
        while *runs {
            runs = handle.session_ended.wait(runs).expect("session");
        }
        // SAFETY: the adapter is open.
        let session = unsafe { (handle.wintun.start_session)(handle.adapter, capacity) };
        if session.is_null() {
            let error = Error::last_os_error();
            return Err(Error::new(error.kind(), format!("starting the Wintun session: {error}")));
        }
        *runs = true;
        // SAFETY: the session is open; the event belongs to it and is not closed here.
        let read_event = unsafe { (handle.wintun.get_read_wait_event)(session) };
        Ok(Session { handle: handle.clone(), session, read_event })
    }

    pub(super) fn wintun(&self) -> &Wintun {
        &self.handle.wintun
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: nobody holds packets of the session any more.
        unsafe { (self.handle.wintun.end_session)(self.session) };
        *self.handle.session_runs.lock().expect("session") = false;
        self.handle.session_ended.notify_all();
    }
}

/// The session of the device while it is up, and the one it ran before.
#[derive(Default)]
struct Sessions {
    current: Option<Arc<Session>>,
    /// The session of the last time the device was up, while the reading end of the queue
    /// still holds packets of it.
    retired: Weak<Session>,
}

/// A Wintun adapter and its sessions.
pub struct Tun {
    interface: Interface,
    handle: Arc<Handle>,
    ring_capacity: u32,
    /// Both ends of the queue read it for the current session, without keeping each other out.
    sessions: RwLock<Sessions>,
    /// Signalled while the device is up, for the reading end of the queue to wait for.
    up: Event,
}

impl crate::sys::Tunnel for Tun {
    type Source = Source;
    type Sink = Sink;

    fn create(options: &Options) -> Result<Tun> {
        check_options(options)?;
        if options.persist == Some(true) {
            return Err(no_persist());
        }
        let windows = &options.windows;
        let capacity = windows.ring_capacity;
        if !(0x2_0000..=0x400_0000).contains(&capacity) || !capacity.is_power_of_two() {
            return Err(Error::new(ErrorKind::InvalidInput, "the ring capacity is a power of two from 128 KiB to 64 MiB"));
        }
        let wintun = Arc::new(Wintun::load(windows.wintun.as_deref())?);
        if windows.logger.is_some() {
            wintun.set_logger(windows.logger);
        }
        let handle = Arc::new(open_or_create(wintun, options)?);
        // SAFETY: plain old data.
        let mut luid: NET_LUID_LH = unsafe { zeroed() };
        // SAFETY: the adapter is open and `luid` is writable.
        unsafe { (handle.wintun.get_adapter_luid)(handle.adapter, &mut luid) };
        let up = Event::new(true)?;
        Ok(Tun {
            interface: Interface::new(luid)?,
            handle,
            ring_capacity: capacity,
            sessions: RwLock::new(Sessions::default()),
            up,
        })
    }

    fn queues(&self) -> usize {
        1
    }

    fn source(self: &Arc<Tun>, queue: usize, frames: usize) -> Result<Source> {
        check_queue(queue)?;
        Source::new(self.clone(), frames)
    }

    fn sink(self: &Arc<Tun>, queue: usize) -> Result<Sink> {
        check_queue(queue)?;
        Sink::new(self.clone())
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn offload(&self) -> Offload {
        Offload::default()
    }

    /// An adapter made here goes with the device; one that was there before stays, as its own
    /// program has it.
    fn set_persist(&self, persist: bool) -> Result<()> {
        if persist {
            return Err(no_persist());
        }
        if !self.handle.created {
            return Err(Error::new(ErrorKind::Unsupported, "a Wintun adapter that was there before stays when the device goes"));
        }
        Ok(())
    }

    fn configure(&self, options: &Options) -> Result<()> {
        super::configure(self, options)
    }

    fn is_up(&self) -> Result<bool> {
        Ok(self.sessions.read().expect("sessions").current.is_some())
    }

    /// Starts a session, or ends it. The session ends at once, unless the reading end of the
    /// queue holds packets of it: then it ends once they are given back, and the device,
    /// brought up before then, takes it up again.
    fn set_up(&self, up: bool) -> Result<()> {
        let mut sessions = self.sessions.write().expect("sessions");
        match (up, sessions.current.is_some()) {
            (true, false) => {
                let session = match sessions.retired.upgrade() {
                    Some(session) => session,
                    None => Arc::new(Session::start(&self.handle, self.ring_capacity)?),
                };
                sessions.current = Some(session);
                self.up.set()?;
                drop(sessions);
                self.interface.restore_peers()
            }
            (false, true) => {
                let session = sessions.current.take().expect("the device is up");
                sessions.retired = Arc::downgrade(&session);
                self.up.reset()?;
                drop(sessions);
                // A reader waiting for packets wakes, and lets go of the session.
                set_event(session.read_event)
            }
            _ => Ok(()),
        }
    }

    fn driver_version(&self) -> Result<String> {
        // SAFETY: plain query of the loaded driver.
        let version = unsafe { (self.handle.wintun.get_running_driver_version)() };
        if version == 0 {
            return Err(Error::last_os_error());
        }
        Ok(format!("{}.{}", version >> 16, version & 0xffff))
    }
}

impl Tun {
    /// The current session, if the device is up.
    pub(super) fn session(&self) -> Option<Arc<Session>> {
        self.sessions.read().expect("sessions").current.clone()
    }

    /// The capacity of each ring of a session, in bytes.
    pub(super) fn ring_capacity(&self) -> u32 {
        self.ring_capacity
    }

    /// Signalled while the device is up.
    pub(super) fn up_event(&self) -> HANDLE {
        self.up.handle()
    }
}

fn no_persist() -> Error {
    Error::new(ErrorKind::Unsupported, "a Wintun adapter goes away with the device that created it")
}

/// Opens the adapter of the requested name, or creates it. Without a name, the first free name of
/// `tun0`, `tun1` and so on is taken.
fn open_or_create(wintun: Arc<Wintun>, options: &Options) -> Result<Handle> {
    let windows = &options.windows;
    let name = match &options.name {
        Some(name) => name.clone(),
        None => config::free_name("tun")?,
    };
    if name.is_empty() || name.encode_utf16().count() >= 128 {
        return Err(Error::new(ErrorKind::InvalidInput, "an adapter name has 1 to 127 characters"));
    }
    let delete_driver = windows.delete_driver;
    if let Some(luid) = config::luid_of(&name)? {
        if !options.reuse {
            return Err(Error::new(ErrorKind::AlreadyExists, format!("an interface is called {name}")));
        }
        // SAFETY: the name is NUL-terminated.
        let adapter = unsafe { (wintun.open_adapter)(wide(name.as_ref()).as_ptr()) };
        if !adapter.is_null() {
            return Ok(Handle::new(wintun, adapter, false, delete_driver));
        }
        let error = Error::last_os_error();
        // The interface of an adapter that went with the program that had it is listed a
        // moment longer. Once it is gone, the name is free; an interface that stays is of
        // another kind.
        if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) || !config::await_gone(&luid) {
            return Err(Error::new(error.kind(), format!("opening the Wintun adapter {name}: {error}")));
        }
    }
    let guid = GUID::from_u128(windows.guid.unwrap_or_else(|| guid_for(&name)));
    // SAFETY: both strings are NUL-terminated and `guid` lives through the call.
    let adapter = unsafe {
        (wintun.create_adapter)(wide(name.as_ref()).as_ptr(), wide(windows.tunnel_type.as_ref()).as_ptr(), &guid)
    };
    if adapter.is_null() {
        let error = Error::last_os_error();
        return Err(Error::new(error.kind(), format!("creating the Wintun adapter: {error}")));
    }
    Ok(Handle::new(wintun, adapter, true, delete_driver))
}

/// A GUID that stays the same for the same name, so Windows recognizes the network again.
fn guid_for(name: &str) -> u128 {
    let mut hash: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    for byte in name.to_lowercase().bytes() {
        hash ^= u128::from(byte);
        hash = hash.wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013b);
    }
    hash
}
