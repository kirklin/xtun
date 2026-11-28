//! Waiting for an event handle without a thread of our own: the system thread pool watches the
//! handle and wakes the task. Also events, the event behind an interrupt, and blocking waits.

use std::ffi::c_void;
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CREATE_WAITABLE_TIMER_MANUAL_RESET, CloseThreadpoolWait, CreateEventW, CreateThreadpoolWait,
    CreateWaitableTimerExW, INFINITE, PTP_CALLBACK_INSTANCE, PTP_WAIT, ResetEvent, SetEvent, SetThreadpoolWait, SetWaitableTimer,
    TIMER_ALL_ACCESS, WaitForMultipleObjects, WaitForSingleObject, WaitForThreadpoolWaitCallbacks,
};

/// An event object of our own.
pub(crate) struct Event(HANDLE);

// SAFETY: event handles may be used from any thread.
unsafe impl Send for Event {}
// SAFETY: as above.
unsafe impl Sync for Event {}

impl Event {
    /// A new event; a manual-reset event stays signalled until it is reset.
    pub fn new(manual_reset: bool) -> Result<Event> {
        // SAFETY: plain event creation: not signalled, no name.
        let event = unsafe { CreateEventW(std::ptr::null(), i32::from(manual_reset), 0, std::ptr::null()) };
        if event.is_null() {
            return Err(Error::last_os_error());
        }
        Ok(Event(event))
    }

    pub fn handle(&self) -> HANDLE {
        self.0
    }

    pub fn set(&self) -> Result<()> {
        set_event(self.0)
    }

    pub fn reset(&self) -> Result<()> {
        // SAFETY: the event is open.
        if unsafe { ResetEvent(self.0) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: the event was created here and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// A timer of the system, signalled once the time it was set for has passed. Where Windows has
/// high-resolution timers, from Windows 10 1803 on, it is one: it keeps time to a fraction of a
/// millisecond, where every other wait of the system ends on a tick of the clock, up to 15.6 ms
/// late.
pub(crate) struct Timer(HANDLE);

// SAFETY: timer handles may be used from any thread.
unsafe impl Send for Timer {}
// SAFETY: as above.
unsafe impl Sync for Timer {}

impl Timer {
    pub fn new() -> Result<Timer> {
        // A manual-reset timer stays signalled until it is set again, so that asking whether
        // it is signalled changes nothing.
        let create = |flags: u32| {
            // SAFETY: plain creation of a timer without a name.
            unsafe { CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), CREATE_WAITABLE_TIMER_MANUAL_RESET | flags, TIMER_ALL_ACCESS) }
        };
        let mut timer = create(CREATE_WAITABLE_TIMER_HIGH_RESOLUTION);
        if timer.is_null() {
            // A Windows that does not know high-resolution timers refuses the flag.
            timer = create(0);
        }
        if timer.is_null() {
            return Err(Error::last_os_error());
        }
        Ok(Timer(timer))
    }

    pub fn handle(&self) -> HANDLE {
        self.0
    }

    /// Lets the timer be signalled once `after` has passed from now; until then it is not.
    pub fn set(&self, after: Duration) -> Result<()> {
        // A negative time is relative to now, in units of 100 ns.
        let due = -((after.as_nanos() / 100).max(1) as i64);
        // SAFETY: the timer is open and `due` lives through the call.
        if unsafe { SetWaitableTimer(self.0, &due, 0, None, std::ptr::null(), 0) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        // SAFETY: the timer was created here and is closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Signals any event this process may signal.
pub(crate) fn set_event(event: HANDLE) -> Result<()> {
    // SAFETY: the caller keeps the event open through the call.
    if unsafe { SetEvent(event) } == 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Whether `event` is signalled now, without waiting. An auto-reset event that is signalled is
/// reset by the question, as by any wait that it ends.
pub(crate) fn signalled(event: HANDLE) -> Result<bool> {
    // SAFETY: the caller keeps the event open through the call.
    match unsafe { WaitForSingleObject(event, 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(Error::last_os_error()),
    }
}

/// What owns a watched event, held while the thread pool watches the event.
pub(crate) type Keep = Arc<dyn Send + Sync>;

struct State {
    fired: AtomicBool,
    waker: Mutex<Option<Waker>>,
    /// The owner of the watched event. It is let go of once the wait fires, so that a task
    /// that is never polled again holds nothing.
    keep: Mutex<Option<Keep>>,
}

/// A wait of the system thread pool, which wakes a task once the event it watches is signalled.
pub(crate) struct Watch {
    wait: PTP_WAIT,
    state: Arc<State>,
    /// The event the thread pool watches for this wait, while it does.
    armed: Option<HANDLE>,
}

// SAFETY: the thread pool objects may be used from any thread.
unsafe impl Send for Watch {}
// SAFETY: as above.
unsafe impl Sync for Watch {}

unsafe extern "system" fn fired(_instance: PTP_CALLBACK_INSTANCE, context: *mut c_void, _wait: PTP_WAIT, _result: u32) {
    // SAFETY: `context` is the state, which outlives every callback (see `Drop`).
    let state = unsafe { &*context.cast::<State>() };
    // The thread pool watches the event no longer.
    let kept = state.keep.lock().expect("keep").take();
    state.fired.store(true, Ordering::Release);
    if let Some(waker) = state.waker.lock().expect("waker").take() {
        waker.wake();
    }
    drop(kept);
}

impl Watch {
    pub fn new() -> Result<Watch> {
        let state = Arc::new(State { fired: AtomicBool::new(false), waker: Mutex::new(None), keep: Mutex::new(None) });
        // SAFETY: the callback and its context stay valid until the wait is closed.
        let wait = unsafe { CreateThreadpoolWait(Some(fired), Arc::as_ptr(&state).cast_mut().cast(), std::ptr::null()) };
        if wait == 0 {
            return Err(Error::last_os_error());
        }
        Ok(Watch { wait, state, armed: None })
    }

    /// Resolves once `event` is signalled. While the thread pool does not watch the event,
    /// `signalled` is asked whether it is signalled now: if so, the wait resolves at once, and
    /// only otherwise does the thread pool watch the event, until the wait resolves or is
    /// disarmed. A wakeup without a packet is possible. `event` must stay open until the wait
    /// fires or is disarmed: `keep`, the owner of an event that would close otherwise, is held
    /// for that long.
    pub fn poll_signalled(
        &mut self,
        cx: &mut Context<'_>,
        event: HANDLE,
        keep: Option<Keep>,
        signalled: impl FnOnce() -> Result<bool>,
    ) -> Poll<Result<()>> {
        if self.armed.is_some_and(|armed| armed != event) {
            self.disarm();
        }
        if self.armed.is_none() {
            if signalled()? {
                return Poll::Ready(Ok(()));
            }
            self.state.fired.store(false, Ordering::Release);
            *self.state.keep.lock().expect("keep") = keep;
            // SAFETY: the wait and the event are valid; the wait fires once.
            unsafe { SetThreadpoolWait(self.wait, event, std::ptr::null()) };
            self.armed = Some(event);
        }
        if !self.state.fired.load(Ordering::Acquire) {
            *self.state.waker.lock().expect("waker") = Some(cx.waker().clone());
            if !self.state.fired.load(Ordering::Acquire) {
                return Poll::Pending;
            }
        }
        self.armed = None;
        Poll::Ready(Ok(()))
    }

    /// Stops watching the event, so that it may be closed.
    pub fn disarm(&mut self) {
        if self.armed.take().is_some() {
            // SAFETY: stops the wait and waits for a callback that is running; pending callbacks
            // are cancelled.
            unsafe {
                SetThreadpoolWait(self.wait, std::ptr::null_mut(), std::ptr::null());
                WaitForThreadpoolWaitCallbacks(self.wait, 1);
            }
            let kept = self.state.keep.lock().expect("keep").take();
            drop(kept);
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.disarm();
        // SAFETY: no callback runs or is pending any more, so none can reach the state.
        unsafe { CloseThreadpoolWait(self.wait) };
    }
}

/// What an interrupt is made of: a manual-reset event.
pub struct Signal {
    event: Event,
    /// Whether the interrupt is triggered: the event is signalled while it is.
    set: AtomicBool,
    /// Held while a trigger or a reset changes the flag and the event, so that one that comes at
    /// the same time finds both changed or neither.
    changing: Mutex<()>,
}

impl Signal {
    pub fn new() -> Result<Signal> {
        Ok(Signal { event: Event::new(true)?, set: AtomicBool::new(false), changing: Mutex::new(()) })
    }

    pub fn handle(&self) -> HANDLE {
        self.event.handle()
    }

    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }

    /// Signals the event, then sets the flag.
    pub fn trigger(&self) -> Result<()> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        self.event.set()?;
        self.set.store(true, Ordering::Release);
        Ok(())
    }

    /// Resets the event, then clears the flag.
    pub fn reset(&self) -> Result<()> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        self.event.reset()?;
        self.set.store(false, Ordering::Release);
        Ok(())
    }
}

pub(crate) fn interrupted() -> Error {
    Error::new(ErrorKind::Interrupted, "the wait was interrupted")
}

/// Blocks until `event` is signalled, the interrupt is triggered or the deadline passes. With
/// `limit`, returns after that long at most even without a signal.
pub(crate) fn wait(event: Option<HANDLE>, signal: Option<&Signal>, deadline: Option<Instant>, limit: Option<u32>) -> Result<()> {
    if signal.is_some_and(Signal::is_set) {
        return Err(interrupted());
    }
    let mut handles = Vec::with_capacity(2);
    if let Some(signal) = signal {
        handles.push(signal.handle());
    }
    if let Some(event) = event {
        handles.push(event);
    }
    loop {
        let left = deadline.map(|deadline| {
            let left = deadline.saturating_duration_since(Instant::now());
            // Rounded up, so that a wait never ends before its deadline.
            left.as_nanos().div_ceil(1_000_000).min(u128::from(INFINITE - 1)) as u32
        });
        if left == Some(0) {
            return Err(Error::new(ErrorKind::TimedOut, "the wait timed out"));
        }
        let timeout = match (left, limit) {
            (Some(left), Some(limit)) => left.min(limit),
            (Some(left), None) => left,
            (None, Some(limit)) => limit,
            (None, None) => INFINITE,
        };
        if handles.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(timeout)));
            return Ok(());
        }
        // SAFETY: every handle is open for the length of the call.
        let result = unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout) };
        match result {
            WAIT_FAILED => return Err(Error::last_os_error()),
            WAIT_TIMEOUT if limit.is_some() && left.is_none_or(|left| left > timeout) => return Ok(()),
            // The system counts a timeout in ticks of its clock and may end the wait up to a tick
            // early: the wait goes on for what is left until the deadline.
            WAIT_TIMEOUT => {}
            index if signal.is_some() && index == WAIT_OBJECT_0 => return Err(interrupted()),
            _ => return Ok(()),
        }
    }
}
