//! Keeps the computer awake while it is shared, so it stays reachable after the user walks
//! away (locked with Win+L, idle for hours), and its screen on while a device watches it.
//!
//! On Windows these are power requests, which `powercfg /requests` lists under the reasons
//! below; the screen may still turn off when nobody is connected. Elsewhere nothing is held
//! and the launcher hides the setting.

use std::sync::Mutex;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use velora_protocol::identity::StateDir;

const PREFS: &str = "power.json";

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Prefs {
    stay_awake: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self { stay_awake: true }
    }
}

pub struct Awake {
    /// Held while the host runs and the setting is on.
    system: Mutex<Option<imp::Request>>,
}

impl Awake {
    /// Starts holding the computer awake when the setting (on by default) says so.
    pub fn start(state: &StateDir) -> Self {
        let awake = Self { system: Mutex::new(None) };
        let on = state.load::<Prefs>(PREFS).unwrap_or_default().stay_awake;
        awake.apply(on);
        awake
    }

    /// The current setting, or `None` where this host can't keep the computer awake.
    pub fn setting(&self, state: &StateDir) -> Option<bool> {
        imp::SUPPORTED.then(|| state.load::<Prefs>(PREFS).unwrap_or_default().stay_awake)
    }

    pub fn set(&self, state: &StateDir, on: bool) -> Result<()> {
        anyhow::ensure!(imp::SUPPORTED, "this computer can't be kept awake by Velora");
        state.save(PREFS, &Prefs { stay_awake: on })?;
        self.apply(on);
        Ok(())
    }

    fn apply(&self, on: bool) {
        let mut system = self.system.lock().unwrap();
        if on == system.is_some() {
            return;
        }
        *system = if on { imp::Request::system() } else { None };
        tracing::info!("{} the computer awake while sharing", if system.is_some() { "keeping" } else { "not keeping" });
    }

    /// Keeps the screen on until the guard is dropped, for a session.
    pub fn screen_on(&self) -> Option<imp::Request> {
        imp::Request::display()
    }
}

#[cfg(windows)]
mod imp {
    use windows::{
        core::{HSTRING, PWSTR},
        Win32::{
            Foundation::{CloseHandle, HANDLE},
            System::{
                Power::{
                    PowerClearRequest, PowerCreateRequest, PowerRequestDisplayRequired, PowerRequestSystemRequired,
                    PowerSetRequest, POWER_REQUEST_TYPE,
                },
                Threading::{POWER_REQUEST_CONTEXT_SIMPLE_STRING, REASON_CONTEXT, REASON_CONTEXT_0},
            },
        },
    };

    pub const SUPPORTED: bool = true;

    /// An active power request; cleared and closed when dropped.
    pub struct Request {
        handle: HANDLE,
        kind: POWER_REQUEST_TYPE,
    }

    // SAFETY: a power request handle may be used and closed from any thread.
    unsafe impl Send for Request {}

    impl Request {
        pub fn system() -> Option<Self> {
            Self::new(PowerRequestSystemRequired, "Velora is sharing this computer")
        }

        pub fn display() -> Option<Self> {
            Self::new(PowerRequestDisplayRequired, "A device is viewing this screen through Velora")
        }

        fn new(kind: POWER_REQUEST_TYPE, reason: &str) -> Option<Self> {
            const POWER_REQUEST_CONTEXT_VERSION: u32 = 0;
            let reason = HSTRING::from(reason);
            let context = REASON_CONTEXT {
                Version: POWER_REQUEST_CONTEXT_VERSION,
                Flags: POWER_REQUEST_CONTEXT_SIMPLE_STRING,
                Reason: REASON_CONTEXT_0 { SimpleReasonString: PWSTR(reason.as_ptr() as *mut u16) },
            };
            // SAFETY: `context` and the string it points to outlive the call, which copies them.
            let handle = match unsafe { PowerCreateRequest(&context) } {
                Ok(handle) => handle,
                Err(e) => {
                    tracing::warn!("could not create a power request: {e}");
                    return None;
                }
            };
            // SAFETY: a valid power request handle, closed on failure.
            if let Err(e) = unsafe { PowerSetRequest(handle, kind) } {
                tracing::warn!("could not set a power request: {e}");
                let _ = unsafe { CloseHandle(handle) };
                return None;
            }
            Some(Self { handle, kind })
        }
    }

    impl Drop for Request {
        fn drop(&mut self) {
            // SAFETY: the handle is valid and set with `kind`; nothing uses it afterwards.
            unsafe {
                let _ = PowerClearRequest(self.handle, self.kind);
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub const SUPPORTED: bool = false;

    pub struct Request;

    impl Request {
        pub fn system() -> Option<Self> {
            None
        }

        pub fn display() -> Option<Self> {
            None
        }
    }
}
