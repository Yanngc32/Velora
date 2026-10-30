//! Keyboard capture on Windows: while the session window is in front, the keys Windows keeps
//! for itself (Alt+Tab, the Windows key and its shortcuts, Alt+F4, Ctrl+Esc, Print Screen…) go
//! to the remote computer instead of acting here.
//!
//! A low-level keyboard hook sees every key before Windows acts on it. While capturing, it
//! takes them all, not only those shortcuts, and hands them to the window in the order they
//! came: Alt through the window and Tab through the hook could reach the host the wrong way
//! round. Ctrl+Alt+Del and Win+L stay with Windows, which lets no program take them.

use std::{cell::RefCell, collections::VecDeque};

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    System::LibraryLoader::GetModuleHandleW,
    UI::WindowsAndMessaging::{
        CallNextHookEx, GetForegroundWindow, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT,
        LLKHF_EXTENDED, LLKHF_INJECTED, LLKHF_UP, WH_KEYBOARD_LL,
    },
};
use winit::{
    event_loop::EventLoopProxy,
    keyboard::{KeyCode, PhysicalKey},
    platform::scancode::PhysicalKeyExtScancode,
    window::Window,
};

use crate::keymap;

const VK_PAUSE: u32 = 0x13;
const VK_NUMLOCK: u32 = 0x90;
const VK_RSHIFT: u32 = 0xA1;

struct State {
    window: HWND,
    on: bool,
    /// Keys taken from Windows, waiting for the window: the key, and whether it went down.
    keys: VecDeque<(KeyCode, bool)>,
    wake: EventLoopProxy<()>,
}

thread_local! {
    // The hook runs on the thread that set it, the one running the window.
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// The hook, set while it lives. On the window's thread only.
pub struct Grab(HHOOK);

impl Grab {
    /// Starts capturing for `window`; `wake` brings the taken keys to it.
    pub fn new(window: &Window, wake: EventLoopProxy<()>) -> Option<Self> {
        let RawWindowHandle::Win32(handle) = window.window_handle().ok()?.as_raw() else { return None };
        let window = HWND(handle.hwnd.get() as *mut _);
        // SAFETY: `hook` is a hook procedure; the thread that sets it runs a message loop.
        let hook = unsafe {
            let module = GetModuleHandleW(None).ok()?;
            SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook), Some(module.into()), 0)
        };
        let hook = match hook {
            Ok(hook) => hook,
            Err(e) => {
                tracing::warn!("cannot capture the keyboard; Alt+Tab and the Windows key act here: {e}");
                return None;
            }
        };
        STATE.with_borrow_mut(|s| *s = Some(State { window, on: true, keys: VecDeque::new(), wake }));
        Some(Self(hook))
    }

    pub fn set_on(&self, on: bool) {
        STATE.with_borrow_mut(|s| {
            if let Some(s) = s {
                s.on = on;
            }
        });
    }

    /// The keys taken since the last call, in order.
    pub fn take(&self) -> Vec<(KeyCode, bool)> {
        STATE.with_borrow_mut(|s| s.as_mut().map(|s| s.keys.drain(..).collect()).unwrap_or_default())
    }
}

impl Drop for Grab {
    fn drop(&mut self) {
        STATE.with_borrow_mut(|s| *s = None);
        // SAFETY: the hook this set, removed once.
        let _ = unsafe { UnhookWindowsHookEx(self.0) };
    }
}

unsafe extern "system" fn hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 {
        // SAFETY: for HC_ACTION, `lparam` points to the key's KBDLLHOOKSTRUCT.
        let info = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
        if take(info) {
            return LRESULT(1);
        }
    }
    // SAFETY: passing the call on, as received.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

/// Whether the key is the session's: then it is queued for the window and Windows never sees it.
fn take(info: &KBDLLHOOKSTRUCT) -> bool {
    STATE.with(|s| {
        let Ok(mut state) = s.try_borrow_mut() else { return false };
        let Some(state) = state.as_mut() else { return false };
        // Keys typed by programs are left alone.
        // SAFETY: plain query.
        if !state.on || info.flags.contains(LLKHF_INJECTED) || unsafe { GetForegroundWindow() } != state.window {
            return false;
        }
        // AltGr comes with a Ctrl press Windows makes up (scan code 0x21D): the host makes its own.
        if info.scanCode & 0xFF00 != 0 {
            return true;
        }
        let scancode = match info.vkCode {
            // Both report scan code 0x45; winit tells them apart by the extended bit.
            VK_NUMLOCK => 0xE045,
            VK_PAUSE => 0x0045,
            // Some keyboards flag it extended, which winit would not know.
            VK_RSHIFT => 0x0036,
            _ => info.scanCode | if info.flags.contains(LLKHF_EXTENDED) { 0xE000 } else { 0 },
        };
        let PhysicalKey::Code(key) = PhysicalKey::from_scancode(scancode) else { return false };
        if keymap::to_evdev(key).is_none() {
            return false;
        }
        state.keys.push_back((key, !info.flags.contains(LLKHF_UP)));
        let _ = state.wake.send_event(());
        true
    })
}
