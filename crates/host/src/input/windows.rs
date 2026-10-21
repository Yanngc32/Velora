//! Windows injection through `SendInput`, using hardware scan codes so the result does not
//! depend on the host's keyboard layout matching the client's.
//!
//! `SendInput` cannot reach windows of elevated processes unless the host runs elevated, and
//! cannot reach the secure desktop (UAC, lock screen) unless it runs as a service.

use std::mem::size_of;

use anyhow::{bail, Result};
use velora_protocol::wire::{KeyState, MouseButton};
use windows::Win32::UI::{
    Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_EXTENDEDKEY,
        KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL,
        MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
        MOUSEEVENTF_XUP, MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY, VK_NUMLOCK, VK_PAUSE,
    },
    WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, XBUTTON1,
        XBUTTON2,
    },
};

use super::Backend;
use crate::capture::DisplayRect;

pub struct SendInputBackend {
    rect: DisplayRect,
}

impl SendInputBackend {
    pub fn new() -> Self {
        Self { rect: DisplayRect::default() }
    }
}

fn send(inputs: &[INPUT]) -> Result<()> {
    // SAFETY: `inputs` is a valid slice of initialized INPUT structs.
    let sent = unsafe { SendInput(inputs, size_of::<INPUT>() as i32) };
    if sent as usize != inputs.len() {
        bail!("SendInput injected {sent}/{} events (blocked by UIPI?)", inputs.len());
    }
    Ok(())
}

fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn keyboard(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
    }
}

/// Maps a pixel to `0..=65535` over the virtual desktop, aiming at the pixel center so
/// Windows' truncating conversion lands on exactly that pixel.
fn to_virtual_desk(pixel: i64, origin: i64, size: i64) -> i32 {
    let size = size.max(1);
    (((2 * (pixel - origin) + 1) * 32768) / size).clamp(0, 65535) as i32
}

impl Backend for SendInputBackend {
    fn set_display(&mut self, rect: DisplayRect) {
        self.rect = rect;
    }

    fn move_abs(&mut self, x: u16, y: u16) -> Result<()> {
        let r = self.rect;
        // SAFETY: trivial metric queries.
        let (vx, vy, vw, vh) = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN) as i64,
                GetSystemMetrics(SM_YVIRTUALSCREEN) as i64,
                GetSystemMetrics(SM_CXVIRTUALSCREEN) as i64,
                GetSystemMetrics(SM_CYVIRTUALSCREEN) as i64,
            )
        };
        let px = r.x as i64 + x as i64 * (r.width.max(1) as i64 - 1) / 65535;
        let py = r.y as i64 + y as i64 * (r.height.max(1) as i64 - 1) / 65535;
        send(&[mouse(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            to_virtual_desk(px, vx, vw),
            to_virtual_desk(py, vy, vh),
            0,
        )])
    }

    fn button(&mut self, button: MouseButton, down: bool) -> Result<()> {
        let (flags, data) = match (button, down) {
            (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
            (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
            (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
            (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
            (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
            (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
            (MouseButton::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1 as i32),
            (MouseButton::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1 as i32),
            (MouseButton::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2 as i32),
            (MouseButton::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2 as i32),
        };
        send(&[mouse(flags, 0, 0, data)])
    }

    fn key(&mut self, code: u16, state: KeyState) -> Result<()> {
        let up = if state == KeyState::Up { KEYEVENTF_KEYUP } else { KEYBD_EVENT_FLAGS(0) };
        // Windows has no hardware auto-repeat for injected keys: forward repeats as key-downs.
        let input = match code {
            // Pause and Num Lock have ambiguous scan codes (E1 1D 45 / 45): use virtual keys.
            119 => keyboard(VK_PAUSE, 0, up),
            69 => keyboard(VK_NUMLOCK, 0, up | KEYEVENTF_EXTENDEDKEY),
            _ => {
                let Some((scan, extended)) = evdev_to_scancode(code) else { return Ok(()) };
                let ext = if extended { KEYEVENTF_EXTENDEDKEY } else { KEYBD_EVENT_FLAGS(0) };
                keyboard(VIRTUAL_KEY(0), scan, KEYEVENTF_SCANCODE | ext | up)
            }
        };
        send(&[input])
    }

    fn text(&mut self, text: &str) -> Result<()> {
        // KEYEVENTF_UNICODE types any character regardless of the host's keyboard layout.
        let mut inputs = Vec::with_capacity(text.len() * 2);
        for c in text.chars() {
            match c {
                '\r' => continue,
                '\n' => {
                    for up in [KEYBD_EVENT_FLAGS(0), KEYEVENTF_KEYUP] {
                        inputs.push(keyboard(VIRTUAL_KEY(0), 0x1C, KEYEVENTF_SCANCODE | up));
                    }
                }
                _ => {
                    let mut units = [0u16; 2];
                    for &unit in c.encode_utf16(&mut units).iter() {
                        for up in [KEYBD_EVENT_FLAGS(0), KEYEVENTF_KEYUP] {
                            inputs.push(keyboard(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE | up));
                        }
                    }
                }
            }
        }
        if inputs.is_empty() {
            return Ok(());
        }
        send(&inputs)
    }

    fn scroll(&mut self, dx: i16, dy: i16) -> Result<()> {
        let mut inputs = Vec::with_capacity(2);
        if dy != 0 {
            inputs.push(mouse(MOUSEEVENTF_WHEEL, 0, 0, dy as i32));
        }
        if dx != 0 {
            inputs.push(mouse(MOUSEEVENTF_HWHEEL, 0, 0, dx as i32));
        }
        if inputs.is_empty() {
            return Ok(());
        }
        send(&inputs)
    }
}

/// Linux evdev key code -> PC/AT scan code set 1 (`E0`-prefixed keys flagged as extended).
/// Codes 1..=83 and 86..=88 were assigned from set 1 and map to themselves.
fn evdev_to_scancode(code: u16) -> Option<(u16, bool)> {
    let mapped = match code {
        1..=83 | 86..=88 => (code, false),
        89 => (0x73, false),                       // RO
        92 => (0x79, false),                       // HENKAN
        93 => (0x70, false),                       // KATAKANAHIRAGANA
        94 => (0x7B, false),                       // MUHENKAN
        96 => (0x1C, true),                        // KPENTER
        97 => (0x1D, true),                        // RIGHTCTRL
        98 => (0x35, true),                        // KPSLASH
        99 => (0x37, true),                        // SYSRQ / Print Screen
        100 => (0x38, true),                       // RIGHTALT
        102 => (0x47, true),                       // HOME
        103 => (0x48, true),                       // UP
        104 => (0x49, true),                       // PAGEUP
        105 => (0x4B, true),                       // LEFT
        106 => (0x4D, true),                       // RIGHT
        107 => (0x4F, true),                       // END
        108 => (0x50, true),                       // DOWN
        109 => (0x51, true),                       // PAGEDOWN
        110 => (0x52, true),                       // INSERT
        111 => (0x53, true),                       // DELETE
        113 => (0x20, true),                       // MUTE
        114 => (0x2E, true),                       // VOLUMEDOWN
        115 => (0x30, true),                       // VOLUMEUP
        117 => (0x59, false),                      // KPEQUAL
        121 => (0x7E, false),                      // KPCOMMA
        122 => (0x72, false),                      // HANGEUL
        123 => (0x71, false),                      // HANJA
        124 => (0x7D, false),                      // YEN
        125 => (0x5B, true),                       // LEFTMETA
        126 => (0x5C, true),                       // RIGHTMETA
        127 => (0x5D, true),                       // COMPOSE / Menu
        163 => (0x19, true),                       // NEXTSONG
        164 => (0x22, true),                       // PLAYPAUSE
        165 => (0x10, true),                       // PREVIOUSSONG
        166 => (0x24, true),                       // STOPCD
        183..=193 => (0x64 + (code - 183), false), // F13..F23
        194 => (0x76, false),                      // F24
        _ => return None,
    };
    Some(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scancodes() {
        assert_eq!(evdev_to_scancode(30), Some((0x1E, false))); // A
        assert_eq!(evdev_to_scancode(103), Some((0x48, true))); // Up
        assert_eq!(evdev_to_scancode(193), Some((0x6E, false))); // F23
        assert_eq!(evdev_to_scancode(84), None);
    }

    #[test]
    fn virtual_desk_mapping_hits_pixel_centers() {
        // Windows converts back with floor(v * size / 65536).
        for size in [1920i64, 2560, 3840 + 1920] {
            for px in [0, 1, size / 2, size - 1] {
                let v = to_virtual_desk(px, 0, size) as i64;
                assert_eq!(v * size / 65536, px, "size {size} px {px}");
            }
        }
    }
}
