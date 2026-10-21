//! Linux injection through uinput virtual devices. Works on X11 and Wayland alike because the
//! events enter the kernel input stack like a real keyboard and an absolute pointer (the same
//! approach as a VM "tablet" device).
//!
//! Requires write access to `/dev/uinput` (see README for the udev rule).

use anyhow::{Context, Result};
use evdev::{
    uinput::VirtualDevice, AbsInfo, AbsoluteAxisCode, AttributeSet, EventType, InputEvent, KeyCode, RelativeAxisCode,
    UinputAbsSetup,
};
use velora_protocol::wire::{KeyState, MouseButton};

use super::{x11_keymap::Keymap, Backend};

/// Highest regular key code (`KEY_MICMUTE`); button codes start at 0x100.
const MAX_KEY: u16 = 248;
const WHEEL_UNIT: i32 = 120;

pub struct Uinput {
    keyboard: VirtualDevice,
    pointer: VirtualDevice,
    wheel_remainder: (i32, i32),
}

impl Uinput {
    pub fn new() -> Result<Self> {
        let mut keys = AttributeSet::<KeyCode>::new();
        for code in 1..=MAX_KEY {
            keys.insert(KeyCode(code));
        }
        let keyboard = VirtualDevice::builder()
            .context("cannot open /dev/uinput")?
            .name("Velora Keyboard")
            .with_keys(&keys)?
            .build()?;

        let mut buttons = AttributeSet::<KeyCode>::new();
        for b in [KeyCode::BTN_LEFT, KeyCode::BTN_RIGHT, KeyCode::BTN_MIDDLE, KeyCode::BTN_SIDE, KeyCode::BTN_EXTRA] {
            buttons.insert(b);
        }
        let mut wheels = AttributeSet::<RelativeAxisCode>::new();
        for w in [
            RelativeAxisCode::REL_WHEEL,
            RelativeAxisCode::REL_HWHEEL,
            RelativeAxisCode::REL_WHEEL_HI_RES,
            RelativeAxisCode::REL_HWHEEL_HI_RES,
        ] {
            wheels.insert(w);
        }
        let axis = |code| UinputAbsSetup::new(code, AbsInfo::new(0, 0, u16::MAX as i32, 0, 0, 0));
        let pointer = VirtualDevice::builder()?
            .name("Velora Pointer")
            .with_keys(&buttons)?
            .with_relative_axes(&wheels)?
            .with_absolute_axis(&axis(AbsoluteAxisCode::ABS_X))?
            .with_absolute_axis(&axis(AbsoluteAxisCode::ABS_Y))?
            .build()?;

        Ok(Self { keyboard, pointer, wheel_remainder: (0, 0) })
    }
}

fn ev(kind: EventType, code: u16, value: i32) -> InputEvent {
    InputEvent::new(kind.0, code, value)
}

impl Backend for Uinput {
    fn move_abs(&mut self, x: u16, y: u16) -> Result<()> {
        self.pointer.emit(&[
            ev(EventType::ABSOLUTE, AbsoluteAxisCode::ABS_X.0, x as i32),
            ev(EventType::ABSOLUTE, AbsoluteAxisCode::ABS_Y.0, y as i32),
        ])?;
        Ok(())
    }

    fn button(&mut self, button: MouseButton, down: bool) -> Result<()> {
        let code = match button {
            MouseButton::Left => KeyCode::BTN_LEFT,
            MouseButton::Right => KeyCode::BTN_RIGHT,
            MouseButton::Middle => KeyCode::BTN_MIDDLE,
            MouseButton::Back => KeyCode::BTN_SIDE,
            MouseButton::Forward => KeyCode::BTN_EXTRA,
        };
        self.pointer.emit(&[ev(EventType::KEY, code.0, down as i32)])?;
        Ok(())
    }

    fn key(&mut self, code: u16, state: KeyState) -> Result<()> {
        if code == 0 || code > MAX_KEY {
            return Ok(());
        }
        let value = match state {
            KeyState::Up => 0,
            KeyState::Down => 1,
            // The compositor/X server generates its own auto-repeat from the held key.
            KeyState::Repeat => return Ok(()),
        };
        self.keyboard.emit(&[ev(EventType::KEY, code, value)])?;
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<()> {
        // Reloaded each time: the user may switch layouts while connected.
        let keymap = Keymap::load()?;
        let mut missing = String::new();
        for c in text.chars() {
            let Some(strokes) = keymap.strokes(c) else {
                missing.push(c);
                continue;
            };
            for stroke in strokes {
                let mut mods = Vec::new();
                if stroke.shift {
                    mods.push(super::x11_keymap::SHIFT);
                }
                if let (true, Some(altgr)) = (stroke.altgr, keymap.altgr) {
                    mods.push(altgr);
                }
                for &m in &mods {
                    self.keyboard.emit(&[ev(EventType::KEY, m, 1)])?;
                }
                self.keyboard.emit(&[ev(EventType::KEY, stroke.code, 1)])?;
                self.keyboard.emit(&[ev(EventType::KEY, stroke.code, 0)])?;
                for &m in mods.iter().rev() {
                    self.keyboard.emit(&[ev(EventType::KEY, m, 0)])?;
                }
            }
        }
        if !missing.is_empty() {
            tracing::warn!("the host keyboard layout cannot type {missing:?}");
        }
        Ok(())
    }

    fn scroll(&mut self, dx: i16, dy: i16) -> Result<()> {
        let mut events = Vec::with_capacity(4);
        let (rx, ry) = &mut self.wheel_remainder;
        for (delta, rem, hi_res, notch) in [
            (dy as i32, ry, RelativeAxisCode::REL_WHEEL_HI_RES, RelativeAxisCode::REL_WHEEL),
            (dx as i32, rx, RelativeAxisCode::REL_HWHEEL_HI_RES, RelativeAxisCode::REL_HWHEEL),
        ] {
            if delta == 0 {
                continue;
            }
            events.push(ev(EventType::RELATIVE, hi_res.0, delta));
            // Legacy clients only understand whole notches.
            *rem += delta;
            let notches = *rem / WHEEL_UNIT;
            if notches != 0 {
                *rem -= notches * WHEEL_UNIT;
                events.push(ev(EventType::RELATIVE, notch.0, notches));
            }
        }
        if !events.is_empty() {
            self.pointer.emit(&events)?;
        }
        Ok(())
    }
}
