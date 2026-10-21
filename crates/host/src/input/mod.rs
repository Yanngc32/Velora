//! Input injection.
//!
//! All events go through one dedicated thread so injection never blocks the network tasks and
//! events are applied in arrival order. The thread tracks pressed keys and buttons so a
//! disconnect or focus loss on the client can never leave anything stuck down on the host.

use std::{collections::HashSet, sync::mpsc};

use anyhow::Result;
use velora_protocol::wire::{KeyState, MouseButton};

use crate::capture::DisplayRect;

#[cfg(target_os = "linux")]
mod uinput;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
mod x11_keymap;

#[derive(Debug, Clone)]
pub enum InputCmd {
    Move { x: u16, y: u16 },
    Button { button: MouseButton, down: bool, x: u16, y: u16 },
    Key { code: u16, state: KeyState },
    Scroll { dx: i16, dy: i16 },
    ReleaseAll,
    SetDisplay(DisplayRect),
    Text(String),
}

/// Platform injector. Coordinates are normalized to `0..=65535` over the captured display.
trait Backend {
    fn move_abs(&mut self, x: u16, y: u16) -> Result<()>;
    fn button(&mut self, button: MouseButton, down: bool) -> Result<()>;
    fn key(&mut self, code: u16, state: KeyState) -> Result<()>;
    fn scroll(&mut self, dx: i16, dy: i16) -> Result<()>;
    /// Types characters independently of physical keys.
    fn text(&mut self, text: &str) -> Result<()>;
    fn set_display(&mut self, _rect: DisplayRect) {}
}

fn open_backend() -> Result<Box<dyn Backend>> {
    #[cfg(target_os = "linux")]
    return Ok(Box::new(uinput::Uinput::new()?));
    #[cfg(windows)]
    return Ok(Box::new(windows::SendInputBackend::new()));
    #[cfg(not(any(target_os = "linux", windows)))]
    anyhow::bail!("input injection is not implemented for this platform");
}

#[derive(Clone)]
pub struct InputHandle(mpsc::Sender<InputCmd>);

impl InputHandle {
    pub fn send(&self, cmd: InputCmd) {
        // The thread only exits with the process.
        let _ = self.0.send(cmd);
    }
}

/// Starts the injection thread. If the platform injector cannot be opened the host keeps
/// working in view-only mode.
pub fn spawn() -> InputHandle {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("input".into())
        .spawn(move || {
            let backend = match open_backend() {
                Ok(b) => Some(b),
                Err(e) => {
                    tracing::warn!("input injection unavailable, view-only mode: {e:#}");
                    None
                }
            };
            let mut injector = Injector { backend, keys: HashSet::new(), buttons: HashSet::new() };
            for cmd in rx {
                injector.apply(cmd);
            }
        })
        .expect("spawning input thread");
    InputHandle(tx)
}

struct Injector {
    backend: Option<Box<dyn Backend>>,
    keys: HashSet<u16>,
    buttons: HashSet<MouseButton>,
}

impl Injector {
    fn apply(&mut self, cmd: InputCmd) {
        let Some(backend) = self.backend.as_mut() else { return };
        let result = match cmd {
            InputCmd::Move { x, y } => backend.move_abs(x, y),
            InputCmd::Button { button, down, x, y } => {
                if down {
                    self.buttons.insert(button);
                } else {
                    self.buttons.remove(&button);
                }
                backend.move_abs(x, y).and_then(|_| backend.button(button, down))
            }
            InputCmd::Key { code, state } => {
                match state {
                    KeyState::Down | KeyState::Repeat => self.keys.insert(code),
                    KeyState::Up => self.keys.remove(&code),
                };
                backend.key(code, state)
            }
            InputCmd::Scroll { dx, dy } => backend.scroll(dx, dy),
            InputCmd::Text(text) => backend.text(&text),
            InputCmd::SetDisplay(rect) => {
                backend.set_display(rect);
                Ok(())
            }
            InputCmd::ReleaseAll => {
                let mut result = Ok(());
                for code in self.keys.drain() {
                    result = result.and(backend.key(code, KeyState::Up));
                }
                for button in self.buttons.drain() {
                    result = result.and(backend.button(button, false));
                }
                result
            }
        };
        if let Err(e) = result {
            tracing::warn!("input injection failed: {e:#}");
        }
    }
}
