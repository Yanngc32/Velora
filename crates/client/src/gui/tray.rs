//! The icon next to the clock (Windows). It shows whether this PC is shared, opens the
//! launcher, turns sharing on and off, quits, and announces devices asking to send files
//! while the launcher's window is closed.
//!
//! It lives on a thread of its own, with a hidden window for the icon's messages, because
//! egui draws nothing while the launcher's window is hidden: everything here has to work
//! without it.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicIsize, Ordering},
        Arc,
    },
};

use eframe::egui;
use velora_protocol::control::Request;
use windows::{
    core::{w, PCWSTR},
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_RESPECT_QUIET_TIME,
                NIIF_USER, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_BALLOONUSERCLICK, NIN_SELECT,
                NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
            },
            WindowsAndMessaging::{
                AppendMenuW, CreateIcon, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
                DispatchMessageW, GetCursorPos, GetForegroundWindow, GetMessageW, GetSystemMetrics, GetWindowLongPtrW,
                IsIconic, IsWindowVisible, PostMessageW, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow,
                SetMenuDefaultItem, SetTimer, SetWindowLongPtrW, ShowWindow, TrackPopupMenu, TranslateMessage,
                GWLP_USERDATA, HICON, MF_CHECKED, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, SM_CXSMICON, SW_RESTORE,
                SW_SHOW, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, WINDOW_EX_STYLE, WM_APP, WM_CONTEXTMENU,
                WM_NULL, WM_TIMER, WNDCLASSW, WS_OVERLAPPED,
            },
        },
    },
};

use super::{
    strings::{fill, Strings},
    this_pc::{spawn_host, HostHandle},
};

const ICON_ID: u32 = 1;
/// The icon's mouse and keyboard events.
const WM_TRAY: u32 = WM_APP + 1;
/// From the launcher: its window was just closed to the tray.
const WM_HIDDEN: u32 = WM_APP + 2;
/// The icon selected with the keyboard (`NIN_SELECT | NINF_KEY`).
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
const TIMER: usize = 1;
/// How often the icon follows the host, like the launcher's own poll.
const REFRESH_MS: u32 = 1000;

const ID_OPEN: usize = 1;
const ID_SHARE: usize = 2;
const ID_QUIT: usize = 3;

pub struct Tray {
    /// The icon's hidden window.
    window: isize,
    /// The launcher's window, known once eframe created it.
    launcher: Arc<AtomicIsize>,
}

impl Tray {
    /// Adds the icon. `rgba` is the app icon (square); the icon dims while sharing is off.
    pub fn start(
        rgba: &image::RgbaImage,
        host: HostHandle,
        ctx: egui::Context,
        config_dir: Option<PathBuf>,
        s: &'static Strings,
    ) -> Option<Self> {
        let size = (unsafe { GetSystemMetrics(SM_CXSMICON) }).clamp(16, 64) as u32;
        let on = icon(rgba, size, false)?;
        let off = icon(rgba, size, true)?;
        let launcher = Arc::new(AtomicIsize::new(0));
        let (ready, window) = std::sync::mpsc::channel();
        let state = State {
            launcher: launcher.clone(),
            host,
            ctx,
            config_dir,
            s,
            on: on.0 as isize,
            off: off.0 as isize,
            shown: None,
            seen: Vec::new(),
            told_hidden: false,
            taskbar_created: 0,
        };
        std::thread::Builder::new().name("tray".into()).spawn(move || run(state, ready)).ok()?;
        let window = window.recv().ok()??;
        Some(Self { window, launcher })
    }

    /// Hands over the launcher's window, to show it from the icon.
    pub fn set_launcher(&self, hwnd: isize) {
        self.launcher.store(hwnd, Ordering::Relaxed);
    }

    /// The launcher's window was just hidden: the first time, say where it went.
    pub fn hidden(&self) {
        // SAFETY: posting to a window of this process; harmless if it is gone.
        let _ = unsafe { PostMessageW(Some(HWND(self.window as _)), WM_HIDDEN, WPARAM(0), LPARAM(0)) };
    }
}

impl Drop for Tray {
    /// Removes the icon now: once the process exits, Windows would leave it until hovered.
    fn drop(&mut self) {
        let data = base(HWND(self.window as _));
        // SAFETY: a valid structure; removing an icon that is gone fails harmlessly.
        let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
    }
}

/// Everything the icon's window needs, owned by its thread.
struct State {
    launcher: Arc<AtomicIsize>,
    host: HostHandle,
    ctx: egui::Context,
    config_dir: Option<PathBuf>,
    s: &'static Strings,
    on: isize,
    off: isize,
    /// The tooltip and sharing state on the icon now.
    shown: Option<(String, bool)>,
    /// File requests already announced.
    seen: Vec<u64>,
    /// Said once where the closed window went.
    told_hidden: bool,
    /// Sent to every window when Explorer restarts: the icon has to be added again.
    taskbar_created: u32,
}

/// Creates the icon's window, sends it back (or `None` when that failed), then serves it
/// until the process exits.
fn run(mut state: State, ready: std::sync::mpsc::Sender<Option<isize>>) {
    // SAFETY: plain Win32 calls with valid arguments; the window and its state live as long
    // as this thread, which is as long as the process.
    unsafe {
        let Some(hwnd) = create_window() else {
            let _ = ready.send(None);
            return;
        };
        state.taskbar_created = RegisterWindowMessageW(w!("TaskbarCreated"));
        let state = Box::into_raw(Box::new(state));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
        add_icon(hwnd, &mut *state);
        SetTimer(Some(hwnd), TIMER, REFRESH_MS, None);
        let _ = ready.send(Some(hwnd.0 as isize));

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// A hidden top-level window rather than a message-only one: only top-level windows hear
/// that Explorer restarted.
unsafe fn create_window() -> Option<HWND> {
    // SAFETY: valid class and window parameters.
    unsafe {
        let instance = HINSTANCE(GetModuleHandleW(PCWSTR::null()).ok()?.0);
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: w!("VeloraTray"),
            ..Default::default()
        };
        RegisterClassW(&class);
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("VeloraTray"),
            w!("Velora"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance),
            None,
        )
        .ok()
    }
}

/// The shell structure naming this icon.
fn base(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW { cbSize: size_of::<NOTIFYICONDATAW>() as u32, hWnd: hwnd, uID: ICON_ID, ..Default::default() }
}

fn copy_wide(dst: &mut [u16], text: &str) {
    let n = dst.len() - 1;
    for (slot, unit) in dst.iter_mut().zip(text.encode_utf16().take(n)) {
        *slot = unit;
    }
}

unsafe fn add_icon(hwnd: HWND, state: &mut State) {
    let mut data = base(hwnd);
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = WM_TRAY;
    data.hIcon = HICON(state.off as _);
    copy_wide(&mut data.szTip, "Velora");
    // SAFETY: valid structure for this window.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_ADD, &data);
        data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        let _ = Shell_NotifyIconW(NIM_SETVERSION, &data);
    }
    state.shown = None;
    refresh(hwnd, state);
}

/// Follows the host: tooltip and icon, and a notification for each new file request while
/// the launcher is out of sight.
fn refresh(hwnd: HWND, state: &mut State) {
    let s = state.s;
    let view = state.host.view();
    let status = view.status.as_ref();
    let tip = match status {
        None => s.tray_tip_off.to_string(),
        Some(st) => match st.devices.iter().find(|d| d.connected) {
            Some(device) => fill(s.tray_tip_connected, &[&device.name]),
            None => s.tray_tip_on.to_string(),
        },
    };
    let sharing = status.is_some();
    if state.shown.as_ref() != Some(&(tip.clone(), sharing)) {
        let mut data = base(hwnd);
        data.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        data.hIcon = HICON(if sharing { state.on } else { state.off } as _);
        copy_wide(&mut data.szTip, &tip);
        // SAFETY: valid structure for this window.
        let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
        state.shown = Some((tip, sharing));
    }

    let requests = status.map(|st| st.requests.as_slice()).unwrap_or_default();
    let in_sight = launcher_in_sight(state);
    for request in requests.iter().filter(|r| !state.seen.contains(&r.id)) {
        if !in_sight {
            notify(hwnd, state, &fill(s.request_title, &[&request.name]));
        }
    }
    state.seen = requests.iter().map(|r| r.id).collect();
}

/// The launcher is open and in front: it shows file requests itself.
fn launcher_in_sight(state: &State) -> bool {
    let hwnd = HWND(state.launcher.load(Ordering::Relaxed) as _);
    // SAFETY: queries on a window handle, harmless if it is gone.
    !hwnd.is_invalid()
        && unsafe { IsWindowVisible(hwnd).as_bool() && !IsIconic(hwnd).as_bool() && GetForegroundWindow() == hwnd }
}

fn notify(hwnd: HWND, state: &State, text: &str) {
    let mut data = base(hwnd);
    data.uFlags = NIF_INFO;
    data.dwInfoFlags = NIIF_USER | NIIF_RESPECT_QUIET_TIME;
    data.hBalloonIcon = HICON(state.on as _);
    copy_wide(&mut data.szInfoTitle, "Velora");
    copy_wide(&mut data.szInfo, text);
    // SAFETY: valid structure for this window.
    let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) };
}

fn show_launcher(state: &State) {
    let hwnd = HWND(state.launcher.load(Ordering::Relaxed) as _);
    if hwnd.is_invalid() {
        return;
    }
    // SAFETY: plain calls on the launcher's window.
    unsafe {
        let _ = ShowWindow(hwnd, if IsIconic(hwnd).as_bool() { SW_RESTORE } else { SW_SHOW });
        let _ = SetForegroundWindow(hwnd);
    }
    // egui stops drawing while hidden: tell it the window is back, and wake it.
    state.ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    state.ctx.request_repaint();
}

fn menu(hwnd: HWND, state: &mut State) {
    let s = state.s;
    let status = state.host.view().status.clone();
    // SAFETY: a menu built, shown and destroyed here, owned by this thread's window.
    let chosen = unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
        let open = wide(s.tray_open);
        let _ = AppendMenuW(menu, MF_STRING, ID_OPEN, PCWSTR(open.as_ptr()));
        let _ = SetMenuDefaultItem(menu, ID_OPEN as u32, 0);
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        // The service would only start the host again: nothing to turn off from here.
        let service = status.as_ref().is_some_and(|st| st.service);
        let share = wide(if service { s.tray_sharing_service } else { s.tray_sharing });
        let mut flags = MF_STRING;
        if status.is_some() {
            flags |= MF_CHECKED;
        }
        if service {
            flags |= MF_GRAYED;
        }
        let _ = AppendMenuW(menu, flags, ID_SHARE, PCWSTR(share.as_ptr()));
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let quit = wide(s.tray_quit);
        let _ = AppendMenuW(menu, MF_STRING, ID_QUIT, PCWSTR(quit.as_ptr()));

        let mut at = POINT::default();
        let _ = GetCursorPos(&mut at);
        // Without this the menu stays open when clicking elsewhere.
        let _ = SetForegroundWindow(hwnd);
        let chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY, at.x, at.y, None, hwnd, None);
        let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
        let _ = DestroyMenu(menu);
        chosen.0 as usize
    };
    match chosen {
        ID_OPEN => show_launcher(state),
        ID_SHARE => match status {
            Some(st) if !st.service => state.host.send(Request::Shutdown),
            Some(_) => {}
            None => {
                if let Err(e) = spawn_host(state.config_dir.as_deref(), s.host_missing) {
                    notify(hwnd, state, &format!("{e:#}"));
                }
            }
        },
        ID_QUIT => {
            let data = base(hwnd);
            // SAFETY: valid structure for this window.
            let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) };
            // Settings are saved as they change and sessions are processes of their own:
            // nothing is lost by leaving now, even with the window hidden and egui asleep.
            std::process::exit(0);
        }
        _ => {}
    }
}

extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: the pointer was stored by `run` and lives as long as the window; only this
    // thread touches it.
    let state = unsafe { (GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut State).as_mut() };
    let Some(state) = state else {
        // SAFETY: default handling for messages before the state is set.
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    };
    match msg {
        WM_TIMER if wparam.0 == TIMER => refresh(hwnd, state),
        WM_TRAY => match (lparam.0 as u32) & 0xffff {
            NIN_SELECT | NIN_KEYSELECT | NIN_BALLOONUSERCLICK => show_launcher(state),
            WM_CONTEXTMENU => menu(hwnd, state),
            _ => {}
        },
        WM_HIDDEN => {
            if !state.told_hidden {
                state.told_hidden = true;
                notify(hwnd, state, state.s.tray_still_running);
            }
        }
        _ if msg == state.taskbar_created && msg != 0 => {
            // SAFETY: re-adding this window's icon.
            unsafe { add_icon(hwnd, state) };
        }
        // SAFETY: default handling.
        _ => return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
    LRESULT(0)
}

/// The app icon at `size` pixels, greyed when `dim`.
fn icon(rgba: &image::RgbaImage, size: u32, dim: bool) -> Option<HICON> {
    let small = image::imageops::resize(rgba, size, size, image::imageops::FilterType::Lanczos3);
    // A 32-bit colour bitmap, BGRA, top-down; the alpha channel does the masking.
    let mut color = Vec::with_capacity((size * size * 4) as usize);
    for px in small.pixels() {
        let [r, g, b, a] = px.0;
        let (r, g, b) = if dim {
            let grey = ((r as u32 * 30 + g as u32 * 59 + b as u32 * 11) / 100) as u8;
            (grey, grey, grey)
        } else {
            (r, g, b)
        };
        color.extend_from_slice(&[b, g, r, if dim { (a as u32 * 3 / 5) as u8 } else { a }]);
    }
    // Rows of the monochrome mask are padded to 16 bits; all clear, alpha decides.
    let mask = vec![0u8; (size.div_ceil(16) * 2 * size) as usize];
    // SAFETY: both buffers hold `size` rows in the layouts described above.
    unsafe { CreateIcon(None, size as i32, size as i32, 1, 32, mask.as_ptr(), color.as_ptr()) }.ok()
}
