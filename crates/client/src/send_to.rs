//! "Send to → Velora" in Explorer: `velora send <files>` asks the host on this computer to
//! send them to the device connected to it, into that device's Downloads folder.

use std::path::PathBuf;

use anyhow::{Context, Result};
use velora_protocol::control::{self, Request};

use crate::gui::strings::{current, fill};

/// Hands `paths` to the local host and tells the user what happened: in a message box, since
/// Send To starts this without a console.
pub fn send(paths: Vec<PathBuf>) -> Result<()> {
    let s = current();
    let result = (|| -> Result<String> {
        let paths = paths
            .iter()
            .map(|p| std::path::absolute(p).with_context(|| format!("{}", p.display())))
            .collect::<Result<Vec<_>>>()?;
        let count = paths.len();
        let status = control::request(&Request::SendFiles { paths })?;
        let device = status.devices.iter().find(|d| d.connected).map_or("?", |d| d.name.as_str());
        Ok(fill(s.files_send_started, &[&count.to_string(), device]))
    })();
    let (text, failed) = match &result {
        Ok(text) => (text.clone(), false),
        Err(e) => (fill(s.files_send_failed, &[&format!("{e:#}")]), true),
    };
    println!("{text}");
    notify(&text, failed);
    result.map(drop)
}

#[cfg(windows)]
fn notify(text: &str, failed: bool) {
    use windows::{
        core::HSTRING,
        Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK},
    };
    let icon = if failed { MB_ICONERROR } else { MB_ICONINFORMATION };
    // SAFETY: valid strings; no owner window.
    unsafe {
        MessageBoxW(None, &HSTRING::from(text), &HSTRING::from("Velora"), MB_OK | icon);
    }
}

#[cfg(not(windows))]
fn notify(_text: &str, _failed: bool) {}

/// Adds Velora to Explorer's Send To menu, pointing at this executable (refreshed each start,
/// so it follows the app when it moves).
#[cfg(windows)]
pub fn install() -> Result<()> {
    use windows::{
        core::{Interface, HSTRING},
        Win32::{
            System::Com::{
                CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
            },
            UI::Shell::{FOLDERID_SendTo, IShellLinkW, SHGetKnownFolderPath, ShellLink, KF_FLAG_DEFAULT},
        },
    };
    let exe = std::env::current_exe()?;
    // SAFETY: COM objects are released on drop; the folder path is copied, then freed.
    unsafe {
        // Already initialized on this thread is fine.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let folder = SHGetKnownFolderPath(&FOLDERID_SendTo, KF_FLAG_DEFAULT, None)?;
        let dir = PathBuf::from(folder.to_string()?);
        windows::Win32::System::Com::CoTaskMemFree(Some(folder.0 as *const _));
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(&HSTRING::from(exe.as_os_str()))?;
        link.SetArguments(&HSTRING::from("send"))?;
        link.SetDescription(&HSTRING::from(current().files_send_to_description))?;
        link.cast::<IPersistFile>()?.Save(&HSTRING::from(dir.join("Velora.lnk").as_os_str()), true)?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn install() -> Result<()> {
    Ok(())
}
