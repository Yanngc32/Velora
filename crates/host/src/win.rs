//! Windows helpers: who may open the control pipe, and following the input desktop.

use std::{cell::RefCell, os::windows::io::RawHandle};

use anyhow::{Context, Result};
use windows::{
    core::{HSTRING, PWSTR},
    Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            GetTokenInformation, TokenElevationType, TokenElevationTypeFull, TokenElevationTypeLimited, TokenGroups,
            TokenUser, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
            TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Pipes::GetNamedPipeClientProcessId,
            RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken},
            StationsAndDesktops::{
                CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop, DESKTOP_ACCESS_FLAGS,
                DESKTOP_CONTROL_FLAGS, HDESK, UOI_NAME,
            },
            Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
        },
    },
};

thread_local! {
    /// The desktop this thread was last moved to, and its name.
    static DESKTOP: RefCell<Option<(HDESK, String)>> = const { RefCell::new(None) };
}

/// Moves the calling thread to the desktop that currently receives input, if it changed.
///
/// Windows shows the lock screen, the logon screen and UAC prompts on the `Winlogon` desktop
/// and everything else on `Default`. Capture and `SendInput` only reach the desktop of the
/// calling thread, so the capture and input threads call this before working. Opening
/// `Winlogon` needs the SYSTEM account (the host running as a service); otherwise this fails
/// and the thread stays where it is. The thread must not own windows or hooks.
pub fn follow_input_desktop() {
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    // SAFETY: the handle is closed below unless it becomes the thread's desktop.
    let Ok(desk) =
        (unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(MAXIMUM_ALLOWED)) })
    else {
        return;
    };
    let name = desktop_name(desk);
    DESKTOP.with_borrow_mut(|current| {
        if current.as_ref().is_some_and(|(_, n)| *n == name) {
            // SAFETY: opened above and not used further.
            unsafe {
                let _ = CloseDesktop(desk);
            }
            return;
        }
        // SAFETY: valid desktop handle; the previous one is closed once the thread has left it.
        match unsafe { SetThreadDesktop(desk) } {
            Ok(()) => {
                tracing::info!("following the input desktop to '{name}'");
                if let Some((old, _)) = current.replace((desk, name)) {
                    unsafe {
                        let _ = CloseDesktop(old);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("cannot switch to desktop '{name}': {e}");
                unsafe {
                    let _ = CloseDesktop(desk);
                }
            }
        }
    });
}

fn desktop_name(desk: HDESK) -> String {
    let mut buf = [0u16; 64];
    let mut needed = 0u32;
    // SAFETY: the buffer and its size in bytes are passed together.
    let ok = unsafe {
        GetUserObjectInformationW(
            HANDLE(desk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr().cast()),
            size_of_val(&buf) as u32,
            Some(&mut needed),
        )
    };
    if ok.is_err() {
        return String::new();
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// A kernel handle closed on drop.
pub struct Handle(pub HANDLE);

impl Handle {
    /// Gives up ownership without closing the handle.
    pub fn into_raw(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: owned handle, closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const SE_GROUP_ENABLED: u32 = 0x4;

/// Access to the control pipe: the system and administrators, plus the user the host serves.
/// That is the process owner normally, and the user logged on to the console for a service
/// (nobody else while the logon screen is up). The user gets read and write data only:
/// generic write would include creating further instances of the pipe, i.e. posing as the
/// host to everyone else.
pub fn pipe_sddl(service: bool) -> String {
    /// FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_APPEND_DATA (= create instance).
    const READ_WRITE_DATA: u32 = 0x0012_019B;
    let user = if service { console_user_sid() } else { process_user_sid() };
    let mut sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_string();
    match user {
        Ok(sid) => sddl.push_str(&format!("(A;;{READ_WRITE_DATA:#x};;;{sid})")),
        Err(e) => tracing::debug!("control pipe limited to administrators: {e:#}"),
    }
    sddl
}

fn process_user_sid() -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle of the current process needs no closing.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.context("OpenProcessToken")?;
    token_user_sid(&Handle(token))
}

fn console_user_sid() -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: plain session query. Needs the TCB privilege (SYSTEM).
    unsafe { WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &mut token) }.context("no user logged on")?;
    token_user_sid(&Handle(token))
}

/// Reads token information of variable size into an 8-byte aligned buffer.
fn token_info(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: the first call only reports the size; the second fills a buffer of that size.
    unsafe {
        let _ = GetTokenInformation(token.0, class, None, 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        GetTokenInformation(token.0, class, Some(buf.as_mut_ptr().cast()), len, &mut len)
            .context("GetTokenInformation")?;
        Ok(buf)
    }
}

pub fn sid_string(sid: PSID) -> Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: valid SID; the string is freed after copying.
    unsafe {
        ConvertSidToStringSidW(sid, &mut text).context("ConvertSidToStringSid")?;
        let out = text.to_string();
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        Ok(out?)
    }
}

fn token_user_sid(token: &Handle) -> Result<String> {
    let buf = token_info(token, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER followed by the SID it points to.
    sid_string(unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid })
}

/// Whether the process on the other end of a control pipe is SYSTEM or an administrator. An
/// administrator's unelevated token (UAC) counts: they could elevate anyway, and pairing a
/// phone should not need a UAC prompt. Standard users do not.
pub fn pipe_client_is_admin(pipe: RawHandle) -> bool {
    let check = || -> Result<bool> {
        let mut pid = 0u32;
        // SAFETY: valid pipe handle and out-pointer; process and token are closed on drop.
        let token = unsafe {
            GetNamedPipeClientProcessId(HANDLE(pipe), &mut pid)?;
            let process = Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?);
            let mut token = HANDLE::default();
            OpenProcessToken(process.0, TOKEN_QUERY, &mut token)?;
            Handle(token)
        };
        if token_user_sid(&token)? == SYSTEM_SID {
            return Ok(true);
        }
        let elevation = token_info(&token, TokenElevationType)?;
        // Full: elevated; Limited: the filtered token of an administrator under UAC.
        if [TokenElevationTypeFull.0, TokenElevationTypeLimited.0].contains(&(elevation[0] as i32)) {
            return Ok(true);
        }
        // UAC off: an administrator's token has the group enabled.
        let groups = token_info(&token, TokenGroups)?;
        // SAFETY: the buffer holds a TOKEN_GROUPS with `GroupCount` entries.
        let groups = unsafe {
            let g = &*(groups.as_ptr() as *const TOKEN_GROUPS);
            std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize)
                .iter()
                .map(|a| (a.Sid, a.Attributes))
                .collect::<Vec<_>>()
        };
        Ok(groups.into_iter().any(|(sid, attributes)| {
            attributes & SE_GROUP_ENABLED != 0 && sid_string(sid).is_ok_and(|s| s == ADMINISTRATORS_SID)
        }))
    };
    check().unwrap_or_else(|e| {
        tracing::debug!("cannot identify the control client: {e:#}");
        false
    })
}

/// `SECURITY_ATTRIBUTES` built from SDDL, freed on drop.
pub struct SecurityAttributes {
    attributes: SECURITY_ATTRIBUTES,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl SecurityAttributes {
    pub fn from_sddl(sddl: &str) -> Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid string and out-pointer; the descriptor is freed in Drop.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .with_context(|| format!("invalid security descriptor {sddl}"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        Ok(Self { attributes, descriptor })
    }

    pub fn descriptor(&self) -> PSECURITY_DESCRIPTOR {
        self.descriptor
    }

    pub fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        (&mut self.attributes as *mut SECURITY_ATTRIBUTES).cast()
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}
