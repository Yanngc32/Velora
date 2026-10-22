//! File access for a host running as the service. The host is SYSTEM, but files must be read
//! and written with the rights of the user signed in at the console: each file stream is served
//! by `velora-host files-agent`, started as that user, through its standard input and output.
//! A bug in file handling therefore never runs with more than that user's rights.

use std::{ffi::c_void, os::windows::io::FromRawHandle, path::Path, time::Duration};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use windows::{
    core::{HSTRING, PWSTR},
    Win32::{
        Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0},
        Security::SECURITY_ATTRIBUTES,
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            Pipes::CreatePipe,
            RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken},
            Threading::{
                CreateProcessAsUserW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
                TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW,
                CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
                STARTUPINFOW,
            },
        },
    },
};

use crate::win::Handle;

/// How long an agent may take to exit once its streams are closed, before it is killed.
const EXIT_GRACE: Duration = Duration::from_secs(5);

/// A process handle, which any thread may use.
struct Process(Handle);

// SAFETY: process handles are not tied to the thread that opened them.
unsafe impl Send for Process {}

pub struct Agent {
    process: Process,
    stdin: tokio::fs::File,
    stdout: tokio::fs::File,
}

impl Agent {
    /// Starts `exe files-agent <args>` as the user signed in at the console.
    pub fn spawn(exe: &Path, args: &[String]) -> Result<Self> {
        let mut command_line: Vec<u16> = std::iter::once(quote(&exe.display().to_string()))
            .chain(std::iter::once("files-agent".to_string()))
            .chain(args.iter().map(|a| quote(a)))
            .collect::<Vec<_>>()
            .join(" ")
            .encode_utf16()
            .chain([0])
            .collect();
        // SAFETY: every handle is owned by a `Handle` and closed on drop; pointers refer to
        // locals that outlive the calls.
        unsafe {
            let mut token = HANDLE::default();
            WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &mut token)
                .context("nobody is signed in on this computer")?;
            let token = Handle(token);

            let inheritable = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                bInheritHandle: true.into(),
                ..Default::default()
            };
            let (mut child_in, mut our_in, mut our_out, mut child_out) =
                (HANDLE::default(), HANDLE::default(), HANDLE::default(), HANDLE::default());
            CreatePipe(&mut child_in, &mut our_in, Some(&inheritable), 0).context("CreatePipe")?;
            let (child_in, our_in) = (Handle(child_in), Handle(our_in));
            CreatePipe(&mut our_out, &mut child_out, Some(&inheritable), 0).context("CreatePipe")?;
            let (our_out, child_out) = (Handle(our_out), Handle(child_out));
            for ours in [&our_in, &our_out] {
                SetHandleInformation(ours.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
            }

            // Only the two pipe ends are inherited, never another handle of this SYSTEM process.
            let inherit = [child_in.0, child_out.0];
            let mut size = 0usize;
            let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
            let mut list_buf = vec![0u8; size];
            let list = LPPROC_THREAD_ATTRIBUTE_LIST(list_buf.as_mut_ptr().cast());
            InitializeProcThreadAttributeList(Some(list), 1, None, &mut size)
                .context("InitializeProcThreadAttributeList")?;
            let result = (|| -> Result<PROCESS_INFORMATION> {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    Some(inherit.as_ptr().cast()),
                    size_of_val(&inherit),
                    None,
                    None,
                )
                .context("UpdateProcThreadAttribute")?;
                let startup = STARTUPINFOEXW {
                    StartupInfo: STARTUPINFOW {
                        cb: size_of::<STARTUPINFOEXW>() as u32,
                        dwFlags: STARTF_USESTDHANDLES,
                        hStdInput: child_in.0,
                        hStdOutput: child_out.0,
                        ..Default::default()
                    },
                    lpAttributeList: list,
                };
                let mut environment: *mut c_void = std::ptr::null_mut();
                CreateEnvironmentBlock(&mut environment, Some(token.0), false).context("CreateEnvironmentBlock")?;
                let mut info = PROCESS_INFORMATION::default();
                let created = CreateProcessAsUserW(
                    Some(token.0),
                    &HSTRING::from(exe.as_os_str()),
                    Some(PWSTR(command_line.as_mut_ptr())),
                    None,
                    None,
                    true,
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                    Some(environment),
                    None,
                    &startup.StartupInfo,
                    &mut info,
                );
                let _ = DestroyEnvironmentBlock(environment);
                created.context("CreateProcessAsUser")?;
                Ok(info)
            })();
            DeleteProcThreadAttributeList(list);
            let info = result?;
            drop(Handle(info.hThread));
            // The child holds its own copies now.
            drop((child_in, child_out));
            let (our_in, our_out) = (our_in.into_raw(), our_out.into_raw());
            Ok(Self {
                process: Process(Handle(info.hProcess)),
                stdin: tokio::fs::File::from_std(std::fs::File::from_raw_handle(our_in.0)),
                stdout: tokio::fs::File::from_std(std::fs::File::from_raw_handle(our_out.0)),
            })
        }
    }

    /// Connects the agent to a file stream until both directions end, then waits for it to
    /// exit (so it can clean up an interrupted transfer) or kills it.
    pub async fn bridge(self, mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
        let Self { process, mut stdin, mut stdout } = self;
        let up = async {
            let copied = tokio::io::copy(&mut recv, &mut stdin).await;
            let _ = stdin.flush().await;
            // Closes the pipe: the agent sees the end of its input.
            drop(stdin);
            copied
        };
        let down = async {
            tokio::io::copy(&mut stdout, &mut send).await?;
            send.finish()?;
            anyhow::Ok(())
        };
        let (up, down) = tokio::join!(up, down);
        tokio::task::spawn_blocking(move || {
            // The whole wrapper, not just its (non-Send) handle field.
            let process = process;
            // SAFETY: owned process handle.
            unsafe {
                if WaitForSingleObject(process.0 .0, EXIT_GRACE.as_millis() as u32) != WAIT_OBJECT_0 {
                    let _ = TerminateProcess(process.0 .0, 1);
                }
            }
        });
        down?;
        up?;
        Ok(())
    }
}

/// Windows command-line quoting: backslashes before the closing quote are doubled, or `"C:\"`
/// would end with an escaped quote.
fn quote(arg: &str) -> String {
    let trailing = arg.len() - arg.trim_end_matches('\\').len();
    format!("\"{arg}{}\"", "\\".repeat(trailing))
}
