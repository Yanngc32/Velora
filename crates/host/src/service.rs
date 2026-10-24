//! Windows service, so the computer can be reached on the lock screen, at UAC prompts and
//! right after boot, before anyone logs on.
//!
//! The service itself (session 0, no desktop) only supervises: it starts `velora-host run` as
//! SYSTEM in the session shown on the physical console, where capture and input injection
//! work, and starts it again when it exits or when another session takes the console (user
//! switching, log off). Running as SYSTEM lets the host follow the input desktop to the lock
//! screen (see `win::follow_input_desktop`).
//!
//! The service runs from Program Files and keeps its state in ProgramData, both writable only
//! by administrators and SYSTEM: a binary or key that a user could replace would hand that
//! user the SYSTEM account.

use std::{
    ffi::OsString,
    fs,
    os::windows::{fs::MetadataExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{bail, Context, Result};
use velora_protocol::{control, identity::StateDir, wire::DEFAULT_PORT};
use windows::{
    core::{GUID, HSTRING, PWSTR},
    Win32::{
        Foundation::{HANDLE, WAIT_OBJECT_0},
        Security::{
            DuplicateTokenEx, GetFileSecurityW, GetSecurityDescriptorOwner, SecurityImpersonation, SetFileSecurityW,
            SetTokenInformation, TokenPrimary, TokenSessionId, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_ADJUST_DEFAULT,
            TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
        },
        System::{
            Com::CoTaskMemFree,
            RemoteDesktop::WTSGetActiveConsoleSessionId,
            Threading::{
                CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
                CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
        UI::Shell::{
            FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_System, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
        },
    },
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::{
    reach,
    win::{self, Handle},
};

pub const SERVICE_NAME: &str = "Velora";
const DISPLAY_NAME: &str = "Velora Host";
const DESCRIPTION: &str = "Lets paired devices view and control this computer, including on the lock screen.";
/// Inbound firewall rule for the installed host. A SYSTEM process never gets Windows' "allow
/// access" prompt, so without this rule the firewall silently drops every client.
const FIREWALL_RULE: &str = "Velora (service)";
/// Waits between restarts of a host that keeps failing: 1 s, doubling up to this.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// A host that ran this long was healthy; the next failure starts the backoff over.
const HEALTHY_RUN: Duration = Duration::from_secs(60);
/// No console session while Windows switches between sessions.
const NO_SESSION: u32 = u32::MAX;
/// Owned by the administrators, readable and writable only by SYSTEM and administrators.
const PRIVATE_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// The same, plus read and execute for users, who run the launcher from there.
const PROGRAM_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// What an installation consists of, next to the executable. Only these are copied into
/// Program Files: any other DLL there would be loaded by a SYSTEM process.
const PACKAGE_FILES: &[&str] = &["velora-host.exe", "velora.exe", "LICENSE", "NOTICE.txt", "FFMPEG-LICENSE.txt"];
const PACKAGE_DLLS: &[&str] = &["avcodec-", "avutil-", "swresample-"];

/// `C:\Program Files\Velora`. Known folders rather than environment variables, which the
/// user can redefine for the elevated installer.
pub fn install_dir() -> PathBuf {
    known_folder(&FOLDERID_ProgramFiles).unwrap_or_else(|| r"C:\Program Files".into()).join("Velora")
}

/// `C:\ProgramData\Velora`, the service's `--config-dir`.
pub fn config_dir() -> PathBuf {
    known_folder(&FOLDERID_ProgramData).unwrap_or_else(|| r"C:\ProgramData".into()).join("Velora")
}

fn known_folder(id: &GUID) -> Option<PathBuf> {
    // SAFETY: the returned string is copied, then freed with CoTaskMemFree.
    unsafe {
        let path = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let out = path.to_string().ok();
        CoTaskMemFree(Some(path.0 as *const _));
        out.map(PathBuf::from)
    }
}

/// Installs (or upgrades) and starts the service. Needs an elevated administrator.
/// `user_config` is the configuration of the user's own host, migrated so paired devices
/// keep working.
pub fn install(user_config: Option<PathBuf>) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the service manager (run this as an administrator)")?;

    // An upgrade: the running service locks its files.
    if let Ok(existing) = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS) {
        stop_and_wait(&existing)?;
    }
    // A host the user started would hold the port and the control pipe.
    if control::request(&control::Request::Shutdown).is_ok() {
        println!("Stopped the host running in this session.");
        std::thread::sleep(Duration::from_secs(2));
    }

    let target = install_dir();
    secure_dir(&target, PROGRAM_SDDL)?;
    copy_installation(&target)?;
    restrict_tree(&target, PROGRAM_SDDL)?;
    let state = config_dir();
    secure_dir(&state, PRIVATE_SDDL)?;
    migrate_state(user_config, &state)?;

    let exe = target.join("velora-host.exe");
    // Not fatal: a third-party firewall may stand in for Windows'.
    if let Err(e) = allow_through_firewall(&exe) {
        eprintln!("Could not add the firewall rule, allow UDP port {DEFAULT_PORT} for {}: {e:#}", exe.display());
    }
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["service".into(), "run".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(s) => {
            s.change_config(&info)?;
            s
        }
        Err(_) => manager.create_service(&info, access).context("creating the service")?,
    };
    service.set_description(DESCRIPTION)?;
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    // Also restart after a clean exit with an error code: the supervisor exits that way to
    // run a newly installed version of itself.
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.start::<&str>(&[]).context("starting the service")?;
    println!("Installed in {} and started. State: {}", target.display(), state.display());
    Ok(())
}

/// Stops and removes the service. Files stay in Program Files and ProgramData.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the service manager (run this as an administrator)")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE)
        .context("the service is not installed (or this is not an administrator)")?;
    stop_and_wait(&service)?;
    service.delete()?;
    let _ = remove_firewall_rule();
    println!("Removed the service. Files remain in {} and {}.", install_dir().display(), config_dir().display());
    Ok(())
}

/// Replaces the service's firewall rule with one allowing `exe` on the host's UDP port.
fn allow_through_firewall(exe: &Path) -> Result<()> {
    let _ = remove_firewall_rule();
    netsh(&[
        "add",
        "rule",
        &format!("name=\"{FIREWALL_RULE}\""),
        "dir=in",
        "action=allow",
        &format!("program=\"{}\"", exe.display()),
        "protocol=UDP",
        &format!("localport={DEFAULT_PORT}"),
        // Public networks too: the PC's network may be one its user cannot mark as Private.
        "profile=any",
        "enable=yes",
    ])
}

fn remove_firewall_rule() -> Result<()> {
    netsh(&["delete", "rule", &format!("name=\"{FIREWALL_RULE}\"")])
}

/// Runs `netsh advfirewall firewall <args>`. By full path: a search would also look next to
/// this executable, which may be in a folder the user can write to, and this runs elevated.
/// Arguments are passed raw, since netsh wants `name="..."` rather than the whole argument
/// quoted.
fn netsh(args: &[&str]) -> Result<()> {
    let exe = known_folder(&FOLDERID_System).context("locating System32")?.join("netsh.exe");
    let mut command = Command::new(&exe);
    command.args(["advfirewall", "firewall"]);
    for arg in args {
        command.raw_arg(arg);
    }
    let output = command.output().with_context(|| format!("running {}", exe.display()))?;
    if !output.status.success() {
        bail!("netsh failed: {}", String::from_utf8_lossy(&output.stdout).trim());
    }
    Ok(())
}

fn stop_and_wait(service: &windows_service::service::Service) -> Result<()> {
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while service.query_status()?.current_state != ServiceState::Stopped {
        if Instant::now() > deadline {
            bail!("the service did not stop");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

/// Copies the package files next to this executable.
fn copy_installation(target: &Path) -> Result<()> {
    let source = std::env::current_exe()?.parent().context("executable has no directory")?.to_path_buf();
    if same_dir(&source, target) {
        return Ok(());
    }
    let copy = |from: &Path, to: &Path| -> Result<()> {
        fs::copy(from, to).with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
        Ok(())
    };
    for entry in fs::read_dir(&source)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let dll = name.to_lowercase().ends_with(".dll") && PACKAGE_DLLS.iter().any(|p| name.starts_with(p));
        if entry.file_type()?.is_file() && (dll || PACKAGE_FILES.contains(&name.as_str())) {
            copy(&entry.path(), &target.join(&name))?;
        }
    }
    let licenses = source.join("licenses");
    if licenses.is_dir() {
        fs::create_dir_all(target.join("licenses"))?;
        for entry in fs::read_dir(&licenses)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                copy(&entry.path(), &target.join("licenses").join(entry.file_name()))?;
            }
        }
    }
    Ok(())
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Creates `dir`, or takes over an existing one, so that only SYSTEM and administrators can
/// change it (`sddl`), replacing every previous entry of its access list and its contents'.
/// Refuses a folder (or link) that someone else created first: ProgramData lets any user
/// create folders, and the owner of one could keep access to the host's private key.
fn secure_dir(dir: &Path, sddl: &str) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if is_link(&meta) {
                bail!("{} is a link; remove it and install again", dir.display());
            }
            let owner = owner_sid(dir)?;
            if !["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"]
                .contains(&owner.as_str())
            {
                bail!("{} was created by another account ({owner}); remove it and install again", dir.display());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(dir)?,
        Err(e) => return Err(e).with_context(|| format!("checking {}", dir.display())),
    }
    restrict_tree(dir, sddl)
}

fn is_link(meta: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn restrict_tree(path: &Path, sddl: &str) -> Result<()> {
    let descriptor = win::SecurityAttributes::from_sddl(sddl)?;
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: valid path and security descriptor.
    unsafe { SetFileSecurityW(&HSTRING::from(path.as_os_str()), info, descriptor.descriptor()) }
        .ok()
        .with_context(|| format!("restricting access to {}", path.display()))?;
    if fs::symlink_metadata(path)?.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if is_link(&entry.metadata()?) {
                bail!("{} is a link; remove it and install again", entry.path().display());
            }
            restrict_tree(&entry.path(), sddl)?;
        }
    }
    Ok(())
}

fn owner_sid(path: &Path) -> Result<String> {
    let name = HSTRING::from(path.as_os_str());
    let mut len = 0u32;
    // SAFETY: the first call reports the size, the second fills a buffer of that size; the
    // owner SID points into that buffer, which outlives its use.
    unsafe {
        let _ = GetFileSecurityW(&name, OWNER_SECURITY_INFORMATION.0, None, 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let descriptor = PSECURITY_DESCRIPTOR(buf.as_mut_ptr().cast());
        GetFileSecurityW(&name, OWNER_SECURITY_INFORMATION.0, Some(descriptor), len, &mut len)
            .ok()
            .with_context(|| format!("reading the owner of {}", path.display()))?;
        let mut owner = PSID::default();
        let mut defaulted = false.into();
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted)?;
        win::sid_string(owner)
    }
}

/// Brings the user's host identity, paired devices and reach files (the DHT key, the device secrets, the switches, the
/// relays) over, so phones stay paired and keep finding and opening the host.
fn migrate_state(user_config: Option<PathBuf>, service_config: &Path) -> Result<()> {
    let to = StateDir::open(Some(service_config.to_path_buf()), "host")?;
    let Some(from) = copy_user_state(user_config, &to)? else { return Ok(()) };
    // Copies take the folder's access list, but set it explicitly anyway.
    restrict_tree(to.dir(), PRIVATE_SDDL)?;
    if from.path(StateDir::IDENTITY).exists() {
        println!("Kept this computer's identity and paired devices from {}.", from.dir().display());
    }
    Ok(())
}

/// Copies what the user's host keeps into the service's state directory `to`, file by file and only the files there
/// are. A service that has an identity already keeps its state as it is, and nothing is copied (`None`); otherwise the
/// user's state directory is returned.
fn copy_user_state(user_config: Option<PathBuf>, to: &StateDir) -> Result<Option<StateDir>> {
    if to.path(StateDir::IDENTITY).exists() {
        return Ok(None);
    }
    let from = StateDir::open(user_config, "host")?;
    let paired = [StateDir::IDENTITY, StateDir::AUTHORIZED_CLIENTS, StateDir::ACCESS_PASSWORD];
    for file in paired.into_iter().chain(reach::STATE_FILES) {
        if from.path(file).exists() {
            fs::copy(from.path(file), to.path(file))?;
        }
    }
    Ok(Some(from))
}

define_windows_service!(ffi_service_main, service_main);

/// Entry point when started by the service manager.
pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("not started by the service manager")
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
    }
}

enum Event {
    Stop,
    /// Someone logged on or off, or switched users: check the console session now.
    SessionChange,
}

fn run_service() -> Result<()> {
    let (events, rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = events.send(Event::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(_) => {
            let _ = events.send(Event::SessionChange);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    let report = |state, accept, exit_code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::SESSION_CHANGE,
        ServiceExitCode::Win32(0),
    )?;
    tracing::info!("service {} started", velora_update::Version::current());
    let outcome = supervise(&rx, || {
        let _ = report(ServiceState::StopPending, ServiceControlAccept::empty(), ServiceExitCode::Win32(0));
    });
    let exit_code = match outcome {
        Outcome::Stopped => ServiceExitCode::Win32(0),
        // A failure exit makes the service manager start the new version (see `install`).
        Outcome::Updated => ServiceExitCode::ServiceSpecific(1),
    };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), exit_code)?;
    Ok(())
}

enum Outcome {
    Stopped,
    /// Our executable was replaced by an update: restart into it.
    Updated,
}

/// Keeps one host running in the console session until the service stops.
fn supervise(events: &mpsc::Receiver<Event>, stopping: impl Fn()) -> Outcome {
    let exe = std::env::current_exe().expect("service executable path");
    let installed = modified(&exe);
    // Also here: installs that update themselves never run `install` again.
    if let Err(e) = allow_through_firewall(&exe) {
        tracing::warn!("could not add the firewall rule: {e:#}");
    }
    let mut host: Option<Host> = None;
    let mut backoff = Duration::from_secs(1);
    let mut next_start = Instant::now();
    let outcome = loop {
        // SAFETY: plain query.
        let console = unsafe { WTSGetActiveConsoleSessionId() };
        if let Some(h) = &host {
            let exited = h.exited();
            // Between sessions there is no console; wait until one shows up.
            let moved = console != NO_SESSION && h.session != console;
            if exited || moved {
                if !exited {
                    tracing::info!("console moved to session {console}; restarting the host there");
                    h.stop();
                } else if h.started.elapsed() < HEALTHY_RUN {
                    next_start = Instant::now() + backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    tracing::warn!("host exited early; retrying in {:?} (see host.log)", next_start - Instant::now());
                } else {
                    backoff = Duration::from_secs(1);
                }
                host = None;
                if modified(&exe) != installed {
                    tracing::info!("a new version was installed; restarting the service");
                    break Outcome::Updated;
                }
            }
        }
        if host.is_none() && console != NO_SESSION && Instant::now() >= next_start {
            match Host::start(&exe, console) {
                Ok(h) => host = Some(h),
                Err(e) => {
                    tracing::error!("cannot start the host in session {console}: {e:#}");
                    next_start = Instant::now() + backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        match events.recv_timeout(Duration::from_secs(1)) {
            Ok(Event::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break Outcome::Stopped,
            Ok(Event::SessionChange) | Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    stopping();
    if let Some(h) = host {
        h.stop();
    }
    tracing::info!("service stopped");
    outcome
}

fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The host process running in a console session.
struct Host {
    process: Handle,
    session: u32,
    started: Instant,
}

impl Host {
    /// Starts `velora-host run` as SYSTEM in `session`, on its interactive desktop.
    fn start(exe: &Path, session: u32) -> Result<Self> {
        let config = config_dir();
        let log = StateDir::open(Some(config.clone()), "host")?.path("host.log");
        let mut command_line: Vec<u16> = format!(
            "\"{}\" --config-dir \"{}\" run --service --log-file \"{}\"",
            exe.display(),
            config.display(),
            log.display()
        )
        .encode_utf16()
        .chain([0])
        .collect();
        let desktop = HSTRING::from(r"winsta0\default");
        // SAFETY: tokens are closed on drop; all pointers refer to locals that outlive the
        // calls.
        unsafe {
            let mut own = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut own)
                .context("OpenProcessToken")?;
            let own = Handle(own);
            let mut token = HANDLE::default();
            let access =
                TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
            DuplicateTokenEx(own.0, access, None, SecurityImpersonation, TokenPrimary, &mut token)
                .context("DuplicateTokenEx")?;
            let token = Handle(token);
            SetTokenInformation(token.0, TokenSessionId, (&session as *const u32).cast(), size_of::<u32>() as u32)
                .context("SetTokenInformation(TokenSessionId)")?;
            let startup = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop.as_ptr() as *mut u16),
                ..Default::default()
            };
            let mut info = PROCESS_INFORMATION::default();
            CreateProcessAsUserW(
                Some(token.0),
                &HSTRING::from(exe.as_os_str()),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                None,
                None,
                &startup,
                &mut info,
            )
            .context("CreateProcessAsUser")?;
            drop(Handle(info.hThread));
            tracing::info!("started the host in session {session} (pid {})", info.dwProcessId);
            Ok(Self { process: Handle(info.hProcess), session, started: Instant::now() })
        }
    }

    fn exited(&self) -> bool {
        // SAFETY: owned process handle.
        unsafe { WaitForSingleObject(self.process.0, 0) == WAIT_OBJECT_0 }
    }

    /// Ends the host and waits until it is gone, so its port and pipe are free for the next
    /// one. Clients see the connection drop and reconnect.
    fn stop(&self) {
        // SAFETY: owned process handle.
        unsafe {
            let _ = TerminateProcess(self.process.0, 1);
            WaitForSingleObject(self.process.0, 5000);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Two empty folders, one for the user's host and one for the service, removed at the end.
    struct Folders {
        user: PathBuf,
        service: PathBuf,
    }

    impl Folders {
        fn new() -> Folders {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let tag = format!("velora-migrate-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed));
            let base = std::env::temp_dir().join(tag);
            let _ = fs::remove_dir_all(&base);
            Folders { user: base.join("user"), service: base.join("service") }
        }

        /// The state directory of the user's host, or of the service.
        fn user(&self) -> StateDir {
            StateDir::open(Some(self.user.clone()), "host").unwrap()
        }

        fn service(&self) -> StateDir {
            StateDir::open(Some(self.service.clone()), "host").unwrap()
        }
    }

    impl Drop for Folders {
        fn drop(&mut self) {
            if let Some(base) = self.user.parent() {
                let _ = fs::remove_dir_all(base);
            }
        }
    }

    const PAIRED: [&str; 3] = [StateDir::IDENTITY, StateDir::AUTHORIZED_CLIENTS, StateDir::ACCESS_PASSWORD];

    fn write(state: &StateDir, file: &str, whose: &str) {
        fs::write(state.path(file), format!("{file} of {whose}")).unwrap();
    }

    fn read(state: &StateDir, file: &str) -> Option<String> {
        fs::read_to_string(state.path(file)).ok()
    }

    #[test]
    fn the_identity_the_paired_devices_and_every_file_of_the_reach_code_are_brought_over() {
        let folders = Folders::new();
        let (user, service) = (folders.user(), folders.service());
        for file in PAIRED.into_iter().chain(reach::STATE_FILES) {
            write(&user, file, "the user");
        }
        let from = copy_user_state(Some(folders.user.clone()), &service).unwrap().expect("it copied");
        assert_eq!(from.dir(), user.dir());
        for file in PAIRED.into_iter().chain(reach::STATE_FILES) {
            assert_eq!(read(&service, file), Some(format!("{file} of the user")), "{file}");
        }
    }

    #[test]
    fn what_the_user_does_not_have_is_not_invented() {
        let folders = Folders::new();
        let (user, service) = (folders.user(), folders.service());
        write(&user, StateDir::IDENTITY, "the user");
        copy_user_state(Some(folders.user.clone()), &service).unwrap().expect("it copied");
        assert_eq!(read(&service, StateDir::IDENTITY), Some("identity.json of the user".into()));
        for file in reach::STATE_FILES {
            assert_eq!(read(&service, file), None, "{file}");
        }
    }

    #[test]
    fn a_service_that_has_an_identity_keeps_all_its_state_as_it_is() {
        let folders = Folders::new();
        let (user, service) = (folders.user(), folders.service());
        for file in PAIRED.into_iter().chain(reach::STATE_FILES) {
            write(&user, file, "the user");
        }
        // The service has its identity, and a DHT key and secrets of its own; the rest it does not have.
        write(&service, StateDir::IDENTITY, "the service");
        write(&service, reach::STATE_FILES[0], "the service");
        assert!(copy_user_state(Some(folders.user.clone()), &service).unwrap().is_none());
        assert_eq!(read(&service, StateDir::IDENTITY), Some("identity.json of the service".into()));
        assert_eq!(read(&service, reach::STATE_FILES[0]), Some(format!("{} of the service", reach::STATE_FILES[0])));
        for file in reach::STATE_FILES.into_iter().skip(1) {
            assert_eq!(read(&service, file), None, "{file} is not copied over a service that has its own state");
        }
        assert_eq!(read(&service, StateDir::AUTHORIZED_CLIENTS), None);
    }
}
