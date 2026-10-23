#[cfg(windows)]
mod agent;
mod awake;
mod capture;
mod control;
mod encode;
mod input;
mod password;
mod rate;
mod server;
#[cfg(windows)]
mod service;
mod transfer;
#[cfg(windows)]
mod win;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use encode::EncoderChoice;
use velora_protocol::{
    identity::{AuthorizedClient, StateDir},
    pairing::PairingCode,
    tls::Fingerprint,
    wire::DEFAULT_PORT,
};

#[derive(Parser)]
#[command(name = "velora-host", version, about = "Share this computer's screen and accept remote input")]
struct Cli {
    /// Directory for identity and paired devices (defaults to the OS config directory).
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,
    /// Don't install updates in the background (release builds update themselves by default).
    #[arg(long, global = true)]
    no_update: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the host.
    Run {
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)))]
        bind: SocketAddr,
        /// Name shown to clients.
        #[arg(long)]
        name: Option<String>,
        /// Maximum frames per second.
        #[arg(long, default_value_t = 60)]
        fps: u32,
        /// Target video bitrate in kbit/s: the most, as it adapts to the network.
        #[arg(long, default_value_t = 12_000)]
        bitrate: u32,
        /// Keep the bitrate fixed instead of lowering it when the network falls behind.
        #[arg(long)]
        fixed_bitrate: bool,
        /// Print a one-time pairing code (valid for 10 minutes) to add a new device.
        #[arg(long)]
        pair: bool,
        /// Video encoder: auto (first working hardware encoder, else software), software,
        /// nvenc, qsv, amf, vaapi, or ffmpeg:<name> for any FFmpeg encoder.
        #[arg(long, default_value = "auto")]
        encoder: EncoderChoice,
        /// Started by the Windows service (set by the service itself).
        #[arg(long, hide = true)]
        service: bool,
        /// Write the log to this file instead of stderr.
        #[arg(long, hide = true)]
        log_file: Option<PathBuf>,
    },
    /// List paired devices.
    Clients,
    /// Remove a paired device by name or fingerprint.
    Revoke { device: String },
    /// Set the password paired devices must also give to connect (asked without echo).
    Password {
        /// Remove the password instead.
        #[arg(long)]
        clear: bool,
    },
    /// Install the latest release now (restart a running host to use it).
    Update,
    /// Serve one file stream on standard input and output (started by the service's host as
    /// the user signed in at the console).
    #[command(hide = true)]
    FilesAgent {
        /// Offer these files and folders to the connected device instead.
        #[arg(long, num_args = 1..)]
        send: Vec<PathBuf>,
    },
    /// Run as a Windows service, to be reachable on the lock screen and before logon.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceAction {
    /// Copy Velora to Program Files and install and start the service (as administrator).
    /// Paired devices are kept.
    Install {
        /// Write the outcome to this file (empty on success), for the launcher.
        #[arg(long, hide = true)]
        report: Option<PathBuf>,
    },
    /// Stop and remove the service (as administrator).
    Uninstall {
        #[arg(long, hide = true)]
        report: Option<PathBuf>,
    },
    /// Entry point for the service manager.
    #[command(hide = true)]
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli)?;

    // Physical pixels everywhere: DXGI reports them, and SendInput must agree under scaling.
    #[cfg(windows)]
    // SAFETY: process-wide setting applied before any window or capture object exists.
    unsafe {
        use windows::Win32::UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    // Captured before an update renames the running file.
    let exe = std::env::current_exe()?;
    velora_update::cleanup_current_exe();
    let state = || StateDir::open(cli.config_dir.clone(), "host");

    match cli.command {
        Command::Run { bind, name, fps, bitrate, fixed_bitrate, pair, encoder, service, log_file: _ } => {
            let options = server::HostOptions {
                bind,
                name: name.unwrap_or_else(hostname),
                fps: fps.clamp(1, 240),
                bitrate_kbps: bitrate.max(100),
                encoder,
                service,
                adaptive_bitrate: !fixed_bitrate,
            };
            let auto_update = velora_update::auto_update_enabled(cli.no_update);
            let updated = server::run(options, state()?, pair, auto_update).await?;
            // Under the service, exit and let it start the new version.
            if updated && !service {
                velora_update::restart(&exe);
            }
            Ok(())
        }
        Command::FilesAgent { send } => transfer::agent(send).await,
        Command::Update => {
            match velora_update::update_now()? {
                Some(v) => println!("Updated to {v}. Restart velora-host to use it."),
                None => println!("Already up to date ({}).", velora_update::Version::current()),
            }
            Ok(())
        }
        Command::Clients => {
            let clients: Vec<AuthorizedClient> = state()?.load(StateDir::AUTHORIZED_CLIENTS)?;
            if clients.is_empty() {
                println!("No paired devices. Run `velora-host run --pair` to add one.");
            }
            for c in clients {
                let fp = Fingerprint::from_base64(&c.fingerprint).map(|f| f.short()).unwrap_or(c.fingerprint);
                println!("{:<24} {fp}", c.name);
            }
            Ok(())
        }
        Command::Revoke { device } => {
            let removed = server::revoke(&state()?, &device)?;
            if removed == 0 {
                bail!("no paired device matches '{device}'");
            }
            println!("Removed {removed} device(s). Active sessions continue until they disconnect.");
            Ok(())
        }
        Command::Password { clear } => {
            let new = if clear {
                None
            } else {
                let first = rpassword::prompt_password("New password: ")?;
                if rpassword::prompt_password("Repeat it: ")? != first {
                    bail!("the passwords do not match");
                }
                Some(first)
            };
            // Through the running host when there is one: it knows where its state is (the
            // service keeps it in ProgramData, not in this user's folder).
            let running = cli.config_dir.is_none()
                && velora_protocol::control::request(&velora_protocol::control::Request::Status).is_ok();
            if running {
                velora_protocol::control::request(&velora_protocol::control::Request::SetPassword {
                    password: new.clone(),
                })?;
            } else {
                password::set(&state()?, new.as_deref())?;
            }
            match new {
                Some(_) => println!("Password set. Paired devices will be asked for it when they connect."),
                None => println!("Password removed: paired devices connect without one."),
            }
            Ok(())
        }
        #[cfg(windows)]
        Command::Service { action } => service_command(action, cli.config_dir.clone()),
    }
}

#[cfg(windows)]
fn service_command(action: ServiceAction, config_dir: Option<PathBuf>) -> Result<()> {
    let (result, report) = match action {
        ServiceAction::Install { report } => (service::install(config_dir), report),
        ServiceAction::Uninstall { report } => (service::uninstall(), report),
        ServiceAction::Run => return service::run_dispatcher(),
    };
    // The launcher runs these elevated, without a console to read. `create_new` never
    // follows a link someone planted at that path in the user's temporary folder.
    if let Some(path) = report {
        let text = result.as_ref().err().map(|e| format!("{e:#}")).unwrap_or_default();
        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
            use std::io::Write;
            let _ = file.write_all(text.as_bytes());
        }
    }
    result
}

/// Logs to stderr, or to a file for processes without a console: the service, and the host it
/// starts (`--log-file`).
fn init_logging(cli: &Cli) -> Result<()> {
    let filter = || tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let file = match &cli.command {
        Command::Run { log_file: Some(path), .. } => Some(path.clone()),
        #[cfg(windows)]
        Command::Service { action: ServiceAction::Run } => Some(service::config_dir().join("service.log")),
        _ => None,
    };
    match file {
        Some(path) => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let file = std::fs::File::create(&path)?;
            tracing_subscriber::fmt()
                .with_env_filter(filter())
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(file))
                .init();
        }
        None => tracing_subscriber::fmt().with_env_filter(filter()).with_writer(std::io::stderr).init(),
    }
    Ok(())
}

fn print_pairing(code: &PairingCode, addr: &str, also: &[String]) {
    println!();
    println!("Pairing code (single use, valid for 10 minutes):");
    println!();
    println!("    {}", code.encode());
    println!();
    println!("On a phone, scan this with the Velora app:");
    let link = velora_protocol::pairing::pairing_uri_with(addr, also, code);
    match qrcode::QrCode::new(link.as_bytes()) {
        // Light modules drawn as blocks: reads correctly on the usual dark terminal background.
        Ok(qr) => println!(
            "{}",
            qr.render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build()
        ),
        Err(e) => println!("    (cannot render QR code: {e})"),
    }
    println!("On a computer run:");
    println!("    velora pair {addr} {}", code.encode());
    println!();
    println!("Host fingerprint: {}", code.host.short());
    println!();
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "host".into())
}
