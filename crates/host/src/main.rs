mod capture;
mod encode;
mod input;
mod server;

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sm_protocol::{
    identity::{AuthorizedClient, StateDir},
    pairing::PairingCode,
    tls::Fingerprint,
    wire::DEFAULT_PORT,
};

const PAIRING_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Parser)]
#[command(name = "sm-host", version, about = "Share this computer's screen and accept remote input")]
struct Cli {
    /// Directory for identity and paired devices (defaults to the OS config directory).
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,
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
        /// Target video bitrate in kbit/s.
        #[arg(long, default_value_t = 12_000)]
        bitrate: u32,
        /// Print a one-time pairing code (valid for 10 minutes) to add a new device.
        #[arg(long)]
        pair: bool,
    },
    /// List paired devices.
    Clients,
    /// Remove a paired device by name or fingerprint.
    Revoke { device: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();

    // Physical pixels everywhere: DXGI reports them, and SendInput must agree under scaling.
    #[cfg(windows)]
    // SAFETY: process-wide setting applied before any window or capture object exists.
    unsafe {
        use windows::Win32::UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    let cli = Cli::parse();
    let state = StateDir::open(cli.config_dir, "host")?;

    match cli.command {
        Command::Run { bind, name, fps, bitrate, pair } => {
            let identity = state.load_or_create_identity()?;
            let pairing = if pair {
                let code = PairingCode::generate(identity.fingerprint())?;
                print_pairing(&code, bind.port());
                Some((code, PAIRING_TTL))
            } else {
                None
            };
            let options = server::HostOptions {
                bind,
                name: name.unwrap_or_else(hostname),
                fps: fps.clamp(1, 240),
                bitrate_kbps: bitrate.max(100),
            };
            server::run(options, state, pairing).await
        }
        Command::Clients => {
            let clients: Vec<AuthorizedClient> = state.load(StateDir::AUTHORIZED_CLIENTS)?;
            if clients.is_empty() {
                println!("No paired devices. Run `sm-host run --pair` to add one.");
            }
            for c in clients {
                let fp = Fingerprint::from_base64(&c.fingerprint).map(|f| f.short()).unwrap_or(c.fingerprint);
                println!("{:<24} {fp}", c.name);
            }
            Ok(())
        }
        Command::Revoke { device } => {
            let mut clients: Vec<AuthorizedClient> = state.load(StateDir::AUTHORIZED_CLIENTS)?;
            let before = clients.len();
            clients.retain(|c| {
                let short = Fingerprint::from_base64(&c.fingerprint).map(|f| f.short()).unwrap_or_default();
                c.name != device && c.fingerprint != device && short != device
            });
            if clients.len() == before {
                bail!("no paired device matches '{device}'");
            }
            state.save(StateDir::AUTHORIZED_CLIENTS, &clients)?;
            println!("Removed {} device(s). Active sessions continue until they disconnect.", before - clients.len());
            Ok(())
        }
    }
}

fn print_pairing(code: &PairingCode, port: u16) {
    let addr = local_ip().map(|ip| format!("{ip}:{port}")).unwrap_or_else(|| format!("<this-pc-address>:{port}"));
    println!();
    println!("Pairing code (single use, valid for 10 minutes):");
    println!();
    println!("    {}", code.encode());
    println!();
    println!("On the new device run:");
    println!("    sm-client pair {addr} {}", code.encode());
    println!();
    println!("Host fingerprint: {}", code.host.short());
    println!();
}

/// Primary LAN address, found by asking the OS which interface would route to a public IP
/// (no packet is sent).
fn local_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    Some(socket.local_addr().ok()?.ip())
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
