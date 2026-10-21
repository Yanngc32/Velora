//! Connection handling, authorization and the per-session capture/encode/send pipeline.
//!
//! Latency control: the host keeps at most `ceil(RTT / frame interval) + 2` frames in flight
//! (encoded but not yet acknowledged by the client). When the link or the client cannot keep
//! up, new frames are simply not captured, so queues never build up and the picture on the
//! client is always recent, at the cost of frame rate.

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use tokio::sync::{mpsc, oneshot};
use velora_protocol::{
    identity::{AuthorizedClient, StateDir},
    pairing::PairingCode,
    tls::{self, Fingerprint},
    wire::{self, ClientMsg, Codec, FrameHeader, HostMsg, MouseMove, PROTOCOL_VERSION},
};

use crate::{
    capture::{self, DisplayRect},
    encode::{self, EncoderChoice, EncoderSettings},
    input::{InputCmd, InputHandle},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_IN_FLIGHT: u32 = 2;
const MAX_IN_FLIGHT: u32 = 16;
/// If no ack arrives for this long, assume the counter is out of sync and resume sending.
const ACK_STALL_RESET: Duration = Duration::from_secs(2);
const STATS_INTERVAL: Duration = Duration::from_secs(5);
const UPDATE_FIRST_CHECK: Duration = Duration::from_secs(60);
const UPDATE_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const UPDATE_IDLE_POLL: Duration = Duration::from_secs(30);

pub struct HostOptions {
    pub bind: SocketAddr,
    pub name: String,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub encoder: EncoderChoice,
}

struct PendingPairing {
    code: PairingCode,
    expires: Instant,
}

struct Shared {
    options: HostOptions,
    state: StateDir,
    input: InputHandle,
    pairing: Mutex<Option<PendingPairing>>,
    active: Mutex<Option<quinn::Connection>>,
}

/// Runs until the endpoint fails, or until an update was installed and the host is idle;
/// then returns `true` so the caller restarts into the new version.
pub async fn run(
    options: HostOptions,
    state: StateDir,
    pairing: Option<(PairingCode, Duration)>,
    auto_update: bool,
) -> Result<bool> {
    let identity = state.load_or_create_identity()?;
    let endpoint = quinn::Endpoint::server(tls::server_config(&identity)?, options.bind)
        .with_context(|| format!("binding {}", options.bind))?;
    tracing::info!(
        "host '{}' {} listening on {} (fingerprint {})",
        options.name,
        velora_update::Version::current(),
        endpoint.local_addr()?,
        identity.fingerprint()
    );

    let shared = Arc::new(Shared {
        options,
        state,
        input: crate::input::spawn(),
        pairing: Mutex::new(pairing.map(|(code, ttl)| PendingPairing { code, expires: Instant::now() + ttl })),
        active: Mutex::new(None),
    });

    let updated = async {
        if auto_update {
            update_loop(&shared).await
        } else {
            std::future::pending().await
        }
    };
    tokio::pin!(updated);

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { return Ok(false) };
                let shared = shared.clone();
                tokio::spawn(async move {
                    let remote = incoming.remote_address();
                    if let Err(e) = handle_connection(incoming, shared).await {
                        tracing::info!("connection from {remote} ended: {e:#}");
                    }
                });
            }
            () = &mut updated => {
                // Release the UDP port before the new version binds it.
                endpoint.close(0u32.into(), b"host is updating");
                endpoint.wait_idle().await;
                return Ok(true);
            }
        }
    }
}

/// Periodically installs new releases; resolves once one is installed and nobody is using
/// the host (no session, no open pairing window).
async fn update_loop(shared: &Shared) {
    let mut delay = UPDATE_FIRST_CHECK;
    loop {
        tokio::time::sleep(delay).await;
        delay = UPDATE_INTERVAL;
        match tokio::task::spawn_blocking(velora_update::update_now).await {
            Ok(Ok(Some(version))) => {
                tracing::info!("installed version {version}; restarting when idle");
                break;
            }
            Ok(Ok(None)) => tracing::debug!("up to date"),
            Ok(Err(e)) => tracing::warn!("update check failed: {e:#}"),
            Err(e) => tracing::warn!("update task failed: {e}"),
        }
    }
    loop {
        let pairing_open = shared.pairing.lock().unwrap().as_ref().is_some_and(|p| p.expires > Instant::now());
        if shared.active.lock().unwrap().is_none() && !pairing_open {
            return;
        }
        tokio::time::sleep(UPDATE_IDLE_POLL).await;
    }
}

async fn handle_connection(incoming: quinn::Incoming, shared: Arc<Shared>) -> Result<()> {
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await.context("handshake timeout")??;
    let fingerprint = tls::peer_fingerprint(&conn)?;

    let (mut send, mut recv) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.accept_bi()).await.context("no control stream")??;
    let body = tokio::time::timeout(HANDSHAKE_TIMEOUT, wire::read_msg(&mut recv))
        .await
        .context("no hello")??
        .context("closed before hello")?;
    let ClientMsg::Hello { version, name, pairing_secret } = ClientMsg::decode(&body)? else {
        bail!("expected hello");
    };
    // Shown in logs and stored in the paired list: strip control characters.
    let name: String = name.chars().filter(|c| !c.is_control()).collect();

    let reject = |reason: &str| HostMsg::Rejected { reason: reason.into() }.encode();
    if version != PROTOCOL_VERSION {
        send.write_all(&reject("incompatible protocol version")).await?;
        let _ = send.finish();
        let _ = send.stopped().await;
        bail!("client '{name}' uses protocol {version}");
    }

    match authorize(&shared, fingerprint, &name, pairing_secret)? {
        Auth::Known => {}
        Auth::Paired => send.write_all(&HostMsg::Paired.encode()).await?,
        Auth::Denied => {
            send.write_all(&reject("this device is not paired with the host")).await?;
            let _ = send.finish();
            let _ = send.stopped().await;
            bail!("unauthorized client '{name}' ({fingerprint})");
        }
    }
    tracing::info!("client '{name}' ({fingerprint}) connected from {}", conn.remote_address());

    // A newly connected device takes over: switching from the phone to a PC should just work.
    if let Some(old) = shared.active.lock().unwrap().replace(conn.clone()) {
        old.close(1u32.into(), b"another device took over");
    }

    let result = run_session(&conn, send, recv, &shared).await;

    shared.input.send(InputCmd::ReleaseAll);
    let mut active = shared.active.lock().unwrap();
    if active.as_ref().is_some_and(|c| c.stable_id() == conn.stable_id()) {
        *active = None;
    }
    result
}

enum Auth {
    Known,
    Paired,
    Denied,
}

fn authorize(
    shared: &Shared,
    fingerprint: Fingerprint,
    name: &str,
    secret: Option<[u8; wire::PAIRING_SECRET_LEN]>,
) -> Result<Auth> {
    let fp = fingerprint.to_base64();
    // Re-read on every connection so `velora-host revoke` applies without a restart.
    let mut clients: Vec<AuthorizedClient> = shared.state.load(StateDir::AUTHORIZED_CLIENTS)?;
    if clients.iter().any(|c| c.fingerprint == fp) {
        return Ok(Auth::Known);
    }
    let Some(secret) = secret else { return Ok(Auth::Denied) };

    let mut pairing = shared.pairing.lock().unwrap();
    let valid = pairing.as_ref().is_some_and(|p| p.expires > Instant::now() && p.code.secret_matches(&secret));
    if !valid {
        return Ok(Auth::Denied);
    }
    // Single use.
    *pairing = None;
    clients.push(AuthorizedClient {
        name: name.to_string(),
        fingerprint: fp,
        added_unix: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
    });
    shared.state.save(StateDir::AUTHORIZED_CLIENTS, &clients)?;
    tracing::info!("paired new client '{name}' ({fingerprint})");
    Ok(Auth::Paired)
}

/// State shared between the capture thread and the network tasks of one session.
struct Session {
    running: AtomicBool,
    keyframe_requested: AtomicBool,
    in_flight: AtomicU32,
    max_in_flight: AtomicU32,
    last_ack: Mutex<Instant>,
    stats: Mutex<Stats>,
}

struct OutFrame {
    id: u32,
    keyframe: bool,
    width: u16,
    height: u16,
    captured: Instant,
    data: Vec<u8>,
}

impl Session {
    /// Saturating decrement: the counter may have been reset by the stall guard.
    fn ack_frame(&self) {
        let mut n = self.in_flight.load(Ordering::Acquire);
        while n > 0 {
            match self.in_flight.compare_exchange_weak(n, n - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(actual) => n = actual,
            }
        }
    }
}

async fn run_session(
    conn: &quinn::Connection,
    mut control_send: quinn::SendStream,
    mut control_recv: quinn::RecvStream,
    shared: &Arc<Shared>,
) -> Result<()> {
    let opts = &shared.options;
    let session = Arc::new(Session {
        running: AtomicBool::new(true),
        keyframe_requested: AtomicBool::new(true),
        in_flight: AtomicU32::new(0),
        max_in_flight: AtomicU32::new(MIN_IN_FLIGHT + 1),
        last_ack: Mutex::new(Instant::now()),
        stats: Mutex::new(Stats::default()),
    });

    let (frame_tx, mut frame_rx) = mpsc::channel::<OutFrame>(4);
    let (ready_tx, ready_rx) = oneshot::channel();
    {
        let session = session.clone();
        let input = shared.input.clone();
        let settings = EncoderSettings { fps: opts.fps, bitrate_kbps: opts.bitrate_kbps };
        let choice = opts.encoder.clone();
        std::thread::Builder::new().name("capture".into()).spawn(move || {
            if let Err(e) = capture_loop(&session, &choice, settings, frame_tx, ready_tx, &input) {
                tracing::error!("capture stopped: {e:#}");
            }
            session.running.store(false, Ordering::Relaxed);
        })?;
    }
    let rect = match ready_rx.await.context("capture thread exited")? {
        Ok(rect) => rect,
        Err(e) => {
            // Tell the client why instead of just dropping the connection.
            let reason = format!("host cannot stream: {e:#}");
            control_send.write_all(&HostMsg::Rejected { reason }.encode()).await?;
            let _ = control_send.finish();
            let _ = control_send.stopped().await;
            return Err(e);
        }
    };

    control_send
        .write_all(
            &HostMsg::Welcome {
                version: PROTOCOL_VERSION,
                host_name: opts.name.clone(),
                codec: Codec::H264,
                width: (rect.width & !1) as u16,
                height: (rect.height & !1) as u16,
            }
            .encode(),
        )
        .await?;

    let video = async {
        while let Some(frame) = frame_rx.recv().await {
            let header =
                FrameHeader { frame_id: frame.id, keyframe: frame.keyframe, width: frame.width, height: frame.height };
            session.stats.lock().unwrap().sent(frame.id, frame.captured, frame.data.len());
            let mut stream = conn.open_uni().await?;
            stream.write_all(&header.encode()).await?;
            stream.write_all(&frame.data).await?;
            stream.finish()?;
        }
        anyhow::Ok(())
    };

    let control = async {
        while let Some(body) = wire::read_msg(&mut control_recv).await? {
            match ClientMsg::decode(&body)? {
                ClientMsg::Key { code, state } => shared.input.send(InputCmd::Key { code, state }),
                ClientMsg::MouseButton { button, down, x, y } => {
                    shared.input.send(InputCmd::Button { button, down, x, y })
                }
                ClientMsg::Scroll { dx, dy } => shared.input.send(InputCmd::Scroll { dx, dy }),
                ClientMsg::ReleaseAll => shared.input.send(InputCmd::ReleaseAll),
                ClientMsg::RequestKeyframe => session.keyframe_requested.store(true, Ordering::Relaxed),
                ClientMsg::FrameAck { frame_id } => {
                    session.ack_frame();
                    *session.last_ack.lock().unwrap() = Instant::now();
                    session.stats.lock().unwrap().acked(frame_id);
                }
                ClientMsg::Text { text } => shared.input.send(InputCmd::Text(text)),
                ClientMsg::Unsupported { tag } => tracing::debug!("ignoring unsupported message {tag}"),
                ClientMsg::Hello { .. } => bail!("unexpected hello"),
            }
        }
        anyhow::Ok(())
    };

    let pointer = async {
        let mut last_seq = 0u32;
        loop {
            let datagram = conn.read_datagram().await?;
            let Ok(m) = MouseMove::decode(&datagram) else { continue };
            if m.is_newer_than(last_seq) {
                last_seq = m.seq;
                shared.input.send(InputCmd::Move { x: m.x, y: m.y });
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };

    let monitor = async {
        let frame_interval = Duration::from_secs_f64(1.0 / opts.fps as f64);
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut last_log = Instant::now();
        while session.running.load(Ordering::Relaxed) {
            tick.tick().await;
            let rtt = conn.rtt();
            let budget = (rtt.as_secs_f64() / frame_interval.as_secs_f64()).ceil() as u32 + MIN_IN_FLIGHT;
            session.max_in_flight.store(budget.clamp(MIN_IN_FLIGHT, MAX_IN_FLIGHT), Ordering::Relaxed);
            if last_log.elapsed() >= STATS_INTERVAL {
                let elapsed = last_log.elapsed();
                last_log = Instant::now();
                session.stats.lock().unwrap().log(elapsed, rtt);
            }
        }
        anyhow::Ok(())
    };

    let result = tokio::select! {
        r = video => r,
        r = control => r,
        r = pointer => r,
        r = monitor => r,
        e = conn.closed() => Err(e.into()),
    };
    session.running.store(false, Ordering::Relaxed);
    result
}

fn capture_loop(
    session: &Session,
    choice: &EncoderChoice,
    settings: EncoderSettings,
    frames: mpsc::Sender<OutFrame>,
    ready: oneshot::Sender<Result<DisplayRect>>,
    input: &InputHandle,
) -> Result<()> {
    let setup = || -> Result<_> {
        let capturer = capture::open()?;
        let rect = capturer.rect();
        let encoder = encode::open(choice, settings, rect.width, rect.height)?;
        tracing::info!("encoder: {}", encoder.name());
        Ok((capturer, encoder))
    };
    let (mut capturer, mut encoder) = match setup() {
        Ok(v) => v,
        Err(e) => {
            let _ = ready.send(Err(anyhow::anyhow!("{e:#}")));
            return Err(e);
        }
    };
    let mut rect = capturer.rect();
    input.send(InputCmd::SetDisplay(rect));
    let _ = ready.send(Ok(rect));

    let interval = Duration::from_secs_f64(1.0 / settings.fps.max(1) as f64);
    let mut have_picture = false;
    let mut next_id = 0u32;
    let mut last_capture = Instant::now() - interval;

    while session.running.load(Ordering::Relaxed) {
        // Never capture faster than the target frame rate.
        let since = last_capture.elapsed();
        if since < interval {
            std::thread::sleep(interval - since);
        }

        let in_flight = session.in_flight.load(Ordering::Acquire);
        if in_flight >= session.max_in_flight.load(Ordering::Relaxed) {
            if session.last_ack.lock().unwrap().elapsed() > ACK_STALL_RESET {
                tracing::warn!("no frame acks for {ACK_STALL_RESET:?}, resetting flow control");
                session.in_flight.store(0, Ordering::Release);
                *session.last_ack.lock().unwrap() = Instant::now();
            } else {
                session.stats.lock().unwrap().throttled += 1;
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
        }

        let keyframe = session.keyframe_requested.load(Ordering::Relaxed);
        // Block until the screen changes (bounded so shutdown and keyframe requests are
        // noticed), but return immediately when a keyframe of an unchanged screen is due.
        let timeout = if keyframe && have_picture { Duration::ZERO } else { Duration::from_millis(100) };
        let frame = capturer.capture(timeout)?;
        let changed = frame.is_some();
        let captured_at = Instant::now();
        last_capture = captured_at;
        if !changed && !(keyframe && have_picture) {
            continue;
        }
        have_picture = true;

        session.keyframe_requested.store(false, Ordering::Relaxed);
        let encode_start = Instant::now();
        let encoded = encoder.encode(frame.as_ref(), keyframe)?;
        {
            let mut stats = session.stats.lock().unwrap();
            stats.convert_time += encoded.convert_time;
            stats.encode_time += encode_start.elapsed() - encoded.convert_time;
        }

        if capturer.rect() != rect {
            rect = capturer.rect();
            input.send(InputCmd::SetDisplay(rect));
        }

        for encoded in encoded.frames {
            session.in_flight.fetch_add(1, Ordering::AcqRel);
            let frame = OutFrame {
                id: next_id,
                keyframe: encoded.keyframe,
                width: encoded.width,
                height: encoded.height,
                captured: captured_at,
                data: encoded.data,
            };
            next_id = next_id.wrapping_add(1);
            if frames.blocking_send(frame).is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct Stats {
    pending: VecDeque<(u32, Instant)>,
    frames: u32,
    bytes: u64,
    throttled: u32,
    convert_time: Duration,
    encode_time: Duration,
    latency_sum: Duration,
    latency_max: Duration,
    acked: u32,
}

impl Stats {
    fn sent(&mut self, id: u32, captured: Instant, bytes: usize) {
        self.frames += 1;
        self.bytes += bytes as u64;
        self.pending.push_back((id, captured));
        if self.pending.len() > 256 {
            self.pending.pop_front();
        }
    }

    fn acked(&mut self, id: u32) {
        while let Some(&(pending, captured)) = self.pending.front() {
            self.pending.pop_front();
            if pending == id {
                let latency = captured.elapsed();
                self.latency_sum += latency;
                self.latency_max = self.latency_max.max(latency);
                self.acked += 1;
                break;
            }
        }
    }

    fn log(&mut self, elapsed: Duration, rtt: Duration) {
        let secs = elapsed.as_secs_f64();
        let per_frame = |d: Duration, n: u32| if n == 0 { 0.0 } else { d.as_secs_f64() * 1000.0 / n as f64 };
        tracing::info!(
            "video: {:.1} fps, {:.2} Mbit/s, convert {:.1} ms, encode {:.1} ms, capture->client {:.1} ms (max {:.1}), rtt {:.1} ms, throttled {}",
            self.frames as f64 / secs,
            self.bytes as f64 * 8.0 / secs / 1e6,
            per_frame(self.convert_time, self.frames),
            per_frame(self.encode_time, self.frames),
            per_frame(self.latency_sum, self.acked),
            self.latency_max.as_secs_f64() * 1000.0,
            rtt.as_secs_f64() * 1000.0,
            self.throttled,
        );
        let pending = std::mem::take(&mut self.pending);
        *self = Self { pending, ..Self::default() };
    }
}
