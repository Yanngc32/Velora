//! Platform-independent client: connection, authentication, input sending and video
//! delivery. UIs only draw frames and feed input: the desktop gets decoded RGB pictures,
//! mobile apps get the H.264 stream in order and decode it in hardware.

pub mod hosts;
mod reorder;
#[cfg(feature = "decode")]
mod video;

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context, Result};
use sm_protocol::{
    identity::Identity,
    tls::{self, Fingerprint},
    wire::{self, ClientMsg, FrameHeader, HostMsg, KeyState, MouseButton, MouseMove, PROTOCOL_VERSION},
};
use tokio::sync::mpsc;

#[cfg(feature = "decode")]
pub use video::{FrameSlot, VideoFrame};

/// An encoded frame, delivered in order. Acknowledge it with [`InputSender::frame_done`] once
/// it has been displayed: that is what paces the host.
pub struct EncodedFrame {
    pub frame_id: u32,
    pub keyframe: bool,
    pub width: u16,
    pub height: u16,
    /// H.264 Annex-B access unit.
    pub data: Vec<u8>,
}

pub enum VideoOutput {
    /// Decode in software into `slot`; `on_frame` runs (on the decoder thread) after each new
    /// picture, e.g. to request a redraw. Frames are acknowledged automatically.
    #[cfg(feature = "decode")]
    Decoded { slot: Arc<FrameSlot>, on_frame: Arc<dyn Fn() + Send + Sync> },
    /// Hand encoded frames, in order, to the caller's decoder.
    Encoded(Arc<dyn Fn(EncodedFrame) + Send + Sync>),
}

pub struct ConnectParams {
    pub addr: SocketAddr,
    pub host_fingerprint: Fingerprint,
    pub identity: Identity,
    pub device_name: String,
    /// Set when pairing for the first time.
    pub pairing_secret: Option<[u8; wire::PAIRING_SECRET_LEN]>,
}

pub struct Session {
    pub host_name: String,
    /// The host accepted the pairing secret and stored this device.
    pub newly_paired: bool,
    pub width: u16,
    pub height: u16,
    pub input: InputSender,
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl Session {
    /// Resolves when the connection ends, with the reason.
    pub async fn closed(&self) -> String {
        match self.conn.closed().await {
            quinn::ConnectionError::ApplicationClosed(c) => String::from_utf8_lossy(&c.reason).into_owned(),
            e => e.to_string(),
        }
    }

    pub fn rtt(&self) -> std::time::Duration {
        self.conn.rtt()
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"client closed");
    }
}

/// Connects, authenticates and starts delivering video to `output`.
pub async fn connect(params: ConnectParams, output: VideoOutput) -> Result<Session> {
    let bind: SocketAddr = if params.addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(tls::client_config(&params.identity, params.host_fingerprint)?);

    let conn = endpoint
        .connect(params.addr, tls::SERVER_NAME)?
        .await
        .context("could not establish a secure connection (wrong address or host fingerprint changed?)")?;

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(
        &ClientMsg::Hello {
            version: PROTOCOL_VERSION,
            name: params.device_name,
            pairing_secret: params.pairing_secret,
        }
        .encode(),
    )
    .await?;

    let mut newly_paired = false;
    let (host_name, width, height) = loop {
        let body = wire::read_msg(&mut recv).await?.context("host closed the connection")?;
        match HostMsg::decode(&body)? {
            HostMsg::Paired => newly_paired = true,
            HostMsg::Welcome { version, host_name, width, height, .. } => {
                if version != PROTOCOL_VERSION {
                    bail!("host uses protocol version {version}, expected {PROTOCOL_VERSION}");
                }
                break (host_name, width, height);
            }
            HostMsg::Rejected { reason } => bail!("host rejected the connection: {reason}"),
        }
    };

    let (control_tx, mut control_rx) = mpsc::unbounded_channel::<ClientMsg>();
    tokio::spawn(async move {
        while let Some(msg) = control_rx.recv().await {
            if send.write_all(&msg.encode()).await.is_err() {
                break;
            }
        }
    });
    // Keep reading so a host-side close is noticed; no further host messages are defined yet.
    tokio::spawn(async move { while let Ok(Some(_)) = wire::read_msg(&mut recv).await {} });

    let decoder = match output {
        #[cfg(feature = "decode")]
        VideoOutput::Decoded { slot, on_frame } => video::spawn_decoder(slot, control_tx.clone(), on_frame),
        VideoOutput::Encoded(sink) => spawn_encoded(sink, control_tx.clone()),
    };
    {
        let conn = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = conn.accept_uni().await {
                let decoder = decoder.clone();
                tokio::spawn(async move {
                    let mut header = [0u8; FrameHeader::LEN];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let Ok(data) = stream.read_to_end(wire::MAX_FRAME_BYTES).await else { return };
                    let _ = decoder.send(reorder::Packet { header: FrameHeader::decode(&header), data });
                });
            }
        });
    }

    Ok(Session {
        host_name,
        newly_paired,
        width,
        height,
        input: InputSender { conn: conn.clone(), control: control_tx, seq: Arc::new(AtomicU32::new(0)) },
        conn,
        _endpoint: endpoint,
    })
}

/// Thread-safe, non-blocking input sink. Coordinates are normalized to `0..=65535` over the
/// remote display.
#[derive(Clone)]
pub struct InputSender {
    conn: quinn::Connection,
    control: mpsc::UnboundedSender<ClientMsg>,
    seq: Arc<AtomicU32>,
}

impl InputSender {
    /// Sent as an unreliable datagram: a lost position is superseded by the next one.
    pub fn mouse_move(&self, x: u16, y: u16) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let datagram = MouseMove { seq, x, y }.encode();
        let _ = self.conn.send_datagram(bytes::Bytes::copy_from_slice(&datagram));
    }

    pub fn mouse_button(&self, button: MouseButton, down: bool, x: u16, y: u16) {
        self.send(ClientMsg::MouseButton { button, down, x, y });
    }

    /// `code` is a Linux evdev key code.
    pub fn key(&self, code: u16, state: KeyState) {
        self.send(ClientMsg::Key { code, state });
    }

    /// 120 units per wheel notch; positive `dy` scrolls up, positive `dx` scrolls right.
    pub fn scroll(&self, dx: i16, dy: i16) {
        self.send(ClientMsg::Scroll { dx, dy });
    }

    pub fn release_all(&self) {
        self.send(ClientMsg::ReleaseAll);
    }

    pub fn request_keyframe(&self) {
        self.send(ClientMsg::RequestKeyframe);
    }

    /// Types text on the host (layout-independent), for soft keyboards that produce
    /// characters rather than key presses.
    pub fn text(&self, text: &str) {
        for chunk in wire::split_text(text) {
            self.send(ClientMsg::Text { text: chunk.to_string() });
        }
    }

    /// Acknowledges a frame delivered through [`VideoOutput::Encoded`] once it is on screen.
    pub fn frame_done(&self, frame_id: u32) {
        self.send(ClientMsg::FrameAck { frame_id });
    }

    fn send(&self, msg: ClientMsg) {
        let _ = self.control.send(msg);
    }
}

/// Delivers encoded frames in order. After a gap (only possible if frames were lost), frames
/// are dropped and acknowledged until the next keyframe, which is requested.
fn spawn_encoded(
    sink: Arc<dyn Fn(EncodedFrame) + Send + Sync>,
    control: mpsc::UnboundedSender<ClientMsg>,
) -> std::sync::mpsc::Sender<reorder::Packet> {
    let (tx, rx) = std::sync::mpsc::channel::<reorder::Packet>();
    std::thread::Builder::new()
        .name("video".into())
        .spawn(move || {
            let mut reorder = reorder::Reorder::default();
            let mut need_keyframe = false;
            for packet in rx {
                let (ready, resynced) = reorder.push(packet);
                if resynced {
                    need_keyframe = true;
                    let _ = control.send(ClientMsg::RequestKeyframe);
                }
                for p in ready {
                    let h = p.header;
                    if need_keyframe && !h.keyframe {
                        let _ = control.send(ClientMsg::FrameAck { frame_id: h.frame_id });
                        continue;
                    }
                    need_keyframe = false;
                    sink(EncodedFrame {
                        frame_id: h.frame_id,
                        keyframe: h.keyframe,
                        width: h.width,
                        height: h.height,
                        data: p.data,
                    });
                }
            }
        })
        .expect("spawning video thread");
    tx
}
