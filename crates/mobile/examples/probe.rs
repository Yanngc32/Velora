//! Exercises the exported API like an app would, against a running host:
//! `probe <config-dir> pair <address> <code> [seconds]` or `probe <config-dir> connect <host> [seconds]`.
//! Frames are decoded in software to check they arrive valid and in order.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use velora_mobile::{Client, Session, SessionListener, VideoFrame};

struct Probe {
    session: OnceLock<Arc<Session>>,
    decoder: Mutex<openh264::decoder::Decoder>,
    stats: Mutex<(u32, u32, u32)>, // frames, decoded pictures, errors
}

impl SessionListener for Probe {
    fn on_video_frame(&self, frame: VideoFrame) {
        let decoded = self.decoder.lock().unwrap().decode(&frame.data).map(|p| p.is_some());
        let mut s = self.stats.lock().unwrap();
        s.0 += 1;
        match decoded {
            Ok(true) => s.1 += 1,
            Ok(false) => {}
            Err(_) => s.2 += 1,
        }
        // Rendered: acknowledge so the host keeps sending.
        self.session.get().expect("session set before start").frame_done(frame.frame_id);
    }

    fn on_closed(&self, reason: String) {
        println!("closed: {reason}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let client = Client::new(args[1].clone(), "probe".into()).unwrap();
    let (session, seconds) = match args[2].as_str() {
        "pair" => (client.pair(args[3].clone(), args[4].clone()).unwrap(), args.get(5)),
        _ => (client.connect(args[3].clone()).unwrap(), args.get(4)),
    };
    let seconds: u64 = seconds.and_then(|s| s.parse().ok()).unwrap_or(5);
    println!("connected to {} ({}x{})", session.host_name(), session.width(), session.height());

    let probe = Arc::new(Probe {
        session: OnceLock::new(),
        decoder: Mutex::new(openh264::decoder::Decoder::new().unwrap()),
        stats: Mutex::new((0, 0, 0)),
    });
    probe.session.set(session.clone()).ok().unwrap();
    session.start(probe.clone());

    // Exercise input and text paths.
    session.mouse_move(32768, 32768);
    session.text("ação".into());
    std::thread::sleep(Duration::from_secs(seconds));
    let (frames, pictures, errors) = *probe.stats.lock().unwrap();
    println!(
        "{frames} frames ({:.1} fps), {pictures} decoded, {errors} decode errors, rtt {:.1} ms, hosts: {:?}",
        frames as f64 / seconds as f64,
        session.rtt_ms(),
        client.hosts().unwrap().iter().map(|h| h.name.clone()).collect::<Vec<_>>()
    );
    session.disconnect();
}
