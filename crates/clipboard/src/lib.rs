//! The clipboard shared during a session: text and images, in both directions.
//!
//! Each side watches its own clipboard and sends what changes; what arrives from the other side
//! is put on the clipboard and remembered, so it is not sent straight back. Images travel as
//! PNG, which keeps screenshots small.

use std::{
    borrow::Cow,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use anyhow::{bail, ensure, Context, Result};

/// Largest clip sent or accepted, encoded.
pub const MAX_CLIP_BYTES: u64 = 32 * 1024 * 1024;

/// Kind byte of an encoded clip.
pub const TEXT: u8 = 1;
pub const PNG: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Clip {
    Text(String),
    /// Straight RGBA, rows top to bottom.
    Image {
        width: u32,
        height: u32,
        rgba: Vec<u8>,
    },
}

impl Clip {
    /// The kind byte and the bytes to send.
    pub fn encode(&self) -> Result<(u8, Vec<u8>)> {
        match self {
            Self::Text(text) => Ok((TEXT, text.as_bytes().to_vec())),
            Self::Image { width, height, rgba } => {
                let mut out = Vec::new();
                let mut encoder = png::Encoder::new(&mut out, *width, *height);
                encoder.set_color(png::ColorType::Rgba);
                encoder.set_depth(png::BitDepth::Eight);
                encoder.set_compression(png::Compression::Fast);
                encoder.write_header()?.write_image_data(rgba)?;
                Ok((PNG, out))
            }
        }
    }

    pub fn decode(kind: u8, bytes: &[u8]) -> Result<Self> {
        match kind {
            TEXT => Ok(Self::Text(String::from_utf8(bytes.to_vec()).context("clipboard text is not UTF-8")?)),
            PNG => {
                let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
                decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
                let mut reader = decoder.read_info()?;
                let mut buf = vec![0; reader.output_buffer_size().context("image too large")?];
                let info = reader.next_frame(&mut buf)?;
                buf.truncate(info.buffer_size());
                let rgba = match info.color_type {
                    png::ColorType::Rgba => buf,
                    png::ColorType::Rgb => {
                        buf.as_chunks::<3>().0.iter().flat_map(|&[r, g, b]| [r, g, b, 255]).collect()
                    }
                    png::ColorType::GrayscaleAlpha => {
                        buf.as_chunks::<2>().0.iter().flat_map(|&[g, a]| [g, g, g, a]).collect()
                    }
                    png::ColorType::Grayscale => buf.iter().flat_map(|&g| [g, g, g, 255]).collect(),
                    other => bail!("unsupported image colors {other:?}"),
                };
                Ok(Self::Image { width: info.width, height: info.height, rgba })
            }
            other => bail!("unknown clipboard content {other}"),
        }
    }

    fn fingerprint(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.hash(&mut h);
        h.finish()
    }
}

/// This computer's clipboard, as one side of the shared one.
pub struct Clipboard {
    inner: arboard::Clipboard,
    /// What was last sent or received, so the same content is not sent twice.
    known: Option<u64>,
    /// Windows' clipboard change counter when last looked at: nothing is read while it holds.
    #[cfg(windows)]
    sequence: u32,
}

impl Clipboard {
    /// Opens the clipboard. What is on it now counts as known: only later copies are sent.
    pub fn new() -> Result<Self> {
        let mut this = Self {
            inner: arboard::Clipboard::new().context("opening the clipboard")?,
            known: None,
            #[cfg(windows)]
            sequence: 0,
        };
        this.known = this.read().map(|c| c.fingerprint());
        #[cfg(windows)]
        {
            this.sequence = sequence();
        }
        Ok(this)
    }

    /// What was copied here since the last call (or since content arrived), if anything.
    pub fn changed(&mut self) -> Option<Clip> {
        #[cfg(windows)]
        {
            let now = sequence();
            if now == self.sequence {
                return None;
            }
            self.sequence = now;
        }
        let clip = self.read()?;
        let fingerprint = clip.fingerprint();
        if self.known == Some(fingerprint) {
            return None;
        }
        self.known = Some(fingerprint);
        Some(clip)
    }

    /// Puts content from the other side on the clipboard.
    pub fn set(&mut self, clip: &Clip) -> Result<()> {
        match clip {
            Clip::Text(text) => self.inner.set_text(text.as_str())?,
            Clip::Image { width, height, rgba } => {
                let expected = *width as usize * *height as usize * 4;
                ensure!(rgba.len() == expected, "image size does not match its dimensions");
                self.inner.set_image(arboard::ImageData {
                    width: *width as usize,
                    height: *height as usize,
                    bytes: Cow::Borrowed(rgba),
                })?
            }
        }
        self.known = Some(clip.fingerprint());
        #[cfg(windows)]
        {
            self.sequence = sequence();
        }
        Ok(())
    }

    /// Text if there is some, else an image.
    fn read(&mut self) -> Option<Clip> {
        if let Ok(text) = self.inner.get_text() {
            if !text.is_empty() {
                return Some(Clip::Text(text));
            }
        }
        let image = self.inner.get_image().ok()?;
        Some(Clip::Image { width: image.width as u32, height: image.height as u32, rgba: image.bytes.into_owned() })
    }
}

/// How often the clipboard is looked at for something new.
const POLL: std::time::Duration = std::time::Duration::from_millis(400);

/// Shares this computer's clipboard with the other side: a thread owns it, puts on it what is
/// sent to the returned sender, and passes what is copied here to `on_copy`. Ends when the
/// sender is dropped. `None` when there is no clipboard to open.
pub fn spawn(on_copy: impl Fn(Clip) + Send + 'static) -> Option<std::sync::mpsc::Sender<Clip>> {
    let (tx, rx) = std::sync::mpsc::channel::<Clip>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("clipboard".into())
        .spawn(move || {
            let mut clipboard = match Clipboard::new() {
                Ok(c) => {
                    let _ = ready_tx.send(true);
                    c
                }
                Err(e) => {
                    eprintln!("clipboard sharing is off: {e:#}");
                    let _ = ready_tx.send(false);
                    return;
                }
            };
            loop {
                match rx.recv_timeout(POLL) {
                    Ok(clip) => {
                        if let Err(e) = clipboard.set(&clip) {
                            eprintln!("could not paste the other computer's clipboard here: {e:#}");
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if let Some(clip) = clipboard.changed() {
                            on_copy(clip);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        })
        .ok()?;
    ready_rx.recv().unwrap_or(false).then_some(tx)
}

#[cfg(windows)]
fn sequence() -> u32 {
    // SAFETY: plain query.
    unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clips_round_trip() {
        for clip in [
            Clip::Text("olá, área de transferência ✓".into()),
            Clip::Image { width: 2, height: 1, rgba: vec![255, 0, 0, 255, 0, 0, 255, 128] },
        ] {
            let (kind, bytes) = clip.encode().unwrap();
            assert_eq!(Clip::decode(kind, &bytes).unwrap(), clip);
        }
        assert!(Clip::decode(9, b"x").is_err());
    }
}
