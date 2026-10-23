//! Video encoding: hardware encoders through FFmpeg (cargo feature `ffmpeg`) and OpenH264 as
//! the always-available software fallback.

#[cfg(any(feature = "ffmpeg", test))]
mod bitstream;
mod convert;
#[cfg(all(windows, feature = "ffmpeg"))]
mod d3d11;
#[cfg(feature = "ffmpeg")]
mod ffmpeg;
mod openh264;

use std::{str::FromStr, time::Duration};

use anyhow::Result;

use crate::capture::Frame;

pub struct EncodedFrame {
    pub keyframe: bool,
    pub width: u16,
    pub height: u16,
    /// Annex-B bitstream.
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct Encoded {
    /// Usually one frame; zero while a pipelined encoder is still busy, more when it catches up.
    pub frames: Vec<EncodedFrame>,
    pub convert_time: Duration,
}

pub trait VideoEncoder {
    fn name(&self) -> &str;

    /// Encodes `frame`, or re-encodes the previous picture when `None` (keyframe requested
    /// while the screen is unchanged).
    fn encode(&mut self, frame: Option<&Frame>, keyframe: bool) -> Result<Encoded>;

    /// Changes the target bitrate from the next frame on, without a keyframe. False when the
    /// encoder cannot: then it has to be opened again.
    fn set_bitrate(&mut self, kbps: u32) -> bool;

    /// Takes frames on the capture's GPU ([`Frame::texture`]) rather than in memory.
    fn on_gpu(&self) -> bool {
        false
    }
}

/// The GPU device a capture leaves its frames on, for encoders that can take them there.
#[cfg(windows)]
pub type GpuDevice = windows::Win32::Graphics::Direct3D11::ID3D11Device;
#[cfg(not(windows))]
pub type GpuDevice = ();

/// Whether hardware encoders may take frames on the GPU. `VELORA_ZERO_COPY=0` turns it off.
pub fn zero_copy() -> bool {
    std::env::var("VELORA_ZERO_COPY").map_or(true, |v| v != "0")
}

#[derive(Debug, Clone, Copy)]
pub struct EncoderSettings {
    pub fps: u32,
    pub bitrate_kbps: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderChoice {
    /// First hardware encoder that opens, else software.
    Auto,
    Software,
    /// An FFmpeg encoder by name, e.g. `h264_nvenc`.
    Ffmpeg(String),
}

impl FromStr for EncoderChoice {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "auto" => Self::Auto,
            "software" => Self::Software,
            "nvenc" => Self::Ffmpeg("h264_nvenc".into()),
            "qsv" => Self::Ffmpeg("h264_qsv".into()),
            "amf" => Self::Ffmpeg("h264_amf".into()),
            "vaapi" => Self::Ffmpeg("h264_vaapi".into()),
            _ => match s.strip_prefix("ffmpeg:") {
                Some(name) if !name.is_empty() => Self::Ffmpeg(name.into()),
                _ => return Err("expected auto, software, nvenc, qsv, amf, vaapi or ffmpeg:<encoder>".into()),
            },
        })
    }
}

/// Hardware encoders tried by `auto`, in order of preference.
#[cfg(feature = "ffmpeg")]
const HARDWARE: &[&str] =
    if cfg!(windows) { &["h264_nvenc", "h264_amf", "h264_qsv"] } else { &["h264_nvenc", "h264_vaapi", "h264_qsv"] };

/// Opens the encoder `choice` names. With `gpu` (the capture's device), hardware encoders take
/// frames there when they can (see [`VideoEncoder::on_gpu`]).
pub fn open(
    choice: &EncoderChoice,
    settings: EncoderSettings,
    width: u32,
    height: u32,
    #[allow(unused_variables)] gpu: Option<&GpuDevice>,
) -> Result<Box<dyn VideoEncoder>> {
    let encoder: Box<dyn VideoEncoder> = match choice {
        EncoderChoice::Software => Box::new(openh264::Software::new(settings)?),
        #[cfg(feature = "ffmpeg")]
        EncoderChoice::Ffmpeg(name) => Box::new(ffmpeg::Ffmpeg::open(name, settings, width, height, gpu)?),
        #[cfg(not(feature = "ffmpeg"))]
        EncoderChoice::Ffmpeg(name) => anyhow::bail!("encoder '{name}' needs a build with the `ffmpeg` feature"),
        EncoderChoice::Auto => {
            #[cfg(feature = "ffmpeg")]
            for name in HARDWARE {
                match ffmpeg::Ffmpeg::probe(name, settings, width, height, gpu) {
                    Ok(e) => return Ok(Box::new(e)),
                    Err(e) => tracing::debug!("{name} unavailable: {e:#}"),
                }
            }
            #[cfg(not(feature = "ffmpeg"))]
            let _ = (width, height);
            Box::new(openh264::Software::new(settings)?)
        }
    };
    Ok(encoder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_encoder_choices() {
        assert_eq!("auto".parse(), Ok(EncoderChoice::Auto));
        assert_eq!("nvenc".parse(), Ok(EncoderChoice::Ffmpeg("h264_nvenc".into())));
        assert_eq!("ffmpeg:libx264".parse(), Ok(EncoderChoice::Ffmpeg("libx264".into())));
        assert!("ffmpeg:".parse::<EncoderChoice>().is_err());
        assert!("bogus".parse::<EncoderChoice>().is_err());
    }
}
