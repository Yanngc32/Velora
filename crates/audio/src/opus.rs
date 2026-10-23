//! Opus through libavcodec's libopus: 48 kHz stereo, 20 ms packets, the low-delay mode.

use std::{
    ffi::{c_int, CStr},
    ptr,
    sync::Once,
};

use anyhow::{bail, Result};
use ffmpeg_sys_next as ff;

use crate::{CHANNELS, FRAME, SAMPLE_RATE};

/// FFmpeg logs to stderr on its own; keep only errors.
fn init_logging() {
    static INIT: Once = Once::new();
    // SAFETY: global log level setter.
    INIT.call_once(|| unsafe { ff::av_log_set_level(ff::AV_LOG_ERROR) });
}

fn av_error(code: i32) -> String {
    let mut buf = [0 as std::ffi::c_char; 256];
    // SAFETY: buffer and length are valid; av_strerror always NUL-terminates.
    unsafe {
        ff::av_strerror(code, buf.as_mut_ptr(), buf.len());
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

fn check(code: i32, what: &str) -> Result<i32> {
    if code < 0 {
        bail!("{what}: {}", av_error(code));
    }
    Ok(code)
}

/// The FFmpeg objects of one encoder or decoder, freed on drop.
struct Codec {
    ctx: *mut ff::AVCodecContext,
    frame: *mut ff::AVFrame,
    packet: *mut ff::AVPacket,
}

// SAFETY: each codec is created and used on one thread at a time; the pointers are owned.
unsafe impl Send for Codec {}

impl Codec {
    /// Allocates around `codec`, set up for our sample rate and channels.
    unsafe fn alloc(codec: *const ff::AVCodec) -> Result<Self> {
        // SAFETY: plain FFmpeg allocations; `Drop` frees whatever was made on failure.
        unsafe {
            let this = Self {
                ctx: ff::avcodec_alloc_context3(codec),
                frame: ff::av_frame_alloc(),
                packet: ff::av_packet_alloc(),
            };
            if this.ctx.is_null() || this.frame.is_null() || this.packet.is_null() {
                bail!("out of memory");
            }
            let ctx = &mut *this.ctx;
            ctx.sample_rate = SAMPLE_RATE as c_int;
            ctx.time_base = ff::AVRational { num: 1, den: SAMPLE_RATE as c_int };
            ff::av_channel_layout_default(&mut ctx.ch_layout, CHANNELS as c_int);
            Ok(this)
        }
    }
}

impl Drop for Codec {
    fn drop(&mut self) {
        // SAFETY: the pointers are owned and freed once; the free functions accept null.
        unsafe {
            ff::av_packet_free(&mut self.packet);
            ff::av_frame_free(&mut self.frame);
            ff::avcodec_free_context(&mut self.ctx);
        }
    }
}

pub struct Encoder {
    codec: Codec,
    pts: i64,
}

impl Encoder {
    pub fn new(bitrate: i64) -> Result<Self> {
        init_logging();
        // SAFETY: FFmpeg setup on objects owned by `codec`.
        unsafe {
            let encoder = ff::avcodec_find_encoder_by_name(c"libopus".as_ptr());
            if encoder.is_null() {
                bail!("FFmpeg has no Opus encoder (libopus)");
            }
            let codec = Codec::alloc(encoder)?;
            let ctx = &mut *codec.ctx;
            ctx.sample_fmt = ff::AVSampleFormat::AV_SAMPLE_FMT_FLT;
            ctx.bit_rate = bitrate;
            let mut options = ptr::null_mut();
            for (key, value) in [(c"application", c"lowdelay"), (c"frame_duration", c"20")] {
                ff::av_dict_set(&mut options, key.as_ptr(), value.as_ptr(), 0);
            }
            let opened = ff::avcodec_open2(codec.ctx, encoder, &mut options);
            ff::av_dict_free(&mut options);
            check(opened, "opening the Opus encoder")?;
            if ctx.frame_size != FRAME as c_int {
                bail!("the Opus encoder wants {} samples a frame", ctx.frame_size);
            }

            let frame = &mut *codec.frame;
            frame.nb_samples = FRAME as c_int;
            frame.format = ff::AVSampleFormat::AV_SAMPLE_FMT_FLT as c_int;
            frame.sample_rate = SAMPLE_RATE as c_int;
            check(ff::av_channel_layout_copy(&mut frame.ch_layout, &ctx.ch_layout), "setting up the audio frame")?;
            check(ff::av_frame_get_buffer(codec.frame, 0), "allocating the audio frame")?;
            Ok(Self { codec, pts: 0 })
        }
    }

    /// Encodes one frame of `FRAME` interleaved stereo samples; adds the packets it yields.
    pub fn encode(&mut self, samples: &[f32], packets: &mut Vec<Vec<u8>>) -> Result<()> {
        debug_assert_eq!(samples.len(), FRAME * CHANNELS);
        // SAFETY: the frame holds `FRAME * CHANNELS` interleaved floats; packets are copied out
        // before being unreferenced.
        unsafe {
            check(ff::av_frame_make_writable(self.codec.frame), "preparing the audio frame")?;
            let frame = &mut *self.codec.frame;
            ptr::copy_nonoverlapping(samples.as_ptr(), frame.data[0] as *mut f32, FRAME * CHANNELS);
            frame.pts = self.pts;
            self.pts += FRAME as i64;
            check(ff::avcodec_send_frame(self.codec.ctx, self.codec.frame), "encoding sound")?;
            loop {
                let ret = ff::avcodec_receive_packet(self.codec.ctx, self.codec.packet);
                if ret == ff::AVERROR(ff::EAGAIN) || ret == ff::AVERROR_EOF {
                    return Ok(());
                }
                check(ret, "encoding sound")?;
                let packet = &*self.codec.packet;
                packets.push(std::slice::from_raw_parts(packet.data, packet.size as usize).to_vec());
                ff::av_packet_unref(self.codec.packet);
            }
        }
    }
}

pub struct Decoder {
    codec: Codec,
}

impl Decoder {
    pub fn new() -> Result<Self> {
        init_logging();
        // SAFETY: FFmpeg setup on objects owned by `codec`.
        unsafe {
            let mut decoder = ff::avcodec_find_decoder_by_name(c"libopus".as_ptr());
            if decoder.is_null() {
                decoder = ff::avcodec_find_decoder(ff::AVCodecID::AV_CODEC_ID_OPUS);
            }
            if decoder.is_null() {
                bail!("FFmpeg has no Opus decoder");
            }
            let codec = Codec::alloc(decoder)?;
            (*codec.ctx).request_sample_fmt = ff::AVSampleFormat::AV_SAMPLE_FMT_FLT;
            check(ff::avcodec_open2(codec.ctx, decoder, ptr::null_mut()), "opening the Opus decoder")?;
            Ok(Self { codec })
        }
    }

    /// Decodes one packet, adding interleaved stereo samples to `out`.
    pub fn decode(&mut self, data: &[u8], out: &mut Vec<f32>) -> Result<()> {
        // SAFETY: the packet gets its own padded copy of `data`; frames are read within the
        // sample counts and plane layout FFmpeg reports, then unreferenced.
        unsafe {
            check(ff::av_new_packet(self.codec.packet, data.len() as c_int), "allocating a packet")?;
            ptr::copy_nonoverlapping(data.as_ptr(), (*self.codec.packet).data, data.len());
            let sent = ff::avcodec_send_packet(self.codec.ctx, self.codec.packet);
            ff::av_packet_unref(self.codec.packet);
            check(sent, "decoding sound")?;
            loop {
                let ret = ff::avcodec_receive_frame(self.codec.ctx, self.codec.frame);
                if ret == ff::AVERROR(ff::EAGAIN) || ret == ff::AVERROR_EOF {
                    return Ok(());
                }
                check(ret, "decoding sound")?;
                let frame = &*self.codec.frame;
                let (n, channels) = (frame.nb_samples as usize, frame.ch_layout.nb_channels.max(1) as usize);
                let sample = |c: usize, i: usize| -> f32 {
                    let c = c.min(channels - 1);
                    match frame.format {
                        f if f == ff::AVSampleFormat::AV_SAMPLE_FMT_FLT as c_int => {
                            *(frame.data[0] as *const f32).add(i * channels + c)
                        }
                        f if f == ff::AVSampleFormat::AV_SAMPLE_FMT_FLTP as c_int => {
                            *(frame.data[c] as *const f32).add(i)
                        }
                        f if f == ff::AVSampleFormat::AV_SAMPLE_FMT_S16 as c_int => {
                            *(frame.data[0] as *const i16).add(i * channels + c) as f32 / 32768.0
                        }
                        _ => 0.0,
                    }
                };
                out.reserve(n * CHANNELS);
                for i in 0..n {
                    for c in 0..CHANNELS {
                        out.push(sample(c, i));
                    }
                }
                ff::av_frame_unref(self.codec.frame);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rms(samples: &[f32]) -> f32 {
        (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
    }

    #[test]
    fn a_tone_survives_encoding() {
        let mut encoder = Encoder::new(96_000).unwrap();
        let mut decoder = Decoder::new().unwrap();
        let tone: Vec<f32> = (0..FRAME * 20)
            .flat_map(|i| {
                let s = 0.5 * (i as f32 * 440.0 * std::f32::consts::TAU / SAMPLE_RATE as f32).sin();
                [s, s]
            })
            .collect();
        let (mut packets, mut out) = (Vec::new(), Vec::new());
        for frame in tone.chunks(FRAME * CHANNELS) {
            encoder.encode(frame, &mut packets).unwrap();
        }
        assert!(packets.len() >= 15, "about one packet per frame, got {}", packets.len());
        assert!(packets.iter().all(|p| p.len() < 1000), "packets fit in a datagram");
        for packet in &packets {
            decoder.decode(packet, &mut out).unwrap();
        }
        // Past the encoder's lookahead, the tone keeps its level.
        let (input, output) = (rms(&tone[tone.len() / 2..]), rms(&out[out.len() / 2..]));
        assert!((output / input - 1.0).abs() < 0.2, "level {output} vs {input}");
    }
}
