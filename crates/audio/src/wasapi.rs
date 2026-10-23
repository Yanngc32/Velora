//! WASAPI on the default output device: captured (loopback) on the host, played to on the
//! client. Both ask for 48 kHz float stereo and let Windows convert from and to the device's
//! own format. A device that changes or goes away (headphones plugged in) is opened again.

use std::{ptr, sync::Mutex, time::Duration};

use anyhow::Result;
use windows::{
    core::GUID,
    Win32::{
        Media::Audio::{
            eConsole, eRender, IAudioCaptureClient, IAudioClient, IAudioRenderClient, IMMDeviceEnumerator,
            MMDeviceEnumerator, AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM, AUDCLNT_STREAMFLAGS_LOOPBACK, AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
            WAVEFORMATEX, WAVEFORMATEXTENSIBLE, WAVEFORMATEXTENSIBLE_0,
        },
        System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED},
    },
};

use crate::{Ring, CHANNELS, SAMPLE_RATE};

/// How often the device's buffer is looked at.
const POLL: Duration = Duration::from_millis(5);
const RETRY: Duration = Duration::from_secs(1);
/// The device buffer asked for, in 100 ns units: 100 ms.
const BUFFER: i64 = 1_000_000;
/// Frames playing keeps queued in the device: enough to ride over a late poll, little enough
/// to stay in step with the picture.
const QUEUED: u32 = SAMPLE_RATE * 30 / 1000;

const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;
const KSDATAFORMAT_SUBTYPE_IEEE_FLOAT: GUID = GUID::from_u128(0x00000003_0000_0010_8000_00aa00389b71);
/// Front left and right.
const STEREO: u32 = 0x3;

fn format() -> WAVEFORMATEXTENSIBLE {
    let block = (CHANNELS * size_of::<f32>()) as u16;
    WAVEFORMATEXTENSIBLE {
        Format: WAVEFORMATEX {
            wFormatTag: WAVE_FORMAT_EXTENSIBLE,
            nChannels: CHANNELS as u16,
            nSamplesPerSec: SAMPLE_RATE,
            nAvgBytesPerSec: SAMPLE_RATE * block as u32,
            nBlockAlign: block,
            wBitsPerSample: 32,
            cbSize: (size_of::<WAVEFORMATEXTENSIBLE>() - size_of::<WAVEFORMATEX>()) as u16,
        },
        Samples: WAVEFORMATEXTENSIBLE_0 { wValidBitsPerSample: 32 },
        dwChannelMask: STEREO,
        SubFormat: KSDATAFORMAT_SUBTYPE_IEEE_FLOAT,
    }
}

/// COM on this thread, for as long as it lives.
struct Com(bool);

impl Com {
    fn init() -> Self {
        // SAFETY: per-thread initialization, undone on drop when it took. A thread already in
        // another apartment keeps it, which WASAPI accepts too.
        Self(unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok())
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: pairs the successful `CoInitializeEx` above.
            unsafe { CoUninitialize() };
        }
    }
}

/// The default output device's client, initialized with `flags` in our format.
unsafe fn open(flags: u32) -> Result<IAudioClient> {
    // SAFETY: COM calls on interfaces we own; `format` outlives `Initialize`, which copies it.
    unsafe {
        let enumerator: IMMDeviceEnumerator = CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
        let device = enumerator.GetDefaultAudioEndpoint(eRender, eConsole)?;
        let client: IAudioClient = device.Activate(CLSCTX_ALL, None)?;
        let format = format();
        client.Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            flags | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
            BUFFER,
            0,
            &format as *const WAVEFORMATEXTENSIBLE as *const WAVEFORMATEX,
            None,
        )?;
        Ok(client)
    }
}

/// Captures what the default output plays, interleaved stereo, until `running` turns false or
/// `on_samples` returns false (or fails, which is returned).
pub fn capture(running: &dyn Fn() -> bool, mut on_samples: impl FnMut(&[f32]) -> Result<bool>) -> Result<()> {
    let _com = Com::init();
    let mut silence = Vec::new();
    let mut failed = None;
    while running() {
        let mut on = |samples: &[f32]| match on_samples(samples) {
            Ok(keep) => keep,
            Err(e) => {
                failed = Some(e);
                false
            }
        };
        // SAFETY: COM is initialized on this thread.
        let result = unsafe { capture_device(running, &mut on, &mut silence) };
        if let Some(e) = failed.take() {
            return Err(e);
        }
        match result {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(e) => {
                tracing::debug!("sound capture: {e:#}; opening the device again");
                std::thread::sleep(RETRY);
            }
        }
    }
    Ok(())
}

/// One device until it fails. `Ok(false)`: the consumer is done; `Ok(true)`: `running` ended.
unsafe fn capture_device(
    running: &dyn Fn() -> bool,
    on_samples: &mut dyn FnMut(&[f32]) -> bool,
    silence: &mut Vec<f32>,
) -> Result<bool> {
    // SAFETY: the buffer WASAPI hands out holds `frames` frames of our format until released.
    unsafe {
        let client = open(AUDCLNT_STREAMFLAGS_LOOPBACK)?;
        let capture: IAudioCaptureClient = client.GetService()?;
        client.Start()?;
        let result = (|| -> Result<bool> {
            while running() {
                std::thread::sleep(POLL);
                while capture.GetNextPacketSize()? > 0 {
                    let (mut data, mut frames, mut flags) = (ptr::null_mut(), 0u32, 0u32);
                    capture.GetBuffer(&mut data, &mut frames, &mut flags, None, None)?;
                    let n = frames as usize * CHANNELS;
                    let keep = if data.is_null() || flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 {
                        silence.resize(n, 0.0);
                        on_samples(&silence[..n])
                    } else {
                        on_samples(std::slice::from_raw_parts(data as *const f32, n))
                    };
                    capture.ReleaseBuffer(frames)?;
                    if !keep {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })();
        let _ = client.Stop();
        result
    }
}

/// Plays what `ring` holds on the default output until `running` turns false.
pub fn play(running: &dyn Fn() -> bool, ring: &Mutex<Ring>) {
    let _com = Com::init();
    while running() {
        // SAFETY: COM is initialized on this thread.
        if let Err(e) = unsafe { play_device(running, ring) } {
            tracing::debug!("sound output: {e:#}; opening the device again");
            std::thread::sleep(RETRY);
        }
    }
}

unsafe fn play_device(running: &dyn Fn() -> bool, ring: &Mutex<Ring>) -> Result<()> {
    // SAFETY: the buffer WASAPI hands out has room for `frames` frames until released.
    unsafe {
        let client = open(0)?;
        let render: IAudioRenderClient = client.GetService()?;
        let size = client.GetBufferSize()?;
        client.Start()?;
        let result = (|| -> Result<()> {
            while running() {
                std::thread::sleep(POLL);
                let frames = QUEUED.min(size).saturating_sub(client.GetCurrentPadding()?);
                if frames == 0 {
                    continue;
                }
                let buffer = render.GetBuffer(frames)?;
                let out = std::slice::from_raw_parts_mut(buffer as *mut f32, frames as usize * CHANNELS);
                ring.lock().unwrap().fill(out);
                render.ReleaseBuffer(frames, 0)?;
            }
            Ok(())
        })();
        let _ = client.Stop();
        result
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    #[ignore = "needs an audio output device"]
    fn loopback_and_output_open() {
        let _com = Com::init();
        let start = Instant::now();
        let running = || start.elapsed() < Duration::from_millis(300);
        // SAFETY: COM is initialized on this thread.
        let captured = unsafe { capture_device(&running, &mut |_| true, &mut Vec::new()) };
        assert!(captured.unwrap(), "ran until stopped");
        let start = Instant::now();
        let running = || start.elapsed() < Duration::from_millis(300);
        // SAFETY: as above.
        unsafe { play_device(&running, &Mutex::new(Ring::default())) }.unwrap();
    }
}
