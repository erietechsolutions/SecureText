//! Audio in and out of a call: 48 kHz mono, 20 ms frames, Opus-coded.
//!
//! Devices sit behind [`AudioBackend`] so the same call path runs with a
//! real microphone and speakers ([`CpalBackend`]) or, in tests, with a
//! synthetic tone in and a recorder out ([`ToneBackend`]), which is how the
//! tests prove sound actually crosses the relay intact.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

pub const SAMPLE_RATE: u32 = 48_000;
/// 20 ms at 48 kHz.
pub const FRAME: usize = 960;
/// Per-peer playback queue cap: older audio is dropped past this, so a
/// burst after a network stall doesn't turn into lasting delay.
const MAX_QUEUED: usize = SAMPLE_RATE as usize / 4;

/// Decoded audio from every participant, mixed on the way out.
#[derive(Default)]
pub struct Mixer {
    queues: HashMap<String, VecDeque<i16>>,
}

impl Mixer {
    pub fn push(&mut self, peer: &str, samples: &[i16]) {
        let queue = self.queues.entry(peer.to_string()).or_default();
        queue.extend(samples);
        while queue.len() > MAX_QUEUED {
            queue.pop_front();
        }
    }

    pub fn remove(&mut self, peer: &str) {
        self.queues.remove(peer);
    }

    /// Fill `out` with the sum of every participant's next samples
    /// (silence where a queue has run dry).
    pub fn pull(&mut self, out: &mut [i16]) {
        let mut mixed = vec![0i32; out.len()];
        for queue in self.queues.values_mut() {
            for slot in mixed.iter_mut() {
                match queue.pop_front() {
                    Some(s) => *slot += s as i32,
                    None => break,
                }
            }
        }
        for (o, m) in out.iter_mut().zip(mixed) {
            *o = m.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        }
    }
}

pub type SharedMixer = Arc<Mutex<Mixer>>;

/// Something that captures 20 ms frames into `capture` and plays whatever
/// the mixer holds. The returned guard keeps the devices open; dropping it
/// stops them.
pub trait AudioBackend: Send + Sync + 'static {
    fn start(&self, capture: mpsc::Sender<Vec<i16>>, playback: SharedMixer) -> anyhow::Result<Box<dyn Send>>;

    /// Test backends: what the last two seconds of playback sounded like.
    fn heard(&self) -> Option<Heard> {
        None
    }
}

pub struct OpusEncoder(opus::Encoder);
pub struct OpusDecoder(opus::Decoder);

impl OpusEncoder {
    pub fn new() -> anyhow::Result<Self> {
        let mut enc = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)?;
        enc.set_bitrate(opus::Bitrate::Bits(32_000))?;
        enc.set_inband_fec(true)?;
        Ok(Self(enc))
    }

    pub fn encode(&mut self, frame: &[i16]) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0u8; 1500];
        let n = self.0.encode(frame, &mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

impl OpusDecoder {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self(opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono)?))
    }

    pub fn decode(&mut self, packet: &[u8]) -> anyhow::Result<Vec<i16>> {
        let mut out = vec![0i16; FRAME * 6];
        let n = self.0.decode(packet, &mut out, false)?;
        out.truncate(n);
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// Test backend
// ---------------------------------------------------------------------

/// A sine tone in, a recorder out.
pub struct ToneBackend {
    pub frequency: f32,
    pub played: Arc<Mutex<Vec<i16>>>,
}

impl ToneBackend {
    pub fn new(frequency: f32) -> Self {
        Self { frequency, played: Arc::new(Mutex::new(Vec::new())) }
    }
}

impl AudioBackend for ToneBackend {
    fn start(&self, capture: mpsc::Sender<Vec<i16>>, playback: SharedMixer) -> anyhow::Result<Box<dyn Send>> {
        let freq = self.frequency;
        let played = self.played.clone();
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            let mut phase = 0f32;
            let step = 2.0 * std::f32::consts::PI * freq / SAMPLE_RATE as f32;
            loop {
                tick.tick().await;
                let frame: Vec<i16> = (0..FRAME)
                    .map(|_| {
                        phase = (phase + step) % (2.0 * std::f32::consts::PI);
                        (phase.sin() * 8000.0) as i16
                    })
                    .collect();
                if capture.try_send(frame).is_err() && capture.is_closed() {
                    break;
                }
                let mut out = vec![0i16; FRAME];
                playback.lock().unwrap().pull(&mut out);
                played.lock().unwrap().extend_from_slice(&out);
            }
        });
        Ok(Box::new(AbortOnDrop(task)))
    }

    fn heard(&self) -> Option<Heard> {
        let played = self.played.lock().unwrap();
        analyse(&played[played.len().saturating_sub(2 * SAMPLE_RATE as usize)..])
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What a stretch of played audio sounded like: its pitch, measured only
/// over the audible parts, and how much of it was audible at all (gaps
/// are dropouts: late or lost packets).
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
pub struct Heard {
    pub frequency: f32,
    pub audible_fraction: f32,
}

/// Analyse `samples` (at [`SAMPLE_RATE`]) in 10 ms blocks. The pitch comes
/// from zero crossings within audible blocks only, so dropouts show up in
/// `audible_fraction` instead of dragging the pitch down. Good enough to
/// tell a 440 Hz tone that survived encode → encrypt → relay → decrypt →
/// decode from anything else.
pub fn analyse(samples: &[i16]) -> Option<Heard> {
    const BLOCK: usize = SAMPLE_RATE as usize / 100;
    let blocks: Vec<&[i16]> = samples.as_chunks::<BLOCK>().0.iter().map(|b| b.as_slice()).collect();
    if blocks.is_empty() {
        return None;
    }
    let audible: Vec<&&[i16]> = blocks
        .iter()
        .filter(|b| {
            let energy: f64 = b.iter().map(|s| (*s as f64).powi(2)).sum::<f64>() / BLOCK as f64;
            energy.sqrt() > 300.0
        })
        .collect();
    if audible.len() < 10 {
        return None;
    }
    let crossings: usize = audible.iter().map(|b| b.windows(2).filter(|w| (w[0] < 0) != (w[1] < 0)).count()).sum();
    let seconds = (audible.len() * BLOCK) as f32 / SAMPLE_RATE as f32;
    Some(Heard {
        frequency: crossings as f32 / 2.0 / seconds,
        audible_fraction: audible.len() as f32 / blocks.len() as f32,
    })
}

/// Just the pitch (see [`analyse`]).
pub fn dominant_frequency(samples: &[i16]) -> Option<f32> {
    analyse(samples).map(|h| h.frequency)
}

// ---------------------------------------------------------------------
// Real devices
// ---------------------------------------------------------------------

/// The system's default microphone and speakers, through cpal (ALSA —
/// and so PipeWire/PulseAudio — on Linux, WASAPI on Windows). cpal's
/// streams can't move between threads on every platform, so they live on
/// a dedicated thread for the call's lifetime.
pub struct CpalBackend;

impl AudioBackend for CpalBackend {
    fn start(&self, capture: mpsc::Sender<Vec<i16>>, playback: SharedMixer) -> anyhow::Result<Box<dyn Send>> {
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<anyhow::Result<()>>();
        std::thread::Builder::new().name("securetext-audio".into()).spawn(move || {
            match cpal_streams(capture, playback) {
                Ok(streams) => {
                    let _ = ready_tx.send(Ok(()));
                    let _ = stop_rx.recv();
                    drop(streams);
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            }
        })?;
        ready_rx.recv_timeout(Duration::from_secs(10))??;
        Ok(Box::new(StopOnDrop(stop_tx)))
    }
}

struct StopOnDrop(std::sync::mpsc::Sender<()>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

fn cpal_streams(capture: mpsc::Sender<Vec<i16>>, playback: SharedMixer) -> anyhow::Result<(cpal::Stream, cpal::Stream)> {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    let host = cpal::default_host();
    let input = host.default_input_device().ok_or_else(|| anyhow::anyhow!("no microphone found"))?;
    let output = host.default_output_device().ok_or_else(|| anyhow::anyhow!("no speakers or headphones found"))?;

    let in_cfg = input.default_input_config()?;
    let out_cfg = output.default_output_config()?;
    let in_rate = in_cfg.sample_rate().0;
    let out_rate = out_cfg.sample_rate().0;
    let in_channels = in_cfg.channels() as usize;
    let out_channels = out_cfg.channels() as usize;
    let err = |e| eprintln!("[securetext] audio device error: {e}");

    // Capture: downmix to mono, resample to 48 kHz, cut into 20 ms frames.
    let mut pending: Vec<i16> = Vec::with_capacity(FRAME * 2);
    let mut resampler = Resampler::new(in_rate, SAMPLE_RATE);
    let in_stream = input.build_input_stream(
        &in_cfg.config(),
        move |data: &[f32], _| {
            let mono: Vec<f32> = data.chunks(in_channels).map(|c| c.iter().sum::<f32>() / in_channels as f32).collect();
            for s in resampler.process(&mono) {
                pending.push((s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16);
                if pending.len() == FRAME {
                    let _ = capture.try_send(std::mem::replace(&mut pending, Vec::with_capacity(FRAME)));
                }
            }
        },
        err,
        None,
    )?;

    // Playback: pull mixed 48 kHz mono, resample to the device rate, and
    // copy to every output channel.
    let mut out_resampler = Resampler::new(SAMPLE_RATE, out_rate);
    let mut ready: VecDeque<f32> = VecDeque::new();
    let out_stream = output.build_output_stream(
        &out_cfg.config(),
        move |data: &mut [f32], _| {
            let frames = data.len() / out_channels;
            while ready.len() < frames {
                let mut chunk = vec![0i16; 480];
                playback.lock().unwrap().pull(&mut chunk);
                let as_f32: Vec<f32> = chunk.iter().map(|s| *s as f32 / i16::MAX as f32).collect();
                ready.extend(out_resampler.process(&as_f32));
            }
            for frame in data.chunks_mut(out_channels) {
                let s = ready.pop_front().unwrap_or(0.0);
                frame.iter_mut().for_each(|o| *o = s);
            }
        },
        err,
        None,
    )?;
    in_stream.play()?;
    out_stream.play()?;
    Ok((in_stream, out_stream))
}

/// Linear-interpolation resampler: plenty for speech at these rates.
struct Resampler {
    step: f64,
    pos: f64,
    last: f32,
}

impl Resampler {
    fn new(from: u32, to: u32) -> Self {
        Self { step: from as f64 / to as f64, pos: 0.0, last: 0.0 }
    }

    fn process(&mut self, input: &[f32]) -> Vec<f32> {
        if (self.step - 1.0).abs() < f64::EPSILON {
            return input.to_vec();
        }
        let mut out = Vec::with_capacity((input.len() as f64 / self.step) as usize + 1);
        while self.pos < input.len() as f64 {
            let i = self.pos.floor() as isize;
            let frac = (self.pos - i as f64) as f32;
            let a = if i <= 0 { self.last } else { input[i as usize - 1] };
            let b = input[i.max(0) as usize];
            out.push(if i <= 0 { self.last + (b - self.last) * frac } else { a + (b - a) * frac });
            self.pos += self.step;
        }
        self.pos -= input.len() as f64;
        self.last = *input.last().unwrap_or(&self.last);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opus_round_trip_keeps_the_tone() {
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();
        let mut out = Vec::new();
        let step = 2.0 * std::f32::consts::PI * 440.0 / SAMPLE_RATE as f32;
        for f in 0..50 {
            let frame: Vec<i16> = (0..FRAME).map(|i| (((f * FRAME + i) as f32 * step).sin() * 8000.0) as i16).collect();
            let packet = enc.encode(&frame).unwrap();
            assert!(packet.len() < 200, "32 kb/s Opus frames are small");
            out.extend(dec.decode(&packet).unwrap());
        }
        let f = dominant_frequency(&out[FRAME * 5..]).unwrap();
        assert!((f - 440.0).abs() < 15.0, "{f}");
    }

    #[test]
    fn dropouts_lower_the_audible_fraction_not_the_pitch() {
        let step = 2.0 * std::f32::consts::PI * 660.0 / SAMPLE_RATE as f32;
        let mut samples: Vec<i16> = (0..SAMPLE_RATE as usize).map(|i| ((i as f32 * step).sin() * 8000.0) as i16).collect();
        // Knock out every fifth 20 ms frame, as lost packets would.
        for frame in samples.chunks_mut(FRAME).step_by(5) {
            frame.fill(0);
        }
        let h = analyse(&samples).unwrap();
        assert!((h.frequency - 660.0).abs() < 10.0, "{h:?}");
        assert!((h.audible_fraction - 0.8).abs() < 0.05, "{h:?}");
        assert!(analyse(&vec![0; SAMPLE_RATE as usize]).is_none(), "silence");
    }

    #[test]
    fn the_mixer_sums_participants_and_bounds_delay() {
        let mut m = Mixer::default();
        m.push("a", &[100, 100]);
        m.push("b", &[1, 2, 3]);
        let mut out = [0i16; 4];
        m.pull(&mut out);
        assert_eq!(out, [101, 102, 3, 0]);
        m.push("a", &vec![1; MAX_QUEUED * 2]);
        assert_eq!(m.queues["a"].len(), MAX_QUEUED);
    }

    #[test]
    fn resampling_keeps_pitch() {
        let mut r = Resampler::new(44_100, SAMPLE_RATE);
        let step = 2.0 * std::f32::consts::PI * 440.0 / 44_100.0;
        let input: Vec<f32> = (0..44_100).map(|i| (i as f32 * step).sin()).collect();
        let out: Vec<i16> = input.chunks(441).flat_map(|c| r.process(c)).map(|s| (s * 8000.0) as i16).collect();
        let f = dominant_frequency(&out).unwrap();
        assert!((f - 440.0).abs() < 10.0, "{f}");
    }
}
