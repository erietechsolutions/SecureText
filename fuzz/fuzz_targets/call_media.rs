//! Call media frames as they arrive from the network, and SDP checks.
#![no_main]
use securetext_call::crypto::{CallKey, MediaKind};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let key = CallKey::new(&[5u8; 32], "fuzz-call").unwrap();
    let _ = key.open(MediaKind::Audio, data);
    let _ = key.open(MediaKind::Video, data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = securetext_call::engine::check_relay_only(text);
    }
    if let Ok(mut dec) = securetext_call::audio::OpusDecoder::new() {
        let _ = dec.decode(data);
    }
});
