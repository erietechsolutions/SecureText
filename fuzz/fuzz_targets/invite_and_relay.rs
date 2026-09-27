//! Invite links and relay addresses (pasted by users, so attacker-chosen)
//! and relay protocol requests (from anyone who can reach a relay).
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = securetext_invite::Invite::from_link(text);
        let _ = securetext_relay::RelayAddress::parse(text);
    }
    let _ = serde_json::from_slice::<securetext_relay::Request>(data);
    let _ = serde_json::from_slice::<securetext_relay::Response>(data);
});
