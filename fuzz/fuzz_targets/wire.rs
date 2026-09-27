//! Peer-protocol frames and MLS payloads, as parsed from the network.
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| securetext_app::fuzzing::wire(data));
