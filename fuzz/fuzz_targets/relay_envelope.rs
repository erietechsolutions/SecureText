//! What a contact could leave in our relay mailbox, after decryption.
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| securetext_app::fuzzing::relay_envelope(data));
