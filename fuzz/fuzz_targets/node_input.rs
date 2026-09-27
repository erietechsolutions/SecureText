//! A live node handling any frame from a stranger or a contact, or any
//! MLS payload from a contact.
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| securetext_app::fuzzing::node_input(data));
