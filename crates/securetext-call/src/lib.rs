//! Voice and video calls (roadmap Phase 7): the one disclosed exception to
//! "everything over Tor" (threat-model.md, architecture.md §9).
//!
//! - [`engine`]: WebRTC (webrtc-rs) peer connections, one per other
//!   participant, **forced through TURN relays**, so participants never
//!   learn each other's IP address.
//! - [`crypto`]: a per-call key, distributed inside MLS, that seals every
//!   audio and video frame on top of DTLS-SRTP.
//! - [`audio`]: Opus at 48 kHz, with devices behind a trait so tests can
//!   push a real tone through the whole path.
//! - [`turn_server`]: a TURN server for people who want to run their own.
//!
//! Call media runs in Rust rather than in the webview because the WebKitGTK
//! builds shipped by Ubuntu and Fedora (and the GNOME runtime) are compiled
//! without WebRTC (tech-stack.md). Video frames are captured by the
//! webview's camera API, which does work there, and carried as sealed JPEGs
//! over a WebRTC data channel.

#![forbid(unsafe_code)]

pub mod audio;
pub mod crypto;
pub mod engine;
pub mod turn_server;

pub use audio::{AudioBackend, CpalBackend, ToneBackend};
pub use engine::{CallEngine, EngineConfig, EngineEvent, PeerStats, TurnServer};
