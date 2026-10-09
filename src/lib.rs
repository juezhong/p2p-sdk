//! Core value types and safety invariants for the future Rust P2P SDK.
//!
//! M0 only: no ICE agent, UDP probing, authenticated QUIC transport, or
//! production-ready connectivity is implemented yet.

pub mod candidate;
pub mod channel;
pub mod dual_quic;
pub mod config;
pub mod packet_demux;
pub mod peer_pin;
pub mod manual_pairing;
pub mod session_binding;
pub mod state;
pub mod stun;
pub mod stun_client;
pub mod tls_identity;

pub use candidate::{Candidate, CandidateKind, Family, TransportProtocol};
pub use config::{Config, ConfigError};
pub use state::{ConnectionPhase, ConnectionState, StateError};

pub mod verified_session;

pub mod ice_signaling;
pub mod multi_stun;
