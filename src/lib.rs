//! Core value types and safety invariants for the future Rust P2P SDK.
//!
//! M0 only: no ICE agent, UDP probing, authenticated QUIC transport, or
//! production-ready connectivity is implemented yet.

pub mod candidate;
pub mod config;
pub mod state;
pub mod stun;

pub use candidate::{Candidate, CandidateKind, Family, TransportProtocol};
pub use config::{Config, ConfigError};
pub use state::{ConnectionPhase, ConnectionState, StateError};
