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
pub mod udp_owner;
pub mod quinn_socket;
pub mod ice_agent;

#[cfg(test)]
mod ice_quinn_integration;
pub mod manual_ice_v2;

pub mod ice_gather;
pub mod ice_multi;

#[cfg(test)]
mod manual_full_integration;

pub mod local_network;

/// Parallel, direct-only ICE candidate discovery and nomination by real UDP interface.
pub mod multi_interface;

pub mod nat_pmp;
pub mod nat_pmp_lease;
pub mod gateway;
pub mod managed_candidates;
pub mod network_diagnostics;
pub mod upnp_lease;
pub mod pcp;
pub mod pcp_lease;

/// Reauthenticated Data QUIC lane pool with fault-driven repair.
pub mod resilient_data;
pub mod punch;
