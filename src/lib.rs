//! 可复用的直连 P2P 网络 SDK：网络候选、认证打洞、ICE、QUIC 与诊断。
//!
//! 通用应用入口为 direct_peer 的 INVITE/REPLY 配对与
//! ReadyCreator/ReadyJoiner::connect_transport()。
//! Transport session 默认只建立认证 Control QUIC；额外 QUIC 由应用按需请求。
//! 文件数据分配、分片、ACK、重传和四路 Stripe 策略不属于 SDK。
//! 自动化 CI 与环回连接成功不代表真实复杂 NAT 环境已完成对等验收。

pub mod candidate;
#[doc(hidden)]
pub mod channel;
#[doc(hidden)]
pub mod dual_quic;
#[doc(hidden)]
pub mod config;
pub mod packet_demux;
pub mod peer_pin;
pub mod manual_pairing;
pub mod session_binding;
#[doc(hidden)]
pub mod state;
pub mod stun;
pub mod stun_client;
pub mod tls_identity;

pub use candidate::{Candidate, CandidateKind, Family, TransportProtocol};
#[doc(hidden)]
pub use config::{Config, ConfigError};
#[doc(hidden)]
pub use state::{ConnectionPhase, ConnectionState, StateError};

#[doc(hidden)]
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
mod udp_errors;
pub mod managed_candidates;
pub mod network_diagnostics;
pub mod direct_peer;
/// Generic Control-only network session with opt-in authenticated QUIC links.
pub mod transport_session;

/// 面向业务程序的精简推荐 API；旧模块路径继续兼容现有 Transfer。
pub use direct_peer::{
    begin_creator, begin_creator_auto, begin_joiner, begin_joiner_auto,
    DirectPeerError, PendingCreator, ReadyCreator, ReadyJoiner,
};
pub use transport_session::{
    AuthenticatedDataLink, ConnectedTransportPeer, ManagedAuthenticatedLink,
    ManagedLinkPhase, ManagedLinkStatus, TransportDiagnostic, TransportError,
};
pub mod upnp_lease;
pub mod pcp;
pub mod pcp_lease;

pub mod punch;
pub mod punch_loop;
