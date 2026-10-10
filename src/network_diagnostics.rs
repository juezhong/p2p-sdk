//! Read-only, credential-free SDK network diagnostics matching the useful
//! fields of Go p2p-friend's ConnectionInfo.
//! Never include ICE ufrag/password, pairing codes, TLS private material,
//! SAS, session secret or raw HMAC packets in status/log output.

use std::net::SocketAddr;

use crate::{
    ice_signaling::{IceCandidateType, IceDescription, IceRole},
    gateway::GatewayLease,
    managed_candidates::ManagedPath,
    multi_stun::MappingConsistency,
    verified_session::VerifiedManualSession,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkHealth {
    Healthy,
    DataDegraded,
    ControlDisconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayMethod { Pcp, NatPmp, Upnp }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkDiagnostic {
    /// The actual nominated UDP Owner (not the source of a STUN probe).
    pub local_udp: SocketAddr,
    pub remote_udp: SocketAddr,
    pub ice_role: IceRole,
    /// Advertised Host endpoints, not necessarily still-open UDP sockets.
    pub offered_host_candidates: Vec<SocketAddr>,
    /// Observed on the exact winning UDP Owner; None means no STUN evidence.
    pub stun_consistency: Option<MappingConsistency>,
    pub gateway_method: Option<GatewayMethod>,
    pub remote_candidate_kind: Option<IceCandidateType>,
    pub ipv6: bool,
    pub control_remote_udp: SocketAddr,
    pub control_connected: bool,
    pub base_data_connected: bool,
    pub desired_data_lanes: usize,
    pub active_data_lanes: usize,
    pub data_remotes: Vec<SocketAddr>,
    pub stun_mappings: Vec<SocketAddr>,
    pub gateway_mapping: Option<SocketAddr>,
    pub authenticated_peer_reflexive: Vec<SocketAddr>,
    pub health: LinkHealth,
}

pub async fn snapshot(
    session: &VerifiedManualSession,
    selected: &ManagedPath,
    local_description: &IceDescription,
    remote_description: &IceDescription,
    authenticated_sources: &[SocketAddr],
) -> NetworkDiagnostic {
    let path = selected.selected.path;
    let stun_consistency = selected.selected.stun_mapping.as_ref()
        .map(|report| report.consistency());
    let gateway_method = selected.mapping_lease.as_ref().map(|lease| match lease {
        GatewayLease::Pcp(_) => GatewayMethod::Pcp,
        GatewayLease::NatPmp(_) => GatewayMethod::NatPmp,
        GatewayLease::Upnp(_) => GatewayMethod::Upnp,
    });
    let mut offered_host_candidates = local_description.candidates.iter()
        .filter(|candidate| candidate.kind == IceCandidateType::Host)
        .map(|candidate| candidate.address).collect::<Vec<_>>();
    offered_host_candidates.sort();
    offered_host_candidates.dedup();
    let control_connected = session.control().close_reason().is_none();
    let base_data_connected = session.data().close_reason().is_none();
    let desired_data_lanes = 1;
    let active_data_lanes = usize::from(base_data_connected);
    let data_remotes = if base_data_connected {
        vec![session.data().remote_address()]
    } else {
        Vec::new()
    };
    let remote_candidate_kind = remote_description.candidates.iter()
        .find(|c| c.address == path.remote).map(|c| c.kind);
    let mut stun_mappings = local_description.candidates.iter()
        .filter(|c| c.kind == IceCandidateType::ServerReflexive)
        .map(|c| c.address).collect::<Vec<_>>();
    stun_mappings.sort();
    stun_mappings.dedup();
    let gateway_mapping = selected.mapping_lease.as_ref()
        .and_then(|lease| lease.subscribe().mapped_address());
    let mut authenticated_peer_reflexive = authenticated_sources.to_vec();
    authenticated_peer_reflexive.sort();
    authenticated_peer_reflexive.dedup();
    // The absence of data lanes is not treated as Control loss. The upper
    // transfer protocol is responsible for retrying unacknowledged blocks.
    let health = if !control_connected {
        LinkHealth::ControlDisconnected
    } else if active_data_lanes == 0 {
        LinkHealth::DataDegraded
    } else {
        LinkHealth::Healthy
    };
    NetworkDiagnostic {
        local_udp: path.local, remote_udp: path.remote,
        ice_role: local_description.role,
        offered_host_candidates, stun_consistency, gateway_method,
        remote_candidate_kind, ipv6: path.local.is_ipv6(),
        control_remote_udp: session.control().remote_address(),
        control_connected, base_data_connected,
        desired_data_lanes, active_data_lanes, data_remotes,
        stun_mappings, gateway_mapping,
        authenticated_peer_reflexive, health,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_fields_have_no_credential_strings() {
        let value = NetworkDiagnostic {
            local_udp: "192.0.2.3:40001".parse().unwrap(),
            remote_udp: "198.51.100.4:42000".parse().unwrap(),
            remote_candidate_kind: Some(IceCandidateType::PeerReflexive),
            ice_role: IceRole::Controlling,
            offered_host_candidates: vec![],
            stun_consistency: None,
            gateway_method: None,
            ipv6: false,
            control_remote_udp: "198.51.100.4:42000".parse().unwrap(),
            control_connected: true,
            base_data_connected: false,
            active_data_lanes: 0, desired_data_lanes: 4,
            data_remotes: vec![],
            stun_mappings: vec![],
            gateway_mapping: None,
            authenticated_peer_reflexive: vec![],
            health: LinkHealth::DataDegraded,
        };
        let out = format!("{value:?}");
        assert!(out.contains("DataDegraded"));
        assert!(!out.contains("ufrag"));
        assert!(!out.contains("secret"));
        assert!(!out.contains("private"));
        assert!(!out.contains("password"));
    }
}
