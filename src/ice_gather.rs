//! Candidate discovery for an existing UDP owner.
//!
//! Host and STUN server-reflexive candidates must refer to the same
//! effective UDP socket. STUN mapping observations do NOT imply reachable
//! candidate pairs; only ICE can make that decision. Port mapping and
//! multi-interface packet-info support are separate future steps.

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use crate::{
    ice_agent::new_ice_credentials,
    ice_signaling::{IceCandidate, IceCandidateType, IceDescription, IceRole, MAX_CANDIDATES},
    multi_stun::{query_via_owner, MappingReport, MultiStunError},
    udp_owner::UdpOwnerHandle,
};

const HOST_PRIORITY: u32 = 2_130_706_431;
const SRFLX_PRIORITY: u32 = 1_690_000_000;
const PORTMAP_PRIORITY: u32 = 1_800_000_000;

#[derive(Debug)]
pub enum CandidateGatherError {
    InvalidLocalEndpoint,
    Stun(MultiStunError),
}

/// Diagnostics deliberately remain separate from the authenticated signaling
/// object. Avoid logging the latter: it contains short-term ICE passwords.
pub struct GatherResult {
    pub description: IceDescription,
    pub mapping: Option<MappingReport>,
}

/// Gather the host candidate and at most one unique srflx per observed
/// mapping from the *same* bound UDP endpoint used by Quinn.
///
/// `servers` may be empty for LAN-only operation. One pinned local IP is
/// currently required: 0.0.0.0/:: bind would need per-packet local IP info
/// before it could safely advertise all interfaces.
pub async fn gather(
    owner: &UdpOwnerHandle,
    servers: &[SocketAddr],
    role: IceRole,
    stun_deadline: Duration,
) -> Result<GatherResult, CandidateGatherError> {
    let local = owner.local_address();
    if local.port() == 0 || local.ip().is_unspecified() || local.ip().is_multicast() {
        return Err(CandidateGatherError::InvalidLocalEndpoint);
    }
    let credentials = new_ice_credentials();
    let mut candidates = vec![IceCandidate {
        address: local,
        kind: IceCandidateType::Host,
        priority: HOST_PRIORITY,
    }];
    let mapping = if servers.is_empty() {
        None
    } else {
        // STUN is an optional enhancement: unavailable public servers must
        // never disable a valid local Host candidate or offline LAN pairing.
        let report = query_via_owner(owner, servers, stun_deadline).await.ok();
        if let Some(report) = report {
        append_stun_observations(&mut candidates, local, &report);
        if report.observations.is_empty() { None } else { Some(report) }
        } else {
            None
        }
    };
    let description = IceDescription {
        role,
        ufrag: credentials.ufrag,
        password: credentials.pass,
        candidates,
    };
    Ok(GatherResult { description, mapping })
}

/// 将同一实际 UDP Owner 观测到的 srflx 加入既有 ICE 凭据，不得重新创建绑定。
pub(crate) fn append_stun_observations(
    candidates: &mut Vec<IceCandidate>, local: SocketAddr, report: &MappingReport,
) {
    let mut seen: HashSet<SocketAddr> =
        candidates.iter().map(|candidate| candidate.address).collect();
    seen.insert(local);
    for observation in &report.observations {
        let addr = observation.mapped_address;
        if addr.port() == 0 || addr.ip().is_unspecified()
            || addr.ip().is_multicast() || addr.is_ipv4() != local.is_ipv4()
        {
            continue;
        }
        if seen.insert(addr) && candidates.len() < MAX_CANDIDATES {
            candidates.push(IceCandidate {
                address: addr,
                kind: IceCandidateType::ServerReflexive,
                priority: SRFLX_PRIORITY,
            });
        }
    }
}

/// Attach a gateway-confirmed mapping as an ICE candidate ONLY if it
/// maps this exact UDP owner's host IP and source port. The remote peer must
/// still successfully run authenticated ICE connectivity checks: a gateway
/// mapping reply alone is never a usable QUIC path.
pub fn add_portmapped_candidate(
    description: &mut IceDescription,
    local: SocketAddr,
    external: SocketAddr,
) -> Result<bool, CandidateGatherError> {
    if description.candidates.iter().all(|c| {
        c.kind != IceCandidateType::Host || c.address != local
    }) || external.port() == 0 || external.ip().is_unspecified()
        || external.ip().is_multicast() || external.is_ipv4() != local.is_ipv4()
    {
        return Err(CandidateGatherError::InvalidLocalEndpoint);
    }
    if description.candidates.iter().any(|c| c.address == external) {
        return Ok(false);
    }
    if description.candidates.len() >= MAX_CANDIDATES {
        return Ok(false);
    }
    description.candidates.push(IceCandidate {
        address: external,
        kind: IceCandidateType::PortMapped,
        priority: PORTMAP_PRIORITY,
    });
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp_owner::UdpOwner;

    #[tokio::test]
    async fn gateway_mapping_must_match_real_ice_udp_owner_before_advertising() {
        let owner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut desc = gather(&owner.handle, &[], IceRole::Controlling,
            Duration::from_secs(1)).await.unwrap().description;
        let actual = owner.handle.local_address();
        let mapped: SocketAddr = "198.51.100.9:55001".parse().unwrap();
        assert!(add_portmapped_candidate(&mut desc, actual, mapped).unwrap());
        assert_eq!(desc.candidates.last().unwrap().kind, IceCandidateType::PortMapped);
        assert!(!add_portmapped_candidate(&mut desc, actual, mapped).unwrap());
        assert!(add_portmapped_candidate(&mut desc,
            "127.0.0.1:9999".parse().unwrap(), mapped).is_err());
        assert!(add_portmapped_candidate(&mut desc,
            actual, "[2001:db8::10]:50000".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn lan_without_stun_always_gathers_same_udp_socket() {
        let owner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let result = gather(
            &owner.handle, &[], IceRole::Controlling, Duration::from_secs(1),
        ).await.unwrap();
        assert!(result.mapping.is_none());
        assert_eq!(result.description.candidates.len(), 1);
        assert_eq!(result.description.candidates[0].address, owner.handle.local_address());
        assert_eq!(result.description.candidates[0].kind, IceCandidateType::Host);
        result.description.validate().unwrap();
    }

    #[tokio::test]
    async fn unreachable_stun_does_not_break_offline_lan() {
        let owner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        // A loopback UDP destination with no STUN server gives a deterministic
        // short timeout; Host is still valid when optional discovery fails.
        let unreachable: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let result = gather(&owner.handle, &[unreachable], IceRole::Controlling,
            Duration::from_millis(100)).await.unwrap();
        assert!(result.mapping.is_none());
        assert_eq!(result.description.candidates.len(), 1);
        assert_eq!(result.description.candidates[0].kind, IceCandidateType::Host);
        assert_eq!(result.description.candidates[0].address,
            owner.handle.local_address());
        result.description.validate().unwrap();
    }

    #[tokio::test]
    async fn rejects_wildcard_bind_as_unadvertisable_candidate() {
        let owner = UdpOwner::bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
        assert!(matches!(
            gather(&owner.handle, &[], IceRole::Controlling, Duration::from_millis(100)).await,
            Err(CandidateGatherError::InvalidLocalEndpoint)
        ));
    }
}
