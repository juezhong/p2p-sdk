//! Direct-only multi-owner ICE path discovery and race.
//!
//! Every physical UDP owner must bind its own true source address/port and
//! gather srflx mappings on that exact socket. Offer signaling contains a
//! single ICE credential pair plus candidates from all participating owners.
//! Each independently checked ICE agent receives ONLY its owner's candidates,
//! so a candidate belonging to another NIC is never falsely claimed as a
//! source from this socket. The first authenticated nominated path wins;
//! unsuccessful owners are dropped and never advertised as QUIC endpoints.
//!
//! This is a network building block; Transfer's existing one-interface
//! pairing UI has not yet been migrated. ICE consent/restart remains separate.

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use tokio::task::JoinSet;

use crate::{
    ice_agent::NominatedPath,
    ice_gather::{gather, CandidateGatherError},
    ice_multi::{nominate_direct_candidates, nominate_with_authenticated_punch},
    ice_signaling::{IceDescription, IceRole, MAX_CANDIDATES},
    punch::AuthenticatedPunch,
    session_binding::SessionCredentials,
    udp_owner::UdpOwner,
};

pub const MAX_ACTIVE_INTERFACES: usize = 8;

#[derive(Debug)]
pub enum MultiInterfaceError {
    Empty,
    TooMany,
    InvalidAddress,
    Bind,
    Candidate(CandidateGatherError),
    NoDirectPath,
}

pub struct InterfaceOwner {
    pub owner: UdpOwner,
    /// Candidates of this UDP owner only, with the *shared* credentials.
    pub local: IceDescription,
}

pub struct CandidateSet {
    /// Single authenticated signaling object for manual or rendezvous mode.
    pub combined: IceDescription,
    pub interfaces: Vec<InterfaceOwner>,
}

pub struct SelectedDirectPath {
    pub owner: UdpOwner,
    pub path: NominatedPath,
}

/// Bind one UDP owner per requested local address, concurrently gather Host
/// plus same-socket STUN mappings, and publish a single combined candidate
/// offer. Missing/failed interface binds are nonfatal when another works.
/// Caller must use real OS interface discovery for normal operation.
pub async fn gather_interfaces(
    addresses: &[SocketAddr],
    stun: &[SocketAddr],
    role: IceRole,
    timeout: Duration,
) -> Result<CandidateSet, MultiInterfaceError> {
    if addresses.is_empty() { return Err(MultiInterfaceError::Empty); }
    if addresses.len() > MAX_ACTIVE_INTERFACES || timeout.is_zero() {
        return Err(MultiInterfaceError::TooMany);
    }
    let mut jobs = JoinSet::new();
    let mut seen = HashSet::new();
    for (index, address) in addresses.iter().copied().enumerate() {
        if address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err(MultiInterfaceError::InvalidAddress);
        }
        if address.port() != 0 && !seen.insert(address) {
            return Err(MultiInterfaceError::InvalidAddress);
        }
        let stun = stun.iter().copied().filter(|s| s.is_ipv4() == address.is_ipv4())
            .collect::<Vec<_>>();
        jobs.spawn(async move {
            let owner = UdpOwner::bind(address).await.map_err(|_| MultiInterfaceError::Bind)?;
            let discovered = gather(&owner.handle, &stun, role, timeout)
                .await.map_err(MultiInterfaceError::Candidate)?;
            Ok::<_, MultiInterfaceError>((index, InterfaceOwner {
                owner,
                local: discovered.description,
            }))
        });
    }

    let mut obtained = Vec::new();
    while let Some(result) = jobs.join_next().await {
        if let Ok(Ok(owner)) = result { obtained.push(owner); }
    }
    if obtained.is_empty() { return Err(MultiInterfaceError::Bind); }
    obtained.sort_by_key(|(index, _)| *index);

    // All independent ICE checks must use one exchanged ufrag/password pair.
    // No ICE agent may claim candidates collected on a different UDP owner.
    let (first_ufrag, first_password) = (
        obtained[0].1.local.ufrag.clone(),
        obtained[0].1.local.password.clone(),
    );
    let mut advertised = Vec::new();
    let mut owners = Vec::new();
    for (_, mut item) in obtained {
        if advertised.len() >= MAX_CANDIDATES { break; }
        item.local.ufrag = first_ufrag.clone();
        item.local.password = first_password.clone();
        let room = MAX_CANDIDATES - advertised.len();
        item.local.candidates.truncate(room);
        advertised.extend(item.local.candidates.iter().cloned());
        owners.push(item);
    }
    let combined = IceDescription {
        role, ufrag: first_ufrag,
        password: first_password, candidates: advertised,
    };
    combined.validate().map_err(|_| MultiInterfaceError::InvalidAddress)?;
    Ok(CandidateSet { combined, interfaces: owners })
}

impl CandidateSet {
    /// Run real authenticated ICE checks across all bound sockets in
    /// parallel rather than serially waiting for IPv6 to time out before IPv4.
    /// The returned winning owner retains exactly the ICE-validated UDP socket
    /// for subsequently authenticated QUIC, while loser owners are dropped.
    pub async fn nominate_first(
        self,
        remote: &IceDescription,
        deadline: Duration,
    ) -> Result<SelectedDirectPath, MultiInterfaceError> {
        remote.validate().map_err(|_| MultiInterfaceError::InvalidAddress)?;
        if deadline.is_zero() { return Err(MultiInterfaceError::NoDirectPath); }
        let mut tasks = JoinSet::new();
        for mut interface in self.interfaces {
            let remote = remote.clone();
            tasks.spawn(async move {
                let result = nominate_direct_candidates(
                    &mut interface.owner, &interface.local, &remote, deadline,
                ).await;
                (interface.owner, result)
            });
        }
        let result = tokio::time::timeout(deadline, async {
            while let Some(joined) = tasks.join_next().await {
                if let Ok((owner, Ok(path))) = joined {
                    tasks.abort_all();
                    return Ok(SelectedDirectPath { owner, path });
                }
            }
            Err(MultiInterfaceError::NoDirectPath)
        }).await;
        result.unwrap_or(Err(MultiInterfaceError::NoDirectPath))
    }
    /// Like nominate_first, but first send authenticated probes and add only
    /// HMAC-verified peer-reflexive endpoints to the subsequent ICE checks.
    /// A learned source never counts as a nominated path without ICE proof.
    pub async fn nominate_first_with_authenticated_punch(
        self,
        remote: &IceDescription,
        credentials: SessionCredentials,
        deadline: Duration,
    ) -> Result<SelectedDirectPath, MultiInterfaceError> {
        remote.validate().map_err(|_| MultiInterfaceError::InvalidAddress)?;
        if deadline <= Duration::from_millis(200) {
            return Err(MultiInterfaceError::NoDirectPath);
        }
        let mut tasks = JoinSet::new();
        for mut interface in self.interfaces {
            let remote = remote.clone();
            let proof = AuthenticatedPunch::new(credentials.clone(), interface.local.role);
            tasks.spawn(async move {
                let result = nominate_with_authenticated_punch(
                    &mut interface.owner, &interface.local, &remote, &proof, deadline,
                ).await;
                (interface.owner, result)
            });
        }
        let result = tokio::time::timeout(deadline, async {
            while let Some(joined) = tasks.join_next().await {
                if let Ok((owner, Ok(path))) = joined {
                    tasks.abort_all();
                    return Ok(SelectedDirectPath { owner, path });
                }
            }
            Err(MultiInterfaceError::NoDirectPath)
        }).await;
        result.unwrap_or(Err(MultiInterfaceError::NoDirectPath))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gathers_two_sockets_but_never_confuses_their_candidate_bases() {
        let a = "127.0.0.1:0".parse().unwrap();
        let set = gather_interfaces(
            &[a, a], &[], IceRole::Controlling,
            Duration::from_millis(400),
        ).await.unwrap();
        assert_eq!(set.interfaces.len(), 2);
        assert_eq!(set.combined.candidates.len(), 2);
        assert_ne!(set.interfaces[0].owner.handle.local_address(),
            set.interfaces[1].owner.handle.local_address());
        set.combined.validate().unwrap();
        for interface in &set.interfaces {
            assert_eq!(interface.local.ufrag, set.combined.ufrag);
            assert_eq!(interface.local.password, set.combined.password);
            assert_eq!(interface.local.candidates.len(), 1);
            assert_eq!(interface.local.candidates[0].address,
                interface.owner.handle.local_address());
        }
    }

    #[tokio::test]
    async fn mixed_candidate_race_uses_actual_nominated_udp_socket() {
        let bind = "127.0.0.1:0".parse().unwrap();
        let a = gather_interfaces(&[bind, bind], &[], IceRole::Controlling,
            Duration::from_millis(200)).await.unwrap();
        let b = gather_interfaces(&[bind, bind], &[], IceRole::Controlled,
            Duration::from_millis(200)).await.unwrap();
        let a_remote = b.combined.clone();
        let b_remote = a.combined.clone();
        let (left, right) = tokio::join!(
            a.nominate_first(&a_remote, Duration::from_secs(5)),
            b.nominate_first(&b_remote, Duration::from_secs(5)),
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_eq!(left.path.local, left.owner.handle.local_address());
        assert_eq!(right.path.local, right.owner.handle.local_address());
        // The selected address must be one of the peer's real advertised
        // candidates, not a guessed LAN prefix or a STUN-only observation.
        assert!(a_remote.candidates.iter().any(|c| c.address == left.path.remote));
        assert!(b_remote.candidates.iter().any(|c| c.address == right.path.remote));
    }

    #[tokio::test]
    async fn rejects_wildcard_and_empty_interface_offer() {
        assert!(matches!(gather_interfaces(&[], &[], IceRole::Controlling,
            Duration::from_secs(1)).await, Err(MultiInterfaceError::Empty)));
        assert!(matches!(gather_interfaces(&["0.0.0.0:0".parse().unwrap()], &[],
            IceRole::Controlling, Duration::from_secs(1)).await,
            Err(MultiInterfaceError::InvalidAddress)));
    }
}
