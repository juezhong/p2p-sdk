//! Bounded ICE multi-candidate checks using an existing UDP socket owner.
//!
//! This extends single host-host checking with STUN-observed srflx addresses.
//! It does NOT bind new UDP sockets, advertise TURN relays or assume that a
//! server-reflexive address is externally reachable before nomination.

use std::{collections::HashSet, time::{Duration, Instant}};

use is::{
    stun::{StunMessage, StunPacket},
    Candidate, IceAgent, IceAgentEvent, Protocol,
};
use tokio::{sync::mpsc, time::{sleep, timeout, MissedTickBehavior}};

use crate::{
    ice_agent::{credentials_from_description, IceCheckError, NominatedPath},
    ice_signaling::{IceCandidateType, IceDescription, IceRole, MAX_CANDIDATES},
    punch::{unix_seconds, AuthenticatedPunch},
    udp_owner::UdpOwner,
};

pub async fn nominate_direct_candidates(
    owner: &mut UdpOwner,
    local: &IceDescription,
    remote: &IceDescription,
    limit: Duration,
) -> Result<NominatedPath, IceCheckError> {
    nominate_direct_candidates_inner(owner, local, remote, limit, None).await
}

async fn nominate_direct_candidates_inner(
    owner: &mut UdpOwner,
    local: &IceDescription,
    remote: &IceDescription,
    limit: Duration,
    punch: Option<&AuthenticatedPunch>,
) -> Result<NominatedPath, IceCheckError> {
    local.validate().map_err(|_| IceCheckError::InvalidCredentials)?;
    remote.validate().map_err(|_| IceCheckError::InvalidCredentials)?;
    if limit.is_zero() || local.role == remote.role {
        return Err(IceCheckError::InvalidCredentials);
    }
    let socket_addr = owner.handle.local_address();
    if socket_addr.port() == 0 || socket_addr.ip().is_unspecified() {
        return Err(IceCheckError::InvalidCandidate);
    }
    // One confirmed base candidate (same bound socket) is mandatory. A
    // wildcard multi-interface socket is unsafe without packet-info support.
    if !local.candidates.iter().any(|c|
        c.kind == IceCandidateType::Host && c.address == socket_addr
    ) {
        return Err(IceCheckError::InvalidCandidate);
    }
    let mut agent = IceAgent::new(credentials_from_description(local));
    agent.set_controlling(local.role == IceRole::Controlling);
    agent.set_remote_credentials(credentials_from_description(remote));

    for candidate in &local.candidates {
        if candidate.address.is_ipv4() != socket_addr.is_ipv4() {
            continue;
        }
        let ice = match candidate.kind {
            IceCandidateType::Host => Candidate::host(candidate.address, Protocol::Udp),
            IceCandidateType::ServerReflexive => {
                Candidate::server_reflexive(candidate.address, socket_addr, Protocol::Udp)
            }
            IceCandidateType::PeerReflexive | IceCandidateType::PortMapped => continue,
        }.map_err(|_| IceCheckError::InvalidCandidate)?;
        agent.add_local_candidate(ice);
    }

    let remote_base = remote.candidates.iter().find(|c| {
        c.kind == IceCandidateType::Host
            && c.address.is_ipv4() == socket_addr.is_ipv4()
    }).map(|c| c.address);
    let mut destination_count = 0usize;
    let mut checked_destinations = HashSet::new();
    for candidate in &remote.candidates {
        if candidate.address.is_ipv4() != socket_addr.is_ipv4() {
            continue;
        }
        let ice = match candidate.kind {
            IceCandidateType::Host | IceCandidateType::PortMapped => {
                Candidate::host(candidate.address, Protocol::Udp)
            }
            IceCandidateType::ServerReflexive => {
                let Some(base) = remote_base else { continue };
                Candidate::server_reflexive(candidate.address, base, Protocol::Udp)
            }
            // prflx is discovered by authenticated peer traffic, not
            // accepted as an unverified remote signaling assertion here.
            IceCandidateType::PeerReflexive => continue,
        }.map_err(|_| IceCheckError::InvalidCandidate)?;
        agent.add_remote_candidate(ice);
        checked_destinations.insert(candidate.address);
        destination_count += 1;
    }
    if destination_count == 0 {
        return Err(IceCheckError::InvalidCandidate);
    }

    let start = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let result = async {
        loop {
            agent.handle_timeout(Instant::now());
            while let Some(tx) = agent.poll_transmit() {
                if tx.proto != Protocol::Udp {
                    return Err(IceCheckError::InvalidCandidate);
                }
                // A srflx candidate may be a logical network address; all
                // actual sends still use the existing UDP owner base socket.
                if tx.source != socket_addr && !local.candidates.iter().any(|c|
                    c.kind == IceCandidateType::ServerReflexive && c.address == tx.source
                ) {
                    return Err(IceCheckError::InvalidCandidate);
                }
                owner.handle.send_ice(tx.destination, &tx.contents).await
                    .map_err(|_| IceCheckError::UdpOwnerClosed)?;
            }
            while let Some(event) = agent.poll_event() {
                if let IceAgentEvent::NominatedSend { destination, proto, .. } = event {
                    if proto == Protocol::Udp {
                        return Ok(NominatedPath {
                            local: socket_addr, // actual effective UDP endpoint
                            remote: destination,
                        });
                    }
                }
            }
            let now = Instant::now();
            let next = agent.poll_timeout().unwrap_or(now + Duration::from_millis(25));
            let delay = next.saturating_duration_since(now).max(Duration::from_millis(1));
            tokio::select! {
                _ = ticker.tick(), if punch.is_some() => {
                    // Keep punching throughout ICE. A peer may acquire a new
                    // NAT mapping long after the initial discovery interval.
                    if let Some(proof) = punch {
                        let _ = proof.send_to_candidates(&owner.handle, remote).await;
                    }
                }
                packet = owner.punch_packets.recv(), if punch.is_some() => {
                    let packet = packet.ok_or(IceCheckError::UdpOwnerClosed)?;
                    let Some(proof) = punch else { continue };
                    let Ok(now) = unix_seconds() else { continue };
                    let Ok(source) = proof.authenticate(&packet.bytes, packet.source, now)
                        else { continue };
                    if source.is_ipv4() != socket_addr.is_ipv4()
                        || checked_destinations.contains(&source)
                        || checked_destinations.len() >= MAX_CANDIDATES
                    {
                        continue;
                    }
                    // HMAC only permits trying a new address. The ICE agent
                    // must still integrity-check and nominate it before QUIC.
                    let Ok(candidate) = Candidate::host(source, Protocol::Udp) else {
                        continue;
                    };
                    agent.add_remote_candidate(candidate);
                    checked_destinations.insert(source);
                    if let Ok(reply) = proof.make_packet(now) {
                        let _ = owner.handle.send_punch(source, &reply).await;
                    }
                }
                packet = owner.ice_packets.recv() => {
                    let packet = packet.ok_or(IceCheckError::UdpOwnerClosed)?;
                    if let Ok(message) = StunMessage::parse(&packet.bytes) {
                        agent.handle_packet(Instant::now(), StunPacket {
                            proto: Protocol::Udp,
                            source: packet.source,
                            destination: socket_addr,
                            message,
                        });
                    }
                }
                _ = sleep(delay) => {}
            }
        }
    };
    let remain = limit.saturating_sub(start.elapsed());
    timeout(remain, result).await.unwrap_or(Err(IceCheckError::NoDirectPath))
}

/// Keep session-authenticated probing active for the entire ICE deadline.
/// Peer-reflexive sources discovered at any time are checked by ICE before
/// nomination; the initial 600ms discovery window must not lose late NAT paths.
pub async fn nominate_with_authenticated_punch(
    owner: &mut UdpOwner,
    local: &IceDescription,
    remote: &IceDescription,
    punch: &AuthenticatedPunch,
    budget: Duration,
) -> Result<NominatedPath, IceCheckError> {
    if budget <= Duration::from_millis(200) {
        return Err(IceCheckError::InvalidCredentials);
    }
    nominate_direct_candidates_inner(owner, local, remote, budget, Some(punch)).await
}

/// 初次 ICE 提名完成后，仍在该真实 UDP Owner 上持续验证 NAT 变化。
/// HMAC Punch 仅允许添加待检查 candidate；只有 ICE NominatedSend
/// 才能发送给 QUIC 竞速。绝不把未认证的地址直接传给 Quinn。
pub(crate) async fn verify_dynamic_peer_reflexive(
    owner: &mut UdpOwner,
    local: &IceDescription,
    remote: &IceDescription,
    proof: &AuthenticatedPunch,
    verified: mpsc::Sender<std::net::SocketAddr>,
    budget: Duration,
) -> Result<(), IceCheckError> {
    local.validate().map_err(|_| IceCheckError::InvalidCredentials)?;
    remote.validate().map_err(|_| IceCheckError::InvalidCredentials)?;
    if local.role == remote.role || budget.is_zero() {
        return Err(IceCheckError::InvalidCredentials);
    }
    let bound = owner.handle.local_address();
    if bound.port() == 0 || bound.ip().is_unspecified()
        || !local.candidates.iter().any(|candidate|
            candidate.kind == IceCandidateType::Host && candidate.address == bound)
    {
        return Err(IceCheckError::InvalidCandidate);
    }
    let mut agent = IceAgent::new(credentials_from_description(local));
    agent.set_controlling(local.role == IceRole::Controlling);
    agent.set_remote_credentials(credentials_from_description(remote));
    agent.add_local_candidate(
        Candidate::host(bound, Protocol::Udp)
            .map_err(|_| IceCheckError::InvalidCandidate)?
    );
    let mut learned = HashSet::new();
    let mut reported = HashSet::new();
    let mut cadence = tokio::time::interval(Duration::from_millis(250));
    cadence.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(());
        }
        agent.handle_timeout(Instant::now());
        while let Some(tx) = agent.poll_transmit() {
            // 本轮仅公告 Host base；不允许在其它 NIC 或伪造的
            // srflx 地址上发送 ICE。
            if tx.proto != Protocol::Udp || tx.source != bound {
                return Err(IceCheckError::InvalidCandidate);
            }
            owner.handle.send_ice(tx.destination, &tx.contents).await
                .map_err(|_| IceCheckError::UdpOwnerClosed)?;
        }
        while let Some(event) = agent.poll_event() {
            if let IceAgentEvent::NominatedSend { destination, proto, .. } = event {
                if proto == Protocol::Udp && learned.contains(&destination)
                    && reported.insert(destination)
                    && verified.send(destination).await.is_err()
                {
                    return Ok(());
                }
            }
        }
        let now = Instant::now();
        let next = agent.poll_timeout().unwrap_or(now + Duration::from_millis(25));
        let delay = next.saturating_duration_since(now).max(Duration::from_millis(1));
        tokio::select! {
            _ = cadence.tick() => {
                let _ = proof.send_to_candidates(&owner.handle, remote).await;
            }
            packet = owner.punch_packets.recv() => {
                let packet = packet.ok_or(IceCheckError::UdpOwnerClosed)?;
                let Ok(now) = unix_seconds() else { continue };
                let Ok(source) = proof.authenticate(&packet.bytes, packet.source, now)
                    else { continue };
                if source.is_ipv4() != bound.is_ipv4()
                    || learned.contains(&source)
                    || learned.len() >= MAX_CANDIDATES
                {
                    continue;
                }
                // 认证 HMAC 后仍只能进入待检查表，不能通知 QUIC。
                let Ok(candidate) = Candidate::host(source, Protocol::Udp) else {
                    continue;
                };
                agent.add_remote_candidate(candidate);
                learned.insert(source);
                if let Ok(reply) = proof.make_packet(now) {
                    let _ = owner.handle.send_punch(source, &reply).await;
                }
            }
            packet = owner.ice_packets.recv() => {
                let packet = packet.ok_or(IceCheckError::UdpOwnerClosed)?;
                if let Ok(message) = StunMessage::parse(&packet.bytes) {
                    agent.handle_packet(Instant::now(), StunPacket {
                        proto: Protocol::Udp,
                        source: packet.source,
                        destination: bound,
                        message,
                    });
                }
            }
            _ = sleep(delay) => {}
            _ = tokio::time::sleep_until(deadline) => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice_gather::gather;

    #[tokio::test]
    async fn post_nomination_nat_change_requires_new_ice_proof() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let mut creator = UdpOwner::bind("127.0.0.1:0".parse().unwrap())
                .await.unwrap();
            let mut joiner = UdpOwner::bind("127.0.0.1:0".parse().unwrap())
                .await.unwrap();
            let creator_address = creator.handle.local_address();
            let joiner_address = joiner.handle.local_address();
            let local = gather(&creator.handle, &[], IceRole::Controlling,
                Duration::from_millis(100)).await.unwrap().description;
            let remote = gather(&joiner.handle, &[], IceRole::Controlled,
                Duration::from_millis(100)).await.unwrap().description;
            let mut stale = remote.clone();
            stale.candidates[0].address = "127.0.0.1:9".parse().unwrap();
            let credentials = crate::session_binding::SessionCredentials::new(
                [71; 16], [19; 32]
            ).unwrap();
            let creator_proof = AuthenticatedPunch::new(
                credentials.clone(), IceRole::Controlling
            );
            let joiner_proof = AuthenticatedPunch::new(
                credentials, IceRole::Controlled
            );
            let (creator_tx, mut creator_rx) = mpsc::channel(2);
            let (joiner_tx, mut joiner_rx) = mpsc::channel(2);
            let (left, right, authenticated_left, authenticated_right) = tokio::join!(
                verify_dynamic_peer_reflexive(
                    &mut creator, &local, &stale, &creator_proof,
                    creator_tx, Duration::from_secs(4),
                ),
                verify_dynamic_peer_reflexive(
                    &mut joiner, &remote, &local, &joiner_proof,
                    joiner_tx, Duration::from_secs(4),
                ),
                async { creator_rx.recv().await },
                async { joiner_rx.recv().await },
            );
            left.unwrap();
            right.unwrap();
            assert_eq!(authenticated_left, Some(joiner_address));
            assert_eq!(authenticated_right, Some(creator_address));
        }).await.unwrap();
    }

    #[tokio::test]
    async fn valid_hmac_without_ice_nomination_never_reaches_quic() {
        tokio::time::timeout(Duration::from_secs(4), async {
            let mut a = UdpOwner::bind("127.0.0.1:0".parse().unwrap())
                .await.unwrap();
            let b = UdpOwner::bind("127.0.0.1:0".parse().unwrap())
                .await.unwrap();
            let local = gather(&a.handle, &[], IceRole::Controlling,
                Duration::from_millis(20)).await.unwrap().description;
            let remote = gather(&b.handle, &[], IceRole::Controlled,
                Duration::from_millis(20)).await.unwrap().description;
            let credentials = crate::session_binding::SessionCredentials::new(
                [43; 16], [1; 32],
            ).unwrap();
            let proof = AuthenticatedPunch::new(
                credentials.clone(), IceRole::Controlling,
            );
            let valid = AuthenticatedPunch::new(
                credentials, IceRole::Controlled,
            );
            let destination = a.handle.local_address();
            let (tx, mut rx) = mpsc::channel(2);
            let (result, _) = tokio::join!(
                verify_dynamic_peer_reflexive(
                    &mut a, &local, &remote, &proof,
                    tx, Duration::from_millis(700),
                ),
                async {
                    let packet = valid.make_packet(unix_seconds().unwrap()).unwrap();
                    b.handle.send_punch(destination, &packet).await.unwrap();
                    // 对端故意不执行 ICE Agent；合法 HMAC 也不能越权。
                },
            );
            result.unwrap();
            assert!(rx.try_recv().is_err());
        }).await.unwrap();
    }

    #[tokio::test]
    async fn forged_punch_cannot_nominate_dynamic_quic_address() {
        tokio::time::timeout(Duration::from_secs(4), async {
            let mut a = UdpOwner::bind("127.0.0.1:0".parse().unwrap())
                .await.unwrap();
            let b = UdpOwner::bind("127.0.0.1:0".parse().unwrap())
                .await.unwrap();
            let local = gather(&a.handle, &[], IceRole::Controlling,
                Duration::from_millis(20)).await.unwrap().description;
            let remote = gather(&b.handle, &[], IceRole::Controlled,
                Duration::from_millis(20)).await.unwrap().description;
            let proof = AuthenticatedPunch::new(
                crate::session_binding::SessionCredentials::new(
                    [42; 16], [1; 32],
                ).unwrap(), IceRole::Controlling,
            );
            let wrong = AuthenticatedPunch::new(
                crate::session_binding::SessionCredentials::new(
                    [42; 16], [2; 32],
                ).unwrap(), IceRole::Controlled,
            );
            let (tx, mut rx) = mpsc::channel(2);
            let destination = a.handle.local_address();
            let result = tokio::join!(
                verify_dynamic_peer_reflexive(
                    &mut a, &local, &remote, &proof,
                    tx, Duration::from_millis(600),
                ),
                async {
                    let packet = wrong.make_packet(unix_seconds().unwrap()).unwrap();
                    b.handle.send_punch(destination, &packet).await.unwrap();
                },
            );
            result.0.unwrap();
            assert!(rx.try_recv().is_err());
        }).await.unwrap();
    }

    #[tokio::test]
    async fn late_authenticated_peer_source_can_nominate_after_old_probe_window() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let mut creator = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let mut joiner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let creator_address = creator.handle.local_address();
            let joiner_address = joiner.handle.local_address();
            let local = gather(&creator.handle, &[], IceRole::Controlling,
                Duration::from_millis(100)).await.unwrap().description;
            let remote = gather(&joiner.handle, &[], IceRole::Controlled,
                Duration::from_millis(100)).await.unwrap().description;
            // The signaled endpoint became stale. The true endpoint is only
            // learned from session-authenticated traffic after 900ms.
            let mut stale = remote.clone();
            stale.candidates[0].address = "127.0.0.1:9".parse().unwrap();
            let credentials = crate::session_binding::SessionCredentials::new(
                [5; 16], [7; 32],
            ).unwrap();
            let creator_proof = AuthenticatedPunch::new(
                credentials.clone(), IceRole::Controlling,
            );
            let joiner_proof = AuthenticatedPunch::new(
                credentials, IceRole::Controlled,
            );
            let (left, right) = tokio::join!(
                nominate_with_authenticated_punch(
                    &mut creator, &local, &stale,
                    &creator_proof, Duration::from_secs(6),
                ),
                async {
                    tokio::time::sleep(Duration::from_millis(900)).await;
                    nominate_with_authenticated_punch(
                        &mut joiner, &remote, &local,
                        &joiner_proof, Duration::from_secs(5),
                    ).await
                },
            );
            assert_eq!(left.unwrap().remote, joiner_address);
            assert_eq!(right.unwrap().remote, creator_address);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn prefers_reachable_host_candidate_over_invalid_public_fallback() {
        let mut a = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut b = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut left = gather(&a.handle, &[], IceRole::Controlling, Duration::from_secs(1))
            .await.unwrap().description;
        let mut right = gather(&b.handle, &[], IceRole::Controlled, Duration::from_secs(1))
            .await.unwrap().description;
        left.candidates.push(crate::ice_signaling::IceCandidate {
            address: "198.51.100.10:34780".parse().unwrap(),
            kind: IceCandidateType::ServerReflexive, priority: 1,
        });
        right.candidates.push(crate::ice_signaling::IceCandidate {
            address: "198.51.100.11:34781".parse().unwrap(),
            kind: IceCandidateType::ServerReflexive, priority: 1,
        });
        let (lr, rl) = tokio::join!(
            nominate_direct_candidates(&mut a, &left, &right, Duration::from_secs(5)),
            nominate_direct_candidates(&mut b, &right, &left, Duration::from_secs(5)),
        );
        assert_eq!(lr.unwrap().remote, b.handle.local_address());
        assert_eq!(rl.unwrap().remote, a.handle.local_address());
    }

    #[tokio::test]
    async fn rejects_roles_that_conflict_or_missing_base() {
        let mut a = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let desc = gather(&a.handle, &[], IceRole::Controlling, Duration::from_secs(1))
            .await.unwrap().description;
        assert_eq!(
            nominate_direct_candidates(&mut a, &desc, &desc, Duration::from_secs(1)).await,
            Err(IceCheckError::InvalidCredentials)
        );
    }
}
