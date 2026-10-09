//! Standard ICE candidate-pair checks on the SDK's existing UDP owner.
//!
//! Uses the sans-I/O `is` ICE agent to authenticate STUN MESSAGE-INTEGRITY,
//! perform direct candidate checks, resolve roles and nominate a pair.
//! TURN and relayed candidates are NEVER exposed by this API.
//!
//! MVP: one bound host candidate and one remote host candidate on the same
//! IPv4/IPv6 family. STUN srflx/port-mapped candidate integration, consent
//! monitoring, restart, and full multi-interface gathering are next gates.
//! A successful localhost nomination is NOT a cross-NAT result.

use std::{net::SocketAddr, time::{Duration, Instant}};

use is::{
    stun::{StunMessage, StunPacket},
    Candidate, IceAgent, IceAgentEvent, IceCreds, Protocol,
};
use tokio::time::{sleep, timeout};

use crate::udp_owner::{UdpOwner, UdpOwnerError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IceCheckError {
    InvalidCandidate,
    InvalidCredentials,
    UdpOwnerClosed,
    NoDirectPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NominatedPath {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// Complete authenticated direct checks for an already-running UDP owner.
///
/// Both endpoints must exchange candidates and ICE credentials by authenticated
/// signaling first, then independently call this function. The owner remains
/// alive when the function returns and is reused by Quinn on the SAME port.
pub async fn nominate_host_pair(
    owner: &mut UdpOwner,
    remote: SocketAddr,
    local_credentials: IceCreds,
    remote_credentials: IceCreds,
    controlling: bool,
    limit: Duration,
) -> Result<NominatedPath, IceCheckError> {
    let local = owner.handle.local_address();
    if remote.port() == 0 || remote.ip().is_unspecified() || remote.is_ipv4() != local.is_ipv4()
        || limit.is_zero()
    {
        return Err(IceCheckError::InvalidCandidate);
    }
    if local_credentials.ufrag.is_empty() || local_credentials.pass.is_empty()
        || remote_credentials.ufrag.is_empty() || remote_credentials.pass.is_empty()
    {
        return Err(IceCheckError::InvalidCredentials);
    }

    let mut agent = IceAgent::new(local_credentials);
    agent.set_controlling(controlling);
    agent.set_remote_credentials(remote_credentials);
    let local_candidate = Candidate::host(local, "udp").map_err(|_| IceCheckError::InvalidCandidate)?;
    let remote_candidate = Candidate::host(remote, "udp").map_err(|_| IceCheckError::InvalidCandidate)?;
    agent.add_local_candidate(local_candidate);
    agent.add_remote_candidate(remote_candidate);
    let future = async {
        loop {
            agent.handle_timeout(Instant::now());
            while let Some(transmit) = agent.poll_transmit() {
                if transmit.source != local || transmit.proto != Protocol::Udp {
                    return Err(IceCheckError::InvalidCandidate);
                }
                owner.handle.send_ice(transmit.destination, &transmit.contents).await
                    .map_err(|_| IceCheckError::UdpOwnerClosed)?;
            }
            while let Some(event) = agent.poll_event() {
                if let IceAgentEvent::NominatedSend { source, destination, proto } = event {
                    if proto == Protocol::Udp && source == local && destination == remote {
                        return Ok(NominatedPath { local: source, remote: destination });
                    }
                }
            }
            let now = Instant::now();
            let next = agent.poll_timeout().unwrap_or(now + Duration::from_millis(25));
            let delay = next.saturating_duration_since(now).max(Duration::from_millis(1));
            tokio::select! {
                packet = owner.ice_packets.recv() => {
                    let packet = packet.ok_or(IceCheckError::UdpOwnerClosed)?;
                    if let Ok(message) = StunMessage::parse(&packet.bytes) {
                        let incoming = StunPacket {
                            proto: Protocol::Udp,
                            source: packet.source,
                            destination: local,
                            message,
                        };
                        agent.handle_packet(Instant::now(), incoming);
                    }
                }
                _ = sleep(delay) => {}
            }
        }
    };
    match timeout(limit, future).await {
        Ok(result) => result,
        Err(_) => Err(IceCheckError::NoDirectPath),
    }
}

/// Convert the SDK ICE signaling model into the ICE agent's credential type.
/// This is not a TLS identity, does not contain a durable device secret,
/// and is only suitable for RFC 8445 short-term integrity.
pub fn credentials_from_description(desc: &crate::ice_signaling::IceDescription) -> IceCreds {
    IceCreds {
        ufrag: desc.ufrag.clone(),
        pass: desc.password.clone(),
    }
}

/// Create randomly generated ICE credentials for offer/answer signaling.
pub fn new_ice_credentials() -> IceCreds {
    IceCreds::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn two_real_udp_owners_nominate_authenticated_host_candidate_pair() {
        let mut first = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut second = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let first_addr = first.handle.local_address();
        let second_addr = second.handle.local_address();
        let first_creds = new_ice_credentials();
        let second_creds = new_ice_credentials();
        let checks = async {
            tokio::join!(
                nominate_host_pair(&mut first, second_addr, first_creds.clone(), second_creds.clone(), true, Duration::from_secs(5)),
                nominate_host_pair(&mut second, first_addr, second_creds, first_creds, false, Duration::from_secs(5)),
            )
        };
        let (a, b) = tokio::time::timeout(Duration::from_secs(10), checks).await.unwrap();
        assert_eq!(a.unwrap(), NominatedPath { local: first_addr, remote: second_addr });
        assert_eq!(b.unwrap(), NominatedPath { local: second_addr, remote: first_addr });
    }

    #[tokio::test]
    async fn fails_closed_when_peer_has_no_direct_udp_path() {
        let mut owner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let local = new_ice_credentials();
        let remote = new_ice_credentials();
        let result = nominate_host_pair(
            &mut owner, "127.0.0.1:9".parse().unwrap(),
            local, remote, true, Duration::from_millis(150),
        ).await;
        assert_eq!(result, Err(IceCheckError::NoDirectPath));
    }

    #[tokio::test]
    async fn rejects_invalid_or_mixed_family_candidate() {
        let mut owner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let creds = new_ice_credentials();
        let result = nominate_host_pair(
            &mut owner, "[::1]:9000".parse().unwrap(), creds.clone(),
            new_ice_credentials(), true, Duration::from_secs(1),
        ).await;
        assert_eq!(result, Err(IceCheckError::InvalidCandidate));
    }
}
