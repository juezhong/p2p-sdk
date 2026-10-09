//! Transport-agnostic ICE candidate metadata.
//! Priority here is an application *preference*, never proof of reachability.

use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Family {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransportProtocol {
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
    PortMapped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub address: SocketAddr,
    pub kind: CandidateKind,
    pub transport: TransportProtocol,
}

impl Candidate {
    pub fn family(&self) -> Family {
        match self.address.ip() {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }

    pub fn is_usable_endpoint(&self) -> bool {
        let ip = self.address.ip();
        self.address.port() != 0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()
    }

    /// Deterministic UI/debug preference; an ICE agent must perform real checks.
    pub fn preference_key(&self, prefer_ipv6: bool) -> (u8, u8) {
        let family_rank = match (self.family(), prefer_ipv6) {
            (Family::Ipv6, true) | (Family::Ipv4, false) => 0,
            _ => 1,
        };
        let type_rank = match self.kind {
            CandidateKind::Host => 0,
            CandidateKind::PortMapped => 1,
            CandidateKind::ServerReflexive => 2,
            CandidateKind::PeerReflexive => 3,
        };
        (family_rank, type_rank)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(ip: &str, kind: CandidateKind) -> Candidate {
        Candidate {
            address: SocketAddr::new(ip.parse().unwrap(), 4433),
            kind,
            transport: TransportProtocol::Udp,
        }
    }

    #[test]
    fn default_preference_places_ipv6_first() {
        let ipv6 = candidate("2001:db8::1", CandidateKind::Host);
        let ipv4 = candidate("192.0.2.1", CandidateKind::Host);
        assert!(ipv6.preference_key(true) < ipv4.preference_key(true));
        assert!(ipv4.preference_key(false) < ipv6.preference_key(false));
    }

    #[test]
    fn rejects_non_routable_placeholder_endpoints() {
        assert!(!candidate("127.0.0.1", CandidateKind::Host).is_usable_endpoint());
        assert!(!candidate("::1", CandidateKind::Host).is_usable_endpoint());
        assert!(!candidate("0.0.0.0", CandidateKind::Host).is_usable_endpoint());
        assert!(candidate("192.168.1.10", CandidateKind::Host).is_usable_endpoint());
    }
}
