//! Bounded ICE signaling payload for the manually exchanged offer/answer.
//!
//! This is a strict encoding building block, not a full ICE agent. ICE
//! passwords are secrets: never log, persist, or display decoded payloads.
//! The caller must authenticate this payload as part of the pairing transcript.
//! It must not be treated as trusted merely because it parses correctly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAX_CANDIDATES: usize = 32;
pub const MAX_ICE_SIGNAL_SIZE: usize = 4096;
const MAGIC: &[u8; 4] = b"P2IC";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IceSignalError {
    InvalidCredentials,
    TooManyCandidates,
    InvalidCandidate,
    InvalidFormat,
    UnsupportedVersion,
    Truncated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IceRole {
    Controlling,
    Controlled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IceCandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    PortMapped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IceCandidate {
    pub address: SocketAddr,
    pub kind: IceCandidateType,
    pub priority: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct IceDescription {
    pub role: IceRole,
    pub ufrag: String,
    pub password: String,
    pub candidates: Vec<IceCandidate>,
}

impl std::fmt::Debug for IceDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceDescription")
            .field("role", &self.role)
            .field("ufrag", &"[redacted]")
            .field("password", &"[redacted]")
            .field("candidate_count", &self.candidates.len())
            .finish()
    }
}

impl IceDescription {
    pub fn validate(&self) -> Result<(), IceSignalError> {
        if !(4..=256).contains(&self.ufrag.len())
            || !(22..=256).contains(&self.password.len())
            || !self.ufrag.bytes().all(is_ice_char)
            || !self.password.bytes().all(is_ice_char)
        {
            return Err(IceSignalError::InvalidCredentials);
        }
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(IceSignalError::TooManyCandidates);
        }
        for candidate in &self.candidates {
            let ip = candidate.address.ip();
            if candidate.address.port() == 0
                || ip.is_unspecified()
                || ip.is_multicast()
            {
                return Err(IceSignalError::InvalidCandidate);
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, IceSignalError> {
        self.validate()?;
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(match self.role {
            IceRole::Controlling => 1,
            IceRole::Controlled => 2,
        });
        out.push(self.ufrag.len() as u8);
        out.push(self.password.len() as u8);
        out.push(self.candidates.len() as u8);
        out.extend_from_slice(self.ufrag.as_bytes());
        out.extend_from_slice(self.password.as_bytes());
        for c in &self.candidates {
            out.push(match c.kind {
                IceCandidateType::Host => 1,
                IceCandidateType::ServerReflexive => 2,
                IceCandidateType::PeerReflexive => 3,
                IceCandidateType::PortMapped => 4,
            });
            match c.address.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&ip.octets());
                }
            }
            out.extend_from_slice(&c.address.port().to_be_bytes());
            out.extend_from_slice(&c.priority.to_be_bytes());
        }
        if out.len() > MAX_ICE_SIGNAL_SIZE {
            return Err(IceSignalError::InvalidFormat);
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, IceSignalError> {
        if data.len() > MAX_ICE_SIGNAL_SIZE || data.len() < 9 || &data[..4] != MAGIC {
            return Err(IceSignalError::InvalidFormat);
        }
        if data[4] != VERSION {
            return Err(IceSignalError::UnsupportedVersion);
        }
        let role = match data[5] {
            1 => IceRole::Controlling,
            2 => IceRole::Controlled,
            _ => return Err(IceSignalError::InvalidFormat),
        };
        let ufrag_len = data[6] as usize;
        let pwd_len = data[7] as usize;
        let count = data[8] as usize;
        if count > MAX_CANDIDATES {
            return Err(IceSignalError::TooManyCandidates);
        }
        let mut pos = 9;
        let ufrag = take(data, &mut pos, ufrag_len)?;
        let password = take(data, &mut pos, pwd_len)?;
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count {
            let head = take(data, &mut pos, 2)?;
            let kind = match head[0] {
                1 => IceCandidateType::Host,
                2 => IceCandidateType::ServerReflexive,
                3 => IceCandidateType::PeerReflexive,
                4 => IceCandidateType::PortMapped,
                _ => return Err(IceSignalError::InvalidFormat),
            };
            let ip = match head[1] {
                4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(take(data, &mut pos, 4)?).unwrap())),
                6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(take(data, &mut pos, 16)?).unwrap())),
                _ => return Err(IceSignalError::InvalidFormat),
            };
            let port = u16::from_be_bytes(take(data, &mut pos, 2)?.try_into().unwrap());
            let priority = u32::from_be_bytes(take(data, &mut pos, 4)?.try_into().unwrap());
            candidates.push(IceCandidate {
                address: SocketAddr::new(ip, port),
                kind,
                priority,
            });
        }
        if pos != data.len() {
            return Err(IceSignalError::InvalidFormat);
        }
        let desc = Self {
            role,
            ufrag: std::str::from_utf8(ufrag).map_err(|_| IceSignalError::InvalidCredentials)?.to_owned(),
            password: std::str::from_utf8(password).map_err(|_| IceSignalError::InvalidCredentials)?.to_owned(),
            candidates,
        };
        desc.validate()?;
        Ok(desc)
    }
}

fn is_ice_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'+' | b'/')
}

fn take<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], IceSignalError> {
    let end = pos.checked_add(n).ok_or(IceSignalError::Truncated)?;
    let s = data.get(*pos..end).ok_or(IceSignalError::Truncated)?;
    *pos = end;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc() -> IceDescription {
        IceDescription {
            role: IceRole::Controlling,
            ufrag: "Abcd1234".into(),
            password: "abcdefghijklmnopqrstuv012345".into(),
            candidates: vec![
                IceCandidate { address: "192.168.1.20:43567".parse().unwrap(), kind: IceCandidateType::Host, priority: 2_123_456 },
                IceCandidate { address: "[2001:db8::10]:4433".parse().unwrap(), kind: IceCandidateType::ServerReflexive, priority: 2_000_000 },
            ],
        }
    }

    #[test]
    fn roundtrip_dual_stack_candidates_and_roles() {
        for role in [IceRole::Controlling, IceRole::Controlled] {
            let mut d = desc();
            d.role = role;
            let bytes = d.encode().unwrap();
            assert_eq!(IceDescription::decode(&bytes), Ok(d));
        }
    }

    #[test]
    fn rejects_truncated_extra_data_and_invalid_version() {
        let mut wire = desc().encode().unwrap();
        for len in [0, 3, 8, 9, wire.len() - 1] {
            assert!(IceDescription::decode(&wire[..len]).is_err());
        }
        wire.push(3);
        assert_eq!(IceDescription::decode(&wire), Err(IceSignalError::InvalidFormat));
        wire.pop();
        wire[4] = 7;
        assert_eq!(IceDescription::decode(&wire), Err(IceSignalError::UnsupportedVersion));
    }

    #[test]
    fn refuses_unsafe_candidates_and_large_counts() {
        let mut d = desc();
        d.candidates[0].address = "0.0.0.0:0".parse().unwrap();
        assert_eq!(d.encode(), Err(IceSignalError::InvalidCandidate));
        d = desc();
        d.candidates = vec![d.candidates[0].clone(); MAX_CANDIDATES + 1];
        assert_eq!(d.encode(), Err(IceSignalError::TooManyCandidates));
    }

    #[test]
    fn does_not_disclose_credentials_when_debugging() {
        let formatted = format!("{:?}", desc());
        assert!(!formatted.contains("abcdefghijkl"));
        assert!(!formatted.contains("Abcd1234"));
    }

    #[test]
    fn rejects_bad_ice_credentials() {
        let mut d = desc();
        d.password = "too-short".into();
        assert_eq!(d.encode(), Err(IceSignalError::InvalidCredentials));
    }
}
