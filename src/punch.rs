//! Domain-separated, replay-resistant authenticated UDP punch probes.
//! Probes travel through the SAME owner-bound UDP port as ICE and QUIC.
//! No relay or data payload is carried, and candidate addresses learned from
//! probes are never usable until the standard ICE checker verifies them.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ice_signaling::{IceDescription, IceRole},
    session_binding::SessionCredentials,
    udp_owner::{UdpOwnerError, UdpOwnerHandle},
};

pub const PUNCH_MAGIC: &[u8; 4] = b"P2PP";
pub const PACKET_BYTES: usize = 55;
const VERSION: u8 = 1;
const TAG_AT: usize = PACKET_BYTES - 32;
const NONCE_START: usize = TAG_AT - 8;
const MAX_CLOCK_SKEW_SECS: u64 = 30;
const MAX_NONCES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PunchError {
    InvalidPacket,
    InvalidSource,
    InvalidTime,
    WrongRole,
    Unauthorized,
    Replayed,
    ReplayLimit,
    StatePoisoned,
    Entropy,
}

/// Own this guard for the duration of the authenticated pairing. Never create
/// a fresh instance per packet, or replay protection would be bypassed.
pub struct AuthenticatedPunch {
    credentials: SessionCredentials,
    role: IceRole,
    seen: Mutex<HashMap<[u8; 8], u64>>,
}

impl AuthenticatedPunch {
    pub fn new(credentials: SessionCredentials, role: IceRole) -> Self {
        Self { credentials, role, seen: Mutex::new(HashMap::new()) }
    }

    pub fn make_packet(&self, now_seconds: u64) -> Result<[u8; PACKET_BYTES], PunchError> {
        if now_seconds == 0 { return Err(PunchError::InvalidTime); }
        let mut packet = [0u8; PACKET_BYTES];
        packet[0] = 0;
        packet[1..5].copy_from_slice(PUNCH_MAGIC);
        packet[5] = VERSION;
        packet[6] = role_byte(self.role);
        packet[7..15].copy_from_slice(&now_seconds.to_be_bytes());
        getrandom::fill(&mut packet[NONCE_START..TAG_AT])
            .map_err(|_| PunchError::Entropy)?;
        let tag = self.credentials.punch_tag(&packet[..TAG_AT]);
        packet[TAG_AT..].copy_from_slice(&tag);
        Ok(packet)
    }

    /// Return the dynamically observed source address only after verifying
    /// the session key, opposite role, timestamp and unique random nonce.
    /// This is a potential peer-reflexive candidate, NOT an ICE nomination.
    pub fn authenticate(
        &self,
        datagram: &[u8],
        source: SocketAddr,
        now_seconds: u64,
    ) -> Result<SocketAddr, PunchError> {
        if source.port() == 0 || source.ip().is_unspecified()
            || source.ip().is_multicast()
        {
            return Err(PunchError::InvalidSource);
        }
        if datagram.len() != PACKET_BYTES || datagram[0] != 0
            || &datagram[1..5] != PUNCH_MAGIC || datagram[5] != VERSION
        {
            return Err(PunchError::InvalidPacket);
        }
        if datagram[6] != role_byte(opposite(self.role)) {
            return Err(PunchError::WrongRole);
        }
        let time = u64::from_be_bytes(datagram[7..15].try_into()
            .map_err(|_| PunchError::InvalidPacket)?);
        if time == 0 || time.abs_diff(now_seconds) > MAX_CLOCK_SKEW_SECS {
            return Err(PunchError::InvalidTime);
        }
        if !self.credentials.verify_punch_tag(
            &datagram[..TAG_AT], &datagram[TAG_AT..],
        ) {
            return Err(PunchError::Unauthorized);
        }
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&datagram[NONCE_START..TAG_AT]);
        let mut seen = self.seen.lock().map_err(|_| PunchError::StatePoisoned)?;
        seen.retain(|_, time| time.abs_diff(now_seconds) <= MAX_CLOCK_SKEW_SECS);
        if seen.contains_key(&nonce) { return Err(PunchError::Replayed); }
        if seen.len() >= MAX_NONCES { return Err(PunchError::ReplayLimit); }
        seen.insert(nonce, now_seconds);
        Ok(source)
    }

    /// Use an authenticated/confirmed remote ICE description. Sending to
    /// an unverified description would permit traffic amplification.
    /// This function intentionally makes no reachability claim.
    pub async fn send_to_candidates(
        &self,
        handle: &UdpOwnerHandle,
        remote: &IceDescription,
    ) -> Result<usize, UdpOwnerError> {
        let now = unix_seconds().map_err(|_| UdpOwnerError::Io)?;
        if remote.validate().is_err() || remote.role != opposite(self.role) {
            return Err(UdpOwnerError::Io);
        }
        let mut sent = 0usize;
        for candidate in &remote.candidates {
            if candidate.address.is_ipv4() == handle.local_address().is_ipv4() {
                // Fresh nonce per destination allows independently validated
                // peer-reflexive paths without false replay collisions.
                let packet = self.make_packet(now).map_err(|_| UdpOwnerError::Entropy)?;
                handle.send_punch(candidate.address, &packet).await?;
                sent += 1;
            }
        }
        Ok(sent)
    }
}

pub fn unix_seconds() -> Result<u64, PunchError> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).map_err(|_| PunchError::InvalidTime)
}

fn role_byte(role: IceRole) -> u8 {
    match role {
        IceRole::Controlling => 1,
        IceRole::Controlled => 2,
    }
}
fn opposite(role: IceRole) -> IceRole {
    match role {
        IceRole::Controlling => IceRole::Controlled,
        IceRole::Controlled => IceRole::Controlling,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_binding::SessionCredentials;

    fn peers() -> (AuthenticatedPunch, AuthenticatedPunch) {
        let a = SessionCredentials::new([7;16],[11;32]).unwrap();
        let b = a.clone();
        (AuthenticatedPunch::new(a, IceRole::Controlling),
            AuthenticatedPunch::new(b, IceRole::Controlled))
    }

    #[test]
    fn authenticates_same_session_other_role_and_rejects_replay() {
        let (a, b) = peers();
        let bytes = a.make_packet(10_000).unwrap();
        let addr = "192.0.2.50:54444".parse().unwrap();
        assert_eq!(b.authenticate(&bytes, addr, 10_003), Ok(addr));
        assert_eq!(b.authenticate(&bytes, addr, 10_003), Err(PunchError::Replayed));
        assert_eq!(a.authenticate(&bytes, addr, 10_003), Err(PunchError::WrongRole));
        assert_eq!(b.authenticate(&bytes, addr, 10_100), Err(PunchError::InvalidTime));
    }

    #[test]
    fn tampering_or_foreign_session_is_rejected_before_learning_ip() {
        let (a, b) = peers();
        let addr = "198.51.100.35:54000".parse().unwrap();
        let bytes = a.make_packet(100).unwrap();
        let mut damaged = bytes;
        damaged[NONCE_START] ^= 1;
        assert_eq!(b.authenticate(&damaged, addr, 100), Err(PunchError::Unauthorized));
        let stranger = AuthenticatedPunch::new(
            SessionCredentials::new([7;16],[12;32]).unwrap(), IceRole::Controlled);
        assert_eq!(stranger.authenticate(&bytes, addr, 100), Err(PunchError::Unauthorized));
        assert_eq!(b.authenticate(&bytes, "0.0.0.0:0".parse().unwrap(), 100),
            Err(PunchError::InvalidSource));
    }
}
