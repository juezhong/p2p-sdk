//! Offline INVITE/REPLY v2: carry bounded ICE credentials/candidates.
//!
//! V2 wraps the existing ephemeral X25519 invite/reply. The responder's reply
//! commits to the EXACT offer (including ICE bytes) and authenticates its ICE
//! answer with the locally derived session key. The initiator detects tampered
//! offers and replies; the responder must still require an out-of-band
//! comparison-code confirmation against an active MITM. Do not log codes:
//! they contain private network addresses and short-term ICE passwords.
//!
//! NOTE: legacy v1 pairing and this v2 wire format are different. v2 is the
//! SDK's new Rust protocol; no Go p2p-friend compatibility is claimed.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use crate::{
    ice_signaling::{IceDescription, IceRole, IceSignalError, MAX_ICE_SIGNAL_SIZE},
    manual_pairing::{respond as respond_v1, ManualError, ManualInviteState, ManualPairing},
};

const INVITE_PREFIX: &str = "P2PR-INV2-";
const REPLY_PREFIX: &str = "P2PR-REP2-";
const INVITE_MAGIC: &[u8; 4] = b"P2I2";
const REPLY_MAGIC: &[u8; 4] = b"P2R2";
const MAX_BINARY: usize = MAX_ICE_SIGNAL_SIZE + 1024;
const HASH_LENGTH: usize = 32;
const PROOF_LENGTH: usize = 32;
const CONTROLLED_ROLE: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualIceError {
    InvalidCode,
    TooLarge,
    InvalidRole,
    OfferMismatch,
    BadReplyProof,
    Manual(ManualError),
    Ice(IceSignalError),
}

impl From<ManualError> for ManualIceError {
    fn from(value: ManualError) -> Self {
        Self::Manual(value)
    }
}

impl From<IceSignalError> for ManualIceError {
    fn from(value: IceSignalError) -> Self {
        Self::Ice(value)
    }
}

pub struct ManualIceInvite {
    inner: ManualInviteState,
    offer_hash: [u8; 32],
}

/// Create an INVITE with one candidate set gathered on the UDP port Quinn
/// will later use. The caller MUST ensure that local candidates actually
/// originate from that endpoint, not an unrelated STUN probing socket.
pub fn invite(
    now: u64,
    lifetime_secs: u64,
    local_cert_pin: [u8; 32],
    controlling: &IceDescription,
) -> Result<(ManualIceInvite, String), ManualIceError> {
    if controlling.role != IceRole::Controlling {
        return Err(ManualIceError::InvalidRole);
    }
    let (inner, invite_v1) =
        ManualInviteState::create(now, lifetime_secs, local_cert_pin)?;
    let offer = wrap(INVITE_MAGIC, invite_v1.as_bytes(), &controlling.encode()?, &[])?;
    let offer_hash = digest(&offer);
    Ok((
        ManualIceInvite { inner, offer_hash },
        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(offer)),
    ))
}

/// Validate an INVITE's ICE schema and lifetime before prompting the user.
/// The ICE information is not authenticated *until* the reply is checked and
/// the human verification code is independently confirmed by both devices.
pub fn inspect_invite(
    code: &str,
    now: u64,
) -> Result<IceDescription, ManualIceError> {
    let offer = decode_wire(code, INVITE_PREFIX, INVITE_MAGIC)?;
    let (inner, ice, tail) = split_wire(&offer)?;
    if !tail.is_empty() {
        return Err(ManualIceError::InvalidCode);
    }
    let v1 = std::str::from_utf8(inner).map_err(|_| ManualIceError::InvalidCode)?;
    crate::manual_pairing::preview_invite(v1, now)?;
    let desc = IceDescription::decode(ice)?;
    if desc.role != IceRole::Controlling {
        return Err(ManualIceError::InvalidRole);
    }
    Ok(desc)
}

/// Generate a single REPLY and the internal session key on the responder.
/// The reply's MAC binds its answer to the COMPLETE offer transcript.
pub fn respond(
    invite_code: &str,
    now: u64,
    local_cert_pin: [u8; 32],
    controlled: &IceDescription,
) -> Result<(String, ManualPairing, IceDescription), ManualIceError> {
    if controlled.role != IceRole::Controlled {
        return Err(ManualIceError::InvalidRole);
    }
    let offer = decode_wire(invite_code, INVITE_PREFIX, INVITE_MAGIC)?;
    let (inner, candidate_bytes, tail) = split_wire(&offer)?;
    if !tail.is_empty() {
        return Err(ManualIceError::InvalidCode);
    }
    let offer_desc = IceDescription::decode(candidate_bytes)?;
    if offer_desc.role != IceRole::Controlling {
        return Err(ManualIceError::InvalidRole);
    }
    let inner_text = std::str::from_utf8(inner).map_err(|_| ManualIceError::InvalidCode)?;
    let (reply_v1, pairing) = respond_v1(inner_text, now, local_cert_pin)?;
    let offer_hash = digest(&offer);
    let mut reply = wrap(
        REPLY_MAGIC,
        reply_v1.as_bytes(),
        &controlled.encode()?,
        &offer_hash,
    )?;
    let tag = pairing.credentials.ice_signal_tag(CONTROLLED_ROLE, &reply);
    reply.extend_from_slice(&tag);
    if reply.len() > MAX_BINARY {
        return Err(ManualIceError::TooLarge);
    }
    Ok((
        format!("{REPLY_PREFIX}{}", URL_SAFE_NO_PAD.encode(reply)),
        pairing,
        offer_desc,
    ))
}

impl ManualIceInvite {
    /// Consume the invite's ephemeral private key. A successful return gives
    /// the locally derived Session Secret and authenticated remote ICE answer.
    pub fn finish(
        self,
        reply_code: &str,
        now: u64,
    ) -> Result<(ManualPairing, IceDescription), ManualIceError> {
        let reply = decode_wire(reply_code, REPLY_PREFIX, REPLY_MAGIC)?;
        let (inner, ice, tail) = split_wire(&reply)?;
        if tail.len() != HASH_LENGTH + PROOF_LENGTH {
            return Err(ManualIceError::InvalidCode);
        }
        if tail[..HASH_LENGTH] != self.offer_hash {
            return Err(ManualIceError::OfferMismatch);
        }
        let inner_text = std::str::from_utf8(inner).map_err(|_| ManualIceError::InvalidCode)?;
        let pairing = self.inner.finish(inner_text, now)?;
        if !pairing.credentials.verify_ice_signal(
            CONTROLLED_ROLE,
            &reply[..reply.len() - PROOF_LENGTH],
            &reply[reply.len() - PROOF_LENGTH..],
        ) {
            return Err(ManualIceError::BadReplyProof);
        }
        let remote = IceDescription::decode(ice)?;
        if remote.role != IceRole::Controlled {
            return Err(ManualIceError::InvalidRole);
        }
        Ok((pairing, remote))
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn wrap(
    magic: &[u8; 4],
    old_code: &[u8],
    ice: &[u8],
    tail: &[u8],
) -> Result<Vec<u8>, ManualIceError> {
    if old_code.is_empty() || ice.is_empty()
        || old_code.len() > u16::MAX as usize
        || ice.len() > MAX_ICE_SIGNAL_SIZE
    {
        return Err(ManualIceError::InvalidCode);
    }
    let n = 4 + 2 + old_code.len() + 2 + ice.len() + tail.len();
    if n > MAX_BINARY {
        return Err(ManualIceError::TooLarge);
    }
    let mut output = Vec::with_capacity(n);
    output.extend_from_slice(magic);
    output.extend_from_slice(&(old_code.len() as u16).to_be_bytes());
    output.extend_from_slice(old_code);
    output.extend_from_slice(&(ice.len() as u16).to_be_bytes());
    output.extend_from_slice(ice);
    output.extend_from_slice(tail);
    Ok(output)
}

fn decode_wire(
    code: &str,
    prefix: &str,
    magic: &[u8; 4],
) -> Result<Vec<u8>, ManualIceError> {
    let raw = code.strip_prefix(prefix).ok_or(ManualIceError::InvalidCode)?;
    if raw.len() > MAX_BINARY.div_ceil(3) * 4 || raw.len() < 12 {
        return Err(ManualIceError::TooLarge);
    }
    let packet = URL_SAFE_NO_PAD.decode(raw).map_err(|_| ManualIceError::InvalidCode)?;
    if packet.len() > MAX_BINARY || !packet.starts_with(magic) {
        return Err(ManualIceError::InvalidCode);
    }
    Ok(packet)
}

type WireSections<'a> = (&'a [u8], &'a [u8], &'a [u8]);

fn split_wire(bytes: &[u8]) -> Result<WireSections<'_>, ManualIceError> {
    if bytes.len() < 9 {
        return Err(ManualIceError::InvalidCode);
    }
    let old_n = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let old_end = 6usize.checked_add(old_n).ok_or(ManualIceError::InvalidCode)?;
    let ice_len_end = old_end.checked_add(2).ok_or(ManualIceError::InvalidCode)?;
    let ice_len = bytes.get(old_end..ice_len_end).ok_or(ManualIceError::InvalidCode)?;
    let ice_n = u16::from_be_bytes([ice_len[0], ice_len[1]]) as usize;
    if old_n == 0 || ice_n == 0 || ice_n > MAX_ICE_SIGNAL_SIZE {
        return Err(ManualIceError::InvalidCode);
    }
    let ice_end = ice_len_end.checked_add(ice_n).ok_or(ManualIceError::InvalidCode)?;
    let old = bytes.get(6..old_end).ok_or(ManualIceError::InvalidCode)?;
    let ice = bytes.get(ice_len_end..ice_end).ok_or(ManualIceError::InvalidCode)?;
    let tail = bytes.get(ice_end..).ok_or(ManualIceError::InvalidCode)?;
    Ok((old, ice, tail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice_signaling::{IceCandidate, IceCandidateType};
    use std::str::FromStr;

    fn desc(role: IceRole, addr: &str) -> IceDescription {
        IceDescription {
            role,
            ufrag: "Abcd1234".into(),
            password: "abcdefghijklmnopqrstuv012345".into(),
            candidates: vec![IceCandidate {
                address: std::net::SocketAddr::from_str(addr).unwrap(),
                kind: IceCandidateType::Host,
                priority: 1,
            }],
        }
    }

    #[test]
    fn v2_complete_exchange_is_one_invite_and_one_reply() {
        let offer = desc(IceRole::Controlling, "192.168.0.2:34567");
        let answer = desc(IceRole::Controlled, "[2001:db8::1]:56789");
        let (state, code) = invite(100, 600, [1;32], &offer).unwrap();
        assert_eq!(inspect_invite(&code, 101), Ok(offer.clone()));
        let (reply, responder, received_offer) = respond(&code, 102, [2;32], &answer).unwrap();
        let (initiator, received_answer) = state.finish(&reply, 103).unwrap();
        assert_eq!(received_offer, offer);
        assert_eq!(received_answer, answer);
        assert_eq!(initiator.comparison_code, responder.comparison_code);
        assert_eq!(
            crate::session_binding::test_session_proof(
                &initiator.credentials, &[3; 32], &[4; 32]
            ),
            crate::session_binding::test_session_proof(
                &responder.credentials, &[3; 32], &[4; 32]
            )
        );
    }

    #[test]
    fn altered_offer_is_rejected_even_if_responder_answers_it() {
        let offer = desc(IceRole::Controlling, "127.0.0.1:1234");
        let (state, code) = invite(100, 100, [1;32], &offer).unwrap();
        let mut binary = decode_wire(&code, INVITE_PREFIX, INVITE_MAGIC).unwrap();
        // Replace the ICE candidate address, preserving its wire validity.
        let needle = [127, 0, 0, 1];
        let pos = binary.windows(4).position(|w| w == needle).unwrap();
        binary[pos..pos+4].copy_from_slice(&[127, 0, 0, 2]);
        let forged = format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(binary));
        let (reply, _, _) = respond(&forged, 102, [2;32], &desc(IceRole::Controlled, "127.0.0.3:2345")).unwrap();
        assert!(matches!(state.finish(&reply, 103), Err(ManualIceError::OfferMismatch)));
    }

    #[test]
    fn altered_ice_reply_is_rejected_by_session_mac() {
        let offer = desc(IceRole::Controlling, "127.0.0.1:1234");
        let (state, code) = invite(100, 100, [1;32], &offer).unwrap();
        let (reply, _, _) = respond(&code, 102, [2;32], &desc(IceRole::Controlled, "127.0.0.3:2345")).unwrap();
        let mut packet = decode_wire(&reply, REPLY_PREFIX, REPLY_MAGIC).unwrap();
        let pos = packet.windows(4).position(|w| w == [127,0,0,3]).unwrap();
        packet[pos+3] ^= 1;
        let modified = format!("{REPLY_PREFIX}{}", URL_SAFE_NO_PAD.encode(packet));
        assert!(matches!(state.finish(&modified, 103), Err(ManualIceError::BadReplyProof)));
    }

    #[test]
    fn rejects_wrong_role_and_expired_offer() {
        let controlled = desc(IceRole::Controlled, "127.0.0.2:1234");
        assert!(matches!(invite(100, 60, [1;32], &controlled), Err(ManualIceError::InvalidRole)));
        let controlling = desc(IceRole::Controlling, "127.0.0.1:1234");
        let (_, code) = invite(100, 60, [1;32], &controlling).unwrap();
        assert!(inspect_invite(&code, 160).is_err());
        assert!(matches!(respond(&code, 160, [2;32], &controlled), Err(ManualIceError::Manual(ManualError::Expired))));
    }
}
