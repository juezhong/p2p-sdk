//! Experimental offline INVITE/REPLY exchange with no signaling server.
//!
//! This exchanges public X25519 ephemeral keys and TLS certificate pins;
//! the 256-bit lane-binding secret is DERIVED LOCALLY, never displayed.
//! The manual codes are application signaling, NOT ICE candidates yet.
//!
//! IMPORTANT: Codes can be substituted by an active attacker. The two peers
//! must verify the six-digit comparison code over an independent trusted
//! channel and the SDK MUST enforce the advertised TLS certificate pin on
//! both QUIC connections before accepting file/business data.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::session_binding::SessionCredentials;

const INVITE_PREFIX: &str = "P2PR-INV1-";
const REPLY_PREFIX: &str = "P2PR-REP1-";
const INVITE_MAGIC: &[u8; 4] = b"P2PI";
const REPLY_MAGIC: &[u8; 4] = b"P2PA";
const VERSION: u8 = 1;
const OFFER_BYTES: usize = 109;
const REPLY_BYTES: usize = 141;
const MAX_LIFETIME_SECS: u64 = 1800;
const MIN_LIFETIME_SECS: u64 = 10;
const KEY_SALT_CONTEXT: &[u8] = b"p2p-sdk/manual-invite-reply-transcript/v1";
const KEY_INFO: &[u8] = b"p2p-sdk/manual-session-bindings/v1";
const VERIFY_INFO: &[u8] = b"p2p-sdk/manual-compare-code/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualError {
    InvalidLifetime,
    InvalidFingerprint,
    InvalidCode,
    InvalidVersion,
    Expired,
    SessionMismatch,
    OfferMismatch,
    WeakPublicKey,
    Entropy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitePreview {
    pub session_id: [u8; 16],
    pub expires_at: u64,
    /// Hash of the certificate that MUST be verified when Quinn connects.
    pub remote_tls_cert_sha256: [u8; 32],
}

/// One-time state. `finish` consumes the ephemeral private key.
pub struct ManualInviteState {
    offer: [u8; OFFER_BYTES],
    private_key: EphemeralSecret,
}

/// Contains a secret used by *both* QUIC roles; the secret is not serialized.
pub struct ManualPairing {
    pub credentials: SessionCredentials,
    /// Pin this on the actual QUIC peer cert; a code alone is not TLS verification.
    pub remote_tls_cert_sha256: [u8; 32],
    pub expires_at: u64,
    /// Both peers must compare this through an independent trusted channel.
    pub comparison_code: u32,
}

impl ManualPairing {
    pub fn comparison_code_text(&self) -> String {
        format!("{:06}", self.comparison_code)
    }
}

impl ManualInviteState {
    /// The TLS certificate fingerprint should refer to the certificate this
    /// endpoint will actually present during the QUIC handshake.
    pub fn create(
        now: u64,
        lifetime_secs: u64,
        local_tls_cert_sha256: [u8; 32],
    ) -> Result<(Self, String), ManualError> {
        if !(MIN_LIFETIME_SECS..=MAX_LIFETIME_SECS).contains(&lifetime_secs) {
            return Err(ManualError::InvalidLifetime);
        }
        if local_tls_cert_sha256 == [0; 32] {
            return Err(ManualError::InvalidFingerprint);
        }
        let expires_at = now.checked_add(lifetime_secs).ok_or(ManualError::InvalidLifetime)?;
        let mut offer = [0_u8; OFFER_BYTES];
        offer[..4].copy_from_slice(INVITE_MAGIC);
        offer[4] = VERSION;
        getrandom::fill(&mut offer[5..21]).map_err(|_| ManualError::Entropy)?;
        offer[21..29].copy_from_slice(&expires_at.to_be_bytes());
        let private_key = EphemeralSecret::random();
        offer[29..61].copy_from_slice(PublicKey::from(&private_key).as_bytes());
        offer[61..93].copy_from_slice(&local_tls_cert_sha256);
        getrandom::fill(&mut offer[93..109]).map_err(|_| ManualError::Entropy)?;
        let code = format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(offer));
        Ok((Self { offer, private_key }, code))
    }

    /// Consume exactly the REPLY generated for this INVITE.
    pub fn finish(self, reply_code: &str, now: u64) -> Result<ManualPairing, ManualError> {
        let reply = decode_code::<REPLY_BYTES>(reply_code, REPLY_PREFIX, REPLY_MAGIC)?;
        validate_expiry(&self.offer, now)?;
        validate_expiry(&reply, now)?;
        if reply[5..29] != self.offer[5..29] {
            return Err(ManualError::SessionMismatch);
        }
        if reply[109..141] != Sha256::digest(self.offer)[..] {
            return Err(ManualError::OfferMismatch);
        }
        if reply[61..93] == [0; 32] {
            return Err(ManualError::InvalidFingerprint);
        }
        let theirs = PublicKey::from(<[u8; 32]>::try_from(&reply[29..61]).unwrap());
        derive_pairing(
            self.private_key,
            theirs,
            &self.offer,
            &reply,
            <[u8; 32]>::try_from(&reply[61..93]).unwrap(),
        )
    }
}

/// Show an INVITE's claimed peer TLS pin before responding. Displaying the
/// pin does not prove its ownership: confirmation is performed separately.
pub fn preview_invite(code: &str, now: u64) -> Result<InvitePreview, ManualError> {
    let offer = decode_code::<OFFER_BYTES>(code, INVITE_PREFIX, INVITE_MAGIC)?;
    validate_expiry(&offer, now)?;
    if offer[61..93] == [0; 32] {
        return Err(ManualError::InvalidFingerprint);
    }
    Ok(InvitePreview {
        session_id: offer[5..21].try_into().unwrap(),
        expires_at: u64::from_be_bytes(offer[21..29].try_into().unwrap()),
        remote_tls_cert_sha256: offer[61..93].try_into().unwrap(),
    })
}

/// Generate a fresh REPLY and derive the same secret as the INVITE creator.
/// No secret is put in either code. Reply must be delivered back to the
/// initiator before ICE/QUIC starts using this session.
pub fn respond(
    invite_code: &str,
    now: u64,
    local_tls_cert_sha256: [u8; 32],
) -> Result<(String, ManualPairing), ManualError> {
    let offer = decode_code::<OFFER_BYTES>(invite_code, INVITE_PREFIX, INVITE_MAGIC)?;
    validate_expiry(&offer, now)?;
    if local_tls_cert_sha256 == [0; 32] || offer[61..93] == [0; 32] {
        return Err(ManualError::InvalidFingerprint);
    }
    let private_key = EphemeralSecret::random();
    let mut reply = [0_u8; REPLY_BYTES];
    reply[..4].copy_from_slice(REPLY_MAGIC);
    reply[4] = VERSION;
    reply[5..29].copy_from_slice(&offer[5..29]);
    reply[29..61].copy_from_slice(PublicKey::from(&private_key).as_bytes());
    reply[61..93].copy_from_slice(&local_tls_cert_sha256);
    getrandom::fill(&mut reply[93..109]).map_err(|_| ManualError::Entropy)?;
    reply[109..141].copy_from_slice(&Sha256::digest(offer));
    let theirs = PublicKey::from(<[u8; 32]>::try_from(&offer[29..61]).unwrap());
    let pairing = derive_pairing(
        private_key,
        theirs,
        &offer,
        &reply,
        <[u8; 32]>::try_from(&offer[61..93]).unwrap(),
    )?;
    Ok((format!("{REPLY_PREFIX}{}", URL_SAFE_NO_PAD.encode(reply)), pairing))
}

fn decode_code<const N: usize>(
    code: &str,
    prefix: &str,
    magic: &[u8; 4],
) -> Result<[u8; N], ManualError> {
    let contents = code.strip_prefix(prefix).ok_or(ManualError::InvalidCode)?;
    // Size limit before Base64 decoding avoids large untrusted allocations.
    if contents.len() != N.div_ceil(3) * 4 - match N % 3 { 1 => 2, 2 => 1, _ => 0 } {
        return Err(ManualError::InvalidCode);
    }
    let mut bytes = [0_u8; N];
    let decoded = URL_SAFE_NO_PAD.decode_slice(contents, &mut bytes)
        .map_err(|_| ManualError::InvalidCode)?;
    if decoded != N || bytes[..4] != magic[..] {
        return Err(ManualError::InvalidCode);
    }
    if bytes[4] != VERSION {
        return Err(ManualError::InvalidVersion);
    }
    Ok(bytes)
}

fn validate_expiry(bytes: &[u8], now: u64) -> Result<(), ManualError> {
    let expiry = u64::from_be_bytes(bytes[21..29].try_into().unwrap());
    if now >= expiry {
        return Err(ManualError::Expired);
    }
    Ok(())
}

fn derive_pairing(
    private_key: EphemeralSecret,
    remote_key: PublicKey,
    offer: &[u8; OFFER_BYTES],
    reply: &[u8; REPLY_BYTES],
    remote_tls_cert_sha256: [u8; 32],
) -> Result<ManualPairing, ManualError> {
    let shared = private_key.diffie_hellman(&remote_key);
    if !shared.was_contributory() {
        return Err(ManualError::WeakPublicKey);
    }
    let mut hasher = Sha256::new();
    hasher.update(KEY_SALT_CONTEXT);
    hasher.update(offer);
    hasher.update(reply);
    let salt = hasher.finalize();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut secret = [0_u8; 32];
    hk.expand(KEY_INFO, &mut secret).expect("HKDF output length is valid");
    let mut verification_bytes = [0_u8; 4];
    hk.expand(VERIFY_INFO, &mut verification_bytes)
        .expect("HKDF output length is valid");
    let comparison_code = u32::from_be_bytes(verification_bytes) % 1_000_000;
    let session_id = offer[5..21].try_into().unwrap();
    let credentials = SessionCredentials::new(session_id, secret)
        .map_err(|_| ManualError::InvalidCode)?;
    // The internal SessionCredentials owns its copy; no further use here.
    secret.fill(0);
    Ok(ManualPairing {
        credentials,
        remote_tls_cert_sha256,
        expires_at: u64::from_be_bytes(offer[21..29].try_into().unwrap()),
        comparison_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [0xA1; 32];
    const B: [u8; 32] = [0xB2; 32];

    #[test]
    fn manual_pairing_derives_same_private_secret_without_a_server() {
        let (pending, invite) = ManualInviteState::create(1_000, 600, A).unwrap();
        let preview = preview_invite(&invite, 1_001).unwrap();
        assert_eq!(preview.remote_tls_cert_sha256, A);
        let (reply, responder) = respond(&invite, 1_002, B).unwrap();
        let initiator = pending.finish(&reply, 1_003).unwrap();
        assert_eq!(initiator.remote_tls_cert_sha256, B);
        assert_eq!(responder.remote_tls_cert_sha256, A);
        assert_eq!(initiator.credentials.session_id(), responder.credentials.session_id());
        assert_eq!(initiator.comparison_code, responder.comparison_code);
        assert_eq!(initiator.comparison_code_text().len(), 6);
        assert!(!invite.contains(&format!("{:?}", responder.comparison_code)));
        // Both independently derived secrets must produce the same binding proof.
        let c = [3u8; 32];
        let s = [4u8; 32];
        assert_eq!(
            crate::session_binding::test_session_proof(&initiator.credentials, &c, &s),
            crate::session_binding::test_session_proof(&responder.credentials, &c, &s)
        );
    }

    #[test]
    fn refuses_expired_codes_and_bad_lifetimes() {
        assert!(matches!(ManualInviteState::create(0, 0, A), Err(ManualError::InvalidLifetime)));
        assert!(matches!(ManualInviteState::create(0, 1_801, A), Err(ManualError::InvalidLifetime)));
        let (pending, invite) = ManualInviteState::create(100, 10, A).unwrap();
        assert_eq!(preview_invite(&invite, 110), Err(ManualError::Expired));
        assert!(matches!(respond(&invite, 110, B), Err(ManualError::Expired)));
        let (reply, _) = respond(&invite, 109, B).unwrap();
        assert!(matches!(pending.finish(&reply, 110), Err(ManualError::Expired)));
    }

    #[test]
    fn rejects_reply_from_a_different_invite_even_if_the_format_is_valid() {
        let (first, _) = ManualInviteState::create(100, 60, A).unwrap();
        let (_, other_invite) = ManualInviteState::create(100, 60, A).unwrap();
        let (reply, _) = respond(&other_invite, 105, B).unwrap();
        assert!(matches!(first.finish(&reply, 106), Err(ManualError::SessionMismatch)));
    }

    #[test]
    fn rejects_tampering_and_invalid_wire_format() {
        let (_, invite) = ManualInviteState::create(100, 60, A).unwrap();
        assert_eq!(preview_invite("P2PR-INV1-AAAA", 101), Err(ManualError::InvalidCode));
        let mut bytes = decode_code::<OFFER_BYTES>(&invite, INVITE_PREFIX, INVITE_MAGIC).unwrap();
        bytes[4] = 2;
        let bad = format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        assert_eq!(preview_invite(&bad, 101), Err(ManualError::InvalidVersion));
        bytes[4] = VERSION;
        bytes[29..61].fill(0);
        let zero_key = format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        assert!(matches!(respond(&zero_key, 101, B), Err(ManualError::WeakPublicKey)));
    }

    #[test]
    fn rejects_modified_reply_offer_commitment() {
        let (state, invite) = ManualInviteState::create(100, 60, A).unwrap();
        let (reply, _) = respond(&invite, 101, B).unwrap();
        let mut raw = decode_code::<REPLY_BYTES>(&reply, REPLY_PREFIX, REPLY_MAGIC).unwrap();
        raw[140] ^= 1;
        let tampered = format!("{REPLY_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
        assert!(matches!(state.finish(&tampered, 102), Err(ManualError::OfferMismatch)));
    }
}
