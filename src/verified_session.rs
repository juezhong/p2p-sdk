//! Single public entry point for an authorized, manually paired QUIC session.
//!
//! Requires independent human confirmation, current pairing lifetime, peer TLS
//! leaf pin on BOTH connections, and distinct Control/Data HMAC role proofs.
//! The caller still MUST configure strict mutual TLS, manage certificate
//! rotation and validate an ICE-nominated UDP path before using this for P2P.

use std::time::Duration;

use quinn::Connection;

use crate::{
    channel::ChannelRole,
    dual_quic::{DualQuic, DualQuicError},
    manual_pairing::ManualPairing,
    peer_pin::{ManualConfirmation, PeerCertificatePin, PeerPinError},
    session_binding::{
        authenticate_initiator, authenticate_responder, BindingError, ReplayGuard,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedSessionError {
    Expired,
    Confirmation(PeerPinError),
    PeerIdentity(PeerPinError),
    Binding(BindingError),
    Lanes(DualQuicError),
}

pub struct VerifiedManualSession {
    connections: DualQuic,
    session_id: [u8; 16],
    remote_certificate_sha256: [u8; 32],
}

impl VerifiedManualSession {
    pub fn control(&self) -> &Connection {
        self.connections.control()
    }

    pub fn data(&self) -> &Connection {
        self.connections.data()
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn remote_certificate_sha256(&self) -> [u8; 32] {
        self.remote_certificate_sha256
    }

    pub fn close_data(&self) {
        self.connections.close_data();
    }
}

fn authorize(
    pairing: &ManualPairing,
    confirmation: &ManualConfirmation,
    control: &Connection,
    data: &Connection,
    now: u64,
) -> Result<(), VerifiedSessionError> {
    if now >= pairing.expires_at {
        return Err(VerifiedSessionError::Expired);
    }
    confirmation.ensure_pairing_confirmed(
        pairing.credentials.session_id(),
        pairing.comparison_code,
    ).map_err(VerifiedSessionError::Confirmation)?;
    let expected = PeerCertificatePin::new(pairing.remote_tls_cert_sha256)
        .map_err(VerifiedSessionError::PeerIdentity)?;
    expected.verify_connection(control).map_err(VerifiedSessionError::PeerIdentity)?;
    expected.verify_connection(data).map_err(VerifiedSessionError::PeerIdentity)?;
    if control.stable_id() == data.stable_id() {
        return Err(VerifiedSessionError::Lanes(DualQuicError::SameConnection));
    }
    Ok(())
}

/// Both QUIC connections MUST already have completed mutually authenticated
/// TLS. Only this function can assemble the public verified session handle.
pub async fn establish_initiator(
    control: Connection,
    data: Connection,
    pairing: &ManualPairing,
    confirmation: &ManualConfirmation,
    now: u64,
    deadline: Duration,
) -> Result<VerifiedManualSession, VerifiedSessionError> {
    authorize(pairing, confirmation, &control, &data, now)?;
    let first = authenticate_initiator(
        control, &pairing.credentials, ChannelRole::Control, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let second = authenticate_initiator(
        data, &pairing.credentials, ChannelRole::Data, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let connections = DualQuic::from_authenticated_links(first, second)
        .map_err(VerifiedSessionError::Lanes)?;
    Ok(VerifiedManualSession {
        connections,
        session_id: pairing.credentials.session_id(),
        remote_certificate_sha256: pairing.remote_tls_cert_sha256,
    })
}

/// The responder's replay guard must be owned by the application session,
/// shared across both lanes, and not recreated when a data lane is retried.
pub async fn establish_responder(
    control: Connection,
    data: Connection,
    pairing: &ManualPairing,
    confirmation: &ManualConfirmation,
    guard: &ReplayGuard,
    now: u64,
    deadline: Duration,
) -> Result<VerifiedManualSession, VerifiedSessionError> {
    authorize(pairing, confirmation, &control, &data, now)?;
    let first = authenticate_responder(
        control, &pairing.credentials, ChannelRole::Control, guard, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let second = authenticate_responder(
        data, &pairing.credentials, ChannelRole::Data, guard, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let connections = DualQuic::from_authenticated_links(first, second)
        .map_err(VerifiedSessionError::Lanes)?;
    Ok(VerifiedManualSession {
        connections,
        session_id: pairing.credentials.session_id(),
        remote_certificate_sha256: pairing.remote_tls_cert_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manual_pairing::{respond, ManualInviteState};

    #[test]
    fn comparison_gate_cannot_be_reused_for_another_pairing() {
        let (state, invite) = ManualInviteState::create(100, 100, [1; 32]).unwrap();
        let (reply, _) = respond(&invite, 101, [2; 32]).unwrap();
        let pairing = state.finish(&reply, 102).unwrap();
        let (state2, invite2) = ManualInviteState::create(100, 100, [1; 32]).unwrap();
        let (reply2, _) = respond(&invite2, 101, [2; 32]).unwrap();
        let other = state2.finish(&reply2, 102).unwrap();
        let mut confirmation = ManualConfirmation::new(
            pairing.credentials.session_id(), pairing.comparison_code,
        ).unwrap();
        assert!(confirmation.ensure_pairing_confirmed(
            pairing.credentials.session_id(), pairing.comparison_code
        ).is_err());
        confirmation.confirm(&pairing.comparison_code_text()).unwrap();
        assert!(confirmation.ensure_pairing_confirmed(
            other.credentials.session_id(), other.comparison_code
        ).is_err());
    }
}
