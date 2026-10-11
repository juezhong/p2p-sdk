//! Single public entry point for an authorized, manually paired QUIC session.
//!
//! Requires independent human confirmation, current pairing lifetime, peer TLS
//! leaf pin on BOTH connections, and distinct First/Second HMAC role proofs.
//! The caller still MUST configure strict mutual TLS, manage certificate
//! rotation and validate an ICE-nominated UDP path before using this for P2P.

use std::time::Duration;

use quinn::Connection;
use tokio::sync::mpsc;

use crate::{
    channel::LinkProofClass,
    dual_quic::{QuicLinkPair, LinkPairError},
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
    Lanes(LinkPairError),
}

pub struct VerifiedManualSession {
    connections: QuicLinkPair,
    session_id: [u8; 16],
    remote_certificate_sha256: [u8; 32],
}

/// An authenticated QUIC link is no longer usable. Second and First failures
/// are separate events: losing a second lane must not tear down healthy First.
/// Receiving an event does NOT imply that ICE or the QUIC lane was repaired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionLinkEvent {
    SecondDisconnected,
    FirstDisconnected,
}

impl VerifiedManualSession {
    pub fn first(&self) -> &Connection {
        self.connections.first()
    }

    pub fn second(&self) -> &Connection {
        self.connections.second()
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn remote_certificate_sha256(&self) -> [u8; 32] {
        self.remote_certificate_sha256
    }

    pub fn close_second(&self) {
        self.connections.close_second();
    }

    /// Observe link termination independently of First RPC traffic.
    /// The monitor does not extend lifetimes or suppress actual disconnects.
    /// The application can continue using the first link after SecondDisconnected,
    /// but must reauthenticate a replacement Second QUIC connection before
    /// resuming the second link. FirstDisconnected requires a new verified session.
    ///
    /// Dropping the receiver stops the watcher without closing either QUIC
    /// connection. All events are emitted once for this watcher.
    pub fn watch_link_termination(&self) -> mpsc::UnboundedReceiver<SessionLinkEvent> {
        let first = self.first().clone();
        let second = self.second().clone();
        let (sender, receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = sender.closed() => return,
                _ = first.closed() => {
                    let _ = sender.send(SessionLinkEvent::FirstDisconnected);
                    return;
                },
                _ = second.closed() => {
                    if sender.send(SessionLinkEvent::SecondDisconnected).is_err() {
                        return;
                    }
                },
            }
            tokio::select! {
                _ = sender.closed() => {},
                _ = first.closed() => {
                    let _ = sender.send(SessionLinkEvent::FirstDisconnected);
                },
            }
        });
        receiver
    }
}

fn authorize(
    pairing: &ManualPairing,
    confirmation: &ManualConfirmation,
    first: &Connection,
    second: &Connection,
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
    expected.verify_connection(first).map_err(VerifiedSessionError::PeerIdentity)?;
    expected.verify_connection(second).map_err(VerifiedSessionError::PeerIdentity)?;
    if first.stable_id() == second.stable_id() {
        return Err(VerifiedSessionError::Lanes(LinkPairError::SameConnection));
    }
    Ok(())
}

/// Both QUIC connections MUST already have completed mutually authenticated
/// TLS. Only this function can assemble the public verified session handle.
pub async fn establish_initiator(
    first: Connection,
    second: Connection,
    pairing: &ManualPairing,
    confirmation: &ManualConfirmation,
    now: u64,
    deadline: Duration,
) -> Result<VerifiedManualSession, VerifiedSessionError> {
    authorize(pairing, confirmation, &first, &second, now)?;
    let first = authenticate_initiator(
        first, &pairing.credentials, LinkProofClass::Bootstrap, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let second = authenticate_initiator(
        second, &pairing.credentials, LinkProofClass::Additional, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let connections = QuicLinkPair::from_authenticated_links(first, second)
        .map_err(VerifiedSessionError::Lanes)?;
    Ok(VerifiedManualSession {
        connections,
        session_id: pairing.credentials.session_id(),
        remote_certificate_sha256: pairing.remote_tls_cert_sha256,
    })
}

/// The responder's replay guard must be owned by the application session,
/// shared across both lanes, and not recreated when a second lane is retried.
pub async fn establish_responder(
    first: Connection,
    second: Connection,
    pairing: &ManualPairing,
    confirmation: &ManualConfirmation,
    guard: &ReplayGuard,
    now: u64,
    deadline: Duration,
) -> Result<VerifiedManualSession, VerifiedSessionError> {
    authorize(pairing, confirmation, &first, &second, now)?;
    let first = authenticate_responder(
        first, &pairing.credentials, LinkProofClass::Bootstrap, guard, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let second = authenticate_responder(
        second, &pairing.credentials, LinkProofClass::Additional, guard, deadline,
    ).await.map_err(VerifiedSessionError::Binding)?;
    let connections = QuicLinkPair::from_authenticated_links(first, second)
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
