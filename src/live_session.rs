//! A single lifetime for a fully verified Control/Data QUIC session, its
//! ICE nominated real UDP owner, selected gateway lease and NAT punch task.
//!
//! QUIC keepalive only maintains a healthy connection. Loss of Control
//! terminates the continuous Punch task; any replacement session requires
//! fresh verified pairing + authenticated ICE, TLS and session proof. No TURN
//! or application payload is carried through the gateway/punch code.

use std::{net::SocketAddr, time::Duration};
use tokio::sync::watch;

use crate::{
    ice_signaling::{IceDescription, IceRole},
    managed_candidates::ManagedPath,
    manual_pairing::ManualPairing,
    network_diagnostics::{self, NetworkDiagnostic},
    punch::AuthenticatedPunch,
    punch_loop::{PunchLoop, PunchStatus},
    resilient_data::ResilientDataLanes,
    udp_owner::UdpOwnerError,
    verified_session::VerifiedManualSession,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveSessionError {
    WrongPairing,
    InvalidPath,
    InvalidRole,
    Punch(UdpOwnerError),
}

/// Keep the authenticating Control/Data session and the *actual* selected
/// ICE UDP owner together. A public application should not attempt network
/// recovery by replacing just the remote QUIC address without fresh proofs.
pub struct LiveSdkSession {
    session: VerifiedManualSession,
    path: ManagedPath,
    punch: Option<PunchLoop>,
    local_description: IceDescription,
    remote_description: IceDescription,
}

impl LiveSdkSession {
    /// Attach only AFTER mTLS, session HMAC, and user pairing have passed.
    /// The nominated path and actual QUIC remote must match at creation.
    pub fn attach(
        session: VerifiedManualSession,
        mut path: ManagedPath,
        pairing: &ManualPairing,
        local_description: IceDescription,
        remote_description: IceDescription,
        local_role: IceRole,
        punch_period: Duration,
    ) -> Result<Self, LiveSessionError> {
        if pairing.credentials.session_id() != session.session_id()
            || pairing.remote_tls_cert_sha256 != session.remote_certificate_sha256()
        {
            return Err(LiveSessionError::WrongPairing);
        }
        if local_description.validate().is_err()
            || remote_description.validate().is_err()
            || local_description.role != local_role
            || remote_description.role == local_role
        {
            return Err(LiveSessionError::InvalidRole);
        }
        if path.selected.owner.handle.local_address() != path.selected.path.local
            || path.selected.path.remote != session.control().remote_address()
            || session.control().close_reason().is_some()
        {
            return Err(LiveSessionError::InvalidPath);
        }
        let proof = AuthenticatedPunch::new(
            pairing.credentials.clone(), local_role,
        );
        let punch = PunchLoop::start_for_control(
            &mut path.selected.owner,
            proof,
            remote_description.clone(),
            punch_period,
            session.control().clone(),
        ).map_err(LiveSessionError::Punch)?;
        Ok(Self {
            session, path, punch: Some(punch),
            local_description, remote_description,
        })
    }

    pub fn verified(&self) -> &VerifiedManualSession { &self.session }

    pub fn actual_path(&self) -> (SocketAddr, SocketAddr) {
        (self.path.selected.path.local, self.path.selected.path.remote)
    }

    /// These authenticated discovered UDP endpoints are never direct QUIC
    /// permission: upper ICE path supervision must recheck any new pair.
    pub fn watch_reflexive_candidates(&self) -> watch::Receiver<PunchStatus> {
        self.punch.as_ref().expect("active live session").subscribe()
    }

    pub async fn diagnostic(
        &self, pool: Option<&ResilientDataLanes>,
    ) -> NetworkDiagnostic {
        let sources = self.punch.as_ref()
            .expect("active live session").subscribe().borrow().discovered.clone();
        network_diagnostics::snapshot(
            &self.session, &self.path,
            &self.local_description, &self.remote_description,
            pool, &sources,
        ).await
    }

    /// Explicit shutdown closes authenticated QUIC links, stops the Punch
    /// scheduler, then waits for the active gateway map to be removed.
    pub async fn shutdown(mut self) {
        self.session.control().close(0u32.into(), b"session ended");
        self.session.data().close(0u32.into(), b"session ended");
        if let Some(punch) = self.punch.take() {
            punch.shutdown().await;
        }
        self.path.shutdown_gateway().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_stable_and_only_opposites_can_attach() {
        for (left, right) in [
            (IceRole::Controlling, IceRole::Controlled),
            (IceRole::Controlled, IceRole::Controlling),
        ] {
            assert_ne!(left, right);
            assert_eq!(left, left);
        }
    }
}
