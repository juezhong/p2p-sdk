//! Peer certificate pin verification and explicit manual-pairing confirmation.
//!
//! IMPORTANT: TLS itself must validate its peer as well. This is an
//! additional fail-closed check performed before application traffic is
//! permitted, not a certificate verifier or permission to disable TLS.
//! QUIC servers with no client certificate authentication will generally
//! have no peer_identity(): they MUST reject that case here. Production
//! mutual peer identity requires an authenticated client-certificate or
//! equivalent certified peer identity mechanism in Quinn/rustls.

use quinn::Connection;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerPinError {
    InvalidPin,
    MissingIdentity,
    UnsupportedIdentity,
    EmptyCertificateChain,
    IdentityMismatch,
    SessionMismatch,
    UnconfirmedPairing,
    InvalidCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCertificatePin([u8; 32]);

impl PeerCertificatePin {
    pub fn new(digest: [u8; 32]) -> Result<Self, PeerPinError> {
        if digest == [0; 32] {
            return Err(PeerPinError::InvalidPin);
        }
        Ok(Self(digest))
    }

    pub fn from_certificate_der(cert_der: &[u8]) -> Result<Self, PeerPinError> {
        if cert_der.is_empty() {
            return Err(PeerPinError::EmptyCertificateChain);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(cert_der));
        Self::new(digest)
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.0
    }

    /// Fail closed on an unavailable or non-rustls QUIC peer identity.
    /// Do not log DER certificate data or session secrets on error.
    pub fn verify_connection(&self, connection: &Connection) -> Result<(), PeerPinError> {
        let identity = connection.peer_identity().ok_or(PeerPinError::MissingIdentity)?;
        let certs = identity
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .map_err(|_| PeerPinError::UnsupportedIdentity)?;
        let leaf = certs.first().ok_or(PeerPinError::EmptyCertificateChain)?;
        let observed = Self::from_certificate_der(leaf.as_ref())?;
        if observed != *self {
            return Err(PeerPinError::IdentityMismatch);
        }
        Ok(())
    }
}

/// Pairing gate for exactly one application session. Copying a displayed
/// comparison code is not sufficient: the user must explicitly confirm it.
/// This gate does not represent any file-access authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManualConfirmation {
    session_id: [u8; 16],
    expected_comparison_code: u32,
    confirmed: bool,
}

impl ManualConfirmation {
    pub fn new(
        session_id: [u8; 16],
        expected_comparison_code: u32,
    ) -> Result<Self, PeerPinError> {
        if session_id == [0; 16] || expected_comparison_code >= 1_000_000 {
            return Err(PeerPinError::InvalidCode);
        }
        Ok(Self {
            session_id,
            expected_comparison_code,
            confirmed: false,
        })
    }

    /// The UI should display this code and obtain explicit confirmation
    /// over a trusted comparison channel, not auto-confirm it.
    pub fn comparison_code_text(&self) -> String {
        format!("{:06}", self.expected_comparison_code)
    }

    pub fn confirm(&mut self, code: &str) -> Result<(), PeerPinError> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PeerPinError::InvalidCode);
        }
        let parsed: u32 = code.parse().map_err(|_| PeerPinError::InvalidCode)?;
        if parsed != self.expected_comparison_code {
            return Err(PeerPinError::InvalidCode);
        }
        self.confirmed = true;
        Ok(())
    }

    pub fn ensure_confirmed(&self, session_id: [u8; 16]) -> Result<(), PeerPinError> {
        if self.session_id != session_id {
            return Err(PeerPinError::SessionMismatch);
        }
        if !self.confirmed {
            return Err(PeerPinError::UnconfirmedPairing);
        }
        Ok(())
    }

    /// Verify that the explicitly confirmed code belongs to this precise
    /// pairing, not merely to a caller-supplied session ID.
    pub(crate) fn ensure_pairing_confirmed(
        &self,
        session_id: [u8; 16],
        comparison_code: u32,
    ) -> Result<(), PeerPinError> {
        self.ensure_confirmed(session_id)?;
        if self.expected_comparison_code != comparison_code {
            return Err(PeerPinError::InvalidCode);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_real_certificate_bytes() {
        let der = b"this is fixture data, not a valid certificate";
        let pin = PeerCertificatePin::from_certificate_der(der).unwrap();
        let mut expected = [0; 32];
        expected.copy_from_slice(&Sha256::digest(der));
        assert_eq!(pin.fingerprint(), expected);
        assert_eq!(PeerCertificatePin::from_certificate_der(b""), Err(PeerPinError::EmptyCertificateChain));
        assert_eq!(PeerCertificatePin::new([0; 32]), Err(PeerPinError::InvalidPin));
    }

    #[test]
    fn confirmation_is_rejected_until_explicit_and_session_matches() {
        let mut gate = ManualConfirmation::new([3; 16], 701).unwrap();
        assert_eq!(gate.comparison_code_text(), "000701");
        assert_eq!(gate.ensure_confirmed([3; 16]), Err(PeerPinError::UnconfirmedPairing));
        assert_eq!(gate.confirm("000702"), Err(PeerPinError::InvalidCode));
        assert_eq!(gate.confirm("701"), Err(PeerPinError::InvalidCode));
        assert_eq!(gate.confirm("000701"), Ok(()));
        assert_eq!(gate.ensure_confirmed([3; 16]), Ok(()));
        assert_eq!(gate.ensure_confirmed([4; 16]), Err(PeerPinError::SessionMismatch));
    }

    #[test]
    fn rejects_invalid_confirmation_values() {
        assert_eq!(ManualConfirmation::new([0; 16], 123), Err(PeerPinError::InvalidCode));
        assert_eq!(ManualConfirmation::new([1; 16], 1_000_000), Err(PeerPinError::InvalidCode));
    }

    #[tokio::test]
    async fn verifies_leaf_certificate_from_real_quinn_connection() {
        use std::{net::SocketAddr, sync::Arc, time::Duration};
        tokio::time::timeout(Duration::from_secs(10), async {
            let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert = identity.cert.der().clone();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into(),
            );
            let server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
            let server = quinn::Endpoint::server(
                server_config, "127.0.0.1:0".parse::<SocketAddr>().unwrap()
            ).unwrap();
            let server_addr = server.local_addr().unwrap();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let server_task = tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                done_rx.await.unwrap();
                assert!(conn.close_reason().is_none());
            });

            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(cert.clone()).unwrap();
            let client_config =
                quinn::ClientConfig::with_root_certificates(Arc::new(root_store)).unwrap();
            let mut client = quinn::Endpoint::client(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).unwrap();
            client.set_default_client_config(client_config);
            let connection = client.connect(server_addr, "localhost").unwrap().await.unwrap();
            let pin = PeerCertificatePin::from_certificate_der(cert.as_ref()).unwrap();
            pin.verify_connection(&connection).unwrap();
            let other_pin = PeerCertificatePin::from_certificate_der(b"other certificate").unwrap();
            assert_eq!(other_pin.verify_connection(&connection), Err(PeerPinError::IdentityMismatch));
            done_tx.send(()).unwrap();
            server_task.await.unwrap();
            client.close(0u32.into(), b"done");
        }).await.expect("QUIC pin loopback timed out");
    }
}
