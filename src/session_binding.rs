//! Experimental application-session binding for separate QUIC connections.
//!
//! QUIC/TLS MUST have authenticated its transport peer independently.
//! This handshake proves possession of one fresh, shared 256-bit session
//! secret, binds the application session ID and the Control/Data role, and
//! authenticates both sides with independent challenges. It does NOT yet
//! implement persistent device identity or ICE.
//!
//! The secret MUST be generated securely and exchanged through authenticated
//! signaling (or verified manually), never logged or reused between sessions.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use getrandom::fill;
use hmac::{Hmac, Mac};
use quinn::Connection;
use sha2::Sha256;

use crate::channel::ChannelRole;

type HmacSha256 = Hmac<Sha256>;
const MAGIC: [u8; 4] = *b"P2PB";
const VERSION: u8 = 1;
const HELLO_LEN: usize = 4 + 1 + 1 + 16 + 32;
const CHALLENGE_LEN: usize = 4 + 32 + 32;
const NONCE_LEN: usize = 32;
const PROOF_LEN: usize = 32;
const ACCEPT: u8 = 0xa1;
const DOMAIN: &[u8] = b"p2p-sdk/session-connection-binding/v1";
const SERVER_PROOF: u8 = 1;
const CLIENT_PROOF: u8 = 2;
const MAX_REPLAY_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    InvalidCredentials,
    InvalidLimit,
    InvalidRole,
    InvalidProtocol,
    InvalidSession,
    InvalidProof,
    ReplayDetected,
    ReplayCacheFull,
    ReplayCachePoisoned,
    EntropyUnavailable,
    Transport,
    Timeout,
}

#[derive(Clone)]
pub struct SessionCredentials {
    session_id: [u8; 16],
    secret: [u8; 32],
}

impl SessionCredentials {
    /// Session ID is public; `secret` is a CSPRNG-generated 32-byte secret.
    /// A nonzero value alone is not proof of sufficient entropy.
    pub fn new(session_id: [u8; 16], secret: [u8; 32]) -> Result<Self, BindingError> {
        if session_id == [0; 16] || secret == [0; 32] {
            return Err(BindingError::InvalidCredentials);
        }
        Ok(Self { session_id, secret })
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
}

/// Keeps the nonces of *successfully authenticated* peer connections for
/// one application session. Must be shared between control/data acceptors.
///
/// Fail closed when full; don't evict entries while session credentials live.
pub struct ReplayGuard {
    seen: Mutex<HashSet<[u8; NONCE_LEN]>>,
    limit: usize,
}

impl ReplayGuard {
    pub fn new(limit: usize) -> Result<Self, BindingError> {
        if limit == 0 || limit > MAX_REPLAY_ENTRIES {
            return Err(BindingError::InvalidLimit);
        }
        Ok(Self {
            seen: Mutex::new(HashSet::new()),
            limit,
        })
    }

    fn accept(&self, nonce: [u8; NONCE_LEN]) -> Result<(), BindingError> {
        let mut seen = self.seen.lock().map_err(|_| BindingError::ReplayCachePoisoned)?;
        if seen.contains(&nonce) {
            return Err(BindingError::ReplayDetected);
        }
        if seen.len() >= self.limit {
            return Err(BindingError::ReplayCacheFull);
        }
        seen.insert(nonce);
        Ok(())
    }
}

/// Created only by a successful mutual HMAC challenge/response on a QUIC
/// connection. This is an application-session claim, NOT a durable device ID.
#[derive(Clone)]
pub struct AuthenticatedLink {
    connection: Connection,
    session_id: [u8; 16],
    role: ChannelRole,
}

impl AuthenticatedLink {
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn role(&self) -> ChannelRole {
        self.role
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
}

/// Initiator side: one bounded, bidirectional QUIC stream for mutual session
/// proof. Does not disable TLS verification or trust arbitrary certificates.
pub async fn authenticate_initiator(
    connection: Connection,
    credentials: &SessionCredentials,
    role: ChannelRole,
    deadline: Duration,
) -> Result<AuthenticatedLink, BindingError> {
    if deadline.is_zero() {
        return Err(BindingError::InvalidLimit);
    }
    tokio::time::timeout(deadline, async {
        let (mut tx, mut rx) = connection.open_bi().await.map_err(|_| BindingError::Transport)?;
        let mut client_nonce = [0_u8; NONCE_LEN];
        fill(&mut client_nonce).map_err(|_| BindingError::EntropyUnavailable)?;
        let mut hello = [0_u8; HELLO_LEN];
        hello[..4].copy_from_slice(&MAGIC);
        hello[4] = VERSION;
        hello[5] = role_tag(role);
        hello[6..22].copy_from_slice(&credentials.session_id);
        hello[22..54].copy_from_slice(&client_nonce);
        tx.write_all(&hello).await.map_err(|_| BindingError::Transport)?;

        let mut challenge = [0_u8; CHALLENGE_LEN];
        rx.read_exact(&mut challenge).await.map_err(|_| BindingError::Transport)?;
        if challenge[..4] != MAGIC {
            return Err(BindingError::InvalidProtocol);
        }
        let mut server_nonce = [0_u8; NONCE_LEN];
        server_nonce.copy_from_slice(&challenge[4..36]);
        verify_proof(
            credentials, role, &client_nonce, &server_nonce,
            SERVER_PROOF, &challenge[36..68],
        )?;
        let client_proof = proof(credentials, role, &client_nonce, &server_nonce, CLIENT_PROOF);
        tx.write_all(&client_proof).await.map_err(|_| BindingError::Transport)?;
        tx.finish().map_err(|_| BindingError::Transport)?;
        let mut ack = [0_u8; 1];
        rx.read_exact(&mut ack).await.map_err(|_| BindingError::Transport)?;
        if ack != [ACCEPT] {
            return Err(BindingError::InvalidProtocol);
        }
        Ok(AuthenticatedLink {
            connection,
            session_id: credentials.session_id,
            role,
        })
    }).await.map_err(|_| BindingError::Timeout)?
}

/// Responder side. `guard` must be owned by the application session and
/// shared across both QUIC connections; not recreated for every incoming link.
pub async fn authenticate_responder(
    connection: Connection,
    credentials: &SessionCredentials,
    expected_role: ChannelRole,
    guard: &ReplayGuard,
    deadline: Duration,
) -> Result<AuthenticatedLink, BindingError> {
    if deadline.is_zero() {
        return Err(BindingError::InvalidLimit);
    }
    tokio::time::timeout(deadline, async {
        let (mut tx, mut rx) = connection.accept_bi().await.map_err(|_| BindingError::Transport)?;
        let mut hello = [0_u8; HELLO_LEN];
        rx.read_exact(&mut hello).await.map_err(|_| BindingError::Transport)?;
        if hello[..4] != MAGIC || hello[4] != VERSION {
            return Err(BindingError::InvalidProtocol);
        }
        if hello[5] != role_tag(expected_role) {
            return Err(BindingError::InvalidRole);
        }
        if hello[6..22] != credentials.session_id {
            return Err(BindingError::InvalidSession);
        }
        let mut client_nonce = [0_u8; NONCE_LEN];
        client_nonce.copy_from_slice(&hello[22..54]);
        let mut server_nonce = [0_u8; NONCE_LEN];
        fill(&mut server_nonce).map_err(|_| BindingError::EntropyUnavailable)?;

        let mut challenge = [0_u8; CHALLENGE_LEN];
        challenge[..4].copy_from_slice(&MAGIC);
        challenge[4..36].copy_from_slice(&server_nonce);
        challenge[36..68].copy_from_slice(&proof(
            credentials, expected_role, &client_nonce, &server_nonce, SERVER_PROOF,
        ));
        tx.write_all(&challenge).await.map_err(|_| BindingError::Transport)?;
        let mut client_proof = [0_u8; PROOF_LEN];
        rx.read_exact(&mut client_proof).await.map_err(|_| BindingError::Transport)?;
        verify_proof(
            credentials, expected_role, &client_nonce, &server_nonce,
            CLIENT_PROOF, &client_proof,
        )?;
        // Replay cache mutation occurs only after a valid client proof; an
        // unauthenticated attacker cannot fill this cache just with HELLOs.
        guard.accept(client_nonce)?;
        tx.write_all(&[ACCEPT]).await.map_err(|_| BindingError::Transport)?;
        tx.finish().map_err(|_| BindingError::Transport)?;
        Ok(AuthenticatedLink {
            connection,
            session_id: credentials.session_id,
            role: expected_role,
        })
    }).await.map_err(|_| BindingError::Timeout)?
}

fn role_tag(role: ChannelRole) -> u8 {
    match role {
        ChannelRole::Control => 1,
        ChannelRole::Data => 2,
    }
}

fn mac_for(
    credentials: &SessionCredentials, role: ChannelRole,
    client_nonce: &[u8; NONCE_LEN], server_nonce: &[u8; NONCE_LEN],
    direction: u8,
) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(&credentials.secret).expect("fixed 256-bit key");
    mac.update(DOMAIN);
    mac.update(&[direction, role_tag(role)]);
    mac.update(&credentials.session_id);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac
}

fn proof(
    credentials: &SessionCredentials, role: ChannelRole,
    client_nonce: &[u8; NONCE_LEN], server_nonce: &[u8; NONCE_LEN],
    direction: u8,
) -> [u8; PROOF_LEN] {
    let bytes = mac_for(credentials, role, client_nonce, server_nonce, direction)
        .finalize().into_bytes();
    let mut out = [0; PROOF_LEN];
    out.copy_from_slice(&bytes);
    out
}

fn verify_proof(
    credentials: &SessionCredentials, role: ChannelRole,
    client_nonce: &[u8; NONCE_LEN], server_nonce: &[u8; NONCE_LEN],
    direction: u8, expected: &[u8],
) -> Result<(), BindingError> {
    mac_for(credentials, role, client_nonce, server_nonce, direction)
        .verify_slice(expected).map_err(|_| BindingError::InvalidProof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> SessionCredentials {
        SessionCredentials::new([1; 16], [2; 32]).unwrap()
    }

    #[test]
    fn proofs_bind_role_session_nonce_and_direction() {
        let creds = creds();
        let c = [7; 32];
        let s = [8; 32];
        let tag = proof(&creds, ChannelRole::Control, &c, &s, SERVER_PROOF);
        assert!(verify_proof(&creds, ChannelRole::Control, &c, &s, SERVER_PROOF, &tag).is_ok());
        assert_eq!(verify_proof(&creds, ChannelRole::Data, &c, &s, SERVER_PROOF, &tag), Err(BindingError::InvalidProof));
        assert_eq!(verify_proof(&creds, ChannelRole::Control, &c, &s, CLIENT_PROOF, &tag), Err(BindingError::InvalidProof));
        assert_eq!(verify_proof(&creds, ChannelRole::Control, &[9; 32], &s, SERVER_PROOF, &tag), Err(BindingError::InvalidProof));
        let other = SessionCredentials::new([3; 16], [2; 32]).unwrap();
        assert_eq!(verify_proof(&other, ChannelRole::Control, &c, &s, SERVER_PROOF, &tag), Err(BindingError::InvalidProof));
    }

    #[test]
    fn rejects_duplicate_client_nonces_across_roles_and_cache_exhaustion() {
        let guard = ReplayGuard::new(2).unwrap();
        assert!(guard.accept([1; 32]).is_ok());
        assert_eq!(guard.accept([1; 32]), Err(BindingError::ReplayDetected));
        assert!(guard.accept([2; 32]).is_ok());
        assert_eq!(guard.accept([3; 32]), Err(BindingError::ReplayCacheFull));
    }

    #[test]
    fn refuses_weak_placeholders_and_unbounded_replay_guard() {
        assert!(matches!(SessionCredentials::new([0; 16], [1; 32]), Err(BindingError::InvalidCredentials)));
        assert!(matches!(SessionCredentials::new([1; 16], [0; 32]), Err(BindingError::InvalidCredentials)));
        assert!(matches!(ReplayGuard::new(0), Err(BindingError::InvalidLimit)));
        assert!(matches!(ReplayGuard::new(4097), Err(BindingError::InvalidLimit)));
    }
}

#[cfg(test)]
mod quinn_integration_tests {
    use super::*;
    use std::{net::SocketAddr, sync::Arc};

    #[tokio::test]
    async fn two_quic_connections_are_bound_to_one_authenticated_session() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let certificate =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert = certificate.cert.der().clone();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                certificate.signing_key.serialize_der().into(),
            );
            let server_tls = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
            let server =
                quinn::Endpoint::server(server_tls, "127.0.0.1:0".parse::<SocketAddr>().unwrap())
                    .unwrap();
            let address = server.local_addr().unwrap();

            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            let client_tls =
                quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
            let mut client =
                quinn::Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
            client.set_default_client_config(client_tls);
            let client_local_addr = client.local_addr().unwrap();

            let credentials = SessionCredentials::new([4; 16], [5; 32]).unwrap();
            let server_creds = credentials.clone();
            let server_task = tokio::spawn(async move {
                let guard = ReplayGuard::new(4).unwrap();
                for role in [ChannelRole::Control, ChannelRole::Data] {
                    let incoming = server.accept().await.expect("incoming connection");
                    let connection = incoming.await.expect("TLS authentication");
                    let link = authenticate_responder(
                        connection, &server_creds, role, &guard, Duration::from_secs(3),
                    ).await.expect("authenticated session-bound connection");
                    assert_eq!(link.role(), role);
                    assert_eq!(link.session_id(), [4; 16]);
                }
                server.close(0u32.into(), b"test complete");
            });

            let control = client.connect(address, "localhost").unwrap().await.unwrap();
            let control = authenticate_initiator(
                control, &credentials, ChannelRole::Control, Duration::from_secs(3),
            ).await.unwrap();
            let data = client.connect(address, "localhost").unwrap().await.unwrap();
            let data = authenticate_initiator(
                data, &credentials, ChannelRole::Data, Duration::from_secs(3),
            ).await.unwrap();
            assert_eq!(client.local_addr().unwrap(), client_local_addr);
            let pair = crate::dual_quic::DualQuic::from_authenticated_links(control, data)
                .expect("same verified application session");
            assert_ne!(pair.control().stable_id(), pair.data().stable_id());
            server_task.await.unwrap();
            client.close(0u32.into(), b"test complete");
        }).await.expect("authentication loopback test timeout");
    }
}
