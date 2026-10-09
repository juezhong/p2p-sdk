//! Mutual TLS configuration for Quinn's two independent QUIC lanes.
//!
//! Both sides MUST present a certificate. Trust anchors are chosen by the
//! caller from the verified pairing, NOT the public operating-system roots.
//! This module does not yet implement certificate provisioning, revocation,
//! persistent device identities or ICE. A post-handshake leaf pin check still
//! binds the certificate to the INVITE/REPLY transcript.

use std::{sync::Arc, time::Duration};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore,
};

const ALPN: &[u8] = b"p2p-sdk/1";

/// Keep both independently authenticated Control and Data QUIC sessions alive
/// when the user is reading help, browsing menus or leaving an idle shell.
/// This is QUIC PATH keepalive, not ICE consent freshness or ICE restart.
fn interactive_transport() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.max_idle_timeout(Some(quinn::VarInt::from_u32(120_000).into()));
    config.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(config)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsConfigError {
    EmptyCertificateChain,
    EmptyTrustRoots,
    InvalidCertificateOrKey,
    InvalidClientVerifier,
    IncompatibleQuicTls,
}

/// Require a certificate from the remote client; anonymous TLS peers are
/// never accepted on this endpoint.
pub fn authenticated_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    trusted_clients: Arc<RootCertStore>,
) -> Result<quinn::ServerConfig, TlsConfigError> {
    if cert_chain.is_empty() {
        return Err(TlsConfigError::EmptyCertificateChain);
    }
    if trusted_clients.is_empty() {
        return Err(TlsConfigError::EmptyTrustRoots);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(trusted_clients, provider.clone())
        .build()
        .map_err(|_| TlsConfigError::InvalidClientVerifier)?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsConfigError::IncompatibleQuicTls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|_| TlsConfigError::InvalidCertificateOrKey)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0; // Reject 0-RTT application data.
    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|_| TlsConfigError::IncompatibleQuicTls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(interactive_transport());
    Ok(config)
}

/// Present a client certificate to the remote endpoint, while verifying the
/// server using explicitly supplied trust anchors. Never skip TLS validation.
pub fn authenticated_client_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    trusted_servers: Arc<RootCertStore>,
) -> Result<quinn::ClientConfig, TlsConfigError> {
    if cert_chain.is_empty() {
        return Err(TlsConfigError::EmptyCertificateChain);
    }
    if trusted_servers.is_empty() {
        return Err(TlsConfigError::EmptyTrustRoots);
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsConfigError::IncompatibleQuicTls)?
        .with_root_certificates((*trusted_servers).clone())
        .with_client_auth_cert(cert_chain, key)
        .map_err(|_| TlsConfigError::InvalidCertificateOrKey)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|_| TlsConfigError::IncompatibleQuicTls)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(interactive_transport());
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_pin::{PeerCertificatePin, PeerPinError};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::{net::SocketAddr, time::Duration};

    struct CertBundle {
        cert: CertificateDer<'static>,
        key: Vec<u8>,
    }

    fn identity(name: &str) -> CertBundle {
        let generated = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
        CertBundle {
            cert: generated.cert.der().clone(),
            key: generated.signing_key.serialize_der(),
        }
    }

    fn private_key(key: &[u8]) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()))
    }

    fn trust(cert: &CertificateDer<'static>) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        Arc::new(roots)
    }

    #[test]
    fn rejects_empty_identity_or_missing_trust() {
        let client = identity("client.local");
        let empty_roots = Arc::new(RootCertStore::empty());
        assert!(matches!(
            authenticated_server_config(
                vec![client.cert.clone()], private_key(&client.key), empty_roots.clone()
            ),
            Err(TlsConfigError::EmptyTrustRoots)
        ));
        assert!(matches!(
            authenticated_client_config(
                vec![], private_key(&client.key), trust(&client.cert)
            ),
            Err(TlsConfigError::EmptyCertificateChain)
        ));
        assert!(matches!(
            authenticated_client_config(
                vec![client.cert.clone()], private_key(&client.key), empty_roots
            ),
            Err(TlsConfigError::EmptyTrustRoots)
        ));
    }

    #[tokio::test]
    async fn idle_control_and_data_connections_survive_default_thirty_second_timeout() {
        tokio::time::timeout(Duration::from_secs(55), async {
            let server_identity = identity("localhost");
            let client_identity = identity("client.local");
            let server_config = authenticated_server_config(
                vec![server_identity.cert.clone()], private_key(&server_identity.key),
                trust(&client_identity.cert),
            ).unwrap();
            let server = quinn::Endpoint::server(
                server_config, "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).unwrap();
            let address = server.local_addr().unwrap();
            let (finished_tx, finished_rx) = tokio::sync::oneshot::channel::<()>();
            let server_task = tokio::spawn(async move {
                let mut links = Vec::new();
                for _ in 0..2 {
                    links.push(server.accept().await.unwrap().await.unwrap());
                }
                tokio::time::sleep(Duration::from_secs(38)).await;
                assert!(links.iter().all(|link| link.close_reason().is_none()),
                    "idle server connections must still be alive");
                let _ = finished_tx.send(());
                server.close(0u32.into(), b"test complete");
            });
            let config = authenticated_client_config(
                vec![client_identity.cert.clone()], private_key(&client_identity.key),
                trust(&server_identity.cert),
            ).unwrap();
            let mut client = quinn::Endpoint::client(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).unwrap();
            client.set_default_client_config(config);
            let control = client.connect(address, "localhost").unwrap().await.unwrap();
            let data = client.connect(address, "localhost").unwrap().await.unwrap();
            tokio::time::sleep(Duration::from_secs(36)).await;
            assert!(control.close_reason().is_none(), "Control QUIC timed out during idle");
            assert!(data.close_reason().is_none(), "Data QUIC timed out during idle");
            finished_rx.await.unwrap();
            client.close(0u32.into(), b"test complete");
            server_task.await.unwrap();
        }).await.expect("idle QUIC regression exceeded deadline");
    }

    #[tokio::test]
    async fn mutual_tls_authenticates_two_connections_and_rejects_other_pins() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let server_identity = identity("localhost");
            let client_identity = identity("client.local");
            let server_pin = PeerCertificatePin::from_certificate_der(
                server_identity.cert.as_ref()
            ).unwrap();
            let client_pin = PeerCertificatePin::from_certificate_der(
                client_identity.cert.as_ref()
            ).unwrap();

            let server_tls = authenticated_server_config(
                vec![server_identity.cert.clone()],
                private_key(&server_identity.key),
                trust(&client_identity.cert),
            ).unwrap();
            let server = quinn::Endpoint::server(
                server_tls, "127.0.0.1:0".parse::<SocketAddr>().unwrap()
            ).unwrap();
            let address = server.local_addr().unwrap();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

            let server_task = tokio::spawn(async move {
                let mut accepted = Vec::new();
                for _ in 0..2 {
                    let conn = server.accept().await.unwrap().await.unwrap();
                    client_pin.verify_connection(&conn).unwrap();
                    assert_eq!(
                        server_pin.verify_connection(&conn),
                        Err(PeerPinError::IdentityMismatch)
                    );
                    accepted.push(conn);
                }
                done_rx.await.unwrap();
                assert!(accepted.iter().all(|conn| conn.close_reason().is_none()));
            });

            let tls = authenticated_client_config(
                vec![client_identity.cert.clone()],
                private_key(&client_identity.key),
                trust(&server_identity.cert),
            ).unwrap();
            let mut client = quinn::Endpoint::client(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap()
            ).unwrap();
            let socket = client.local_addr().unwrap();
            client.set_default_client_config(tls);
            let control = client.connect(address, "localhost").unwrap().await.unwrap();
            server_pin.verify_connection(&control).unwrap();
            let data = client.connect(address, "localhost").unwrap().await.unwrap();
            server_pin.verify_connection(&data).unwrap();
            assert_ne!(control.stable_id(), data.stable_id());
            assert_eq!(socket, client.local_addr().unwrap());
            done_tx.send(()).unwrap();
            server_task.await.unwrap();
            client.close(0u32.into(), b"completed");
        }).await.expect("mTLS integration test timed out");
    }

    #[tokio::test]
    async fn server_rejects_a_client_that_does_not_present_a_certificate() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let server_identity = identity("localhost");
            let client_identity = identity("client.local");
            let server = quinn::Endpoint::server(
                authenticated_server_config(
                    vec![server_identity.cert.clone()],
                    private_key(&server_identity.key),
                    trust(&client_identity.cert)
                ).unwrap(),
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).unwrap();

            let mut client = quinn::Endpoint::client(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).unwrap();
            client.set_default_client_config(
                quinn::ClientConfig::with_root_certificates(
                    trust(&server_identity.cert)
                ).unwrap()
            );
            let connecting = server.accept();
            let result = client.connect(server.local_addr().unwrap(), "localhost").unwrap();
            let incoming = connecting.await.expect("server received a connection");
            assert!(incoming.await.is_err(), "unauthenticated TLS client was accepted");
            let _ = result.await;
            client.close(0u32.into(), b"unauthenticated client");
        }).await.expect("anonymous TLS rejection test timed out");
    }
}
