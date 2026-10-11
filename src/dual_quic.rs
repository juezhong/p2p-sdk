//! A pair of authenticated QUIC connections with independent lifetimes.
//!
//! These are two QUIC connections, NOT two streams of one connection.
//! The surrounding session must authenticate and bind both connections to
//! the same peer/session before constructing this type.
//! This is an experimental transport building block; ICE is not wired up.

use quinn::Connection;
use crate::{channel::LinkProofClass, session_binding::AuthenticatedLink};

#[derive(Clone)]
#[allow(dead_code)]
pub struct QuicLinkPair {
    first: Connection,
    second: Connection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkPairError {
    SameConnection,
    InvalidRole,
    SessionMismatch,
}

#[allow(dead_code)]
impl QuicLinkPair {
    /// Internal transport assembly only. The public VerifiedManualSession
    /// additionally enforces peer certificate pins and manual confirmation.
    pub(crate) fn from_authenticated_links(first: AuthenticatedLink, second: AuthenticatedLink) -> Result<Self, LinkPairError> {
        if first.role() != LinkProofClass::Bootstrap || second.role() != LinkProofClass::Additional {
            return Err(LinkPairError::InvalidRole);
        }
        if first.session_id() != second.session_id() {
            return Err(LinkPairError::SessionMismatch);
        }
        let (first, second) = (first.connection().clone(), second.connection().clone());
        if first.stable_id() == second.stable_id() {
            return Err(LinkPairError::SameConnection);
        }
        Ok(Self { first, second })
    }

    #[cfg(test)]
    pub(crate) fn new(first: Connection, second: Connection) -> Result<Self, LinkPairError> {
        if first.stable_id() == second.stable_id() {
            return Err(LinkPairError::SameConnection);
        }
        Ok(Self { first, second })
    }

    pub fn first(&self) -> &Connection {
        &self.first
    }

    pub fn second(&self) -> &Connection {
        &self.second
    }

    /// Close the bulk-second QUIC connection without closing first QUIC.
    /// Replacing it requires a freshly authenticated session-bound connection.
    pub fn close_second(&self) {
        self.second.close(0u32.into(), b"second connection reset");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    /// Local TLS test trust anchors are explicitly pinned. No disabled
    /// certificate verification, and no production P2P identity claims.
    #[tokio::test]
    async fn data_quic_close_does_not_close_control_quic_on_one_udp_endpoint() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("generate test certificate");
            let cert = certified.cert.der().clone();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                certified.signing_key.serialize_der().into(),
            );
            let server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key)
                .expect("server TLS config");
            let server = quinn::Endpoint::server(
                server_config,
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).expect("bind server UDP");
            let server_address = server.local_addr().unwrap();

            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).expect("pin self-signed test certificate");
            let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots))
                .expect("client TLS config");
            let mut client = quinn::Endpoint::client(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).expect("bind client UDP");
            client.set_default_client_config(client_config);
            let client_udp_address = client.local_addr().unwrap();

            let (verified_tx, verified_rx) = tokio::sync::oneshot::channel::<()>();
            let server_task = tokio::spawn(async move {
                let first = server.accept().await.expect("first incoming")
                    .await.expect("first handshake");
                // Accept the second connection while independently serving first.
                let control_task = tokio::spawn(async move {
                    for expected in [b"first".as_slice(), b"second".as_slice()] {
                        let (mut send, mut recv) = first.accept_bi().await.expect("first RPC stream");
                        let second = recv.read_to_end(128).await.expect("read RPC");
                        assert_eq!(second, expected);
                        send.write_all(b"ok").await.expect("write response");
                        send.finish().expect("finish response");
                    }
                    first
                });
                let second = server.accept().await.expect("second incoming")
                    .await.expect("second handshake");
                second.closed().await;
                let first = control_task.await.expect("first task join");
                assert!(first.close_reason().is_none(), "first QUIC must remain connected");
                // Do not tear down the server Endpoint before the client has
                // asserted that the first QUIC survived the second QUIC close.
                verified_rx.await.expect("client verified first survives");
                server.close(0u32.into(), b"test complete");
            });

            let first = client.connect(server_address, "localhost").unwrap()
                .await.expect("connect first");
            async fn echo(conn: &Connection, message: &[u8]) {
                let (mut send, mut recv) = conn.open_bi().await.expect("open first RPC");
                send.write_all(message).await.expect("write RPC");
                send.finish().expect("finish request");
                assert_eq!(recv.read_to_end(128).await.expect("read response"), b"ok");
            }
            echo(&first, b"first").await;
            let second = client.connect(server_address, "localhost").unwrap()
                .await.expect("connect second");
            let pair = QuicLinkPair::new(first.clone(), second).expect("different QUIC connections");
            assert_eq!(client.local_addr().unwrap(), client_udp_address);
            assert_ne!(pair.first().stable_id(), pair.second().stable_id());
            pair.close_second();
            pair.second().closed().await;
            echo(pair.first(), b"second").await;
            assert!(pair.first().close_reason().is_none());
            verified_tx.send(()).expect("signal client verification");
            server_task.await.expect("server join");
            client.close(0u32.into(), b"test complete");
        }).await.expect("dual-connection isolation test timeout");
    }
}
