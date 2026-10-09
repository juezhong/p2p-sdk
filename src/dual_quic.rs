//! A pair of authenticated QUIC connections with independent lifetimes.
//!
//! These are two QUIC connections, NOT two streams of one connection.
//! The surrounding session must authenticate and bind both connections to
//! the same peer/session before constructing this type.
//! This is an experimental transport building block; ICE is not wired up.

use quinn::Connection;

#[derive(Clone)]
#[allow(dead_code)]
pub struct DualQuic {
    control: Connection,
    data: Connection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualQuicError {
    SameConnection,
}

#[allow(dead_code)]
impl DualQuic {
    /// Caller must verify that both connections refer to the same authenticated
    /// peer and negotiated application session. This is not done here yet.
    pub(crate) fn new(control: Connection, data: Connection) -> Result<Self, DualQuicError> {
        if control.stable_id() == data.stable_id() {
            return Err(DualQuicError::SameConnection);
        }
        Ok(Self { control, data })
    }

    pub fn control(&self) -> &Connection {
        &self.control
    }

    pub fn data(&self) -> &Connection {
        &self.data
    }

    /// Close the bulk-data QUIC connection without closing control QUIC.
    /// Replacing it requires a freshly authenticated session-bound connection.
    pub fn close_data(&self) {
        self.data.close(0u32.into(), b"data connection reset");
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

            let server_task = tokio::spawn(async move {
                let control = server.accept().await.expect("control incoming")
                    .await.expect("control handshake");
                // Accept the data connection while independently serving control.
                let control_task = tokio::spawn(async move {
                    for expected in [b"first".as_slice(), b"second".as_slice()] {
                        let (mut send, mut recv) = control.accept_bi().await.expect("control RPC stream");
                        let data = recv.read_to_end(128).await.expect("read RPC");
                        assert_eq!(data, expected);
                        send.write_all(b"ok").await.expect("write response");
                        send.finish().expect("finish response");
                    }
                    control
                });
                let data = server.accept().await.expect("data incoming")
                    .await.expect("data handshake");
                data.closed().await;
                let control = control_task.await.expect("control task join");
                assert!(control.close_reason().is_none(), "control QUIC must remain connected");
                server.close(0u32.into(), b"test complete");
            });

            let control = client.connect(server_address, "localhost").unwrap()
                .await.expect("connect control");
            async fn echo(conn: &Connection, message: &[u8]) {
                let (mut send, mut recv) = conn.open_bi().await.expect("open control RPC");
                send.write_all(message).await.expect("write RPC");
                send.finish().expect("finish request");
                assert_eq!(recv.read_to_end(128).await.expect("read response"), b"ok");
            }
            echo(&control, b"first").await;
            let data = client.connect(server_address, "localhost").unwrap()
                .await.expect("connect data");
            let pair = DualQuic::new(control.clone(), data).expect("different QUIC connections");
            assert_eq!(client.local_addr().unwrap(), client_udp_address);
            assert_ne!(pair.control().stable_id(), pair.data().stable_id());
            pair.close_data();
            pair.data().closed().await;
            echo(pair.control(), b"second").await;
            assert!(pair.control().close_reason().is_none());
            server_task.await.expect("server join");
            client.close(0u32.into(), b"test complete");
        }).await.expect("dual-connection isolation test timeout");
    }
}
