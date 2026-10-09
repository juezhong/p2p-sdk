//! ICE nomination followed by independent Quinn Control/Data connections.
//! This test uses the exact same owner/socket for nomination and both QUIC
//! connections. It proves localhost integration, NOT cross-NAT reliability.

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use crate::{
        ice_agent::{nominate_host_pair, new_ice_credentials},
        quinn_socket::{demux_endpoint_config, QuinnUdpAdapter},
        udp_owner::UdpOwner,
    };

    #[tokio::test]
    async fn nominated_ice_socket_carries_two_independent_quic_connections() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut server_owner = UdpOwner::bind(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).await.unwrap();
            let mut client_owner = UdpOwner::bind(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ).await.unwrap();
            let server_address = server_owner.handle.local_address();
            let client_address = client_owner.handle.local_address();
            let a = new_ice_credentials();
            let b = new_ice_credentials();
            let (server_path, client_path) = tokio::join!(
                nominate_host_pair(&mut server_owner, client_address, a.clone(), b.clone(),
                    false, Duration::from_secs(5)),
                nominate_host_pair(&mut client_owner, server_address, b, a,
                    true, Duration::from_secs(5)),
            );
            assert_eq!(server_path.unwrap().remote, client_address);
            assert_eq!(client_path.unwrap().remote, server_address);

            let identity = rcgen::generate_simple_self_signed(
                vec!["localhost".into()
            ]).unwrap();
            let cert = identity.cert.der().clone();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into(),
            );
            let server_config = quinn::ServerConfig::with_single_cert(
                vec![cert.clone()], key,
            ).unwrap();

            let server_adapter = QuinnUdpAdapter::from_owner(&mut server_owner).unwrap();
            let server = quinn::Endpoint::new_with_abstract_socket(
                demux_endpoint_config(), Some(server_config),
                Arc::new(server_adapter), quinn::default_runtime().unwrap(),
            ).unwrap();

            let client_adapter = QuinnUdpAdapter::from_owner(&mut client_owner).unwrap();
            let mut client = quinn::Endpoint::new_with_abstract_socket(
                demux_endpoint_config(), None,
                Arc::new(client_adapter), quinn::default_runtime().unwrap(),
            ).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            client.set_default_client_config(
                quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
            );
            assert_eq!(client.local_addr().unwrap(), client_address);
            assert_eq!(server.local_addr().unwrap(), server_address);

            let (finished_tx, finished_rx) = tokio::sync::oneshot::channel::<()>();
            let server_task = tokio::spawn(async move {
                let mut accepted = Vec::new();
                for message in [b"control".as_slice(), b"data".as_slice()] {
                    let conn = server.accept().await.unwrap().await.unwrap();
                    let (mut tx, mut rx) = conn.accept_bi().await.unwrap();
                    assert_eq!(rx.read_to_end(128).await.unwrap(), message);
                    tx.write_all(b"ack").await.unwrap();
                    tx.finish().unwrap();
                    accepted.push(conn);
                }
                finished_rx.await.unwrap();
                assert!(accepted.iter().all(|c| c.close_reason().is_none()));
                server.close(0u32.into(), b"completed");
            });

            let control = client.connect(server_address, "localhost").unwrap().await.unwrap();
            let (mut tx, mut rx) = control.open_bi().await.unwrap();
            tx.write_all(b"control").await.unwrap();
            tx.finish().unwrap();
            assert_eq!(rx.read_to_end(16).await.unwrap(), b"ack");

            let data = client.connect(server_address, "localhost").unwrap().await.unwrap();
            assert_ne!(control.stable_id(), data.stable_id());
            let (mut tx, mut rx) = data.open_bi().await.unwrap();
            tx.write_all(b"data").await.unwrap();
            tx.finish().unwrap();
            assert_eq!(rx.read_to_end(16).await.unwrap(), b"ack");

            finished_tx.send(()).unwrap();
            server_task.await.unwrap();
            client.close(0u32.into(), b"completed");
        }).await.expect("ICE/dual-QUIC integration timeout");
    }
}
