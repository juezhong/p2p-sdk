//! Quinn AsyncUdpSocket adapter over the SDK's one-reader UDP owner.
//!
//! Receives QUIC packets exclusively from the demux's bounded QUIC queue.
//! Transmissions share the exact UDP socket used for STUN / future ICE.
//! Experimental: lacks ECN/source-IP ancillary data, batching and GSO/GRO.
//! Do not interpret a loopback test as a validated NAT/ICE candidate pair.

use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use quinn::{udp::{RecvMeta, Transmit}, AsyncUdpSocket, UdpPoller};
use tokio::{net::UdpSocket, sync::mpsc};

use crate::udp_owner::{InboundDatagram, UdpOwner};

pub struct QuinnUdpAdapter {
    socket: Arc<UdpSocket>,
    incoming: Mutex<mpsc::Receiver<InboundDatagram>>,
}

impl fmt::Debug for QuinnUdpAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuinnUdpAdapter")
            .field("local_address", &self.socket.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl QuinnUdpAdapter {
    /// Can be called once per UDP Owner. Keep the owner alive for the entire
    /// Quinn Endpoint lifetime; it owns the only UDP recv loop.
    pub fn from_owner(owner: &mut UdpOwner) -> io::Result<Self> {
        if owner.quic_adapter_taken {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Quinn adapter already created"));
        }
        let (sender, empty) = mpsc::channel(1);
        drop(sender);
        let incoming = std::mem::replace(&mut owner.quic_packets, empty);
        owner.quic_adapter_taken = true;
        Ok(Self {
            socket: Arc::clone(&owner.socket),
            incoming: Mutex::new(incoming),
        })
    }
}

#[derive(Debug)]
struct Writable {
    socket: Arc<UdpSocket>,
}

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for QuinnUdpAdapter {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable { socket: Arc::clone(&self.socket) })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if let Some(segment_size) = transmit.segment_size {
            if segment_size < transmit.contents.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP segmentation unsupported"));
            }
        }
        // Without packet-info support we must not silently select a wrong
        // local source IP on multi-homed devices.
        if transmit.src_ip.is_some() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "explicit UDP source IP unsupported"));
        }
        let sent = self.socket.try_send_to(transmit.contents, transmit.destination)?;
        if sent != transmit.contents.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"));
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "no receive buffers")));
        }
        let mut receiver = match self.incoming.lock() {
            Ok(guard) => guard,
            Err(_) => return Poll::Ready(Err(io::Error::other("Quinn receive lock poisoned"))),
        };
        match receiver.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let n = packet.bytes.len();
                if n > bufs[0].len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData, "QUIC datagram exceeds receive buffer"
                    )));
                }
                bufs[0][..n].copy_from_slice(&packet.bytes);
                let m = &mut meta[0];
                m.addr = packet.source;
                m.len = n;
                m.stride = n;
                m.dst_ip = None;
                m.ecn = None;
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe, "UDP demultiplexer shut down"
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn max_receive_segments(&self) -> usize { 1 }
    fn max_transmit_segments(&self) -> usize { 1 }
    fn may_fragment(&self) -> bool { true }
}

/// Prevent QUIC fixed-bit greasing, which is incompatible with the
/// RFC 9443 STUN/QUIC packet classifier.
pub fn demux_endpoint_config() -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    config.grease_quic_bit(false);
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddr, time::Duration};

    #[tokio::test]
    async fn shared_udp_owner_routes_quinn_tls_and_stun_on_identical_port() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let certificate =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert = certificate.cert.der().clone();
            let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                certificate.signing_key.serialize_der().into(),
            );
            let server_config = quinn::ServerConfig::with_single_cert(
                vec![cert.clone()], private_key,
            ).unwrap();

            let mut server_owner = UdpOwner::bind(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap()
            ).await.unwrap();
            let server_address = server_owner.handle.local_address();
            let server_adapter = QuinnUdpAdapter::from_owner(&mut server_owner).unwrap();
            assert!(QuinnUdpAdapter::from_owner(&mut server_owner).is_err());
            let server = quinn::Endpoint::new_with_abstract_socket(
                demux_endpoint_config(), Some(server_config),
                Arc::new(server_adapter), quinn::default_runtime().unwrap(),
            ).unwrap();

            let mut client_owner = UdpOwner::bind(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap()
            ).await.unwrap();
            let client_address = client_owner.handle.local_address();
            let client_adapter = QuinnUdpAdapter::from_owner(&mut client_owner).unwrap();
            let mut client = quinn::Endpoint::new_with_abstract_socket(
                demux_endpoint_config(), None,
                Arc::new(client_adapter), quinn::default_runtime().unwrap(),
            ).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert).unwrap();
            client.set_default_client_config(
                quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap()
            );

            let server_task = tokio::spawn(async move {
                let incoming = server.accept().await.expect("quic incoming");
                let conn = incoming.await.expect("quic TLS handshake");
                let (mut tx, mut rx) = conn.accept_bi().await.expect("control stream");
                let received = rx.read_to_end(128).await.unwrap();
                assert_eq!(received, b"same udp port");
                tx.write_all(b"ack").await.unwrap();
                tx.finish().unwrap();
                conn.closed().await;
            });

            // STUN on EXACT SAME client UDP socket while Quinn is running.
            let stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let stun_address = stun.local_addr().unwrap();
            let stun_task = tokio::spawn(async move {
                let mut request = [0u8; 256];
                let (n, source) = stun.recv_from(&mut request).await.unwrap();
                assert_eq!(source, client_address);
                let packet = &request[..n];
                let cookie = crate::stun::MAGIC_COOKIE.to_be_bytes();
                let mut response = packet.to_vec();
                response[..2].copy_from_slice(&0x0101u16.to_be_bytes());
                response[2..4].copy_from_slice(&12u16.to_be_bytes());
                response.extend_from_slice(&0x0020u16.to_be_bytes());
                response.extend_from_slice(&8u16.to_be_bytes());
                response.extend_from_slice(&[0, 1]);
                response.extend_from_slice(&(45000u16 ^ 0x2112).to_be_bytes());
                for i in 0..4 {
                    response.push([198, 51, 100, 10][i] ^ cookie[i]);
                }
                stun.send_to(&response, source).await.unwrap();
            });
            let discovered = client_owner.handle.query_stun(
                stun_address, Duration::from_secs(2)
            ).await.unwrap();
            assert_eq!(discovered, "198.51.100.10:45000".parse().unwrap());
            stun_task.await.unwrap();

            let connection = client.connect(server_address, "localhost").unwrap()
                .await.expect("quinn TLS handshake");
            let (mut tx, mut rx) = connection.open_bi().await.unwrap();
            tx.write_all(b"same udp port").await.unwrap();
            tx.finish().unwrap();
            assert_eq!(rx.read_to_end(32).await.unwrap(), b"ack");
            connection.close(0u32.into(), b"completed");
            server_task.await.unwrap();
            client.close(0u32.into(), b"completed");
        }).await.expect("shared UDP Quinn/STUN integration test timeout");
    }
}
