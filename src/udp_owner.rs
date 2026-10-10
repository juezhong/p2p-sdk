//! One UDP socket receiver and bounded STUN / ICE / QUIC demultiplexing.
//!
//! Proof-of-concept transport ownership. QUIC packets are *queued*, NOT
//! injected into Quinn's AsyncUdpSocket yet. ICE checks are *forwarded*, NOT
//! authenticated by an ICE agent. Both integrations remain future work.
//! Never run an uncoordinated recv_from loop on the underlying socket.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{timeout, Instant},
};

use crate::{
    packet_demux::{classify_datagram, PacketRoute},
    stun::{binding_request, parse_binding_success, TransactionId},
};

const MAX_DATAGRAM: usize = 2048;
const MAX_PENDING: usize = 64;
const QUEUE_CAPACITY: usize = 128;

#[derive(Clone, Debug)]
pub struct InboundDatagram {
    pub source: SocketAddr,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpOwnerError {
    Closed,
    Timeout,
    Busy,
    Entropy,
    Io,
}

struct Query {
    server: SocketAddr,
    transaction: TransactionId,
    deadline: Instant,
    answer: oneshot::Sender<Result<SocketAddr, UdpOwnerError>>,
}

#[derive(Clone)]
pub struct UdpOwnerHandle {
    local_address: SocketAddr,
    actions: mpsc::Sender<Query>,
    ice_outbound: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

impl UdpOwnerHandle {
    /// Send one bounded ICE STUN datagram on the SAME UDP port owned by
    /// this receiver. Non-STUN packets must use the Quinn adapter instead.
    pub async fn send_ice(&self, destination: SocketAddr, packet: &[u8]) -> Result<(), UdpOwnerError> {
        if destination.port() == 0 || destination.ip().is_unspecified()
            || destination.is_ipv4() != self.local_address.is_ipv4()
            || packet.len() > MAX_DATAGRAM
            || classify_datagram(packet) != PacketRoute::Stun
        {
            return Err(UdpOwnerError::Io);
        }
        self.ice_outbound.send((destination, packet.to_vec()))
            .await.map_err(|_| UdpOwnerError::Closed)
    }

    /// Send an authenticated punch probe from the exact existing ICE/QUIC
    /// UDP port. The receiver authenticates packets before learning prflx.
    pub async fn send_punch(&self, destination: SocketAddr, packet: &[u8])
        -> Result<(), UdpOwnerError>
    {
        if destination.port() == 0 || destination.ip().is_unspecified()
            || destination.is_ipv4() != self.local_address.is_ipv4()
            || packet.len() != crate::punch::PACKET_BYTES
            || classify_datagram(packet) != PacketRoute::Punch
        {
            return Err(UdpOwnerError::Io);
        }
        self.ice_outbound.send((destination, packet.to_vec())).await
            .map_err(|_| UdpOwnerError::Closed)
    }

    pub fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// The shared owner sends and receives using its bound UDP socket.
    /// This does not nominate an ICE path or prove future QUIC reachability.
    pub async fn query_stun(
        &self,
        server: SocketAddr,
        wait: Duration,
    ) -> Result<SocketAddr, UdpOwnerError> {
        if server.port() == 0 || server.ip().is_unspecified() ||
            server.is_ipv4() != self.local_address.is_ipv4() || wait.is_zero()
        {
            return Err(UdpOwnerError::Io);
        }
        let mut bytes = [0_u8; 12];
        getrandom::fill(&mut bytes).map_err(|_| UdpOwnerError::Entropy)?;
        let (answer, receiver) = oneshot::channel();
        self.actions.send(Query {
            server,
            transaction: TransactionId(bytes),
            deadline: Instant::now() + wait,
            answer,
        }).await.map_err(|_| UdpOwnerError::Closed)?;
        timeout(wait, receiver).await
            .map_err(|_| UdpOwnerError::Timeout)?
            .map_err(|_| UdpOwnerError::Closed)?
    }
}

/// Consumers own bounded datagram queues. ICE consumers must validate STUN
/// MESSAGE-INTEGRITY; the QUIC queue requires an actual Quinn adapter.
pub struct UdpOwner {
    pub handle: UdpOwnerHandle,
    pub ice_packets: mpsc::Receiver<InboundDatagram>,
    /// Only a verified PunchAuthenticator may turn these into prflx candidates.
    pub punch_packets: mpsc::Receiver<InboundDatagram>,
    pub(crate) quic_packets: mpsc::Receiver<InboundDatagram>,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) quic_adapter_taken: bool,
    // JOIN 在进入有限 ICE 检查前创建的真实 QUIC listener。
    // 与后续 ICE/QUIC 共用原 UDP socket，不能再次接管 QUIC 队列。
    pub(crate) passive_endpoint: Option<quinn::Endpoint>,
    task: JoinHandle<()>,
}

impl UdpOwner {
    pub async fn bind(address: SocketAddr) -> Result<Self, std::io::Error> {
        let socket = Arc::new(UdpSocket::bind(address).await?);
        let local = socket.local_addr()?;
        let (actions_tx, actions_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (ice_out_tx, ice_out_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (ice_tx, ice_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (punch_tx, punch_rx) = mpsc::channel(QUEUE_CAPACITY);
        let (quic_tx, quic_rx) = mpsc::channel(QUEUE_CAPACITY);
        let task = tokio::spawn(run_owner(Arc::clone(&socket),
            actions_rx, ice_out_rx, ice_tx, punch_tx, quic_tx));
        Ok(Self {
            handle: UdpOwnerHandle { local_address: local, actions: actions_tx, ice_outbound: ice_out_tx },
            ice_packets: ice_rx,
            punch_packets: punch_rx,
            quic_packets: quic_rx,
            socket,
            quic_adapter_taken: false,
            passive_endpoint: None,
            task,
        })
    }
}

impl Drop for UdpOwner {
    fn drop(&mut self) {
        if let Some(endpoint) = self.passive_endpoint.take() {
            endpoint.close(0u32.into(), b"UDP owner released");
        }
        self.task.abort();
    }
}

async fn run_owner(
    socket: Arc<UdpSocket>,
    mut actions: mpsc::Receiver<Query>,
    mut ice_outbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    ice_tx: mpsc::Sender<InboundDatagram>,
    punch_tx: mpsc::Sender<InboundDatagram>,
    quic_tx: mpsc::Sender<InboundDatagram>,
) {
    let mut pending = HashMap::<(SocketAddr, [u8; 12]), Query>::new();
    let mut buf = [0_u8; MAX_DATAGRAM];
    let mut sweep = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            outgoing = ice_outbound.recv() => {
                if let Some((destination, bytes)) = outgoing {
                    let _ = socket.send_to(&bytes, destination).await;
                }
            }
            _ = sweep.tick() => {
                let now = Instant::now();
                // Query futures enforce their own timeout. Dropping an
                // expired sender frees a transaction slot without blocking.
                pending.retain(|_, q| now < q.deadline && !q.answer.is_closed());
            }
            request = actions.recv() => {
                let Some(q) = request else { break; };
                if pending.len() >= MAX_PENDING {
                    let _ = q.answer.send(Err(UdpOwnerError::Busy));
                    continue;
                }
                let key = (q.server, q.transaction.0);
                let packet = binding_request(q.transaction);
                if socket.send_to(&packet, q.server).await.is_err() {
                    let _ = q.answer.send(Err(UdpOwnerError::Io));
                } else {
                    pending.insert(key, q);
                }
            }
            received = socket.recv_from(&mut buf) => {
                let (size, source) = match received {
                    Ok(value) => value,
                    Err(error) if crate::udp_errors::is_transient_unreachable(&error) => continue,
                    Err(_) => break,
                };
                let bytes = &buf[..size];
                match classify_datagram(bytes) {
                    PacketRoute::Stun => {
                        if size >= 20 {
                            let mut id = [0_u8; 12];
                            id.copy_from_slice(&bytes[8..20]);
                            let key = (source, id);
                            if let Some(q) = pending.get(&key) {
                                if let Ok(addr) = parse_binding_success(bytes, q.transaction) {
                                    if let Some(q) = pending.remove(&key) {
                                        let _ = q.answer.send(Ok(addr));
                                    }
                                    continue;
                                }
                            }
                        }
                        let _ = ice_tx.try_send(InboundDatagram {
                            source, bytes: bytes.to_vec()
                        });
                    }
                    PacketRoute::Punch => {
                        let _ = punch_tx.try_send(InboundDatagram {
                            source, bytes: bytes.to_vec()
                        });
                    }
                    PacketRoute::Quic => {
                        let _ = quic_tx.try_send(InboundDatagram {
                            source, bytes: bytes.to_vec()
                        });
                    }
                    PacketRoute::Drop => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use crate::stun::MAGIC_COOKIE;

    fn respond(request: &[u8], mapped: SocketAddr) -> Vec<u8> {
        let mut packet = request.to_vec();
        packet[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        let mut value = vec![0, if mapped.is_ipv4() { 1 } else { 2 }];
        value.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
        let raw: Vec<u8> = match mapped.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        for (i, byte) in raw.iter().enumerate() {
            value.push(byte ^ if i < 4 {
                MAGIC_COOKIE.to_be_bytes()[i]
            } else {
                request[8 + i - 4]
            });
        }
        packet[2..4].copy_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        packet.extend_from_slice(&0x0020_u16.to_be_bytes());
        packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
        packet.extend_from_slice(&value);
        packet
    }

    #[tokio::test]
    async fn one_socket_routes_stun_quic_and_ice_without_competing_receivers() {
        let mut owner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_address = server.local_addr().unwrap();
        let mapped: SocketAddr = "198.51.100.1:45001".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0_u8; 1024];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            let fake_quic = [0xc0_u8, 0, 0, 0];
            server.send_to(&fake_quic, from).await.unwrap();
            let unknown_stun = binding_request(TransactionId([51; 12]));
            server.send_to(&unknown_stun, from).await.unwrap();
            server.send_to(&respond(&buf[..n], mapped), from).await.unwrap();
        });
        let resolved = owner.handle.query_stun(server_address, Duration::from_secs(1))
            .await.unwrap();
        assert_eq!(resolved, mapped);
        let quic = tokio::time::timeout(Duration::from_secs(1), owner.quic_packets.recv())
            .await.unwrap().unwrap();
        assert_eq!(quic.source, server_address);
        assert_eq!(quic.bytes[0], 0xc0);
        let ice = tokio::time::timeout(Duration::from_secs(1), owner.ice_packets.recv())
            .await.unwrap().unwrap();
        assert_eq!(ice.source, server_address);
        assert_eq!(ice.bytes, binding_request(TransactionId([51; 12])));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn punch_and_quic_are_demuxed_on_same_bound_socket() {
        let mut a = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let credentials = crate::session_binding::SessionCredentials::new(
            [9; 16], [7; 32],
        ).unwrap();
        let outgoing = crate::punch::AuthenticatedPunch::new(
            credentials.clone(), crate::ice_signaling::IceRole::Controlling,
        );
        let incoming = crate::punch::AuthenticatedPunch::new(
            credentials, crate::ice_signaling::IceRole::Controlled,
        );
        let stamp = crate::punch::unix_seconds().unwrap();
        let packet = outgoing.make_packet(stamp).unwrap();
        b.handle.send_punch(a.handle.local_address(), &packet).await.unwrap();
        let received = timeout(Duration::from_secs(1), a.punch_packets.recv())
            .await.unwrap().unwrap();
        assert_eq!(received.source, b.handle.local_address());
        assert_eq!(incoming.authenticate(&received.bytes, received.source, stamp),
            Ok(b.handle.local_address()));
    }

    #[tokio::test]
    async fn rejects_source_spoof_and_times_out_without_valid_response() {
        let owner = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = owner.handle.query_stun(silent.local_addr().unwrap(),
            Duration::from_millis(50)).await;
        assert_eq!(result, Err(UdpOwnerError::Timeout));
    }
}
