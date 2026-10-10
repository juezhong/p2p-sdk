//! Concurrent multi-server STUN mapping diagnostics on ONE bound UDP socket.
//!
//! This gathers observations only: a stable result does not prove ICE path
//! reachability. The socket is never reused by Quinn or an ICE agent here.
//! One task owns recv_from; transaction + exact server address are checked
//! before accepting any result. Unrelated UDP packets are ignored.

use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::{timeout_at, Instant}};

use crate::stun::{binding_request, parse_binding_success, TransactionId};

const MAX_SERVERS: usize = 8;
const DATAGRAM_SIZE: usize = 2048;

#[derive(Debug)]
pub enum MultiStunError {
    InvalidServers,
    Entropy,
    Io(std::io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StunObservation {
    pub server: SocketAddr,
    pub mapped_address: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingReport {
    pub local_address: SocketAddr,
    pub observations: Vec<StunObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingConsistency {
    InsufficientData,
    Consistent,
    Different,
}

impl MappingReport {
    pub fn consistency(&self) -> MappingConsistency {
        if self.observations.len() < 2 {
            return MappingConsistency::InsufficientData;
        }
        let first = self.observations[0].mapped_address;
        if self.observations.iter().all(|o| o.mapped_address == first) {
            MappingConsistency::Consistent
        } else {
            MappingConsistency::Different
        }
    }
}

/// Query up to 8 distinct same-family servers on the same bound socket.
/// Any response with an unrequested source or mismatching transaction ID is
/// ignored. The time limit applies to the whole batch, not per server.
pub async fn query_same_socket(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    deadline: Duration,
) -> Result<MappingReport, MultiStunError> {
    let local = socket.local_addr().map_err(MultiStunError::Io)?;
    if servers.is_empty() || servers.len() > MAX_SERVERS || deadline.is_zero()
        || servers.iter().any(|s| s.port() == 0 || s.ip().is_unspecified()
            || s.ip().is_multicast() || s.is_ipv4() != local.is_ipv4())
    {
        return Err(MultiStunError::InvalidServers);
    }
    let mut pending = HashMap::<SocketAddr, TransactionId>::new();
    for &server in servers {
        if pending.contains_key(&server) {
            return Err(MultiStunError::InvalidServers);
        }
        let mut id = [0_u8; 12];
        getrandom::fill(&mut id).map_err(|_| MultiStunError::Entropy)?;
        pending.insert(server, TransactionId(id));
    }
    for (&server, &id) in &pending {
        socket.send_to(&binding_request(id), server).await.map_err(MultiStunError::Io)?;
    }
    let end = Instant::now() + deadline;
    let mut observations = Vec::with_capacity(servers.len());
    let mut buf = [0_u8; DATAGRAM_SIZE];
    while !pending.is_empty() {
        let (n, from) = match timeout_at(end, socket.recv_from(&mut buf)).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(err)) => return Err(MultiStunError::Io(err)),
            Err(_) => break,
        };
        if let Some(id) = pending.get(&from) {
            if let Ok(mapped_address) = parse_binding_success(&buf[..n], *id) {
                observations.push(StunObservation { server: from, mapped_address });
                pending.remove(&from);
            }
        }
    }
    observations.sort_by_key(|o| o.server);
    Ok(MappingReport { local_address: local, observations })
}


/// Query several servers concurrently through the *existing* single-reader
/// UDP owner. Unlike `query_same_socket`, this works while ICE/QUIC packets
/// are being demultiplexed by that owner. The owner remains responsible for
/// correlation and the actual UDP port.
pub async fn query_via_owner(
    owner: &crate::udp_owner::UdpOwnerHandle,
    servers: &[SocketAddr],
    deadline: Duration,
) -> Result<MappingReport, MultiStunError> {
    let local = owner.local_address();
    if servers.is_empty() || servers.len() > MAX_SERVERS || deadline.is_zero()
        || servers.iter().any(|s| s.port() == 0 || s.ip().is_unspecified()
            || s.ip().is_multicast() || s.is_ipv4() != local.is_ipv4())
    {
        return Err(MultiStunError::InvalidServers);
    }
    let mut unique = std::collections::HashSet::new();
    if !servers.iter().all(|s| unique.insert(*s)) {
        return Err(MultiStunError::InvalidServers);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for &server in servers {
        let handle = owner.clone();
        tasks.spawn(async move {
            (server, handle.query_stun(server, deadline).await)
        });
    }
    let mut observations = Vec::with_capacity(servers.len());
    let mut grace_deadline: Option<Instant> = None;
    loop {
        // Go 的语义：第一个有效 srflx 足以作为候选；最多再等 220ms
        // 获得第二份观测以判断映射是否依赖目标，而不为无响应服务器拖延。
        let next = match grace_deadline {
            Some(until) => timeout_at(until, tasks.join_next()).await.ok().flatten(),
            None => tasks.join_next().await,
        };
        let Some(result) = next else { break; };
        if let Ok((server, Ok(mapped_address))) = result {
            observations.push(StunObservation { server, mapped_address });
            if observations.len() >= 2 { break; }
            grace_deadline = Some(Instant::now() + Duration::from_millis(220));
        }
    }
    observations.sort_by_key(|o| o.server);
    Ok(MappingReport { local_address: local, observations })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::MAGIC_COOKIE;
    use std::net::IpAddr;

    fn response(request: &[u8], addr: SocketAddr) -> Vec<u8> {
        let mut out = request.to_vec();
        out[0..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        let mut attribute = vec![0, if addr.is_ipv4() { 1 } else { 2 }];
        attribute.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
        let octets: Vec<u8> = match addr.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for (i, &ch) in octets.iter().enumerate() {
            attribute.push(ch ^ if i < 4 { cookie[i] } else { request[8 + i - 4] });
        }
        out[2..4].copy_from_slice(&((attribute.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(&0x0020_u16.to_be_bytes());
        out.extend_from_slice(&(attribute.len() as u16).to_be_bytes());
        out.extend_from_slice(&attribute);
        out
    }

    #[tokio::test]
    async fn simultaneous_servers_share_real_source_udp_port() {
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addresses = [server1.local_addr().unwrap(), server2.local_addr().unwrap()];
        let expected: SocketAddr = "198.51.100.4:50000".parse().unwrap();
        let tasks = [server1, server2].into_iter().map(|server| {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                server.send_to(&response(&buf[..n], expected), from).await.unwrap();
                from
            })
        }).collect::<Vec<_>>();
        let report = query_same_socket(&source, &addresses, Duration::from_secs(1)).await.unwrap();
        assert_eq!(report.observations.len(), 2);
        assert_eq!(report.consistency(), MappingConsistency::Consistent);
        assert_eq!(report.local_address, source.local_addr().unwrap());
        for task in tasks {
            assert_eq!(task.await.unwrap(), source.local_addr().unwrap());
        }
    }

    #[tokio::test]
    async fn reports_different_mappings_and_partial_responses() {
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peers = [first.local_addr().unwrap(), second.local_addr().unwrap()];
        let t1 = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, from) = first.recv_from(&mut buf).await.unwrap();
            first.send_to(&response(&buf[..n], "198.51.100.2:1234".parse().unwrap()), from).await.unwrap();
        });
        let t2 = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, from) = second.recv_from(&mut buf).await.unwrap();
            second.send_to(&response(&buf[..n], "198.51.100.3:1235".parse().unwrap()), from).await.unwrap();
        });
        let result = query_same_socket(&source, &peers, Duration::from_secs(1)).await.unwrap();
        assert_eq!(result.consistency(), MappingConsistency::Different);
        t1.await.unwrap();
        t2.await.unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let only = query_same_socket(&source, &[silent.local_addr().unwrap()], Duration::from_millis(10)).await.unwrap();
        assert_eq!(only.consistency(), MappingConsistency::InsufficientData);
    }

    #[tokio::test]
    async fn multi_stun_via_single_udp_owner_preserves_source_port() {
        let owner = crate::udp_owner::UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destinations = [a.local_addr().unwrap(), b.local_addr().unwrap()];
        let servers = [a, b].into_iter().map(|server| tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&response(&buf[..n], "192.0.2.2:40001".parse().unwrap()), src).await.unwrap();
            src
        })).collect::<Vec<_>>();
        let report = query_via_owner(&owner.handle, &destinations, Duration::from_secs(2))
            .await.unwrap();
        assert_eq!(report.consistency(), MappingConsistency::Consistent);
        assert_eq!(report.observations.len(), 2);
        for server in servers {
            assert_eq!(server.await.unwrap(), report.local_address);
        }
    }

    #[tokio::test]
    async fn first_valid_stun_does_not_wait_for_silent_backup() {
        let owner = crate::udp_owner::UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let fast = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addresses = [fast.local_addr().unwrap(), silent.local_addr().unwrap()];
        let handler = tokio::spawn(async move {
            let mut buffer = [0u8; 128];
            let (size, from) = fast.recv_from(&mut buffer).await.unwrap();
            let reply = response(&buffer[..size], "198.51.100.20:41000".parse().unwrap());
            fast.send_to(&reply, from).await.unwrap();
        });
        let report = tokio::time::timeout(Duration::from_millis(900),
            query_via_owner(&owner.handle, &addresses, Duration::from_secs(3)),
        ).await.expect("one valid STUN should trigger short grace").unwrap();
        assert_eq!(report.observations.len(), 1);
        handler.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_duplicate_servers_and_wrong_address_family() {
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = "127.0.0.1:3478".parse().unwrap();
        assert!(matches!(
            query_same_socket(&source, &[peer, peer], Duration::from_secs(1)).await,
            Err(MultiStunError::InvalidServers)
        ));
        assert!(matches!(
            query_same_socket(&source, &["[::1]:3478".parse().unwrap()], Duration::from_secs(1)).await,
            Err(MultiStunError::InvalidServers)
        ));
    }
}
