//! Experimental UDP STUN Binding discovery (RFC 8489).
//!
//! A successful query discovers a server-reflexive *observation*, not a
//! validated ICE candidate pair or a hole-punched P2P connection.
//! This implementation owns a dedicated UDP socket for its whole lifetime.
//! NEVER use its result as evidence that a different Quinn/ICE socket has
//! the same NAT mapping. The future ICE agent must own/demultiplex its UDP I/O.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, timeout_at, Instant};

use crate::stun::{binding_request, parse_binding_success, TransactionId};

const MAX_ATTEMPTS: u8 = 4;
const MAX_INITIAL_TIMEOUT: Duration = Duration::from_secs(2);
const RECEIVE_BUFFER_SIZE: usize = 2048;

#[derive(Clone, Copy, Debug)]
pub struct ProbeOptions {
    /// Number of Binding Request sends. Each retransmission uses the same transaction ID.
    pub max_attempts: u8,
    /// Initial response timeout, doubled after each retransmission.
    pub initial_timeout: Duration,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            initial_timeout: Duration::from_millis(250),
        }
    }
}

impl ProbeOptions {
    fn validate(&self) -> Result<(), ProbeError> {
        if self.max_attempts == 0
            || self.max_attempts > MAX_ATTEMPTS
            || self.initial_timeout.is_zero()
            || self.initial_timeout > MAX_INITIAL_TIMEOUT
        {
            return Err(ProbeError::InvalidOptions);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeResult {
    /// Server-reflexive address observed by the STUN server.
    pub mapped_address: SocketAddr,
    /// Local address of the dedicated UDP socket that performed the query.
    pub local_address: SocketAddr,
    pub stun_server: SocketAddr,
    pub attempts_used: u8,
}

#[derive(Debug)]
pub enum ProbeError {
    InvalidOptions,
    InvalidServer,
    Entropy(getrandom::Error),
    Io(std::io::Error),
    Timeout,
}

/// Discover the UDP mapping visible to exactly this disposable socket.
///
/// No shared UDP socket is exposed or silently reused. ICE and QUIC must
/// later perform their own checks on their real shared transport socket.
///
/// Checks UDP source address AND 96-bit STUN transaction ID. Nonmatching,
/// malformed, or unrelated packets are ignored until the attempt deadline.
/// Aborting the future safely drops the socket.
pub async fn discover_mapping(
    server: SocketAddr,
    options: ProbeOptions,
) -> Result<ProbeResult, ProbeError> {
    options.validate()?;
    if server.port() == 0 || server.ip().is_unspecified() || server.ip().is_multicast() {
        return Err(ProbeError::InvalidServer);
    }
    let local = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(local).await.map_err(ProbeError::Io)?;
    let local_address = socket.local_addr().map_err(ProbeError::Io)?;

    let mut random_id = [0u8; 12];
    getrandom::fill(&mut random_id).map_err(ProbeError::Entropy)?;
    let transaction = TransactionId(random_id);
    let request = binding_request(transaction);
    let mut received = [0u8; RECEIVE_BUFFER_SIZE];

    for retry in 0..options.max_attempts {
        let wait = options.initial_timeout.saturating_mul(1u32 << retry);
        timeout(wait, socket.send_to(&request, server))
            .await
            .map_err(|_| ProbeError::Timeout)?
            .map_err(ProbeError::Io)?;

        let deadline = Instant::now() + wait;
        loop {
            let result = timeout_at(deadline, socket.recv_from(&mut received)).await;
            let (size, source) = match result {
                Ok(Ok(packet)) => packet,
                Ok(Err(err)) => return Err(ProbeError::Io(err)),
                Err(_) => break,
            };
            if source != server {
                continue;
            }
            if let Ok(mapped_address) = parse_binding_success(&received[..size], transaction) {
                return Ok(ProbeResult {
                    mapped_address,
                    local_address,
                    stun_server: server,
                    attempts_used: retry + 1,
                });
            }
        }
    }
    Err(ProbeError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::MAGIC_COOKIE;

    fn success_response(request: &[u8], mapped: SocketAddr) -> Vec<u8> {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let mut value = vec![0, if mapped.is_ipv4() { 1 } else { 2 }];
        value.extend_from_slice(&(mapped.port() ^ 0x2112).to_be_bytes());
        let octets = match mapped.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        for (i, byte) in octets.iter().enumerate() {
            let mask = if i < 4 { cookie[i] } else { request[8 + i - 4] };
            value.push(byte ^ mask);
        }
        let mut packet = Vec::from(request);
        packet[..2].copy_from_slice(&0x0101u16.to_be_bytes());
        packet[2..4].copy_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        packet.extend_from_slice(&0x0020u16.to_be_bytes());
        packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
        packet.extend_from_slice(&value);
        packet
    }

    #[tokio::test]
    async fn discovers_ipv4_address_using_real_local_udp_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let mapped: SocketAddr = "198.51.100.23:43566".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let (len, peer) = server.recv_from(&mut buffer).await.unwrap();
            let response = success_response(&buffer[..len], mapped);
            server.send_to(&response, peer).await.unwrap();
        });
        let result = discover_mapping(addr, ProbeOptions::default()).await.unwrap();
        assert_eq!(result.mapped_address, mapped);
        assert_eq!(result.stun_server, addr);
        assert_eq!(result.attempts_used, 1);
        assert_ne!(result.local_address.port(), 0);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn ignores_wrong_source_and_transaction_then_accepts_valid_response() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let mapped: SocketAddr = "203.0.113.42:9000".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let valid = success_response(&buf[..len], mapped);
            attacker.send_to(&valid, peer).await.unwrap();
            let mut wrong_id = valid.clone();
            wrong_id[8] ^= 0xff;
            server.send_to(&wrong_id, peer).await.unwrap();
            server.send_to(&valid, peer).await.unwrap();
        });
        let options = ProbeOptions {
            max_attempts: 2,
            initial_timeout: Duration::from_millis(100),
        };
        let result = discover_mapping(addr, options).await.unwrap();
        assert_eq!(result.mapped_address, mapped);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn retransmits_with_the_same_transaction_id() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let mapped: SocketAddr = "198.51.100.5:4555".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut first = [0u8; 1024];
            let mut next = [0u8; 1024];
            let (one, peer) = server.recv_from(&mut first).await.unwrap();
            let (two, peer2) = server.recv_from(&mut next).await.unwrap();
            assert_eq!(peer, peer2);
            assert_eq!(&first[..one], &next[..two]);
            server.send_to(&success_response(&next[..two], mapped), peer).await.unwrap();
        });
        let options = ProbeOptions {
            max_attempts: 2,
            initial_timeout: Duration::from_millis(20),
        };
        let result = discover_mapping(addr, options).await.unwrap();
        assert_eq!(result.attempts_used, 2);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn reports_timeout_without_stun_reply() {
        let silent_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let options = ProbeOptions {
            max_attempts: 2,
            initial_timeout: Duration::from_millis(10),
        };
        let result = discover_mapping(silent_server.local_addr().unwrap(), options).await;
        assert!(matches!(result, Err(ProbeError::Timeout)));
    }

    #[tokio::test]
    async fn validates_configuration_before_binding() {
        let server: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let options = ProbeOptions {
            max_attempts: 0,
            initial_timeout: Duration::from_millis(5),
        };
        assert!(matches!(
            discover_mapping(server, options).await,
            Err(ProbeError::InvalidOptions)
        ));
        assert!(matches!(
            discover_mapping("0.0.0.0:0".parse().unwrap(), ProbeOptions::default()).await,
            Err(ProbeError::InvalidServer)
        ));
    }
}
