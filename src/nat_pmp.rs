//! Optional RFC 6886 NAT-PMP UDP port mapping on an explicitly selected LAN gateway.
//!
//! This is gateway CONTROL traffic, not ICE connectivity checking: it does
//! not consume the QUIC/ICE UDP socket. The request explicitly maps that
//! socket's UDP port and is sent from the SAME local IPv4 address. It does
//! not imply the external endpoint is reachable, or that an ISP CGNAT maps
//! will be open. ICE MUST still check/nominate all advertised paths.
//!
//! API intentionally leaves gateway discovery, renewal/deletion, and mapping
//! address changes to a future long-lived coordinator. Mapping lifetime
//! must be renewed before expiry; never treat this helper as a permanent map.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use tokio::{net::UdpSocket, time::{timeout_at, Instant}};

const VERSION: u8 = 0;
const PUBLIC_IP_REQUEST: [u8; 2] = [VERSION, 0];
const PUBLIC_IP_REPLY: u8 = 128;
const MAP_UDP_REQUEST: u8 = 1;
const MAP_UDP_REPLY: u8 = 129;
const MAX_RESPONSE: usize = 128;

#[derive(Debug)]
pub enum PortMapError {
    InvalidInput,
    Io(std::io::Error),
    Timeout,
    UnsupportedOrDenied(u16),
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpMapping {
    pub local_address: SocketAddrV4,
    pub external_address: SocketAddrV4,
    pub granted_lifetime_seconds: u32,
    pub gateway_epoch_seconds: u32,
}

/// Send gateway control transactions from the same local IP that owns the
/// nominated ICE/QUIC UDP socket, but from a DIFFERENT ephemeral source port.
/// The router maps the requested internal port explicitly.
pub async fn request_udp_mapping(
    local: SocketAddrV4,
    gateway: SocketAddrV4,
    lifetime: Duration,
    transaction_timeout: Duration,
) -> Result<UdpMapping, PortMapError> {
    if local.port() == 0 || local.ip().is_unspecified()
        || gateway.port() == 0 || gateway.ip().is_unspecified()
        || gateway.ip().is_multicast() || lifetime.is_zero()
        || lifetime.as_secs() > u32::MAX as u64 || transaction_timeout.is_zero()
    {
        return Err(PortMapError::InvalidInput);
    }

    let socket = UdpSocket::bind(SocketAddrV4::new(*local.ip(), 0))
        .await.map_err(PortMapError::Io)?;
    let gateway_addr = SocketAddr::V4(gateway);
    let (external_ip, _) = transact(
        &socket, gateway_addr, &PUBLIC_IP_REQUEST,
        PUBLIC_IP_REPLY, transaction_timeout,
        |response| {
            if response.len() != 12 { return None; }
            if response[0] != VERSION || response[1] != PUBLIC_IP_REPLY {
                return None;
            }
            let code = u16::from_be_bytes([response[2], response[3]]);
            if code != 0 { return Some(Err(PortMapError::UnsupportedOrDenied(code))); }
            let ip = Ipv4Addr::new(response[8], response[9], response[10], response[11]);
            if ip.is_unspecified() || ip.is_multicast() { return Some(Err(PortMapError::InvalidResponse)); }
            Some(Ok((ip, u32::from_be_bytes(response[4..8].try_into().unwrap()))))
        },
    ).await?;

    let lifetime_secs = lifetime.as_secs() as u32;
    let mut packet = [0_u8; 12];
    packet[1] = MAP_UDP_REQUEST;
    packet[4..6].copy_from_slice(&local.port().to_be_bytes());
    packet[6..8].copy_from_slice(&local.port().to_be_bytes());
    packet[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());

    let (external_port, epoch_and_life) = transact(
        &socket, gateway_addr, &packet,
        MAP_UDP_REPLY, transaction_timeout,
        |response| {
            if response.len() != 16
                || response[0] != VERSION || response[1] != MAP_UDP_REPLY
            {
                return None;
            }
            let code = u16::from_be_bytes([response[2], response[3]]);
            if code != 0 { return Some(Err(PortMapError::UnsupportedOrDenied(code))); }
            let internal = u16::from_be_bytes([response[8], response[9]]);
            let external = u16::from_be_bytes([response[10], response[11]]);
            let life = u32::from_be_bytes(response[12..16].try_into().unwrap());
            if internal != local.port() || external == 0 || life == 0 {
                return Some(Err(PortMapError::InvalidResponse));
            }
            Some(Ok((external, (
                u32::from_be_bytes(response[4..8].try_into().unwrap()), life,
            ))))
        },
    ).await?;

    Ok(UdpMapping {
        local_address: local,
        external_address: SocketAddrV4::new(external_ip, external_port),
        granted_lifetime_seconds: epoch_and_life.1,
        gateway_epoch_seconds: epoch_and_life.0,
    })
}

/// Correlate by exact UDP gateway source, opcode, version and request-specific
/// echoed fields; ignore stray packets without consuming the whole timeout.
async fn transact<T, U, F>(
    socket: &UdpSocket,
    gateway: SocketAddr,
    request: &[u8],
    expected_opcode: u8,
    timeout: Duration,
    mut decode: F,
) -> Result<(T, U), PortMapError>
where
    F: FnMut(&[u8]) -> Option<Result<(T, U), PortMapError>>,
{
    let deadline = Instant::now() + timeout;
    let mut received = [0_u8; MAX_RESPONSE];
    for attempt in 0..3u32 {
        socket.send_to(request, gateway).await.map_err(PortMapError::Io)?;
        let wait = Duration::from_millis(100 * (1 << attempt));
        let try_until = (Instant::now() + wait).min(deadline);
        loop {
            match timeout_at(try_until, socket.recv_from(&mut received)).await {
                Ok(Ok((n, source))) => {
                    if source == gateway && n >= 2 && received[1] == expected_opcode {
                        if let Some(result) = decode(&received[..n]) {
                            return result;
                        }
                    }
                }
                Ok(Err(err)) => return Err(PortMapError::Io(err)),
                Err(_) => break,
            }
        }
        if Instant::now() >= deadline { break; }
    }
    Err(PortMapError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn public_address_and_udp_mapping_share_local_ipv4_and_verify_reply() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let router_addr: SocketAddrV4 = match router.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr, _ => unreachable!(),
        };
        let control = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, from) = router.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &PUBLIC_IP_REQUEST);
            let first = [0, 128, 0, 0, 0, 0, 0, 4, 198, 51, 100, 100];
            router.send_to(&first, from).await.unwrap();

            let (n, from2) = router.recv_from(&mut buf).await.unwrap();
            assert_eq!(from2, from);
            assert_eq!(n, 12);
            assert_eq!(buf[1], MAP_UDP_REQUEST);
            assert_eq!(&buf[4..6], &54321u16.to_be_bytes());
            let mut reply = [0u8; 16];
            reply[1] = MAP_UDP_REPLY;
            reply[4..8].copy_from_slice(&5u32.to_be_bytes());
            reply[8..10].copy_from_slice(&54321u16.to_be_bytes());
            reply[10..12].copy_from_slice(&49322u16.to_be_bytes());
            reply[12..16].copy_from_slice(&1800u32.to_be_bytes());
            router.send_to(&reply, from2).await.unwrap();
        });
        let result = timeout(Duration::from_secs(3), request_udp_mapping(
            "127.0.0.1:54321".parse().unwrap(), router_addr,
            Duration::from_secs(3600), Duration::from_secs(2),
        )).await.unwrap().unwrap();
        assert_eq!(result.external_address, "198.51.100.100:49322".parse().unwrap());
        assert_eq!(result.granted_lifetime_seconds, 1800);
        control.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_gateway_or_map_port() {
        let invalid: SocketAddrV4 = "0.0.0.0:0".parse().unwrap();
        let gateway: SocketAddrV4 = "127.0.0.1:5351".parse().unwrap();
        assert!(matches!(
            request_udp_mapping(invalid, gateway, Duration::from_secs(100), Duration::from_secs(1)).await,
            Err(PortMapError::InvalidInput)
        ));
    }

    #[tokio::test]
    async fn ignores_forged_wrong_source_and_times_out() {
        let fake = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gateway = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gateway_addr = match gateway.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr, _ => unreachable!(),
        };
        let spoof = tokio::spawn(async move {
            let mut packet = [0; 128];
            let (_, from) = gateway.recv_from(&mut packet).await.unwrap();
            let fake_success = [0, 128, 0, 0, 0, 0, 0, 1, 198, 51, 100, 99];
            fake.send_to(&fake_success, from).await.unwrap();
        });
        let result = request_udp_mapping("127.0.0.1:54321".parse().unwrap(),
            gateway_addr, Duration::from_secs(300), Duration::from_millis(250)).await;
        assert!(matches!(result, Err(PortMapError::Timeout)));
        spoof.await.unwrap();
    }
}
