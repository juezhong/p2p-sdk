//! RFC 6887 PCP MAP UDP port mapping against an explicit trusted gateway.
//!
//! This is opt-in LAN gateway control traffic. ICE/Quinn retain their
//! existing bound UDP socket, and the port mapping references THAT port.
//! No relay, TURN or file-transfer logic is present. A PCP mapping must be
//! renewed and its external endpoint must still pass an authenticated ICE
//! candidate-pair check before application data can use it.
//!
//! Gateway discovery, lifetime renewal, loss detection, and system-wide
//! firewall policy are separate higher-level work.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::{net::UdpSocket, time::{timeout_at, Instant}};

const VERSION: u8 = 2;
const MAP_REQUEST: u8 = 1;
const MAP_REPLY: u8 = 0x81;
const UDP_PROTOCOL_NUMBER: u8 = 17;
const PACKET_LEN: usize = 60;
const MAX_PACKET: usize = 1100;

#[derive(Debug)]
pub enum PcpError {
    InvalidInput,
    Io(std::io::Error),
    Entropy,
    Timeout,
    UnsupportedOrDenied(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcpUdpMapping {
    pub local_address: SocketAddr,
    pub external_address: SocketAddr,
    pub lifetime_seconds: u32,
    pub epoch_seconds: u32,
    /// Must be reused to renew/delete the same existing mapping.
    pub mapping_nonce: [u8; 12],
}

/// Request a UDP MAP for an existing independently-bound Quinn UDP port.
/// PCP requests originate from the same local IP, not from Quinn's port.
pub async fn request_udp_mapping(
    local: SocketAddr,
    gateway: SocketAddr,
    lifetime: Duration,
    time_budget: Duration,
) -> Result<PcpUdpMapping, PcpError> {
    if local.port() == 0 || local.ip().is_unspecified() || local.ip().is_multicast()
        || gateway.port() == 0 || gateway.ip().is_unspecified()
        || gateway.ip().is_multicast() || gateway.is_ipv4() != local.is_ipv4()
        || lifetime.is_zero() || lifetime.as_secs() > u32::MAX as u64 || time_budget.is_zero()
    {
        return Err(PcpError::InvalidInput);
    }

    let socket = UdpSocket::bind(SocketAddr::new(local.ip(), 0))
        .await.map_err(PcpError::Io)?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| PcpError::Entropy)?;
    let mut request = [0u8; PACKET_LEN];
    request[0] = VERSION;
    request[1] = MAP_REQUEST;
    request[4..8].copy_from_slice(&(lifetime.as_secs() as u32).to_be_bytes());
    request[8..24].copy_from_slice(&to_wire_ip(local.ip()));
    request[24..36].copy_from_slice(&nonce);
    request[36] = UDP_PROTOCOL_NUMBER;
    request[40..42].copy_from_slice(&local.port().to_be_bytes());
    // Suggested external port zero: let the gateway choose; no hidden
    // assumption that the returned mapping equals the requested port.
    let mut response = [0u8; MAX_PACKET];
    let expires = Instant::now() + time_budget;
    for attempt in 0..3u32 {
        socket.send_to(&request, gateway).await.map_err(PcpError::Io)?;
        let until = (Instant::now() + Duration::from_millis(100 * (1 << attempt))).min(expires);
        loop {
            match timeout_at(until, socket.recv_from(&mut response)).await {
                Ok(Ok((n, source))) => {
                    if source != gateway || n < PACKET_LEN
                        || response[0] != VERSION || response[1] != MAP_REPLY
                        || response[24..36] != nonce
                        || response[36] != UDP_PROTOCOL_NUMBER
                        || response[40..42] != local.port().to_be_bytes()
                    {
                        continue;
                    }
                    let result = response[3];
                    if result != 0 { return Err(PcpError::UnsupportedOrDenied(result)); }
                    let lifetime_seconds = u32::from_be_bytes(
                        response[4..8].try_into().expect("slice length"),
                    );
                    let epoch_seconds = u32::from_be_bytes(
                        response[8..12].try_into().expect("slice length"),
                    );
                    let assigned_port = u16::from_be_bytes([response[42], response[43]]);
                    let assigned_ip = from_wire_ip(
                        response[44..60].try_into().expect("slice length"),
                    );
                    if lifetime_seconds == 0 || assigned_port == 0
                        || assigned_ip.is_unspecified() || assigned_ip.is_multicast()
                        || assigned_ip.is_ipv4() != local.is_ipv4()
                    {
                        continue;
                    }
                    return Ok(PcpUdpMapping {
                        local_address: local,
                        external_address: SocketAddr::new(assigned_ip, assigned_port),
                        lifetime_seconds,
                        epoch_seconds,
                        mapping_nonce: nonce,
                    });
                }
                Ok(Err(e)) => return Err(PcpError::Io(e)),
                Err(_) => break,
            }
        }
        if Instant::now() >= expires { break; }
    }
    Err(PcpError::Timeout)
}

fn to_wire_ip(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(addr) => addr.to_ipv6_mapped().octets(),
        IpAddr::V6(addr) => addr.octets(),
    }
}

fn from_wire_ip(raw: [u8; 16]) -> IpAddr {
    let ip = Ipv6Addr::from(raw);
    if let Some(v4) = ip.to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[test]
    fn correctly_roundtrips_ipv4_mapped_and_ipv6_addresses() {
        for addr in ["192.0.2.8", "2001:db8::35"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(from_wire_ip(to_wire_ip(ip)), ip);
        }
        assert_eq!(to_wire_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))[10..12], [0xff, 0xff]);
    }

    #[tokio::test]
    async fn maps_same_local_ip_existing_udp_port_with_real_nonce() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1100];
            let (n, source) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, PACKET_LEN);
            assert_eq!(buf[0], VERSION);
            assert_eq!(buf[1], MAP_REQUEST);
            assert_eq!(buf[36], UDP_PROTOCOL_NUMBER);
            assert_eq!(&buf[40..42], &50000u16.to_be_bytes());
            assert_eq!(&buf[8..24], &to_wire_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
            let mut reply = [0u8; PACKET_LEN];
            reply[0] = VERSION;
            reply[1] = MAP_REPLY;
            reply[4..8].copy_from_slice(&1800u32.to_be_bytes());
            reply[8..12].copy_from_slice(&9u32.to_be_bytes());
            reply[24..36].copy_from_slice(&buf[24..36]);
            reply[36] = UDP_PROTOCOL_NUMBER;
            reply[40..42].copy_from_slice(&50000u16.to_be_bytes());
            reply[42..44].copy_from_slice(&60555u16.to_be_bytes());
            reply[44..60].copy_from_slice(&to_wire_ip(
                "198.51.100.90".parse().unwrap(),
            ));
            server.send_to(&reply, source).await.unwrap();
        });
        let mapping = timeout(Duration::from_secs(3), request_udp_mapping(
            "127.0.0.1:50000".parse().unwrap(), target,
            Duration::from_secs(3600), Duration::from_secs(2),
        )).await.unwrap().unwrap();
        assert_eq!(mapping.external_address, "198.51.100.90:60555".parse().unwrap());
        assert_eq!(mapping.lifetime_seconds, 1800);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_foreign_gateway_and_unmatched_nonce() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = server.local_addr().unwrap();
        let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1100];
            let (_, source) = server.recv_from(&mut buf).await.unwrap();
            let mut packet = [0u8; PACKET_LEN];
            packet[0] = VERSION;
            packet[1] = MAP_REPLY;
            packet[4..8].copy_from_slice(&900u32.to_be_bytes());
            packet[36] = UDP_PROTOCOL_NUMBER;
            packet[40..42].copy_from_slice(&50000u16.to_be_bytes());
            packet[42..44].copy_from_slice(&51000u16.to_be_bytes());
            packet[44..60].copy_from_slice(&to_wire_ip(
                "198.51.100.12".parse().unwrap(),
            ));
            // A correct response from another socket must be ignored.
            packet[24..36].copy_from_slice(&buf[24..36]);
            spoof.send_to(&packet, source).await.unwrap();
            // And a response from the correct server with an invalid nonce
            // must also be ignored.
            packet[24] ^= 1;
            server.send_to(&packet, source).await.unwrap();
        });
        let result = request_udp_mapping(
            "127.0.0.1:50000".parse().unwrap(), target,
            Duration::from_secs(300), Duration::from_millis(250),
        ).await;
        assert!(matches!(result, Err(PcpError::Timeout)));
        task.await.unwrap();
    }
}
