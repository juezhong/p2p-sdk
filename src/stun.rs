//! RFC 8489 STUN Binding request/response codec.
//!
//! This is **not** an ICE agent and performs no network I/O. Transaction IDs
//! must come from a cryptographically secure RNG supplied by the caller.
//! A STUN response is untrusted and never authenticates a P2P peer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionId(pub [u8; 12]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StunError {
    Truncated,
    InvalidType,
    InvalidCookie,
    TransactionMismatch,
    InvalidLength,
    MissingXorMappedAddress,
    InvalidAddress,
}

/// Construct a minimal STUN Binding Request. The caller provides 96-bit
/// unpredictable random bytes; never reuse an ID as an authentication secret.
pub fn binding_request(id: TransactionId) -> [u8; HEADER_LEN] {
    let mut message = [0_u8; HEADER_LEN];
    message[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    message[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message[8..20].copy_from_slice(&id.0);
    message
}

/// Parse a success response matching one outstanding transaction.
///
/// The datagram source address must also be validated by the network layer;
/// this codec checks only wire format and transaction ID.
pub fn parse_binding_success(
    packet: &[u8],
    expected: TransactionId,
) -> Result<SocketAddr, StunError> {
    if packet.len() < HEADER_LEN {
        return Err(StunError::Truncated);
    }
    let kind = u16::from_be_bytes([packet[0], packet[1]]);
    if kind != BINDING_SUCCESS {
        return Err(StunError::InvalidType);
    }
    if u32::from_be_bytes(packet[4..8].try_into().unwrap()) != MAGIC_COOKIE {
        return Err(StunError::InvalidCookie);
    }
    if packet[8..20] != expected.0 {
        return Err(StunError::TransactionMismatch);
    }
    let declared = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if declared % 4 != 0 || declared + HEADER_LEN != packet.len() {
        return Err(StunError::InvalidLength);
    }
    let mut offset = HEADER_LEN;
    while offset < packet.len() {
        if packet.len() - offset < 4 {
            return Err(StunError::InvalidLength);
        }
        let attr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        offset += 4;
        if len > packet.len() - offset {
            return Err(StunError::InvalidLength);
        }
        let data = &packet[offset..offset + len];
        let padded = len.checked_add(3).ok_or(StunError::InvalidLength)? & !3;
        if padded > packet.len() - offset {
            return Err(StunError::InvalidLength);
        }
        offset += padded;
        if attr_type == XOR_MAPPED_ADDRESS {
            return parse_xor_address(data, expected);
        }
    }
    Err(StunError::MissingXorMappedAddress)
}

fn parse_xor_address(data: &[u8], id: TransactionId) -> Result<SocketAddr, StunError> {
    if data.len() < 4 || data[0] != 0 {
        return Err(StunError::InvalidAddress);
    }
    let port = u16::from_be_bytes([data[2], data[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let ip = match (data[1], data.len()) {
        (0x01, 8) => {
            let mut octets = [0; 4];
            for i in 0..4 {
                octets[i] = data[i + 4] ^ cookie[i];
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        (0x02, 20) => {
            let mut octets = [0; 16];
            for i in 0..16 {
                octets[i] = data[i + 4] ^ if i < 4 { cookie[i] } else { id.0[i - 4] };
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(StunError::InvalidAddress),
    };
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: TransactionId = TransactionId([0x11; 12]);

    fn response(ip: IpAddr, port: u16) -> Vec<u8> {
        let mut attr = vec![0, if ip.is_ipv4() { 1 } else { 2 }];
        attr.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        let raw: Vec<u8> = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for (i, byte) in raw.iter().enumerate() {
            attr.push(byte ^ if i < 4 { cookie[i] } else { ID.0[i - 4] });
        }
        let mut pkt = Vec::from(binding_request(ID));
        pkt[..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        pkt[2..4].copy_from_slice(&((attr.len() + 4) as u16).to_be_bytes());
        pkt.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        pkt.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&attr);
        pkt
    }

    #[test]
    fn request_is_twenty_byte_binding_request() {
        let msg = binding_request(ID);
        assert_eq!(msg.len(), 20);
        assert_eq!(msg[..2], [0, 1]);
        assert_eq!(&msg[8..], &ID.0);
    }

    #[test]
    fn decodes_ipv4_and_ipv6_xor_mapped_address() {
        for address in ["203.0.113.5:12345", "[2001:db8::42]:54321"] {
            let want: SocketAddr = address.parse().unwrap();
            assert_eq!(parse_binding_success(&response(want.ip(), want.port()), ID), Ok(want));
        }
    }

    #[test]
    fn rejects_mismatched_transaction_and_invalid_lengths() {
        let mut pkt = response("192.0.2.12".parse().unwrap(), 34567);
        assert_eq!(
            parse_binding_success(&pkt, TransactionId([2; 12])),
            Err(StunError::TransactionMismatch)
        );
        pkt[2..4].copy_from_slice(&999_u16.to_be_bytes());
        assert_eq!(parse_binding_success(&pkt, ID), Err(StunError::InvalidLength));
    }

    #[test]
    fn rejects_truncated_and_wrong_cookie() {
        assert_eq!(parse_binding_success(&[0; 12], ID), Err(StunError::Truncated));
        let mut pkt = response("192.0.2.12".parse().unwrap(), 34567);
        pkt[4] = 0;
        assert_eq!(parse_binding_success(&pkt, ID), Err(StunError::InvalidCookie));
    }

    #[test]
    fn rejects_invalid_address_family() {
        let mut pkt = response("192.0.2.12".parse().unwrap(), 34567);
        pkt[25] = 3;
        assert_eq!(parse_binding_success(&pkt, ID), Err(StunError::InvalidAddress));
    }
}
