//! Minimal STUN/QUIC packet classifier for a direct-only UDP endpoint.
//!
//! RFC 9443 defines first-octet demultiplexing for QUIC and STUN.
//! Our SDK deliberately does not implement TURN or RTP/DTLS on this path.
//! QUIC bit greasing MUST be disabled on every Quinn endpoint using this
//! classifier. Classification is NOT authentication: the ICE agent must
//! authenticate STUN integrity and Quinn verifies its own cryptographic data.

use crate::stun::MAGIC_COOKIE;

/// The only two protocols allowed on the shared ICE/QUIC data socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRoute {
    Stun,
    Quic,
    Punch,
    Drop,
}

/// Route one complete UDP datagram; never treat unknown traffic as QUIC.
///
/// A STUN candidate needs a complete RFC 8489 header, correct cookie and
/// attribute length. This is only a cheap prefilter, not STUN validation.
/// QUIC is recognized from the RFC 9443 byte ranges; Quinn must validate
/// the packet. This assumes QUIC fixed-bit greasing is disabled.
pub fn classify_datagram(packet: &[u8]) -> PacketRoute {
    let Some(&first) = packet.first() else {
        return PacketRoute::Drop;
    };
    // Reject malformed probes early, before any HMAC/replay processing.
    // They use the RFC 9443 first-octet STUN range but deliberately cannot
    // be confused with a valid STUN packet (different magic cookie).
    if first == 0 && packet.len() == crate::punch::PACKET_BYTES
        && packet.get(1..5) == Some(crate::punch::PUNCH_MAGIC.as_slice())
        && packet.get(5) == Some(&1)
    {
        return PacketRoute::Punch;
    }
    match first {
        0..=3 => {
            if packet.len() < 20 {
                return PacketRoute::Drop;
            }
            let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
            if cookie != MAGIC_COOKIE {
                return PacketRoute::Drop;
            }
            let attr_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if attr_len % 4 != 0 || attr_len + 20 != packet.len() {
                return PacketRoute::Drop;
            }
            PacketRoute::Stun
        }
        64..=127 | 192..=255 => PacketRoute::Quic,
        _ => PacketRoute::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::{binding_request, TransactionId};

    #[test]
    fn routes_stun_binding_requests() {
        let packet = binding_request(TransactionId([12; 12]));
        assert_eq!(classify_datagram(&packet), PacketRoute::Stun);
    }

    #[test]
    fn separates_authenticated_punch_from_stun_and_quic() {
        let credential = crate::session_binding::SessionCredentials::new([2; 16], [3; 32]).unwrap();
        let probe = crate::punch::AuthenticatedPunch::new(
            credential, crate::ice_signaling::IceRole::Controlling,
        ).make_packet(10).unwrap();
        assert_eq!(classify_datagram(&probe), PacketRoute::Punch);
        assert_eq!(classify_datagram(&probe[..probe.len() - 1]), PacketRoute::Drop);
        let mut bad = probe;
        bad[1] ^= 1;
        assert_eq!(classify_datagram(&bad), PacketRoute::Drop);
    }

    #[test]
    fn routes_quic_short_and_long_header_ranges() {
        for first in [64, 65, 79, 80, 127, 192, 193, 255] {
            assert_eq!(classify_datagram(&[first]), PacketRoute::Quic);
        }
    }

    #[test]
    fn does_not_accept_other_protocols_as_quic() {
        for first in [4, 15, 16, 19, 20, 63, 128, 191] {
            assert_eq!(classify_datagram(&[first]), PacketRoute::Drop);
        }
        assert_eq!(classify_datagram(&[]), PacketRoute::Drop);
    }

    #[test]
    fn rejects_truncated_or_corrupt_stun_packets() {
        let packet = binding_request(TransactionId([7; 12]));
        assert_eq!(classify_datagram(&packet[..19]), PacketRoute::Drop);
        let mut wrong_cookie = packet;
        wrong_cookie[4] ^= 1;
        assert_eq!(classify_datagram(&wrong_cookie), PacketRoute::Drop);
        let mut wrong_length = packet;
        wrong_length[2..4].copy_from_slice(&4_u16.to_be_bytes());
        assert_eq!(classify_datagram(&wrong_length), PacketRoute::Drop);
    }

    #[test]
    fn rejects_unexpected_stun_trailing_bytes() {
        let mut packet = binding_request(TransactionId([3; 12])).to_vec();
        packet.push(1);
        assert_eq!(classify_datagram(&packet), PacketRoute::Drop);
    }
}
