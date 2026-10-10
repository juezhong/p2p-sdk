//! Classify transient asynchronous ICMP errors reported by UDP sockets.
//!
//! Windows may surface ICMP Port Unreachable for an unrelated packet as
//! WSAECONNRESET from recv_from() on an otherwise healthy unconnected UDP
//! socket. Such an event must not kill the ICE/QUIC UDP Owner or prematurely
//! abort NAT mapping probes. It is still a failed packet/path, not success.

pub(crate) fn is_transient_unreachable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn only_unreachable_icmp_classes_can_be_ignored() {
        assert!(is_transient_unreachable(&Error::from(ErrorKind::ConnectionReset)));
        assert!(is_transient_unreachable(&Error::from(ErrorKind::ConnectionRefused)));
        for kind in [ErrorKind::PermissionDenied, ErrorKind::BrokenPipe,
            ErrorKind::InvalidInput, ErrorKind::NotConnected, ErrorKind::Other]
        {
            assert!(!is_transient_unreachable(&Error::from(kind)), "{kind:?}");
        }
    }
}
