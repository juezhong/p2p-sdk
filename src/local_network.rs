//! Interface discovery used by interactive SDK consumers.
//!
//! Discovery is NOT ICE gathering or a reachability guarantee. The caller
//! still binds an actual UDP socket to a chosen address, gathers STUN srflx
//! on THAT same socket, and nominates the path using authenticated ICE.
//! More than one interface requires independent owner/checklist integration.

use std::{collections::HashSet, io, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket}};

/// Return possible non-loopback, unicast local interface addresses.
/// The operating system may expose VPNs and virtual interfaces; these are
/// not necessarily reachable by the other peer.
pub fn local_addresses() -> io::Result<Vec<IpAddr>> {
    let interfaces = if_addrs::get_if_addrs()?;
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for interface in interfaces {
        let ip = interface.ip();
        if usable(ip) && seen.insert(ip) {
            result.push(ip);
        }
    }
    // Network interfaces' enumeration order is platform-specific.
    result.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) if v4.is_private() => (0, ip.to_string()),
        IpAddr::V6(v6) if v6.is_unique_local() => (1, ip.to_string()),
        IpAddr::V6(_) => (2, ip.to_string()),
        IpAddr::V4(_) => (3, ip.to_string()),
    });
    Ok(result)
}

/// Find the first plausible local interface, preferring the OS route's
/// source address when it is usable. UDP connect() here sends NO packets,
/// and cannot prove that any external host is actually reachable.
pub fn default_bind_address() -> io::Result<SocketAddr> {
    let candidates = local_addresses()?;
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no usable LAN, IPv4 or IPv6 interface",
        ));
    }
    for probe in ["1.1.1.1:53", "192.0.2.1:53", "[2606:4700:4700::1111]:53"] {
        let dest: SocketAddr = probe.parse().expect("constant address");
        let bind: SocketAddr = match dest {
            SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        if let Ok(socket) = UdpSocket::bind(bind) {
            if socket.connect(dest).is_ok() {
                if let Ok(local) = socket.local_addr() {
                    if candidates.contains(&local.ip()) {
                        return Ok(SocketAddr::new(local.ip(), 0));
                    }
                }
            }
        }
    }
    Ok(SocketAddr::new(candidates[0], 0))
}

pub fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local()
                && !ip.is_multicast() && !ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
                && !ip.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_unspecified_and_link_local() {
        for ip in ["127.0.0.1", "0.0.0.0", "169.254.1.2", "::1", "::", "fe80::1", "ff02::1"] {
            assert!(!usable(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["192.168.10.1", "10.1.2.3", "2001:db8::1", "fd01::5"] {
            assert!(usable(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn lists_only_usable_unique_addresses() {
        let addresses = local_addresses().unwrap();
        let set = addresses.iter().copied().collect::<HashSet<_>>();
        assert_eq!(set.len(), addresses.len());
        assert!(addresses.iter().all(|&ip| usable(ip)));
    }
}
