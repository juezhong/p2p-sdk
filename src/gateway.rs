//! Cross-platform best-effort default-gateway discovery and optional PCP /
//! NAT-PMP mapping. All requests name the actual already-bound ICE/QUIC UDP
//! port. No candidate is considered reachable until authenticated ICE checks.
//!
//! When the bound address is not on the OS-selected default interface, refuse
//! port mapping instead of silently routing a different interface's port.

use std::{net::{SocketAddr, SocketAddrV4}, time::Duration};
use tokio::sync::watch;

use crate::{
    nat_pmp::PortMapError,
    nat_pmp_lease::{NatPmpLease, NatPmpLeaseStatus},
    pcp::PcpError,
    pcp_lease::{PcpLease, PcpLeaseStatus},
    upnp_lease::{UpnpError, UpnpLease, UpnpStatus},
};

const GATEWAY_MAP_PORT: u16 = 5351;

#[derive(Debug)]
pub enum GatewayError {
    InvalidLocalSocket,
    NoDefaultInterface,
    WrongInterface,
    NoOnLinkGateway,
    AmbiguousGateway,
    NoMapping { pcp: PcpError, nat_pmp: PortMapError, upnp: UpnpError },
    Pcp(PcpError),
    NatPmp(PortMapError),
    Upnp(UpnpError),
}

fn gateway_on_interface(local: SocketAddrV4, iface: &netdev::Interface)
    -> Result<SocketAddrV4, GatewayError>
{
    if local.port() == 0 || local.ip().is_unspecified()
        || local.ip().is_multicast()
    {
        return Err(GatewayError::InvalidLocalSocket);
    }
    let Some(network) = iface.ipv4.iter().find(|net| net.addr() == *local.ip()) else {
        return Err(GatewayError::WrongInterface);
    };
    let Some(router) = iface.gateway.as_ref() else {
        return Err(GatewayError::NoOnLinkGateway);
    };
    let mut eligible = router.ipv4.iter().copied()
        .filter(|gateway| !gateway.is_unspecified()
            && !gateway.is_loopback()
            && !gateway.is_multicast()
            && gateway != local.ip()
            && network.contains(gateway)
            && *gateway != network.broadcast());
    let Some(first) = eligible.next() else {
        return Err(GatewayError::NoOnLinkGateway);
    };
    if eligible.any(|ip| ip != first) {
        return Err(GatewayError::AmbiguousGateway);
    }
    Ok(SocketAddrV4::new(first, GATEWAY_MAP_PORT))
}

/// Resolve the system default gateway only for its *matching local interface*.
/// A multihomed machine must not send a QUIC port mapping through an unrelated
/// router, even if that router happens to be the current global default.
pub fn discover_gateway_for_socket(local: SocketAddrV4)
    -> Result<SocketAddrV4, GatewayError>
{
    let selected = netdev::get_default_interface()
        .map_err(|_| GatewayError::NoDefaultInterface)?;
    gateway_on_interface(local, &selected)
}

pub enum GatewayLease {
    Pcp(PcpLease),
    NatPmp(NatPmpLease),
    Upnp(UpnpLease),
}

pub enum GatewayLeaseUpdates {
    Pcp(watch::Receiver<PcpLeaseStatus>),
    NatPmp(watch::Receiver<NatPmpLeaseStatus>),
    Upnp(watch::Receiver<UpnpStatus>),
}

impl GatewayLeaseUpdates {
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Pcp(rx) => rx.borrow().mapping.map(|m| m.external_address),
            Self::NatPmp(rx) => rx.borrow().mapping
                .map(|m| SocketAddr::V4(m.external_address)),
            Self::Upnp(rx) => rx.borrow().external.map(SocketAddr::V4),
        }
    }

    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        match self {
            Self::Pcp(rx) => rx.changed().await,
            Self::NatPmp(rx) => rx.changed().await,
            Self::Upnp(rx) => rx.changed().await,
        }
    }
}

impl GatewayLease {
    /// Attempt PCP first, then NAT-PMP if PCP is denied or unavailable.
    /// Both are bounded and use the OS-default gateway on the actual
    /// nominated UDP Owner interface. A failure leaves Host/STUN ICE intact.
    pub async fn start_for_socket(
        local: SocketAddrV4,
        lifetime: Duration,
        request_budget: Duration,
    ) -> Result<Self, GatewayError> {
        let gateway = discover_gateway_for_socket(local)?;
        let pcp = PcpLease::start(
            SocketAddr::V4(local), SocketAddr::V4(gateway),
            lifetime, request_budget,
        ).await;
        match pcp {
            Ok(lease) => Ok(Self::Pcp(lease)),
            Err(pcp_error) => match NatPmpLease::start(
                local, gateway, lifetime, request_budget,
            ).await {
                Ok(lease) => Ok(Self::NatPmp(lease)),
                Err(nat_pmp_error) => match UpnpLease::start(
                    local, gateway, lifetime, request_budget,
                ).await {
                    Ok(lease) => Ok(Self::Upnp(lease)),
                    Err(upnp_error) => Err(GatewayError::NoMapping {
                        pcp: pcp_error, nat_pmp: nat_pmp_error, upnp: upnp_error,
                    }),
                },
            },
        }
    }

    pub fn subscribe(&self) -> GatewayLeaseUpdates {
        match self {
            Self::Pcp(lease) => GatewayLeaseUpdates::Pcp(lease.subscribe()),
            Self::NatPmp(lease) => GatewayLeaseUpdates::NatPmp(lease.subscribe()),
            Self::Upnp(lease) => GatewayLeaseUpdates::Upnp(lease.subscribe()),
        }
    }

    pub async fn shutdown(self) -> Result<(), GatewayError> {
        match self {
            Self::Pcp(lease) => lease.shutdown().await.map_err(GatewayError::Pcp),
            Self::NatPmp(lease) => lease.shutdown().await.map_err(GatewayError::NatPmp),
            Self::Upnp(lease) => lease.shutdown().await.map_err(GatewayError::Upnp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::{nat_pmp::UdpMapping, pcp::PcpUdpMapping};

    fn fixture() -> netdev::Interface {
        let mut device = netdev::Interface::dummy();
        device.ipv4 = vec!["192.168.5.23/24".parse().unwrap()];
        let mut gateway = netdev::NetworkDevice::new();
        gateway.ipv4.push(Ipv4Addr::new(192, 168, 5, 1));
        device.gateway = Some(gateway);
        device
    }

    #[test]
    fn selects_only_gateway_matching_the_real_bound_local_ip() {
        let device = fixture();
        let local = "192.168.5.23:55100".parse().unwrap();
        assert_eq!(
            gateway_on_interface(local, &device).unwrap(),
            "192.168.5.1:5351".parse().unwrap(),
        );
        assert!(matches!(
            gateway_on_interface("192.168.99.23:55100".parse().unwrap(), &device),
            Err(GatewayError::WrongInterface),
        ));
        assert!(matches!(
            gateway_on_interface("192.168.5.23:0".parse().unwrap(), &device),
            Err(GatewayError::InvalidLocalSocket),
        ));
    }

    #[test]
    fn refuses_offlink_and_ambiguous_gateway_candidates() {
        let mut device = fixture();
        device.gateway.as_mut().unwrap().ipv4 = vec![Ipv4Addr::new(192, 168, 10, 1)];
        assert!(matches!(
            gateway_on_interface("192.168.5.23:55000".parse().unwrap(), &device),
            Err(GatewayError::NoOnLinkGateway),
        ));
        device.gateway.as_mut().unwrap().ipv4 = vec![
            Ipv4Addr::new(192, 168, 5, 1),
            Ipv4Addr::new(192, 168, 5, 2),
        ];
        assert!(matches!(
            gateway_on_interface("192.168.5.23:55000".parse().unwrap(), &device),
            Err(GatewayError::AmbiguousGateway),
        ));
    }

    #[test]
    fn common_mapping_update_reports_current_address() {
        let sample = PcpUdpMapping {
            local_address: "192.168.5.23:43000".parse().unwrap(),
            external_address: "198.51.100.20:54000".parse().unwrap(),
            lifetime_seconds: 120, epoch_seconds: 3,
            mapping_nonce: [4; 12],
        };
        let (_, receiver) = watch::channel(PcpLeaseStatus {
            mapping: Some(sample), generation: 1,
        });
        let change = GatewayLeaseUpdates::Pcp(receiver);
        assert_eq!(change.mapped_address(),
            Some("198.51.100.20:54000".parse().unwrap()));
        let sample = UdpMapping {
            local_address: "192.168.5.23:43000".parse().unwrap(),
            external_address: "198.51.100.21:54001".parse().unwrap(),
            granted_lifetime_seconds: 120, gateway_epoch_seconds: 3,
        };
        let (_, receiver) = watch::channel(NatPmpLeaseStatus {
            mapping: Some(sample), generation: 1,
        });
        assert_eq!(GatewayLeaseUpdates::NatPmp(receiver).mapped_address(),
            Some("198.51.100.21:54001".parse().unwrap()));
    }
}
