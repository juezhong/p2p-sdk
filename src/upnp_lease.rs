//! Optional UPnP IGD v1/v2 UDP mapping for an actual ICE/QUIC socket.
//! SSDP discovery is bound to the same interface, and the discovered IGD
//! must match the OS-verified default gateway before ANY mapping is created.
//! Mapping is not direct-path proof: all announced candidates require ICE.
//! The mapping remains finite; deletion is best-effort if the process dies.

use std::{net::{IpAddr, SocketAddr, SocketAddrV4}, time::Duration};

use igd_next::{aio::{Gateway, tokio::{search_gateway, Tokio}}, PortMappingProtocol, SearchOptions};
use tokio::{sync::watch, task::JoinHandle, time::{timeout, sleep}};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpnpStatus {
    pub external: Option<SocketAddrV4>,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpnpError {
    InvalidInput,
    Discovery,
    WrongRouter,
    ExternalAddress,
    MappingDenied,
    CleanupFailed,
}

pub struct UpnpLease {
    status: watch::Receiver<UpnpStatus>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), UpnpError>>>,
}

fn allowed_gateway(actual: SocketAddr, expected: SocketAddrV4) -> Result<(), UpnpError> {
    if actual.ip() != IpAddr::V4(*expected.ip()) {
        return Err(UpnpError::WrongRouter);
    }
    Ok(())
}

async fn discover(
    local: SocketAddrV4, expected_router: SocketAddrV4, deadline: Duration,
) -> Result<Gateway<Tokio>, UpnpError> {
    if deadline.is_zero() || local.port() == 0 || local.ip().is_unspecified() {
        return Err(UpnpError::InvalidInput);
    }
    let options = SearchOptions {
        bind_addr: SocketAddr::V4(SocketAddrV4::new(*local.ip(), 0)),
        timeout: Some(deadline),
        single_search_timeout: Some(deadline),
        ..Default::default()
    };
    let router = timeout(deadline, search_gateway(options))
        .await.map_err(|_| UpnpError::Discovery)?
        .map_err(|_| UpnpError::Discovery)?;
    allowed_gateway(router.addr, expected_router)?;
    Ok(router)
}

async fn public_ip(router: &Gateway<Tokio>, deadline: Duration)
    -> Result<std::net::Ipv4Addr, UpnpError>
{
    let ip = timeout(deadline, router.get_external_ip()).await
        .map_err(|_| UpnpError::ExternalAddress)?
        .map_err(|_| UpnpError::ExternalAddress)?;
    match ip {
        IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_multicast()
            && !v4.is_loopback() => Ok(v4),
        _ => Err(UpnpError::ExternalAddress),
    }
}

async fn map_port(router: &Gateway<Tokio>, local: SocketAddrV4,
    existing_port: Option<u16>, lifetime: u32, deadline: Duration,
) -> Result<u16, UpnpError> {
    if let Some(port) = existing_port {
        if timeout(deadline, router.add_port(PortMappingProtocol::UDP, port,
            SocketAddr::V4(local), lifetime, "p2p-sdk"))
            .await.is_ok_and(|r| r.is_ok())
        {
            return Ok(port);
        }
    }
    timeout(deadline, router.add_any_port(PortMappingProtocol::UDP,
        SocketAddr::V4(local), lifetime, "p2p-sdk"))
        .await.map_err(|_| UpnpError::MappingDenied)?
        .map_err(|_| UpnpError::MappingDenied)
}

impl UpnpLease {
    /// The supplied router must be the confirmed on-link default gateway
    /// for this actual local ICE/QUIC address.
    pub async fn start(
        local: SocketAddrV4, router: SocketAddrV4, lifetime: Duration,
        deadline: Duration,
    ) -> Result<Self, UpnpError> {
        if local.port() == 0 || local.ip().is_unspecified()
            || router.ip().is_unspecified() || router.port() != 5351
            || lifetime.is_zero() || lifetime.as_secs() > u32::MAX as u64
            || deadline.is_zero()
        {
            return Err(UpnpError::InvalidInput);
        }
        let igd = discover(local, router, deadline).await?;
        let public = public_ip(&igd, deadline).await?;
        let port = map_port(&igd, local, None, lifetime.as_secs() as u32, deadline).await?;
        let (changed, status) = watch::channel(UpnpStatus {
            external: Some(SocketAddrV4::new(public, port)), generation: 0,
        });
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut active_port = port;
            let mut igd = igd;
            let mut active_router = router;
            loop {
                let period = Duration::from_secs((lifetime.as_secs() / 2).max(1));
                tokio::select! {
                    _ = sleep(period) => {}
                    update = stopping.changed() => {
                        if update.is_err() || *stopping.borrow() { break; }
                        continue;
                    }
                }
                if *stopping.borrow() { break; }
                // A router reboot may change the IGD control service; require
                // discovery and matching the OS-bound interface again.
                let updated = async {
                    let verified = discover(local, active_router, deadline).await?;
                    let public = public_ip(&verified, deadline).await?;
                    let port = map_port(&verified, local, Some(active_port),
                        lifetime.as_secs() as u32, deadline).await?;
                    Ok::<_, UpnpError>((verified, public, port))
                }.await;
                match updated {
                    Ok((replacement, public, port)) => {
                        if active_port != port {
                            // A different mapping must not be left behind.
                            let _ = timeout(deadline, igd.remove_port(
                                PortMappingProtocol::UDP, active_port)).await;
                        }
                        igd = replacement;
                        active_port = port;
                        active_router = router;
                        changed.send_replace(UpnpStatus {
                            external: Some(SocketAddrV4::new(public, port)),
                            generation: changed.borrow().generation.wrapping_add(1),
                        });
                    }
                    Err(_) => {
                        changed.send_replace(UpnpStatus {
                            external: None,
                            generation: changed.borrow().generation.wrapping_add(1),
                        });
                        tokio::select! {
                            _ = sleep(Duration::from_secs(1)) => {}
                            _ = stopping.changed() => {}
                        }
                    }
                }
            }
            changed.send_replace(UpnpStatus {
                external: None,
                generation: changed.borrow().generation.wrapping_add(1),
            });
            timeout(deadline, igd.remove_port(PortMappingProtocol::UDP, active_port))
                .await.map_err(|_| UpnpError::CleanupFailed)?
                .map_err(|_| UpnpError::CleanupFailed)
        });
        Ok(Self { status, stop, task: Some(task) })
    }

    pub fn subscribe(&self) -> watch::Receiver<UpnpStatus> { self.status.clone() }

    pub async fn shutdown(mut self) -> Result<(), UpnpError> {
        self.stop.send_replace(true);
        match self.task.take().expect("task present").await {
            Ok(result) => result,
            Err(_) => Err(UpnpError::CleanupFailed),
        }
    }
}
impl Drop for UpnpLease {
    fn drop(&mut self) { self.stop.send_replace(true); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_verified_router_on_correct_interface_may_map_ports() {
        let router = "192.168.1.1:49152".parse().unwrap();
        let expected = "192.168.1.1:5351".parse().unwrap();
        assert!(allowed_gateway(router, expected).is_ok());
        assert_eq!(allowed_gateway(
            "192.168.2.1:49152".parse().unwrap(), expected),
            Err(UpnpError::WrongRouter));
        assert_eq!(allowed_gateway(
            "127.0.0.1:49152".parse().unwrap(), expected),
            Err(UpnpError::WrongRouter));
    }
}
