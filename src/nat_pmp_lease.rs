//! Long-lived NAT-PMP lease for one already-bound ICE/QUIC UDP source port.
//! An unavailable or changed mapping is never silently treated as permanent.
//! The caller must run authenticated ICE checks before using any mapped peer
//! candidate. This is optional gateway control, not TURN or file relay.

use std::{net::SocketAddrV4, time::Duration};

use tokio::{sync::watch, task::JoinHandle, time::sleep};

use crate::nat_pmp::{self, PortMapError, UdpMapping};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NatPmpLeaseStatus {
    pub mapping: Option<UdpMapping>,
    pub generation: u64,
}

pub struct NatPmpLease {
    status: watch::Receiver<NatPmpLeaseStatus>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), PortMapError>>>,
}

impl NatPmpLease {
    /// The default gateway must already have been verified for this local IP.
    /// The mapping refers to local's QUIC port, not the management socket.
    pub async fn start(
        local: SocketAddrV4,
        gateway: SocketAddrV4,
        lifetime: Duration,
        transaction_timeout: Duration,
    ) -> Result<Self, PortMapError> {
        let first = nat_pmp::request_udp_mapping(
            local, gateway, lifetime, transaction_timeout,
        ).await?;
        let (status_tx, status) = watch::channel(NatPmpLeaseStatus {
            mapping: Some(first), generation: 0,
        });
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut previous = first;
            loop {
                let delay = Duration::from_secs(
                    (u64::from(previous.granted_lifetime_seconds) / 2).max(1)
                );
                tokio::select! {
                    _ = sleep(delay) => {}
                    changed = stopping.changed() => {
                        if changed.is_err() || *stopping.borrow() { break; }
                        continue;
                    }
                }
                if *stopping.borrow() { break; }
                match nat_pmp::request_udp_mapping(
                    local, gateway, lifetime, transaction_timeout,
                ).await {
                    Ok(next) => {
                        previous = next;
                        let generation = status_tx.borrow().generation.wrapping_add(1);
                        status_tx.send_replace(NatPmpLeaseStatus {
                            mapping: Some(next), generation,
                        });
                    }
                    Err(_) => {
                        let generation = status_tx.borrow().generation.wrapping_add(1);
                        status_tx.send_replace(NatPmpLeaseStatus {
                            mapping: None, generation,
                        });
                        tokio::select! {
                            _ = sleep(Duration::from_secs(1)) => {}
                            _ = stopping.changed() => {}
                        }
                    }
                }
            }
            let generation = status_tx.borrow().generation.wrapping_add(1);
            status_tx.send_replace(NatPmpLeaseStatus { mapping: None, generation });
            nat_pmp::release_udp_mapping(local, gateway, transaction_timeout).await
        });
        Ok(Self { status, stop, task: Some(task) })
    }

    pub fn subscribe(&self) -> watch::Receiver<NatPmpLeaseStatus> {
        self.status.clone()
    }

    pub async fn shutdown(mut self) -> Result<(), PortMapError> {
        self.stop.send_replace(true);
        let task = self.task.take().expect("lifecycle task owned once");
        match task.await {
            Ok(result) => result,
            Err(_) => Err(PortMapError::Timeout),
        }
    }
}

impl Drop for NatPmpLease {
    fn drop(&mut self) { self.stop.send_replace(true); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn renews_and_removes_one_real_mock_gateway_map() {
        tokio::time::timeout(Duration::from_secs(6), async {
            let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = match router.local_addr().unwrap() {
                std::net::SocketAddr::V4(addr) => addr,
                _ => unreachable!(),
            };
            let task = tokio::spawn(async move {
                let mut buf = [0u8; 128];
                for i in 0..2u32 {
                    let (n, from) = router.recv_from(&mut buf).await.unwrap();
                    assert_eq!(&buf[..n], &[0, 0]);
                    let public_reply = [0, 128, 0, 0, 0, 0, 0, 1, 198, 51, 100, 25];
                    router.send_to(&public_reply, from).await.unwrap();

                    let (n, from2) = router.recv_from(&mut buf).await.unwrap();
                    assert_eq!(from, from2);
                    assert_eq!(n, 12);
                    assert_eq!(buf[1], 1);
                    assert_eq!(&buf[4..6], &43000u16.to_be_bytes());
                    assert_eq!(&buf[8..12], &2u32.to_be_bytes());
                    let mut reply = [0u8; 16];
                    reply[1] = 129;
                    reply[4..8].copy_from_slice(&(i + 1).to_be_bytes());
                    reply[8..10].copy_from_slice(&43000u16.to_be_bytes());
                    reply[10..12].copy_from_slice(&53000u16.to_be_bytes());
                    reply[12..16].copy_from_slice(&2u32.to_be_bytes());
                    router.send_to(&reply, from2).await.unwrap();
                }
                let (n, from) = router.recv_from(&mut buf).await.unwrap();
                assert_eq!(n, 12);
                assert_eq!(&buf[4..6], &43000u16.to_be_bytes());
                assert_eq!(&buf[8..12], &[0, 0, 0, 0]);
                let mut reply = [0u8; 16];
                reply[1] = 129;
                reply[8..10].copy_from_slice(&43000u16.to_be_bytes());
                router.send_to(&reply, from).await.unwrap();
            });
            let manager = NatPmpLease::start(
                "127.0.0.1:43000".parse().unwrap(), address,
                Duration::from_secs(2), Duration::from_secs(1),
            ).await.unwrap();
            let mut updates = manager.subscribe();
            assert!(updates.borrow().mapping.is_some());
            updates.changed().await.unwrap();
            assert_eq!(updates.borrow().generation, 1);
            manager.shutdown().await.unwrap();
            task.await.unwrap();
        }).await.unwrap();
    }
}
