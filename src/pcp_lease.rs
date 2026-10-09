//! Long-lived PCP MAP lease supervision for a *specific already bound*
//! ICE/QUIC UDP socket. This is gateway control only, never a data relay.
//!
//! The public watch receiver is conservative: if a renewal cannot be
//! authenticated/verified, the external candidate is immediately invalidated.
//! Consumers MUST run ICE checks again before using any newly advertised
//! endpoint, even when the public address did not change.

use std::{net::SocketAddr, time::Duration};

use tokio::{sync::watch, task::JoinHandle, time::sleep};

use crate::pcp::{self, PcpError, PcpUdpMapping};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcpLeaseStatus {
    /// None means this gateway mapping is not safe to advertise for new ICE
    /// nominations. Existing QUIC traffic still has its own path checks.
    pub mapping: Option<PcpUdpMapping>,
    pub generation: u64,
}

/// The owner of a single PCP mapping lifecycle. Call shutdown().await for
/// acknowledgement of explicit deletion. Dropping it triggers best-effort
/// deletion while the Tokio runtime is alive, but a killed process cannot
/// guarantee cleanup; the gateway lease must always be finite.
pub struct PcpLease {
    status: watch::Receiver<PcpLeaseStatus>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), PcpError>>>,
}

impl PcpLease {
    pub async fn start(
        local: SocketAddr,
        gateway: SocketAddr,
        lifetime: Duration,
        transaction_deadline: Duration,
    ) -> Result<Self, PcpError> {
        let first = pcp::request_udp_mapping(
            local, gateway, lifetime, transaction_deadline,
        ).await?;
        let (changed, status) = watch::channel(PcpLeaseStatus {
            mapping: Some(first), generation: 0,
        });
        let (stop, mut stopping) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut last = first;
            loop {
                // Renew before expiry; keep at least one second for small
                // router-granted test leases.
                let delay = Duration::from_secs(
                    (u64::from(last.lifetime_seconds) / 2).max(1)
                );
                tokio::select! {
                    _ = sleep(delay) => {}
                    signal = stopping.changed() => {
                        if signal.is_err() || *stopping.borrow() { break; }
                        continue;
                    }
                }
                if *stopping.borrow() { break; }
                let result = pcp::renew_udp_mapping(
                    &last, gateway, lifetime, transaction_deadline,
                ).await;
                match result {
                    Ok(replacement) => {
                        last = replacement;
                        let generation = changed.borrow().generation.wrapping_add(1);
                        changed.send_replace(PcpLeaseStatus {
                            mapping: Some(replacement), generation,
                        });
                    }
                    Err(_) => {
                        // Do not keep publishing a gateway mapping we can no
                        // longer verify. A later successful renewal recovers it.
                        let generation = changed.borrow().generation.wrapping_add(1);
                        changed.send_replace(PcpLeaseStatus {
                            mapping: None, generation,
                        });
                        tokio::select! {
                            _ = sleep(Duration::from_secs(1)) => {}
                            _ = stopping.changed() => {}
                        }
                    }
                }
            }
            let generation = changed.borrow().generation.wrapping_add(1);
            changed.send_replace(PcpLeaseStatus { mapping: None, generation });
            pcp::release_udp_mapping(&last, gateway, transaction_deadline).await
        });
        Ok(Self { status, stop, task: Some(task) })
    }

    pub fn subscribe(&self) -> watch::Receiver<PcpLeaseStatus> {
        self.status.clone()
    }

    /// Release the exact original PCP nonce and await the router's reply.
    /// A failure is returned so the caller can log it; the candidate is
    /// already invalidated and the lease eventually expires on the gateway.
    pub async fn shutdown(mut self) -> Result<(), PcpError> {
        self.stop.send_replace(true);
        let task = self.task.take().expect("lifecycle task owned once");
        match task.await {
            Ok(result) => result,
            Err(_) => Err(PcpError::Timeout),
        }
    }
}

impl Drop for PcpLease {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn renews_and_deletes_a_real_mock_gateway_mapping() {
        tokio::time::timeout(Duration::from_secs(6), async {
            let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let gateway = router.local_addr().unwrap();
            let worker = tokio::spawn(async move {
                let mut seen_nonce = None;
                for (seq, expected_lifetime) in [(0, 4u32), (1, 4u32), (2, 0u32)] {
                    let mut buf = [0u8; 1100];
                    let (n, from) = router.recv_from(&mut buf).await.unwrap();
                    assert_eq!(n, 60);
                    assert_eq!(buf[0], 2);
                    assert_eq!(buf[1], 1);
                    assert_eq!(&buf[4..8], &expected_lifetime.to_be_bytes());
                    assert_eq!(&buf[40..42], &44000u16.to_be_bytes());
                    if seq == 0 {
                        seen_nonce = Some(buf[24..36].to_vec());
                    } else {
                        assert_eq!(&buf[24..36], &seen_nonce.as_ref().unwrap()[..]);
                    }
                    let mut reply = [0u8; 60];
                    reply[0] = 2;
                    reply[1] = 0x81;
                    reply[4..8].copy_from_slice(&expected_lifetime.to_be_bytes());
                    reply[8..12].copy_from_slice(&(seq as u32 + 1).to_be_bytes());
                    reply[24..36].copy_from_slice(&buf[24..36]);
                    reply[36] = 17;
                    reply[40..42].copy_from_slice(&44000u16.to_be_bytes());
                    reply[42..44].copy_from_slice(&55000u16.to_be_bytes());
                    // IPv4-mapped IPv6 encoded public address.
                    reply[44..60].copy_from_slice(
                        &Ipv4Addr::new(198, 51, 100, 17).to_ipv6_mapped().octets());
                    router.send_to(&reply, from).await.unwrap();
                }
            });
            let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44000);
            let lease = PcpLease::start(local, gateway,
                Duration::from_secs(4), Duration::from_secs(1)).await.unwrap();
            let mut updates = lease.subscribe();
            assert_eq!(updates.borrow().mapping.unwrap().external_address.port(), 55000);
            updates.changed().await.unwrap();
            assert_eq!(updates.borrow().generation, 1);
            assert!(updates.borrow().mapping.is_some());
            lease.shutdown().await.unwrap();
            worker.await.unwrap();
        }).await.unwrap();
    }
}
