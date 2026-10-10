//! Network discovery that owns the lifetime of any successful UDP gateway
//! mapping. Host and same-socket srflx candidates remain usable when gateway
//! mapping is unavailable. Every advertised port map must refer to the exact
//! already bound UDP owner's source address and internal port; no relay.
//!
//! The selected gateway lease must be kept alive with the selected Quinn
//! Endpoint. Dropping the owner stops renewals and schedules best-effort
//! cleanup; call shutdown() to await router deletion on a clean exit.

use std::{net::SocketAddr, time::Duration};

use crate::{
    gateway::GatewayLease,
    ice_agent::NominatedPath,
    ice_signaling::{IceDescription, IceRole},
    multi_interface::{
        gather_interfaces_with_mapping, CandidatePathRace, CandidateSet, MultiInterfaceError,
        SelectedDirectPath,
    },
};

pub struct ManagedCandidates {
    pub candidates: CandidateSet,
    leases: Vec<(SocketAddr, GatewayLease)>,
}

pub struct ManagedPath {
    /// A single authenticated nominated path on its original real UDP port.
    pub selected: SelectedDirectPath,
    /// Hold the winning gateway lease for as long as QUIC uses its socket.
    pub mapping_lease: Option<GatewayLease>,
}

/// 原始 ICE 端口和相关映射租约必须在 QUIC 握手完成前保留。
/// 该结构只交付经过 ICE 认证的路径，不将其误报为已连接的 QUIC。
pub struct ManagedPathRace {
    candidates: CandidatePathRace,
    leases: Vec<(SocketAddr, GatewayLease)>,
}

impl ManagedPathRace {
    pub async fn next(&mut self) -> Option<ManagedPath> {
        let selected = self.candidates.next().await?;
        let local = selected.owner.handle.local_address();
        let mapping_lease = self.leases.iter().position(|(addr, _)| *addr == local)
            .map(|index| self.leases.swap_remove(index).1);
        Some(ManagedPath { selected, mapping_lease })
    }
}

impl ManagedCandidates {
    /// Collect Host/STUN candidates concurrently across bound NICs, then
    /// request optional port mappings concurrently using the OS-validated
    /// gateways for the same local IPs. The mapping phase has ONE bounded
    /// deadline shared across all physical interfaces.
    pub async fn gather(
        addresses: &[SocketAddr],
        stun: &[SocketAddr],
        role: IceRole,
        discovery_budget: Duration,
        map_budget: Duration,
    ) -> Result<Self, MultiInterfaceError> {
        let mut set = gather_interfaces_with_mapping(
            addresses, stun, role, discovery_budget, map_budget,
        ).await?;
        let leases = std::mem::take(&mut set.mapping_leases);
        Ok(Self { candidates: set, leases })
    }

    pub fn start_authenticated_path_race(
        self, remote: &IceDescription,
        credentials: crate::session_binding::SessionCredentials,
        deadline: Duration,
    ) -> Result<ManagedPathRace, MultiInterfaceError> {
        let candidates = self.candidates.start_authenticated_path_race(
            remote, credentials, deadline,
        )?;
        Ok(ManagedPathRace { candidates, leases: self.leases })
    }

    /// Authenticate runtime NAT endpoints before attempting ICE nomination.
    /// Gateway mappings stay owned until a successful nominated path is
    /// selected; losing mappings are still explicitly cleaned up.
    pub async fn nominate_first_with_authenticated_punch(
        self,
        remote: &IceDescription,
        credentials: crate::session_binding::SessionCredentials,
        deadline: Duration,
    ) -> Result<ManagedPath, MultiInterfaceError> {
        let selected = self.candidates
            .nominate_first_with_authenticated_punch(remote, credentials, deadline).await?;
        let addr = selected.owner.handle.local_address();
        let mut winner = None;
        for (local, lease) in self.leases {
            if local == addr && winner.is_none() {
                winner = Some(lease);
            } else {
                tokio::spawn(async move { let _ = lease.shutdown().await; });
            }
        }
        Ok(ManagedPath { selected, mapping_lease: winner })
    }

    /// Strict ICE nomination is mandatory even for a gateway MAP success.
    /// Drop/close all losing gateway leases, keeping only the one backing the
    /// nominated UDP Owner alive for the subsequent authenticated QUIC session.
    pub async fn nominate_first(
        self, remote: &IceDescription, deadline: Duration,
    ) -> Result<ManagedPath, MultiInterfaceError> {
        let selected = self.candidates.nominate_first(remote, deadline).await?;
        let addr = selected.owner.handle.local_address();
        let mut winner = None;
        for (local, lease) in self.leases {
            if local == addr && winner.is_none() {
                winner = Some(lease);
            } else {
                tokio::spawn(async move { let _ = lease.shutdown().await; });
            }
        }
        Ok(ManagedPath { selected, mapping_lease: winner })
    }
}

impl ManagedPath {
    pub fn nominated(&self) -> NominatedPath { self.selected.path }

    /// Called after QUIC endpoints are closed; the same actual UDP binding
    /// must remain valid until the gateway completes lease cleanup.
    pub async fn shutdown_gateway(&mut self) {
        if let Some(lease) = self.mapping_lease.take() {
            let _ = lease.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_gateway_does_not_disable_authenticated_host_ice() {
        let a = "127.0.0.1:0".parse().unwrap();
        let left = ManagedCandidates::gather(
            &[a], &[], IceRole::Controlling,
            Duration::from_millis(250), Duration::from_millis(150),
        ).await.unwrap();
        let right = ManagedCandidates::gather(
            &[a], &[], IceRole::Controlled,
            Duration::from_millis(250), Duration::from_millis(150),
        ).await.unwrap();
        assert!(left.leases.is_empty());
        assert!(right.leases.is_empty());
        let ld = left.candidates.combined.clone();
        let rd = right.candidates.combined.clone();
        let (l, r) = tokio::join!(
            left.nominate_first(&rd, Duration::from_secs(5)),
            right.nominate_first(&ld, Duration::from_secs(5)),
        );
        assert!(l.unwrap().nominated().remote == rd.candidates[0].address);
        assert!(r.unwrap().nominated().remote == ld.candidates[0].address);
    }

    #[tokio::test]
    async fn zero_map_budget_keeps_plain_lan_candidates() {
        let set = ManagedCandidates::gather(
            &["127.0.0.1:0".parse().unwrap()], &[],
            IceRole::Controlling, Duration::from_millis(250), Duration::ZERO,
        ).await.unwrap();
        assert_eq!(set.candidates.combined.candidates.len(), 1);
        assert!(set.leases.is_empty());
    }
}
