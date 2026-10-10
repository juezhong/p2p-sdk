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

    /// 无论成功/失败均要完成取消任务与路由器映射删除，不能仅依赖
    /// Drop 中的 best-effort 通知（应用可能马上退出 Tokio runtime）。
    pub async fn cleanup(mut self) {
        self.candidates.abort_and_join().await;
        // 多个路由器删除命令必须并发等待；逐个 await 会把成功建连
        // 延迟累加成 N 个网关超时，不符合 Go 的快速可用路径语义。
        let mut cleanup = tokio::task::JoinSet::new();
        for (_, lease) in self.leases.drain(..) {
            cleanup.spawn(async move {
                let _ = lease.shutdown().await;
            });
        }
        while cleanup.join_next().await.is_some() {}
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
    async fn failed_ice_race_cleanup_releases_every_udp_owner() {
        tokio::time::timeout(Duration::from_secs(7), async {
            let bind = "127.0.0.1:0".parse().unwrap();
            let collected = ManagedCandidates::gather(
                &[bind, bind], &[], IceRole::Controlling,
                Duration::from_millis(200), Duration::ZERO,
            ).await.unwrap();
            let occupied = collected.candidates.interfaces.iter()
                .map(|owner| owner.owner.handle.local_address())
                .collect::<Vec<_>>();
            let remote_owner = ManagedCandidates::gather(
                &[bind], &[], IceRole::Controlled,
                Duration::from_millis(200), Duration::ZERO,
            ).await.unwrap();
            let remote = remote_owner.candidates.combined.clone();
            drop(remote_owner); // ICE 对端已退出，剩余 UDP Owner 必须能够回收。
            let credentials = crate::session_binding::SessionCredentials::new(
                [5; 16], [6; 32],
            ).unwrap();
            let mut race = collected.start_authenticated_path_race(
                &remote, credentials, Duration::from_millis(400),
            ).unwrap();
            assert!(race.next().await.is_none());
            race.cleanup().await;
            for addr in occupied {
                // UDP Owner 的 recv task 可能需要一次 runtime 轮询处理 abort；
                // 不允许永久占用端口，但不要依赖任务调度的纳秒级顺序。
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if tokio::net::UdpSocket::bind(addr).await.is_ok() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.expect("failed ICE owner must have been released");
            }
        }).await.unwrap();
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
