//! Direct-only multi-owner ICE path discovery and race.
//!
//! Every physical UDP owner must bind its own true source address/port and
//! gather srflx mappings on that exact socket. Offer signaling contains a
//! single ICE credential pair plus candidates from all participating owners.
//! Each independently checked ICE agent receives ONLY its owner's candidates,
//! so a candidate belonging to another NIC is never falsely claimed as a
//! source from this socket. The first authenticated nominated path wins;
//! unsuccessful owners are dropped and never advertised as QUIC endpoints.
//!
//! This is a network building block; Transfer's existing one-interface
//! pairing UI has not yet been migrated. ICE consent/restart remains separate.

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use tokio::{task::JoinSet, time::{Instant, sleep_until, timeout_at}};

use crate::{
    ice_agent::NominatedPath,
    ice_gather::{gather, add_portmapped_candidate, append_stun_observations, CandidateGatherError},
    gateway::GatewayLease,
    ice_signaling::IceCandidateType,
    ice_multi::{nominate_direct_candidates, nominate_with_authenticated_punch},
    multi_stun::{query_via_owner, MappingReport, MappingConsistency},
    ice_signaling::{IceDescription, IceRole, MAX_CANDIDATES},
    punch::AuthenticatedPunch,
    session_binding::SessionCredentials,
    udp_owner::UdpOwner,
};

/// One owner per advertised interface. Bound by the signaling candidate
/// limit, not by a smaller hidden cap that can exclude a usable IP family.
pub const MAX_ACTIVE_INTERFACES: usize = MAX_CANDIDATES;

#[derive(Debug)]
pub enum MultiInterfaceError {
    Empty,
    TooMany,
    InvalidAddress,
    Bind,
    Candidate(CandidateGatherError),
    NoDirectPath,
}

pub struct InterfaceOwner {
    pub owner: UdpOwner,
    /// Candidates of this UDP owner only, with the *shared* credentials.
    pub local: IceDescription,
    /// Preserve real STUN responses for network diagnostics.
    pub stun_mapping: Option<MappingReport>,
}

pub struct CandidateSet {
    /// Single authenticated signaling object for manual or rendezvous mode.
    pub combined: IceDescription,
    pub interfaces: Vec<InterfaceOwner>,
    /// 网关租约随已公布候选保留给 ManagedCandidates；未公布的立即清理。
    pub mapping_leases: Vec<(SocketAddr, GatewayLease)>,
}

pub struct SelectedDirectPath {
    pub owner: UdpOwner,
    pub path: NominatedPath,
    pub stun_mapping: Option<MappingReport>,
}

/// ICE 结果流：保留未获胜的网络接口，直到某条路径真正完成
/// QUIC/mTLS/会话认证。Drop 会停止剩余 ICE 检查并关闭其 UDP Owner。
pub struct CandidatePathRace {
    workers: JoinSet<Result<SelectedDirectPath, MultiInterfaceError>>,
    expires: Instant,
}

impl CandidatePathRace {
    pub async fn next(&mut self) -> Option<SelectedDirectPath> {
        loop {
            let joined = timeout_at(self.expires, self.workers.join_next())
                .await.ok().flatten()?;
            if let Ok(Ok(path)) = joined {
                return Some(path);
            }
        }
    }
}

impl Drop for CandidatePathRace {
    fn drop(&mut self) {
        self.workers.abort_all();
    }
}

/// Bind one UDP owner per requested local address, concurrently gather Host
/// plus same-socket STUN mappings, and publish a single combined candidate
/// offer. Missing/failed interface binds are nonfatal when another works.
/// Caller must use real OS interface discovery for normal operation.
pub async fn gather_interfaces(
    addresses: &[SocketAddr],
    stun: &[SocketAddr],
    role: IceRole,
    timeout: Duration,
) -> Result<CandidateSet, MultiInterfaceError> {
    gather_interfaces_with_mapping(addresses, stun, role, timeout, Duration::ZERO).await
}

/// 与 Go gatherCandidates 相同：先绑定真实 Owner，再让 STUN 与网关
/// PCP/NAT-PMP/UPnP 在同一个采集阶段并发竞争，而不是两轮串行等待。
pub async fn gather_interfaces_with_mapping(
    addresses: &[SocketAddr],
    stun: &[SocketAddr],
    role: IceRole,
    timeout: Duration,
    mapping_budget: Duration,
) -> Result<CandidateSet, MultiInterfaceError> {
    if addresses.is_empty() { return Err(MultiInterfaceError::Empty); }
    if addresses.len() > MAX_ACTIVE_INTERFACES || timeout.is_zero() {
        return Err(MultiInterfaceError::TooMany);
    }
    let mut jobs = JoinSet::new();
    let mut seen = HashSet::new();
    for (index, address) in addresses.iter().copied().enumerate() {
        if address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err(MultiInterfaceError::InvalidAddress);
        }
        if address.port() != 0 && !seen.insert(address) {
            return Err(MultiInterfaceError::InvalidAddress);
        }
        let stun = stun.iter().copied().filter(|s| s.is_ipv4() == address.is_ipv4())
            .collect::<Vec<_>>();
        jobs.spawn(async move {
            let owner = UdpOwner::bind(address).await.map_err(|_| MultiInterfaceError::Bind)?;
            let local = owner.handle.local_address();
            // 首先创建 Host 候选和 ICE 凭据，STUN 与网关从同一 UDP Owner
            // 并发收集。不能因慢服务端阻塞已经可用的候选。
            let mut discovered = gather(&owner.handle, &[], role, timeout).await
                .map_err(MultiInterfaceError::Candidate)?;
            let stun_budget = timeout.min(Duration::from_millis(1200));
            let mut stun_query = Box::pin(async {
                if stun.is_empty() { None }
                else { query_via_owner(&owner.handle, &stun, stun_budget).await.ok() }
            });
            // 不取消可能已在路由器建立规则的端口映射任务。
            // 如果窗口结束后结果才回来，由 worker 主动释放，避免泄漏。
            let (map_tx, map_rx) = tokio::sync::oneshot::channel();
            if let SocketAddr::V4(v4) = local {
                if !mapping_budget.is_zero() {
                    tokio::spawn(async move {
                        let lease = GatewayLease::start_for_socket(
                            v4, Duration::from_secs(3600), mapping_budget,
                        ).await.ok();
                        if let Err(Some(late)) = map_tx.send(lease) {
                            let _ = late.shutdown().await;
                        }
                    });
                }
            }
            // 对无网关映射的地址，仅需要收集 STUN/Host。
            let mapping_enabled = local.is_ipv4() && !mapping_budget.is_zero();
            let mut map_query = Box::pin(async {
                if mapping_enabled { map_rx.await.ok().flatten() }
                else { None }
            });
            let mut stun_done = false;
            let mut map_done = false;
            let mut lease = None;
            let hard_deadline = Instant::now() + timeout.max(mapping_budget);
            let mut soft_deadline: Option<Instant> = None;
            loop {
                if stun_done && map_done { break; }
                tokio::select! {
                    report = &mut stun_query, if !stun_done => {
                        stun_done = true;
                        if let Some(report) = report {
                            if !report.observations.is_empty() {
                                append_stun_observations(
                                    &mut discovered.description.candidates, local, &report,
                                );
                                let grace = if report.consistency() == MappingConsistency::Different {
                                    Duration::from_millis(420)
                                } else {
                                    Duration::from_millis(180)
                                };
                                discovered.mapping = Some(report);
                                soft_deadline.get_or_insert(Instant::now() + grace);
                            }
                        }
                    }
                    result = &mut map_query, if !map_done => {
                        map_done = true;
                        if let Some(result) = result {
                            lease = Some(result);
                            soft_deadline.get_or_insert(
                                Instant::now() + Duration::from_millis(180)
                            );
                        }
                    }
                    _ = sleep_until(soft_deadline.unwrap_or(hard_deadline)),
                        if soft_deadline.is_some() => { break; }
                    _ = sleep_until(hard_deadline) => { break; }
                }
            }
            // 终止尚未完成的 STUN 查询；未接收的网关成功租约会在后台清理。
            drop(stun_query);
            drop(map_query);
            let mut local_description = discovered.description;
            if let Some(mapping) = lease.as_ref() {
                if let Some(external) = mapping.subscribe().mapped_address() {
                    if !add_portmapped_candidate(
                        &mut local_description, local, external,
                    ).unwrap_or(false) {
                        if let Some(mapping) = lease.take() {
                            tokio::spawn(async move { let _ = mapping.shutdown().await; });
                        }
                    }
                } else if let Some(mapping) = lease.take() {
                    tokio::spawn(async move { let _ = mapping.shutdown().await; });
                }
            }
            Ok::<_, MultiInterfaceError>((index, InterfaceOwner {
                owner,
                local: local_description,
                stun_mapping: discovered.mapping,
            }, lease))
        });
    }

    let mut obtained = Vec::new();
    while let Some(result) = jobs.join_next().await {
        if let Ok(Ok(owner)) = result { obtained.push(owner); }
    }
    if obtained.is_empty() { return Err(MultiInterfaceError::Bind); }
    obtained.sort_by_key(|(index, _, _)| *index);

    // All independent ICE checks must use one exchanged ufrag/password pair.
    // No ICE agent may claim candidates collected on a different UDP owner.
    let (first_ufrag, first_password) = (
        obtained[0].1.local.ufrag.clone(),
        obtained[0].1.local.password.clone(),
    );
    let mut advertised = Vec::new();
    let mut owners = Vec::new();
    let mut mapping_leases = Vec::new();
    for (_, mut item, mut lease) in obtained {
        if advertised.len() >= MAX_CANDIDATES { break; }
        item.local.ufrag = first_ufrag.clone();
        item.local.password = first_password.clone();
        let room = MAX_CANDIDATES - advertised.len();
        item.local.candidates.truncate(room);
        if let Some(mapping) = lease.take() {
            if item.local.candidates.iter().any(|c| c.kind == IceCandidateType::PortMapped) {
                mapping_leases.push((item.owner.handle.local_address(), mapping));
            } else {
                tokio::spawn(async move { let _ = mapping.shutdown().await; });
            }
        }
        advertised.extend(item.local.candidates.iter().cloned());
        owners.push(item);
    }
    let combined = IceDescription {
        role, ufrag: first_ufrag,
        password: first_password, candidates: advertised,
    };
    combined.validate().map_err(|_| MultiInterfaceError::InvalidAddress)?;
    Ok(CandidateSet { combined, interfaces: owners, mapping_leases })
}

impl CandidateSet {
    /// 多接口持续竞速：成功的 ICE 路径只作为候选，不在 QUIC 真正完成
    /// 相互认证前关闭其他 UDP Owner。避免首条 ICE 提名路径的 QUIC 失败
    /// 直接导致整个 P2P 建连失败。
    pub fn start_authenticated_path_race(
        self,
        remote: &IceDescription,
        credentials: SessionCredentials,
        deadline: Duration,
    ) -> Result<CandidatePathRace, MultiInterfaceError> {
        remote.validate().map_err(|_| MultiInterfaceError::InvalidAddress)?;
        if deadline <= Duration::from_millis(200) {
            return Err(MultiInterfaceError::NoDirectPath);
        }
        let mut workers = JoinSet::new();
        for mut interface in self.interfaces {
            let remote = remote.clone();
            let proof = AuthenticatedPunch::new(credentials.clone(), interface.local.role);
            workers.spawn(async move {
                let result = nominate_with_authenticated_punch(
                    &mut interface.owner, &interface.local, &remote, &proof, deadline,
                ).await.map_err(|_| MultiInterfaceError::NoDirectPath)?;
                Ok(SelectedDirectPath {
                    owner: interface.owner,
                    path: result,
                    stun_mapping: interface.stun_mapping,
                })
            });
        }
        Ok(CandidatePathRace {
            workers,
            expires: Instant::now() + deadline,
        })
    }

    /// Run real authenticated ICE checks across all bound sockets in
    /// parallel rather than serially waiting for IPv6 to time out before IPv4.
    /// The returned winning owner retains exactly the ICE-validated UDP socket
    /// for subsequently authenticated QUIC, while loser owners are dropped.
    pub async fn nominate_first(
        self,
        remote: &IceDescription,
        deadline: Duration,
    ) -> Result<SelectedDirectPath, MultiInterfaceError> {
        remote.validate().map_err(|_| MultiInterfaceError::InvalidAddress)?;
        if deadline.is_zero() { return Err(MultiInterfaceError::NoDirectPath); }
        let mut tasks = JoinSet::new();
        for mut interface in self.interfaces {
            let remote = remote.clone();
            tasks.spawn(async move {
                let result = nominate_direct_candidates(
                    &mut interface.owner, &interface.local, &remote, deadline,
                ).await;
                (interface.owner, interface.stun_mapping, result)
            });
        }
        let result = tokio::time::timeout(deadline, async {
            while let Some(joined) = tasks.join_next().await {
                if let Ok((owner, stun_mapping, Ok(path))) = joined {
                    tasks.abort_all();
                    return Ok(SelectedDirectPath { owner, path, stun_mapping });
                }
            }
            Err(MultiInterfaceError::NoDirectPath)
        }).await;
        result.unwrap_or(Err(MultiInterfaceError::NoDirectPath))
    }
    /// Like nominate_first, but first send authenticated probes and add only
    /// HMAC-verified peer-reflexive endpoints to the subsequent ICE checks.
    /// A learned source never counts as a nominated path without ICE proof.
    pub async fn nominate_first_with_authenticated_punch(
        self,
        remote: &IceDescription,
        credentials: SessionCredentials,
        deadline: Duration,
    ) -> Result<SelectedDirectPath, MultiInterfaceError> {
        remote.validate().map_err(|_| MultiInterfaceError::InvalidAddress)?;
        if deadline <= Duration::from_millis(200) {
            return Err(MultiInterfaceError::NoDirectPath);
        }
        let mut tasks = JoinSet::new();
        for mut interface in self.interfaces {
            let remote = remote.clone();
            let proof = AuthenticatedPunch::new(credentials.clone(), interface.local.role);
            tasks.spawn(async move {
                let result = nominate_with_authenticated_punch(
                    &mut interface.owner, &interface.local, &remote, &proof, deadline,
                ).await;
                (interface.owner, interface.stun_mapping, result)
            });
        }
        let result = tokio::time::timeout(deadline, async {
            while let Some(joined) = tasks.join_next().await {
                if let Ok((owner, stun_mapping, Ok(path))) = joined {
                    tasks.abort_all();
                    return Ok(SelectedDirectPath { owner, path, stun_mapping });
                }
            }
            Err(MultiInterfaceError::NoDirectPath)
        }).await;
        result.unwrap_or(Err(MultiInterfaceError::NoDirectPath))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gathers_two_sockets_but_never_confuses_their_candidate_bases() {
        let a = "127.0.0.1:0".parse().unwrap();
        let set = gather_interfaces(
            &[a, a], &[], IceRole::Controlling,
            Duration::from_millis(400),
        ).await.unwrap();
        assert_eq!(set.interfaces.len(), 2);
        assert_eq!(set.combined.candidates.len(), 2);
        assert_ne!(set.interfaces[0].owner.handle.local_address(),
            set.interfaces[1].owner.handle.local_address());
        set.combined.validate().unwrap();
        for interface in &set.interfaces {
            assert_eq!(interface.local.ufrag, set.combined.ufrag);
            assert_eq!(interface.local.password, set.combined.password);
            assert_eq!(interface.local.candidates.len(), 1);
            assert_eq!(interface.local.candidates[0].address,
                interface.owner.handle.local_address());
        }
    }

    #[tokio::test]
    async fn mixed_candidate_race_uses_actual_nominated_udp_socket() {
        let bind = "127.0.0.1:0".parse().unwrap();
        let a = gather_interfaces(&[bind, bind], &[], IceRole::Controlling,
            Duration::from_millis(200)).await.unwrap();
        let b = gather_interfaces(&[bind, bind], &[], IceRole::Controlled,
            Duration::from_millis(200)).await.unwrap();
        let a_remote = b.combined.clone();
        let b_remote = a.combined.clone();
        let (left, right) = tokio::join!(
            a.nominate_first(&a_remote, Duration::from_secs(5)),
            b.nominate_first(&b_remote, Duration::from_secs(5)),
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_eq!(left.path.local, left.owner.handle.local_address());
        assert_eq!(right.path.local, right.owner.handle.local_address());
        // The selected address must be one of the peer's real advertised
        // candidates, not a guessed LAN prefix or a STUN-only observation.
        assert!(a_remote.candidates.iter().any(|c| c.address == left.path.remote));
        assert!(b_remote.candidates.iter().any(|c| c.address == right.path.remote));
    }

    #[tokio::test]
    async fn rejects_wildcard_and_empty_interface_offer() {
        assert!(matches!(gather_interfaces(&[], &[], IceRole::Controlling,
            Duration::from_secs(1)).await, Err(MultiInterfaceError::Empty)));
        assert!(matches!(gather_interfaces(&["0.0.0.0:0".parse().unwrap()], &[],
            IceRole::Controlling, Duration::from_secs(1)).await,
            Err(MultiInterfaceError::InvalidAddress)));
    }
}
