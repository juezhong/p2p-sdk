//! A transport-first SDK session: one authenticated Control QUIC and
//! application-requested, independently authenticated auxiliary QUIC links.
//! This module does not know files, transfer lanes, RPC or stream scheduling.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{Connection, Endpoint};
use tokio::{sync::watch, task::JoinHandle, time::{sleep, timeout_at, Instant}};
use crate::{
    channel::ChannelRole,
    ice_signaling::{IceRole, IceCandidateType},
    gateway::GatewayLease,
    managed_candidates::ManagedPath,
    multi_stun::MappingConsistency,
    network_diagnostics::GatewayMethod,
    peer_pin::PeerCertificatePin,
    punch_loop::PunchLoop,
    quinn_socket::{demux_endpoint_config, QuinnUdpAdapter},
    session_binding::{authenticate_initiator, authenticate_responder, ReplayGuard, SessionCredentials},
    udp_owner::UdpOwner,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    WrongRole,
    ControlDisconnected,
    UdpBind,
    QuicEndpoint,
    QuicConnection,
    Authentication,
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportDiagnostic {
    pub actual_local_udp: SocketAddr,
    pub actual_remote_udp: SocketAddr,
    pub control_connected: bool,
    /// QUIC Control 是否由本端拨号建立（与配对创建/加入角色无关）。
    pub control_outbound: bool,
    pub gateway_mapping: Option<SocketAddr>,
    pub gateway_method: Option<GatewayMethod>,
    pub remote_candidate_kind: Option<IceCandidateType>,
    pub ice_role: IceRole,
    /// These were offered during ICE; loser sockets need not remain open.
    pub offered_host_candidates: Vec<SocketAddr>,
    pub stun_consistency: Option<MappingConsistency>,
    pub authenticated_peer_reflexive: Vec<SocketAddr>,
}

/// One authenticated auxiliary QUIC connection. An independent port, if
/// created, lives as long as this object; stream semantics belong to callers.
pub struct AuthenticatedDataLink {
    pub connection: Connection,
    endpoint: Option<Endpoint>,
    owner: Option<UdpOwner>,
}

impl AuthenticatedDataLink {
    pub fn source_udp(&self) -> Option<SocketAddr> {
        self.owner.as_ref().map(|o| o.handle.local_address())
            .or_else(|| self.endpoint.as_ref().and_then(|e| e.local_addr().ok()))
    }

    pub fn shutdown(self) {
        self.connection.close(0u32.into(), b"auxiliary connection closed");
        if let Some(endpoint) = self.endpoint {
            endpoint.close(0u32.into(), b"auxiliary connection closed");
        }
    }
}

/// 通用连接监测只管理一条经认证的辅助 QUIC；业务决定创建多少个实例。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedLinkPhase {
    Connecting,
    Connected,
    Reconnecting,
    ControlLost,
    AuthenticationFailed,
    Stopped,
}

#[derive(Clone, Debug)]
pub struct ManagedLinkStatus {
    pub phase: ManagedLinkPhase,
    /// 仅在重新通过 TLS/会话 HMAC 后递增。
    pub generation: u64,
    pub connection: Option<Connection>,
    pub last_error: Option<TransportError>,
}

/// 丢弃句柄会取消重拨；显式 shutdown 会等待底层 UDP/QUIC 释放。
pub struct ManagedAuthenticatedLink {
    changed: watch::Receiver<ManagedLinkStatus>,
    stop: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl ManagedAuthenticatedLink {
    pub fn subscribe(&self) -> watch::Receiver<ManagedLinkStatus> {
        self.changed.clone()
    }

    /// 只返回当前存活、曾通过完整认证的 QUIC；业务自己决定 Stream 分配。
    pub fn current(&self) -> Option<Connection> {
        self.changed.borrow().connection.as_ref()
            .filter(|connection| connection.close_reason().is_none())
            .cloned()
    }

    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(worker) = self.worker.take() {
            let _ = worker.await;
        }
    }
}

impl Drop for ManagedAuthenticatedLink {
    fn drop(&mut self) {
        // worker 收到停止信号后自己清理 Endpoint、UDP Owner 和活跃 QUIC。
        self.stop.send_replace(true);
    }
}

/// The generic SDK surface does not create any Data QUIC automatically.
/// Applications may open any number of auxiliary connections using these
/// methods, without importing the Transfer-specific four-lane policy.
pub struct ConnectedTransportPeer {
    // 不能向应用公开原始 Endpoint，否则可绕过每条连接的会话认证。
    pub(crate) endpoint: Endpoint,
    /// 已通过 mTLS 和会话绑定认证的 Control 连接。
    pub control: Connection,
    pub(crate) control_outbound: bool,
    pub(crate) path: ManagedPath,
    pub(crate) punch: Option<PunchLoop>,
    pub(crate) credentials: SessionCredentials,
    pub(crate) remote_pin: [u8; 32],
    pub(crate) role: IceRole,
    pub(crate) client_tls: Option<quinn::ClientConfig>,
    pub(crate) replay_guard: Arc<ReplayGuard>,
    pub(crate) remote_candidate_kind: Option<IceCandidateType>,
    pub(crate) offered_host_candidates: Vec<SocketAddr>,
}

impl ConnectedTransportPeer {
    /// 可选托管一条 Data QUIC；创建者重拨，加入者重新接受，每轮均做
    /// mTLS PIN + Session HMAC。可以创建多个实例，不固定四条也不负责选流。
    ///
    /// 托管对象持有 Arc<Self>。先关闭托管对象，再结束整个 Control 会话；
    /// Control 真正断开后不伪造 ICE Restart 或逻辑会话连续性。
    pub fn manage_authenticated_data(self: &Arc<Self>) -> ManagedAuthenticatedLink {
        let initial = ManagedLinkStatus {
            phase: ManagedLinkPhase::Connecting, generation: 0,
            connection: None, last_error: None,
        };
        let (updates, changed) = watch::channel(initial);
        let (stop, mut stopping) = watch::channel(false);
        let peer = Arc::clone(self);
        let worker = tokio::spawn(async move {
            let mut generation = 0_u64;
            let mut backoff = Duration::from_millis(500);
            let final_phase = loop {
                if *stopping.borrow() { break ManagedLinkPhase::Stopped; }
                if peer.control.close_reason().is_some() {
                    break ManagedLinkPhase::ControlLost;
                }
                let result = tokio::select! {
                    _ = stopping.changed() => break ManagedLinkPhase::Stopped,
                    _ = peer.control.closed() => break ManagedLinkPhase::ControlLost,
                    result = async {
                        // 控制连接真正的拨号方负责主动建立附属连接；
                        // 邀请码创建/加入角色不代表网络方向。
                        match peer.control_outbound {
                            true => peer.open_authenticated_data(Duration::from_secs(12)).await,
                            false => peer.accept_authenticated_data(Duration::from_secs(12)).await,
                        }
                    } => result,
                };
                match result {
                    Ok(link) => {
                        // 连接结果与 Control 关闭可能同时就绪，不能发布虚假的 Healthy。
                        if peer.control.close_reason().is_some() {
                            link.shutdown();
                            break ManagedLinkPhase::ControlLost;
                        }
                        if link.connection.close_reason().is_some() {
                            link.shutdown();
                            updates.send_replace(ManagedLinkStatus {
                                phase: ManagedLinkPhase::Reconnecting,
                                generation, connection: None,
                                last_error: Some(TransportError::QuicConnection),
                            });
                            continue;
                        }
                        generation = generation.wrapping_add(1);
                        backoff = Duration::from_millis(500);
                        updates.send_replace(ManagedLinkStatus {
                            phase: ManagedLinkPhase::Connected,
                            generation,
                            connection: Some(link.connection.clone()),
                            last_error: None,
                        });
                        let reason = tokio::select! {
                            _ = stopping.changed() => ManagedLinkPhase::Stopped,
                            _ = peer.control.closed() => ManagedLinkPhase::ControlLost,
                            _ = link.connection.closed() => ManagedLinkPhase::Reconnecting,
                        };
                        link.shutdown();
                        if reason != ManagedLinkPhase::Reconnecting {
                            break reason;
                        }
                        // 旧连接已关闭，不能继续作为健康连接发布。
                        updates.send_replace(ManagedLinkStatus {
                            phase: ManagedLinkPhase::Reconnecting,
                            generation, connection: None,
                            last_error: Some(TransportError::QuicConnection),
                        });
                    }
                    Err(TransportError::ControlDisconnected) => {
                        break ManagedLinkPhase::ControlLost;
                    }
                    // 错误角色是本地 API 误用；来自网络的认证失败则
                    // 必须拒绝当前连接，但不能让恶意探测永久杀死恢复循环。
                    Err(TransportError::WrongRole) => {
                        break ManagedLinkPhase::AuthenticationFailed;
                    }
                    Err(error) => {
                        updates.send_replace(ManagedLinkStatus {
                            phase: ManagedLinkPhase::Reconnecting,
                            generation, connection: None, last_error: Some(error),
                        });
                    }
                }
                // 有界指数退避，停止与 Control 关闭不会被 sleep 阻塞。
                tokio::select! {
                    _ = stopping.changed() => break ManagedLinkPhase::Stopped,
                    _ = peer.control.closed() => break ManagedLinkPhase::ControlLost,
                    _ = sleep(backoff) => {}
                }
                backoff = backoff.saturating_mul(2).min(Duration::from_secs(5));
            };
            updates.send_replace(ManagedLinkStatus {
                phase: final_phase, generation,
                connection: None,
                last_error: if final_phase == ManagedLinkPhase::ControlLost {
                    Some(TransportError::ControlDisconnected)
                } else if final_phase == ManagedLinkPhase::AuthenticationFailed {
                    Some(TransportError::Authentication)
                } else { None },
            });
        });
        ManagedAuthenticatedLink {
            changed, stop, worker: Some(worker),
        }
    }

    pub fn diagnostic(&self) -> TransportDiagnostic {
        let mut offered_host_candidates = self.offered_host_candidates.clone();
        offered_host_candidates.sort();
        offered_host_candidates.dedup();
        let authenticated_peer_reflexive = self.punch.as_ref()
            .map(|punch| punch.subscribe().borrow().discovered.clone())
            .unwrap_or_default();
        TransportDiagnostic {
            actual_local_udp: self.path.selected.path.local,
            actual_remote_udp: self.path.selected.path.remote,
            control_connected: self.control.close_reason().is_none(),
            control_outbound: self.control_outbound,
            gateway_mapping: self.path.mapping_lease.as_ref()
                .and_then(|lease| lease.subscribe().mapped_address()),
            gateway_method: self.path.mapping_lease.as_ref().map(|lease| match lease {
                GatewayLease::Pcp(_) => GatewayMethod::Pcp,
                GatewayLease::NatPmp(_) => GatewayMethod::NatPmp,
                GatewayLease::Upnp(_) => GatewayMethod::Upnp,
            }),
            remote_candidate_kind: self.remote_candidate_kind,
            ice_role: self.role,
            offered_host_candidates,
            stun_consistency: self.path.selected.stun_mapping.as_ref()
                .map(|report| report.consistency()),
            authenticated_peer_reflexive,
        }
    }

    /// Creator requests a fresh authenticated QUIC transport. Prefer a fresh
    /// local UDP port, then fall back to the nominated Control UDP path.
    /// Every attempt authenticates TLS certificate and session HMAC anew.
    pub async fn open_authenticated_data(
        &self, deadline: Duration,
    ) -> Result<AuthenticatedDataLink, TransportError> {
        if !self.control_outbound { return Err(TransportError::WrongRole); }
        if self.control.close_reason().is_some() {
            return Err(TransportError::ControlDisconnected);
        }
        if deadline.is_zero() { return Err(TransportError::Timeout); }
        // 独立 UDP 尝试与共享路径回退必须使用同一个绝对截止时间。
        let expires = Instant::now() + deadline;
        let remote = self.path.selected.path.remote;
        let dedicated = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = timeout_at(expires, self.try_dedicated_endpoint()) =>
                result.map_err(|_| TransportError::Timeout)?,
        };
        if let Some((owner, endpoint)) = dedicated {
            let attempt = self.authenticated_dial(&endpoint, remote);
            let attempt_expires = expires.min(Instant::now() + Duration::from_secs(6));
            let result = tokio::select! {
                _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
                result = timeout_at(attempt_expires, attempt) => result,
            };
            if let Ok(Ok(connection)) = result {
                return Ok(self.supervise_data(connection, Some(endpoint), Some(owner)));
            }
        }
        let result = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = timeout_at(expires, self.authenticated_dial(&self.endpoint, remote)) => result,
        };
        let connection = result.map_err(|_| TransportError::Timeout)??;
        Ok(self.supervise_data(connection, None, None))
    }

    /// Control QUIC 的实际监听方接受附属连接，在认证的主 UDP 路径上完成。
    /// UDP endpoint, reusing the original session's non-resettable replay guard.
    pub async fn accept_authenticated_data(
        &self, deadline: Duration,
    ) -> Result<AuthenticatedDataLink, TransportError> {
        if self.control_outbound { return Err(TransportError::WrongRole); }
        if self.control.close_reason().is_some() {
            return Err(TransportError::ControlDisconnected);
        }
        if deadline.is_zero() { return Err(TransportError::Timeout); }
        let expires = Instant::now() + deadline;
        let connecting = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = timeout_at(expires, self.endpoint.accept()) =>
                result.map_err(|_| TransportError::Timeout)?
                    .ok_or(TransportError::QuicConnection)?,
        };
        let connection = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = timeout_at(expires, connecting) =>
                result.map_err(|_| TransportError::Timeout)?
                    .map_err(|_| TransportError::QuicConnection)?,
        };
        if let Err(error) = self.verify_remote(&connection) {
            connection.close(1u32.into(), b"unverified remote certificate");
            return Err(error);
        }
        let proof = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = timeout_at(expires, authenticate_responder(
                connection.clone(), &self.credentials, ChannelRole::Data,
                &self.replay_guard, deadline,
            )) => result,
        };
        if !matches!(&proof, Ok(Ok(_))) {
            connection.close(1u32.into(), b"invalid or timed-out data session proof");
            return Err(if proof.is_err() {
                TransportError::Timeout
            } else {
                TransportError::Authentication
            });
        }
        Ok(self.supervise_data(connection, None, None))
    }

    async fn try_dedicated_endpoint(&self) -> Option<(UdpOwner, Endpoint)> {
        let tls = self.client_tls.clone()?;
        let mut owner = UdpOwner::bind(SocketAddr::new(
            self.path.selected.path.local.ip(), 0,
        )).await.ok()?;
        let adapter = QuinnUdpAdapter::from_owner(&mut owner).ok()?;
        let runtime = quinn::default_runtime()?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            demux_endpoint_config(), None, Arc::new(adapter), runtime,
        ).ok()?;
        endpoint.set_default_client_config(tls);
        Some((owner, endpoint))
    }

    async fn authenticated_dial(
        &self, endpoint: &Endpoint, remote: SocketAddr,
    ) -> Result<Connection, TransportError> {
        let connection = endpoint.connect(remote, "localhost")
            .map_err(|_| TransportError::QuicConnection)?
            .await.map_err(|_| TransportError::QuicConnection)?;
        if let Err(error) = self.verify_remote(&connection) {
            connection.close(1u32.into(), b"unverified remote certificate");
            return Err(error);
        }
        if authenticate_initiator(connection.clone(), &self.credentials,
            ChannelRole::Data, Duration::from_secs(6)).await.is_err()
        {
            connection.close(1u32.into(), b"invalid data session proof");
            return Err(TransportError::Authentication);
        }
        Ok(connection)
    }

    fn verify_remote(&self, connection: &Connection) -> Result<(), TransportError> {
        PeerCertificatePin::new(self.remote_pin)
            .map_err(|_| TransportError::Authentication)?
            .verify_connection(connection)
            .map_err(|_| TransportError::Authentication)
    }

    fn supervise_data(
        &self, connection: Connection, endpoint: Option<Endpoint>, owner: Option<UdpOwner>,
    ) -> AuthenticatedDataLink {
        let parent = self.control.clone();
        let data = connection.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = parent.closed() => data.close(0u32.into(), b"control disconnected"),
                _ = data.closed() => {}
            }
        });
        AuthenticatedDataLink { connection, endpoint, owner }
    }

    pub async fn shutdown(mut self) {
        self.control.close(0u32.into(), b"control session ended");
        self.endpoint.close(0u32.into(), b"control session ended");
        if let Some(punch) = self.punch.take() {
            punch.shutdown().await;
        }
        self.path.shutdown_gateway().await;
    }
}
