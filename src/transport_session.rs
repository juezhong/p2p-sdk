//! A transport-first SDK session: one authenticated Control QUIC and
//! application-requested, independently authenticated auxiliary QUIC links.
//! This module does not know files, transfer lanes, RPC or stream scheduling.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{Connection, Endpoint};
use tokio::time::{timeout_at, Instant};
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

/// The generic SDK surface does not create any Data QUIC automatically.
/// Applications may open any number of auxiliary connections using these
/// methods, without importing the Transfer-specific four-lane policy.
pub struct ConnectedTransportPeer {
    // 不能向应用公开原始 Endpoint，否则可绕过每条连接的会话认证。
    pub(crate) endpoint: Endpoint,
    /// 已通过 mTLS 和会话绑定认证的 Control 连接。
    pub control: Connection,
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
        if self.role != IceRole::Controlling { return Err(TransportError::WrongRole); }
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

    /// Joiner accepts an auxiliary connection on the authenticated primary
    /// UDP endpoint, reusing the original session's non-resettable replay guard.
    pub async fn accept_authenticated_data(
        &self, deadline: Duration,
    ) -> Result<AuthenticatedDataLink, TransportError> {
        if self.role != IceRole::Controlled { return Err(TransportError::WrongRole); }
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
        if !matches!(proof, Ok(Ok(_))) {
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
