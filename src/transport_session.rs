//! A transport-first SDK session: one authenticated Control QUIC and
//! application-requested, independently authenticated auxiliary QUIC links.
//! This module does not know files, transfer lanes, RPC or stream scheduling.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use quinn::{Connection, Endpoint};
use crate::{
    channel::ChannelRole,
    ice_signaling::IceRole,
    managed_candidates::ManagedPath,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportDiagnostic {
    pub actual_local_udp: SocketAddr,
    pub actual_remote_udp: SocketAddr,
    pub control_connected: bool,
    pub gateway_mapping: Option<SocketAddr>,
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
    pub endpoint: Endpoint,
    pub control: Connection,
    pub(crate) path: ManagedPath,
    pub(crate) punch: Option<PunchLoop>,
    pub(crate) credentials: SessionCredentials,
    pub(crate) remote_pin: [u8; 32],
    pub(crate) role: IceRole,
    pub(crate) client_tls: Option<quinn::ClientConfig>,
    pub(crate) replay_guard: Arc<ReplayGuard>,
}

impl ConnectedTransportPeer {
    pub fn diagnostic(&self) -> TransportDiagnostic {
        TransportDiagnostic {
            actual_local_udp: self.path.selected.path.local,
            actual_remote_udp: self.path.selected.path.remote,
            control_connected: self.control.close_reason().is_none(),
            gateway_mapping: self.path.mapping_lease.as_ref()
                .and_then(|lease| lease.subscribe().mapped_address()),
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
        let remote = self.path.selected.path.remote;
        let mut dedicated = None;
        if let Some(tls) = self.client_tls.clone() {
            if let Ok(mut owner) = UdpOwner::bind(SocketAddr::new(
                self.path.selected.path.local.ip(), 0,
            )).await {
                if let Ok(adapter) = QuinnUdpAdapter::from_owner(&mut owner) {
                    if let Some(runtime) = quinn::default_runtime() {
                        if let Ok(mut endpoint) = Endpoint::new_with_abstract_socket(
                            demux_endpoint_config(), None, Arc::new(adapter), runtime,
                        ) {
                            endpoint.set_default_client_config(tls);
                            dedicated = Some((owner, endpoint));
                        }
                    }
                }
            }
        }
        if let Some((owner, endpoint)) = dedicated {
            let attempt = self.authenticated_dial(&endpoint, remote);
            let result = tokio::select! {
                _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
                result = tokio::time::timeout(deadline.min(Duration::from_secs(6)), attempt) => result,
            };
            if let Ok(Ok(connection)) = result {
                return Ok(self.supervise_data(connection, Some(endpoint), Some(owner)));
            }
        }
        let result = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = tokio::time::timeout(deadline, self.authenticated_dial(&self.endpoint, remote)) => result,
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
        let connecting = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = tokio::time::timeout(deadline, self.endpoint.accept()) =>
                result.map_err(|_| TransportError::Timeout)?
                    .ok_or(TransportError::QuicConnection)?,
        };
        let connection = tokio::select! {
            _ = self.control.closed() => return Err(TransportError::ControlDisconnected),
            result = tokio::time::timeout(deadline, connecting) =>
                result.map_err(|_| TransportError::Timeout)?
                    .map_err(|_| TransportError::QuicConnection)?,
        };
        self.verify_remote(&connection)?;
        authenticate_responder(connection.clone(), &self.credentials,
            ChannelRole::Data, &self.replay_guard, deadline).await
            .map_err(|_| TransportError::Authentication)?;
        Ok(self.supervise_data(connection, None, None))
    }

    async fn authenticated_dial(
        &self, endpoint: &Endpoint, remote: SocketAddr,
    ) -> Result<Connection, TransportError> {
        let connection = endpoint.connect(remote, "localhost")
            .map_err(|_| TransportError::QuicConnection)?
            .await.map_err(|_| TransportError::QuicConnection)?;
        self.verify_remote(&connection)?;
        authenticate_initiator(connection.clone(), &self.credentials,
            ChannelRole::Data, Duration::from_secs(6)).await
            .map_err(|_| TransportError::Authentication)?;
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
