//! High-level SDK-only manual direct connection workflow.
//! No UI, file protocol, relay, TURN, or user data enters this module.
//! It owns NIC/STUN/portmapping candidate creation, offline INVITE/REPLY,
//! ICE nomination, mutual TLS, authenticated Control/Data, and Data repair.
//! User confirmation of the pairing remains a mandatory explicit gate.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    ice_signaling::{IceDescription, IceRole},
    live_session::LiveSdkSession,
    managed_candidates::ManagedCandidates,
    manual_ice_v2::{self, ManualIceInvite},
    manual_pairing::ManualPairing,
    peer_pin::ManualConfirmation,
    quinn_socket::{demux_endpoint_config, QuinnUdpAdapter},
    resilient_data::{ResilientDataLanes, MAX_DATA_LANES},
    session_binding::ReplayGuard,
    tls_identity::{authenticated_client_config, authenticated_server_config},
    verified_session::{establish_initiator, establish_responder},
};

const GATHER: Duration = Duration::from_secs(3);
const MAPPING: Duration = Duration::from_millis(1200);
const ICE_CHECK: Duration = Duration::from_secs(30);
const QUIC_ACCEPT: Duration = Duration::from_secs(45);
const AUTH_DEADLINE: Duration = Duration::from_secs(10);
const PUNCH_CADENCE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPeerError {
    Identity,
    CandidateGather,
    ManualSignal,
    Confirmation,
    IceCheck,
    TlsConfig,
    UdpAdapter,
    QuicEndpoint,
    QuicHandshake,
    VerifiedSession,
    DataLanePool,
    LiveSession,
}

pub struct PendingCreator {
    identity: rcgen::CertifiedKey<rcgen::KeyPair>,
    gathered: ManagedCandidates,
    pending: ManualIceInvite,
}

struct ReadyBase {
    identity: rcgen::CertifiedKey<rcgen::KeyPair>,
    gathered: ManagedCandidates,
    pairing: ManualPairing,
    remote: IceDescription,
    remote_certificate: Vec<u8>,
}

pub struct ReadyCreator { inner: ReadyBase }
pub struct ReadyJoiner { inner: ReadyBase }

/// Own the Quinn Endpoint until all authenticated streams have shut down.
pub struct ConnectedDirectPeer {
    pub endpoint: quinn::Endpoint,
    pub data_lanes: ResilientDataLanes,
    pub session: LiveSdkSession,
}

fn identity() -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, DirectPeerError> {
    rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|_| DirectPeerError::Identity)
}

/// Caller sends the returned INVITE text privately, then supplies the
/// received REPLY to PendingCreator::receive_reply. No address or port is
/// required from the end user: callers provide OS-enumerated local addresses.
pub async fn begin_creator(
    local_interfaces: &[SocketAddr], stun: &[SocketAddr],
    now: u64, validity_secs: u64,
) -> Result<(PendingCreator, String), DirectPeerError> {
    let identity = identity()?;
    let gathered = ManagedCandidates::gather(
        local_interfaces, stun, IceRole::Controlling, GATHER, MAPPING,
    ).await.map_err(|_| DirectPeerError::CandidateGather)?;
    let (pending, code) = manual_ice_v2::invite_with_certificate(
        now, validity_secs, identity.cert.der().as_ref(),
        &gathered.candidates.combined,
    ).map_err(|_| DirectPeerError::ManualSignal)?;
    Ok((PendingCreator { identity, gathered, pending }, code))
}

impl PendingCreator {
    pub fn receive_reply(
        self, code: &str, now: u64,
    ) -> Result<ReadyCreator, DirectPeerError> {
        let (pairing, remote, remote_certificate) =
            self.pending.finish_with_certificate(code, now)
                .map_err(|_| DirectPeerError::ManualSignal)?;
        Ok(ReadyCreator { inner: ReadyBase {
            identity: self.identity, gathered: self.gathered, pairing,
            remote, remote_certificate,
        } })
    }
}

/// Independently verifies the received INVITE, gathers local IPv4/IPv6/STUN
/// candidates, and generates the authenticated REPLY text to return.
pub async fn begin_joiner(
    invite: &str, local_interfaces: &[SocketAddr],
    stun: &[SocketAddr], now: u64,
) -> Result<(ReadyJoiner, String), DirectPeerError> {
    manual_ice_v2::inspect_invite_with_certificate(invite, now)
        .map_err(|_| DirectPeerError::ManualSignal)?;
    let identity = identity()?;
    let gathered = ManagedCandidates::gather(
        local_interfaces, stun, IceRole::Controlled, GATHER, MAPPING,
    ).await.map_err(|_| DirectPeerError::CandidateGather)?;
    let (reply, pairing, remote, remote_certificate) =
        manual_ice_v2::respond_with_certificate(
            invite, now, identity.cert.der().as_ref(),
            &gathered.candidates.combined,
        ).map_err(|_| DirectPeerError::ManualSignal)?;
    Ok((ReadyJoiner { inner: ReadyBase {
        identity, gathered, pairing, remote, remote_certificate,
    } }, reply))
}

fn confirmation(pairing: &ManualPairing)
    -> Result<ManualConfirmation, DirectPeerError>
{
    ManualConfirmation::new(
        pairing.credentials.session_id(), pairing.comparison_code,
    ).map_err(|_| DirectPeerError::Confirmation)
}

fn trusted_certificate(bytes: Vec<u8>)
    -> Result<Arc<rustls::RootCertStore>, DirectPeerError>
{
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(bytes))
        .map_err(|_| DirectPeerError::TlsConfig)?;
    Ok(Arc::new(roots))
}

impl ReadyCreator {
    pub fn comparison_code(&self) -> String {
        self.inner.pairing.comparison_code_text()
    }
    pub fn confirmation(&self) -> Result<ManualConfirmation, DirectPeerError> {
        confirmation(&self.inner.pairing)
    }

    pub async fn connect(
        self, confirmed: &ManualConfirmation, now: u64,
    ) -> Result<ConnectedDirectPeer, DirectPeerError> {
        let ReadyBase {
            identity, gathered, pairing, remote, remote_certificate,
        } = self.inner;
        confirmed.ensure_pairing_confirmed(
            pairing.credentials.session_id(), pairing.comparison_code,
        ).map_err(|_| DirectPeerError::Confirmation)?;
        let local_description = gathered.candidates.combined.clone();
        let mut selected = gathered.nominate_first(&remote, ICE_CHECK).await
            .map_err(|_| DirectPeerError::IceCheck)?;
        let nominated = selected.nominated();
        let client_config = authenticated_client_config(
            vec![identity.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into()
            ),
            trusted_certificate(remote_certificate)?,
        ).map_err(|_| DirectPeerError::TlsConfig)?;
        let adapter = QuinnUdpAdapter::from_owner(&mut selected.selected.owner)
            .map_err(|_| DirectPeerError::UdpAdapter)?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            demux_endpoint_config(), None, Arc::new(adapter),
            quinn::default_runtime().ok_or(DirectPeerError::QuicEndpoint)?,
        ).map_err(|_| DirectPeerError::QuicEndpoint)?;
        endpoint.set_default_client_config(client_config.clone());
        let control = endpoint.connect(nominated.remote, "localhost")
            .map_err(|_| DirectPeerError::QuicHandshake)?.await
            .map_err(|_| DirectPeerError::QuicHandshake)?;
        let data = endpoint.connect(nominated.remote, "localhost")
            .map_err(|_| DirectPeerError::QuicHandshake)?.await
            .map_err(|_| DirectPeerError::QuicHandshake)?;
        let secure = establish_initiator(
            control, data, &pairing, confirmed, now, AUTH_DEADLINE,
        ).await.map_err(|_| DirectPeerError::VerifiedSession)?;
        let data_lanes = ResilientDataLanes::start_creator_with_independent_udp(
            &secure, endpoint.clone(), nominated.remote, &pairing,
            client_config, MAX_DATA_LANES,
        ).map_err(|_| DirectPeerError::DataLanePool)?;
        let session = LiveSdkSession::attach(
            secure, selected, &pairing, local_description, remote,
            IceRole::Controlling, PUNCH_CADENCE,
        ).map_err(|_| DirectPeerError::LiveSession)?;
        Ok(ConnectedDirectPeer { endpoint, data_lanes, session })
    }
}

impl ReadyJoiner {
    pub fn comparison_code(&self) -> String {
        self.inner.pairing.comparison_code_text()
    }
    pub fn confirmation(&self) -> Result<ManualConfirmation, DirectPeerError> {
        confirmation(&self.inner.pairing)
    }

    pub async fn connect(
        self, confirmed: &ManualConfirmation, now: u64,
    ) -> Result<ConnectedDirectPeer, DirectPeerError> {
        let ReadyBase {
            identity, gathered, pairing, remote, remote_certificate,
        } = self.inner;
        confirmed.ensure_pairing_confirmed(
            pairing.credentials.session_id(), pairing.comparison_code,
        ).map_err(|_| DirectPeerError::Confirmation)?;
        let local_description = gathered.candidates.combined.clone();
        let mut selected = gathered.nominate_first(&remote, ICE_CHECK).await
            .map_err(|_| DirectPeerError::IceCheck)?;
        let tls = authenticated_server_config(
            vec![identity.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into()
            ),
            trusted_certificate(remote_certificate)?,
        ).map_err(|_| DirectPeerError::TlsConfig)?;
        let adapter = QuinnUdpAdapter::from_owner(&mut selected.selected.owner)
            .map_err(|_| DirectPeerError::UdpAdapter)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            demux_endpoint_config(), Some(tls), Arc::new(adapter),
            quinn::default_runtime().ok_or(DirectPeerError::QuicEndpoint)?,
        ).map_err(|_| DirectPeerError::QuicEndpoint)?;
        let control = tokio::time::timeout(QUIC_ACCEPT, endpoint.accept())
            .await.map_err(|_| DirectPeerError::QuicHandshake)?
            .ok_or(DirectPeerError::QuicHandshake)?
            .await.map_err(|_| DirectPeerError::QuicHandshake)?;
        let data = tokio::time::timeout(QUIC_ACCEPT, endpoint.accept())
            .await.map_err(|_| DirectPeerError::QuicHandshake)?
            .ok_or(DirectPeerError::QuicHandshake)?
            .await.map_err(|_| DirectPeerError::QuicHandshake)?;
        let guard = Arc::new(ReplayGuard::new(4096)
            .map_err(|_| DirectPeerError::VerifiedSession)?);
        let secure = establish_responder(
            control, data, &pairing, confirmed, &guard,
            now, AUTH_DEADLINE,
        ).await.map_err(|_| DirectPeerError::VerifiedSession)?;
        let data_lanes = ResilientDataLanes::start_joiner(
            &secure, endpoint.clone(), &pairing, guard, MAX_DATA_LANES,
        ).map_err(|_| DirectPeerError::DataLanePool)?;
        let session = LiveSdkSession::attach(
            secure, selected, &pairing, local_description, remote,
            IceRole::Controlled, PUNCH_CADENCE,
        ).map_err(|_| DirectPeerError::LiveSession)?;
        Ok(ConnectedDirectPeer { endpoint, data_lanes, session })
    }
}

impl ConnectedDirectPeer {
    pub async fn shutdown(self) {
        self.data_lanes.shutdown().await;
        self.endpoint.close(0u32.into(), b"direct sdk peer stopped");
        self.session.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn complete_creator_joiner_pairing_and_control_roundtrip() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let now = 1_800_000_000;
            let (pending, invite) =
                begin_creator(&[bind], &[], now, 1200).await.unwrap();
            let (joiner, reply) =
                begin_joiner(&invite, &[bind], &[], now).await.unwrap();
            let creator = pending.receive_reply(&reply, now).unwrap();
            assert_eq!(creator.comparison_code(), joiner.comparison_code());
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (a, b) = tokio::join!(
                creator.connect(&cc, now),
                joiner.connect(&jc, now),
            );
            let a = a.unwrap();
            let b = b.unwrap();
            let (mut tx, mut rx) =
                a.session.verified().control().open_bi().await.unwrap();
            let (mut reply_tx, mut reply_rx) =
                b.session.verified().control().accept_bi().await.unwrap();
            tx.write_all(b"control-echo").await.unwrap();
            tx.finish().unwrap();
            assert_eq!(reply_rx.read_to_end(64).await.unwrap(), b"control-echo");
            reply_tx.write_all(b"ok").await.unwrap();
            reply_tx.finish().unwrap();
            assert_eq!(rx.read_to_end(64).await.unwrap(), b"ok");
            assert_eq!(a.session.actual_path().1, b.session.actual_path().0);
            a.shutdown().await;
            b.shutdown().await;
        }).await.unwrap();
    }
}
