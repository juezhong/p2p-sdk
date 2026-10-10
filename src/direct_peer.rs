//! High-level SDK-only manual direct connection workflow.
//! No UI, file protocol, relay, TURN, or user data enters this module.
//! It owns NIC/STUN/portmapping candidate creation, offline INVITE/REPLY,
//! ICE nomination, mutual TLS, authenticated Control/Data, and Data repair.
//! User confirmation of the pairing remains a mandatory explicit gate.

use std::{net::SocketAddr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{task::JoinSet, time::{timeout, Instant}};

use crate::{
    ice_signaling::{IceDescription, IceRole, IceCandidateType},
    local_network::local_addresses,
    multi_interface::MAX_ACTIVE_INTERFACES,
    live_session::LiveSdkSession,
    managed_candidates::ManagedCandidates,
    punch::{AuthenticatedPunch, unix_seconds},
    manual_ice_v2::{self, ManualIceInvite},
    manual_pairing::ManualPairing,
    peer_pin::{ManualConfirmation, PeerCertificatePin},
    quinn_socket::{demux_endpoint_config, QuinnUdpAdapter},
    resilient_data::{ResilientDataLanes, MAX_DATA_LANES},
    session_binding::{ReplayGuard, authenticate_initiator, authenticate_responder},
    channel::ChannelRole,
    transport_session::ConnectedTransportPeer,
    punch_loop::PunchLoop,
    tls_identity::{authenticated_client_config, authenticated_server_config},
    verified_session::{establish_initiator, establish_responder},
};

const GATHER: Duration = Duration::from_secs(3);
const MAPPING: Duration = Duration::from_millis(1200);
const ICE_CHECK: Duration = Duration::from_secs(30);
const QUIC_ACCEPT: Duration = Duration::from_secs(45);
const AUTH_DEADLINE: Duration = Duration::from_secs(10);
const PUNCH_CADENCE: Duration = Duration::from_secs(2);
const PASSIVE_POLL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPeerError {
    Identity,
    Clock,
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

fn current_unix_seconds() -> Result<u64, DirectPeerError> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs()).map_err(|_| DirectPeerError::Clock)
}

/// Alternate IPv6 and IPv4 candidates before truncating. OS interface
/// enumeration often returns many VPN/virtual IPv4 addresses first; an
/// arbitrary first-N truncation can silently omit a routable IPv6 path.
fn pick_local_interfaces(ips: Vec<std::net::IpAddr>) -> Vec<SocketAddr> {
    let mut v6 = ips.iter().copied()
        .filter(|ip| ip.is_ipv6()).collect::<Vec<_>>();
    let mut v4 = ips.into_iter()
        .filter(|ip| ip.is_ipv4()).collect::<Vec<_>>();
    v6.sort_by_key(|ip| match ip {
        std::net::IpAddr::V6(addr) if !addr.is_unique_local() => 0,
        _ => 1,
    });
    v4.sort_by_key(|ip| match ip {
        std::net::IpAddr::V4(addr) if !addr.is_private() => 0,
        _ => 1,
    });
    let mut v6 = v6.into_iter();
    let mut v4 = v4.into_iter();
    let mut selected = Vec::new();
    while selected.len() < MAX_ACTIVE_INTERFACES {
        let mut progress = false;
        for family in [&mut v6, &mut v4] {
            if selected.len() >= MAX_ACTIVE_INTERFACES { break; }
            if let Some(ip) = family.next() {
                selected.push(SocketAddr::new(ip, 0));
                progress = true;
            }
        }
        if !progress { break; }
    }
    selected
}

fn discovered_interfaces() -> Result<Vec<SocketAddr>, DirectPeerError> {
    let interfaces = local_addresses()
        .map_err(|_| DirectPeerError::CandidateGather)?;
    let addresses = pick_local_interfaces(interfaces);
    if addresses.is_empty() { return Err(DirectPeerError::CandidateGather); }
    Ok(addresses)
}

async fn resolve_stun(host: &str) -> Vec<SocketAddr> {
    let result = tokio::time::timeout(
        Duration::from_millis(1200), tokio::net::lookup_host(host),
    ).await;
    match result {
        Ok(Ok(addrs)) => addrs.collect(),
        _ => Vec::new(),
    }
}

/// STUN is discovery-only. It may reveal the machine's public UDP endpoint
/// to the STUN operator; it does not carry messages, keys or file contents.
/// Offline LAN still works when all STUN/DNS probes fail or are disabled.
pub async fn discover_default_stun() -> Vec<SocketAddr> {
    if std::env::var_os("P2P_SDK_STUN").as_deref()
        == Some(std::ffi::OsStr::new("off"))
    {
        return Vec::new();
    }
    let (first, second) = tokio::join!(
        resolve_stun("stun.l.google.com:19302"),
        resolve_stun("stun1.l.google.com:19302"),
    );
    let mut unique = Vec::new();
    for addr in first.into_iter().chain(second) {
        if !unique.contains(&addr) { unique.push(addr); }
    }
    unique
}

/// Fully automatic local address, UDP port and optional STUN discovery.
/// No user-supplied IP, port or CLI send/receive role required.
pub async fn begin_creator_auto()
    -> Result<(PendingCreator, String), DirectPeerError>
{
    let interfaces = discovered_interfaces()?;
    let stun = discover_default_stun().await;
    begin_creator(&interfaces, &stun, current_unix_seconds()?, 1200).await
}

pub async fn begin_joiner_auto(invite: &str)
    -> Result<(ReadyJoiner, String), DirectPeerError>
{
    let interfaces = discovered_interfaces()?;
    let stun = discover_default_stun().await;
    begin_joiner(invite, &interfaces, &stun, current_unix_seconds()?).await
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
    pub fn receive_reply_now(self, code: &str)
        -> Result<ReadyCreator, DirectPeerError>
    {
        self.receive_reply(code, current_unix_seconds()?)
    }

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

/// Go runs authenticated Punch concurrently with the creator's connectivity
/// attempts. An isolated pre-ICE probe can end before the joiner sees it.
struct ConnectPunchSender {
    workers: Vec<tokio::task::JoinHandle<()>>,
}

impl ConnectPunchSender {
    fn start(
        gathered: &ManagedCandidates,
        pairing: &ManualPairing,
        remote: &IceDescription,
    ) -> Self {
        let mut workers = Vec::new();
        for interface in &gathered.candidates.interfaces {
            let handle = interface.owner.handle.clone();
            let proof = AuthenticatedPunch::new(
                pairing.credentials.clone(), interface.local.role,
            );
            let remote = remote.clone();
            workers.push(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(PASSIVE_POLL);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    let _ = proof.send_to_candidates(&handle, &remote).await;
                }
            }));
        }
        Self { workers }
    }
}

impl Drop for ConnectPunchSender {
    fn drop(&mut self) {
        for worker in &self.workers { worker.abort(); }
    }
}

/// Go v0.16.4 semantics: REPLY generation is not evidence that the creator
/// has received it. Do not start the finite ICE timeout until an authenticated
/// packet from the creator has been observed on a real local socket.
async fn wait_for_authenticated_creator(
    gathered: &mut ManagedCandidates,
    pairing: &ManualPairing,
    remote: &IceDescription,
) -> Result<(), DirectPeerError> {
    let proofs = gathered.candidates.interfaces.iter().map(|interface| {
        AuthenticatedPunch::new(pairing.credentials.clone(), interface.local.role)
    }).collect::<Vec<_>>();
    loop {
        for (interface, proof) in gathered.candidates.interfaces.iter_mut().zip(&proofs) {
            let handle = interface.owner.handle.clone();
            let Some(packet) = (match interface.owner.punch_packets.try_recv() {
                Ok(packet) => Some(packet),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) =>
                    return Err(DirectPeerError::IceCheck),
            }) else { continue };
            let now = unix_seconds().map_err(|_| DirectPeerError::Clock)?;
            if packet.source.is_ipv4() != handle.local_address().is_ipv4()
                || proof.authenticate(&packet.bytes, packet.source, now).is_err()
            {
                continue;
            }
            // Respond to the verified observed endpoint, not merely the
            // signaled address (which may be stale behind symmetric NAT).
            let reply = proof.make_packet(now).map_err(|_| DirectPeerError::IceCheck)?;
            handle.send_punch(packet.source, &reply).await
                .map_err(|_| DirectPeerError::IceCheck)?;
            return Ok(());
        }
        // Passive NAT keepalive does not turn unverified probes into ICE paths.
        for (interface, proof) in gathered.candidates.interfaces.iter().zip(&proofs) {
            let _ = proof.send_to_candidates(&interface.owner.handle, remote).await;
        }
        tokio::time::sleep(PASSIVE_POLL).await;
    }
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
    pub async fn connect_now(self, confirmed: &ManualConfirmation)
        -> Result<ConnectedDirectPeer, DirectPeerError>
    {
        self.connect(confirmed, current_unix_seconds()?).await
    }

    pub fn comparison_code(&self) -> String {
        self.inner.pairing.comparison_code_text()
    }
    pub fn confirmation(&self) -> Result<ManualConfirmation, DirectPeerError> {
        confirmation(&self.inner.pairing)
    }

    /// Only one authenticated Data connection is created by default.
    /// The application explicitly selects additional concurrent connections.
    pub async fn connect(
        self, confirmed: &ManualConfirmation, now: u64,
    ) -> Result<ConnectedDirectPeer, DirectPeerError> {
        self.connect_with_data_connections(confirmed, now, 1).await
    }

    /// Choose transport connection concurrency; this is NOT a file lane
    /// scheduler. The application owns message framing and stream allocation.
    pub async fn connect_with_data_connections(
        self, confirmed: &ManualConfirmation, now: u64,
        desired_data_connections: usize,
    ) -> Result<ConnectedDirectPeer, DirectPeerError> {
        if !(1..=MAX_DATA_LANES).contains(&desired_data_connections) {
            return Err(DirectPeerError::DataLanePool);
        }
        let ReadyBase {
            identity, gathered, pairing, remote, remote_certificate,
        } = self.inner;
        confirmed.ensure_pairing_confirmed(
            pairing.credentials.session_id(), pairing.comparison_code,
        ).map_err(|_| DirectPeerError::Confirmation)?;
        let local_description = gathered.candidates.combined.clone();
        #[cfg(test)]
        eprintln!("DIRECT_TEST: creator starts ICE and authenticated Punch");
        let sending = ConnectPunchSender::start(&gathered, &pairing, &remote);
        let mut selected = gathered.nominate_first_with_authenticated_punch(
            &remote, pairing.credentials.clone(), ICE_CHECK).await
            .map_err(|_| DirectPeerError::IceCheck)?;
        drop(sending);
        let nominated = selected.nominated();
        #[cfg(test)]
        eprintln!("DIRECT_TEST: creator ICE done, configuring client");
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
        #[cfg(test)]
        eprintln!("DIRECT_TEST: creator dialing Control");
        let control = endpoint.connect(nominated.remote, "localhost")
            .map_err(|_| DirectPeerError::QuicHandshake)?.await
            .map_err(|_| DirectPeerError::QuicHandshake)?;
        let data = endpoint.connect(nominated.remote, "localhost")
            .map_err(|_| DirectPeerError::QuicHandshake)?.await
            .map_err(|_| DirectPeerError::QuicHandshake)?;
        #[cfg(test)]
        eprintln!("DIRECT_TEST: creator QUIC done, HMAC");
        let secure = establish_initiator(
            control, data, &pairing, confirmed, now, AUTH_DEADLINE,
        ).await.map_err(|_| DirectPeerError::VerifiedSession)?;
        let data_lanes = ResilientDataLanes::start_creator_with_independent_udp(
            &secure, endpoint.clone(), nominated.remote, &pairing,
            client_config, desired_data_connections,
        ).map_err(|_| DirectPeerError::DataLanePool)?;
        #[cfg(test)]
        eprintln!("DIRECT_TEST: establishing live session");
        let session = LiveSdkSession::attach(
            secure, selected, &pairing, local_description, remote,
            IceRole::Controlling, PUNCH_CADENCE,
        ).map_err(|_| DirectPeerError::LiveSession)?;
        Ok(ConnectedDirectPeer { endpoint, data_lanes, session })
    }
}

impl ReadyJoiner {
    pub async fn connect_now(self, confirmed: &ManualConfirmation)
        -> Result<ConnectedDirectPeer, DirectPeerError>
    {
        self.connect(confirmed, current_unix_seconds()?).await
    }

    pub fn comparison_code(&self) -> String {
        self.inner.pairing.comparison_code_text()
    }
    pub fn confirmation(&self) -> Result<ManualConfirmation, DirectPeerError> {
        confirmation(&self.inner.pairing)
    }

    /// Only one authenticated Data connection is created by default.
    /// The application explicitly selects additional concurrent connections.
    pub async fn connect(
        self, confirmed: &ManualConfirmation, now: u64,
    ) -> Result<ConnectedDirectPeer, DirectPeerError> {
        self.connect_with_data_connections(confirmed, now, 1).await
    }

    /// Choose transport connection concurrency; this is NOT a file lane
    /// scheduler. The application owns message framing and stream allocation.
    pub async fn connect_with_data_connections(
        self, confirmed: &ManualConfirmation, now: u64,
        desired_data_connections: usize,
    ) -> Result<ConnectedDirectPeer, DirectPeerError> {
        if !(1..=MAX_DATA_LANES).contains(&desired_data_connections) {
            return Err(DirectPeerError::DataLanePool);
        }
        let ReadyBase {
            identity, gathered, pairing, remote, remote_certificate,
        } = self.inner;
        confirmed.ensure_pairing_confirmed(
            pairing.credentials.session_id(), pairing.comparison_code,
        ).map_err(|_| DirectPeerError::Confirmation)?;
        let local_description = gathered.candidates.combined.clone();
        let mut gathered = gathered;
        wait_for_authenticated_creator(&mut gathered, &pairing, &remote).await?;
        #[cfg(test)]
        eprintln!("DIRECT_TEST: joiner starts ICE after verified creator activity");
        let mut selected = gathered.nominate_first_with_authenticated_punch(
            &remote, pairing.credentials.clone(), ICE_CHECK).await
            .map_err(|_| DirectPeerError::IceCheck)?;
        #[cfg(test)]
        eprintln!("DIRECT_TEST: joiner ICE done, configuring server");
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
        #[cfg(test)]
        eprintln!("DIRECT_TEST: joiner waiting Control");
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
        #[cfg(test)]
        eprintln!("DIRECT_TEST: joiner QUIC done, HMAC");
        let secure = establish_responder(
            control, data, &pairing, confirmed, &guard,
            now, AUTH_DEADLINE,
        ).await.map_err(|_| DirectPeerError::VerifiedSession)?;
        let data_lanes = ResilientDataLanes::start_joiner(
            &secure, endpoint.clone(), &pairing, guard, desired_data_connections,
        ).map_err(|_| DirectPeerError::DataLanePool)?;
        #[cfg(test)]
        eprintln!("DIRECT_TEST: establishing live session");
        let session = LiveSdkSession::attach(
            secure, selected, &pairing, local_description, remote,
            IceRole::Controlled, PUNCH_CADENCE,
        ).map_err(|_| DirectPeerError::LiveSession)?;
        Ok(ConnectedDirectPeer { endpoint, data_lanes, session })
    }
}

/// 与 Go connectQUIC/waitForPeerThenConnect 一致，两端同时 Listen/Dial。
/// Joiner 优先 outbound，Creator 优先 inbound；只有同一个成功认证的
/// QUIC 方向才能在双方成为 Control，短暂保留反向连接以防 NAT 单向阻断。
async fn race_authenticated_control(
    endpoint: &quinn::Endpoint,
    remote: SocketAddr,
    pairing: &ManualPairing,
    role: IceRole,
    replay_guard: Arc<ReplayGuard>,
) -> Result<(quinn::Connection, bool), DirectPeerError> {
    let mut workers = JoinSet::new();
    let outgoing = endpoint.clone();
    let credentials = pairing.credentials.clone();
    let pin = pairing.remote_tls_cert_sha256;
    workers.spawn(async move {
        let expires = Instant::now() + QUIC_ACCEPT;
        while Instant::now() < expires {
            if let Ok(connecting) = outgoing.connect(remote, "localhost") {
                if let Ok(Ok(connection)) = timeout(Duration::from_secs(3), connecting).await {
                    let verified = PeerCertificatePin::new(pin)
                        .ok().is_some_and(|p| p.verify_connection(&connection).is_ok());
                    if verified && authenticate_initiator(
                        connection.clone(), &credentials,
                        ChannelRole::Control, AUTH_DEADLINE,
                    ).await.is_ok() {
                        return Ok((connection, true));
                    }
                    connection.close(1u32.into(), b"Control identity or proof rejected");
                }
            }
            tokio::time::sleep(Duration::from_millis(180)).await;
        }
        Err(DirectPeerError::QuicHandshake)
    });
    let incoming = endpoint.clone();
    let credentials = pairing.credentials.clone();
    workers.spawn(async move {
        let expires = Instant::now() + QUIC_ACCEPT;
        while Instant::now() < expires {
            let remaining = expires.saturating_duration_since(Instant::now());
            let Some(connecting) = timeout(remaining, incoming.accept())
                .await.map_err(|_| DirectPeerError::QuicHandshake)?
            else { return Err(DirectPeerError::QuicHandshake) };
            let Ok(Ok(connection)) = timeout(AUTH_DEADLINE, connecting).await else {
                continue;
            };
            let verified = PeerCertificatePin::new(pin)
                .ok().is_some_and(|p| p.verify_connection(&connection).is_ok());
            if verified && authenticate_responder(
                connection.clone(), &credentials,
                ChannelRole::Control, &replay_guard, AUTH_DEADLINE,
            ).await.is_ok() {
                return Ok((connection, false));
            }
            connection.close(1u32.into(), b"Control identity or proof rejected");
        }
        Err(DirectPeerError::QuicHandshake)
    });

    let prefer_outbound = role == IceRole::Controlled;
    let result = timeout(QUIC_ACCEPT, async {
        let mut fallback: Option<(quinn::Connection, bool)> = None;
        loop {
            tokio::select! {
                result = workers.join_next() => {
                    match result {
                        Some(Ok(Ok((connection, outbound)))) => {
                            if outbound == prefer_outbound {
                                if let Some((loser, _)) = fallback.take() {
                                    loser.close(0u32.into(), b"preferred direction won");
                                }
                                return Ok((connection, outbound));
                            }
                            if fallback.is_none() {
                                fallback = Some((connection, outbound));
                            } else {
                                connection.close(0u32.into(), b"connection race loser");
                            }
                        }
                        Some(_) => {},
                        None => return fallback.ok_or(DirectPeerError::QuicHandshake),
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(300)), if fallback.is_some() => {
                    return fallback.ok_or(DirectPeerError::QuicHandshake);
                }
            }
        }
    }).await;
    workers.abort_all();
    result.unwrap_or(Err(DirectPeerError::QuicHandshake))
}

/// A generic SDK consumer can establish exactly one Control QUIC without
/// allocating any Data transport. Unlike the convenience dual-QUIC facade,
/// this interface has no Transfer-shaped lane count or stream scheduler.
impl ReadyCreator {
    pub async fn connect_transport_now(
        self, confirmed: &ManualConfirmation,
    ) -> Result<ConnectedTransportPeer, DirectPeerError> {
        self.connect_transport(confirmed, current_unix_seconds()?).await
    }

    pub async fn connect_transport(
        self, confirmed: &ManualConfirmation, now: u64,
    ) -> Result<ConnectedTransportPeer, DirectPeerError> {
        let ReadyBase {
            identity, gathered, pairing, remote, remote_certificate,
        } = self.inner;
        confirmed.ensure_pairing_confirmed(
            pairing.credentials.session_id(), pairing.comparison_code,
        ).map_err(|_| DirectPeerError::Confirmation)?;
        if now >= pairing.expires_at { return Err(DirectPeerError::ManualSignal); }
        let offered_host_candidates = gathered.candidates.combined.candidates.iter()
            .filter(|c| c.kind == IceCandidateType::Host)
            .map(|c| c.address).collect::<Vec<_>>();

        let sender = ConnectPunchSender::start(&gathered, &pairing, &remote);
        let mut path = gathered.nominate_first_with_authenticated_punch(
            &remote, pairing.credentials.clone(), ICE_CHECK,
        ).await.map_err(|_| DirectPeerError::IceCheck)?;
        drop(sender);
        let nominated = path.nominated();
        let remote_candidate_kind = remote.candidates.iter()
            .find(|c| c.address == nominated.remote).map(|c| c.kind);
        let trusted = trusted_certificate(remote_certificate)?;
        let cert = vec![identity.cert.der().clone()];
        let tls = authenticated_client_config(
            cert.clone(), rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into()
            ), trusted.clone(),
        ).map_err(|_| DirectPeerError::TlsConfig)?;
        let server_tls = authenticated_server_config(
            cert, rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into()
            ), trusted,
        ).map_err(|_| DirectPeerError::TlsConfig)?;
        let adapter = QuinnUdpAdapter::from_owner(&mut path.selected.owner)
            .map_err(|_| DirectPeerError::UdpAdapter)?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            demux_endpoint_config(), Some(server_tls), Arc::new(adapter),
            quinn::default_runtime().ok_or(DirectPeerError::QuicEndpoint)?,
        ).map_err(|_| DirectPeerError::QuicEndpoint)?;
        endpoint.set_default_client_config(tls.clone());
        let replay_guard = Arc::new(ReplayGuard::new(4096)
            .map_err(|_| DirectPeerError::VerifiedSession)?);
        let (control, control_outbound) = race_authenticated_control(
            &endpoint, nominated.remote, &pairing, IceRole::Controlling,
            Arc::clone(&replay_guard),
        ).await?;
        if control.remote_address() != nominated.remote {
            return Err(DirectPeerError::LiveSession);
        }
        let punch = PunchLoop::start_for_control(
            &mut path.selected.owner,
            AuthenticatedPunch::new(pairing.credentials.clone(), IceRole::Controlling),
            remote, PUNCH_CADENCE, control.clone(),
        ).map_err(|_| DirectPeerError::LiveSession)?;
        Ok(ConnectedTransportPeer {
            endpoint, control, path, punch: Some(punch),
            credentials: pairing.credentials,
            remote_pin: pairing.remote_tls_cert_sha256,
            role: IceRole::Controlling, client_tls: Some(tls),
            control_outbound,
            remote_candidate_kind, offered_host_candidates,
            replay_guard,
        })
    }
}

impl ReadyJoiner {
    pub async fn connect_transport_now(
        self, confirmed: &ManualConfirmation,
    ) -> Result<ConnectedTransportPeer, DirectPeerError> {
        self.connect_transport(confirmed, current_unix_seconds()?).await
    }

    pub async fn connect_transport(
        self, confirmed: &ManualConfirmation, now: u64,
    ) -> Result<ConnectedTransportPeer, DirectPeerError> {
        let ReadyBase {
            identity, mut gathered, pairing, remote, remote_certificate,
        } = self.inner;
        confirmed.ensure_pairing_confirmed(
            pairing.credentials.session_id(), pairing.comparison_code,
        ).map_err(|_| DirectPeerError::Confirmation)?;
        if now >= pairing.expires_at { return Err(DirectPeerError::ManualSignal); }
        let offered_host_candidates = gathered.candidates.combined.candidates.iter()
            .filter(|c| c.kind == IceCandidateType::Host)
            .map(|c| c.address).collect::<Vec<_>>();
        wait_for_authenticated_creator(&mut gathered, &pairing, &remote).await?;
        let mut path = gathered.nominate_first_with_authenticated_punch(
            &remote, pairing.credentials.clone(), ICE_CHECK,
        ).await.map_err(|_| DirectPeerError::IceCheck)?;
        let nominated = path.nominated();
        let remote_candidate_kind = remote.candidates.iter()
            .find(|c| c.address == nominated.remote).map(|c| c.kind);
        let trusted = trusted_certificate(remote_certificate)?;
        let cert = vec![identity.cert.der().clone()];
        let tls = authenticated_server_config(
            cert.clone(), rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into()
            ), trusted.clone(),
        ).map_err(|_| DirectPeerError::TlsConfig)?;
        let client_tls = authenticated_client_config(
            cert, rustls::pki_types::PrivateKeyDer::Pkcs8(
                identity.signing_key.serialize_der().into()
            ), trusted,
        ).map_err(|_| DirectPeerError::TlsConfig)?;
        let adapter = QuinnUdpAdapter::from_owner(&mut path.selected.owner)
            .map_err(|_| DirectPeerError::UdpAdapter)?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            demux_endpoint_config(), Some(tls), Arc::new(adapter),
            quinn::default_runtime().ok_or(DirectPeerError::QuicEndpoint)?,
        ).map_err(|_| DirectPeerError::QuicEndpoint)?;
        endpoint.set_default_client_config(client_tls.clone());
        let replay_guard = Arc::new(ReplayGuard::new(4096)
            .map_err(|_| DirectPeerError::VerifiedSession)?);
        let (control, control_outbound) = race_authenticated_control(
            &endpoint, nominated.remote, &pairing, IceRole::Controlled,
            Arc::clone(&replay_guard),
        ).await?;
        if control.remote_address() != nominated.remote {
            return Err(DirectPeerError::LiveSession);
        }
        let punch = PunchLoop::start_for_control(
            &mut path.selected.owner,
            AuthenticatedPunch::new(pairing.credentials.clone(), IceRole::Controlled),
            remote, PUNCH_CADENCE, control.clone(),
        ).map_err(|_| DirectPeerError::LiveSession)?;
        Ok(ConnectedTransportPeer {
            endpoint, control, path, punch: Some(punch),
            credentials: pairing.credentials,
            remote_pin: pairing.remote_tls_cert_sha256,
            role: IceRole::Controlled, client_tls: Some(client_tls), replay_guard,
            control_outbound, remote_candidate_kind, offered_host_candidates,
        })
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
    async fn joiner_waits_for_verified_creator_activity_without_ice_timeout() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let now = 1_800_000_000;
        let (pending, invite) = begin_creator(&[bind], &[], now, 1200).await.unwrap();
        let (joiner, reply) = begin_joiner(&invite, &[bind], &[], now).await.unwrap();
        let creator = pending.receive_reply(&reply, now).unwrap();
        let mut cc = creator.confirmation().unwrap();
        let mut jc = joiner.confirmation().unwrap();
        cc.confirm(&creator.comparison_code()).unwrap();
        jc.confirm(&joiner.comparison_code()).unwrap();
        let waiting = tokio::spawn(async move { joiner.connect(&jc, now).await });
        // An authenticated REPLY alone must never start the joiner's ICE
        // deadline. A missing creator remains a pending, not failed, session.
        tokio::time::sleep(Duration::from_millis(1400)).await;
        assert!(!waiting.is_finished(), "joiner started ICE before creator activity");
        let connected = creator.connect(&cc, now);
        let (creator_result, joiner_result) = tokio::time::timeout(
            Duration::from_secs(60),
            async { tokio::join!(connected, waiting) },
        ).await.unwrap();
        let left = creator_result.unwrap();
        let right = joiner_result.unwrap().unwrap();
        left.shutdown().await;
        right.shutdown().await;
    }

    #[test]
    fn interface_cap_must_not_starve_global_ipv6_behind_vpn_addresses() {
        let mut ips = (1..=40u8).map(|n| {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n))
        }).collect::<Vec<_>>();
        let globally_routed_v6: std::net::IpAddr = "2001:db8::42".parse().unwrap();
        let local_v6: std::net::IpAddr = "fd00::7".parse().unwrap();
        ips.push(local_v6);
        ips.push(globally_routed_v6);
        let selected = pick_local_interfaces(ips);
        assert_eq!(selected.len(), MAX_ACTIVE_INTERFACES);
        assert!(selected.iter().any(|entry| entry.ip() == globally_routed_v6));
        assert!(selected.iter().any(|entry| entry.ip() == local_v6));
        assert!(selected.iter().any(SocketAddr::is_ipv4));
        assert_eq!(selected[0].ip(), globally_routed_v6);
    }

    #[tokio::test]
    async fn generic_managed_data_recovers_without_transfer_lane_scheduler() {
        use crate::transport_session::{
            ManagedAuthenticatedLink, ManagedLinkPhase,
        };

        async fn await_link(
            manager: &ManagedAuthenticatedLink, minimum_generation: u64,
        ) -> quinn::Connection {
            let mut events = manager.subscribe();
            loop {
                let snapshot = events.borrow().clone();
                if snapshot.phase == ManagedLinkPhase::Connected
                    && snapshot.generation >= minimum_generation
                {
                    return snapshot.connection.unwrap();
                }
                assert_ne!(snapshot.phase, ManagedLinkPhase::AuthenticationFailed);
                assert_ne!(snapshot.phase, ManagedLinkPhase::ControlLost);
                events.changed().await.unwrap();
            }
        }

        tokio::time::timeout(Duration::from_secs(65), async {
            let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let now = 1_800_000_000;
            let (pending, invite) = begin_creator(&[bind], &[], now, 1200).await.unwrap();
            let (joiner, reply) = begin_joiner(&invite, &[bind], &[], now).await.unwrap();
            let creator = pending.receive_reply(&reply, now).unwrap();
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (creator, joiner) = tokio::join!(
                creator.connect_transport(&cc, now),
                joiner.connect_transport(&jc, now),
            );
            let creator = Arc::new(creator.unwrap());
            let joiner = Arc::new(joiner.unwrap());

            // 两边都由应用选择创建一条托管 Data QUIC，不预建四条。
            let outgoing = creator.manage_authenticated_data();
            let incoming = joiner.manage_authenticated_data();
            let (first, received) = tokio::join!(
                await_link(&outgoing, 1), await_link(&incoming, 1),
            );
            let old_id = first.stable_id();
            assert_eq!(outgoing.current().unwrap().stable_id(), old_id);

            first.close(1u32.into(), b"inject data quic fault");
            let (replaced, _accepted) = tokio::join!(
                await_link(&outgoing, 2), await_link(&incoming, 2),
            );
            assert_ne!(replaced.stable_id(), old_id);
            assert!(creator.diagnostic().control_connected);
            assert!(joiner.diagnostic().control_connected);
            assert!(received.close_reason().is_some());

            // 真正的 Control 断线会终止重拨，不能伪报会话仍健康。
            creator.control.close(0u32.into(), b"test control close");
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut updates = outgoing.subscribe();
                loop {
                    if updates.borrow().phase == ManagedLinkPhase::ControlLost {
                        break;
                    }
                    updates.changed().await.unwrap();
                }
            }).await.unwrap();
            assert!(outgoing.current().is_none());
            outgoing.shutdown().await;
            incoming.shutdown().await;
            Arc::try_unwrap(creator).ok().unwrap().shutdown().await;
            Arc::try_unwrap(joiner).ok().unwrap().shutdown().await;
        }).await.unwrap();
    }

    #[tokio::test]
    async fn generic_sdk_control_only_and_on_demand_authenticated_quic() {
        tokio::time::timeout(Duration::from_secs(45), async {
            let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let now = 1_800_000_000;
            let (pending, invite) = begin_creator(&[bind], &[], now, 1200).await.unwrap();
            let (joiner, reply) = begin_joiner(&invite, &[bind], &[], now).await.unwrap();
            let creator = pending.receive_reply(&reply, now).unwrap();
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (creator, joiner) = tokio::join!(
                creator.connect_transport(&cc, now),
                joiner.connect_transport(&jc, now),
            );
            let creator = creator.unwrap();
            let joiner = joiner.unwrap();
            assert!(creator.diagnostic().control_connected);
            assert!(joiner.diagnostic().control_connected);
            // Go v0.16.4：创建方偏向入站，加入方偏向出站。
            assert!(!creator.diagnostic().control_outbound);
            assert!(joiner.diagnostic().control_outbound);
            // API 不接受零预算，且不能在未认证前返回附属 QUIC。
            assert!(matches!(
                creator.open_authenticated_data(Duration::ZERO).await,
                Err(crate::transport_session::TransportError::Timeout)
            ));
            assert!(matches!(
                joiner.accept_authenticated_data(Duration::ZERO).await,
                Err(crate::transport_session::TransportError::Timeout)
            ));
            let (mut tx, _) = creator.control.open_bi().await.unwrap();
            tx.write_all(b"generic control").await.unwrap();
            tx.finish().unwrap();
            let (_, mut rx) = joiner.control.accept_bi().await.unwrap();
            assert_eq!(rx.read_to_end(64).await.unwrap(), b"generic control");

            // No Data QUIC was created until this explicit application call.
            let (outgoing, incoming) = tokio::join!(
                creator.open_authenticated_data(Duration::from_secs(12)),
                joiner.accept_authenticated_data(Duration::from_secs(12)),
            );
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            let mut out = outgoing.connection.open_uni().await.unwrap();
            out.write_all(b"generic data").await.unwrap();
            out.finish().unwrap();
            let mut input = incoming.connection.accept_uni().await.unwrap();
            assert_eq!(input.read_to_end(64).await.unwrap(), b"generic data");
            creator.control.close(0u32.into(), b"test control disconnected");
            tokio::time::timeout(Duration::from_secs(5), outgoing.connection.closed())
                .await.unwrap();
            assert!(!creator.diagnostic().control_connected);
            outgoing.shutdown();
            incoming.shutdown();
            creator.shutdown().await;
            joiner.shutdown().await;
        }).await.unwrap();
    }

    #[tokio::test]
    async fn application_can_request_four_links_and_recover_one_failed_data_quic() {
        tokio::time::timeout(Duration::from_secs(50), async {
            let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let now = 1_800_000_000;
            let (pending, invite) = begin_creator(&[bind], &[], now, 1200).await.unwrap();
            let (joiner, reply) = begin_joiner(&invite, &[bind], &[], now).await.unwrap();
            let creator = pending.receive_reply(&reply, now).unwrap();
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (left, right) = tokio::join!(
                creator.connect_with_data_connections(&cc, now, 4),
                joiner.connect_with_data_connections(&jc, now, 4),
            );
            let left = left.unwrap();
            let right = right.unwrap();
            let initial = left.data_lanes.wait_for_count(4, Duration::from_secs(15))
                .await.unwrap();
            right.data_lanes.wait_for_count(4, Duration::from_secs(15))
                .await.unwrap();
            let failed = initial[1].clone();
            let old_id = failed.stable_id();
            failed.close(1u32.into(), b"test induced data failure");
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    let active = left.data_lanes.available().await;
                    if active.len() == 4 && active.iter().all(|c| c.stable_id() != old_id) {
                        break;
                    }
                    assert!(left.session.verified().control().close_reason().is_none());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }).await.unwrap();
            left.shutdown().await;
            right.shutdown().await;
        }).await.unwrap();
    }

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
            eprintln!("DIRECT_TEST: paired codes confirmed, start connect");
            let (a, b) = tokio::join!(
                creator.connect(&cc, now),
                joiner.connect(&jc, now),
            );
            eprintln!("DIRECT_TEST: both connected");
            let a = a.unwrap();
            let b = b.unwrap();
            assert_eq!(a.data_lanes.subscribe().borrow().desired, 1);
            assert_eq!(b.data_lanes.subscribe().borrow().desired, 1);
            let (mut tx, mut rx) =
                a.session.verified().control().open_bi().await.unwrap();
            // QUIC does not notify the peer of a newly opened stream until
            // the initiator actually sends STREAM data. Waiting for accept_bi
            // before the first write causes a deterministic application deadlock.
            tx.write_all(b"control-echo").await.unwrap();
            tx.finish().unwrap();
            let (mut reply_tx, mut reply_rx) =
                b.session.verified().control().accept_bi().await.unwrap();
            assert_eq!(reply_rx.read_to_end(64).await.unwrap(), b"control-echo");
            reply_tx.write_all(b"ok").await.unwrap();
            reply_tx.finish().unwrap();
            assert_eq!(rx.read_to_end(64).await.unwrap(), b"ok");
            assert_eq!(a.session.actual_path().1, b.session.actual_path().0);
            eprintln!("DIRECT_TEST: control echo completed, shutdown creator");
            a.shutdown().await;
            eprintln!("DIRECT_TEST: shutdown joiner");
            b.shutdown().await;
            eprintln!("DIRECT_TEST: finished");
        }).await.unwrap();
    }
}
