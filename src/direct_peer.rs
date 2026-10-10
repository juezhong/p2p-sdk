//! High-level SDK-only manual direct connection workflow.
//! No UI, file protocol, relay, TURN, or user data enters this module.
//! It owns NIC/STUN/portmapping candidate creation, offline INVITE/REPLY,
//! ICE nomination, mutual TLS, authenticated Control/Data, and Data repair.
//! User confirmation of the pairing remains a mandatory explicit gate.

use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::{task::JoinSet, time::{timeout, Instant}};

use crate::{
    ice_signaling::{IceDescription, IceRole, IceCandidateType},
    local_network::local_addresses,
    multi_interface::MAX_ACTIVE_INTERFACES,
    managed_candidates::{ManagedCandidates, ManagedPath},
    punch::{AuthenticatedPunch, unix_seconds},
    manual_ice_v2::{self, ManualIceInvite},
    manual_pairing::ManualPairing,
    peer_pin::{ManualConfirmation, PeerCertificatePin},
    quinn_socket::{demux_endpoint_config, QuinnUdpAdapter},
    session_binding::{ReplayGuard, authenticate_initiator, authenticate_responder},
    channel::ChannelRole,
    transport_session::ConnectedTransportPeer,
    punch_loop::PunchLoop,
    tls_identity::{authenticated_client_config, authenticated_server_config},
};

use crate::manual_pairing::UNLIMITED_INVITE_LIFETIME;

const GATHER: Duration = Duration::from_secs(3);
const MAPPING: Duration = Duration::from_millis(1200);
const ICE_CHECK: Duration = Duration::from_secs(30);
const QUIC_ACCEPT: Duration = Duration::from_secs(45);
const AUTH_DEADLINE: Duration = Duration::from_secs(10);
const PUNCH_CADENCE: Duration = Duration::from_secs(2);
const PASSIVE_POLL: Duration = Duration::from_millis(500);
const PATH_PREFERENCE_GRACE: Duration = Duration::from_millis(180);
const CONTROL_PATH_SELECTED: &[u8] = b"P2P-SDK-CONTROL-PATH-1";

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
    // 提供商冗余：避免仅依赖 Google，且默认值不影响离线 LAN 模式。
    let (cloudflare, google, google_backup) = tokio::join!(
        resolve_stun("stun.cloudflare.com:3478"),
        resolve_stun("stun.l.google.com:19302"),
        resolve_stun("stun1.l.google.com:19302"),
    );
    let mut unique = Vec::new();
    for addr in cloudflare.into_iter().chain(google).chain(google_backup) {
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
    begin_creator(&interfaces, &stun, current_unix_seconds()?, UNLIMITED_INVITE_LIFETIME).await
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
    pub fn comparison_code(&self) -> String {
        self.inner.pairing.comparison_code_text()
    }
    pub fn confirmation(&self) -> Result<ManualConfirmation, DirectPeerError> {
        confirmation(&self.inner.pairing)
    }


}

impl ReadyJoiner {
    pub fn comparison_code(&self) -> String {
        self.inner.pairing.comparison_code_text()
    }
    pub fn confirmation(&self) -> Result<ManualConfirmation, DirectPeerError> {
        confirmation(&self.inner.pairing)
    }


}

/// 与 Go connectQUIC/waitForPeerThenConnect 一致，两端同时 Listen/Dial。
/// Joiner 优先 outbound，Creator 优先 inbound；只有同一个成功认证的
/// QUIC 方向才能在双方成为 Control，短暂保留反向连接以防 NAT 单向阻断。
/// 候选只来自经人工确认的信令，且必须与实际 UDP Owner 地址族一致。
/// 优先已由 ICE 提名的地址；该地址的 QUIC 不通时继续尝试其他候选。
fn quic_candidate_destinations(
    nominated: SocketAddr, advertised: &IceDescription,
) -> Vec<SocketAddr> {
    let mut options = advertised.candidates.clone();
    options.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
    let mut destinations = vec![nominated];
    for candidate in options {
        if candidate.address.is_ipv4() == nominated.is_ipv4()
            && candidate.address.port() != 0
            && !candidate.address.ip().is_unspecified()
            && !candidate.address.ip().is_multicast()
            && !destinations.contains(&candidate.address)
        {
            destinations.push(candidate.address);
        }
    }
    destinations
}

async fn race_authenticated_control(
    endpoint: &quinn::Endpoint,
    remote: SocketAddr,
    advertised: &IceDescription,
    pairing: &ManualPairing,
    role: IceRole,
    replay_guard: Arc<ReplayGuard>,
) -> Result<(quinn::Connection, bool), DirectPeerError> {
    let mut workers = JoinSet::new();
    let outgoing = endpoint.clone();
    let credentials = pairing.credentials.clone();
    let pin = pairing.remote_tls_cert_sha256;
    let dial_addrs = quic_candidate_destinations(remote, advertised);
    workers.spawn(async move {
        let expires = Instant::now() + QUIC_ACCEPT;
        let mut backlog: VecDeque<_> = dial_addrs.iter().copied().collect();
        let mut attempts = JoinSet::new();
        loop {
            while attempts.len() < 4 {
                let Some(address) = backlog.pop_front() else { break };
                let endpoint = outgoing.clone();
                let credentials = credentials.clone();
                attempts.spawn(async move {
                    let connecting = endpoint.connect(address, "localhost")
                        .map_err(|_| DirectPeerError::QuicHandshake)?;
                    let connection = timeout(Duration::from_secs(3), connecting)
                        .await.map_err(|_| DirectPeerError::QuicHandshake)?
                        .map_err(|_| DirectPeerError::QuicHandshake)?;
                    let verified = PeerCertificatePin::new(pin)
                        .ok().is_some_and(|p| p.verify_connection(&connection).is_ok());
                    if verified && authenticate_initiator(
                        connection.clone(), &credentials,
                        ChannelRole::Control, AUTH_DEADLINE,
                    ).await.is_ok() {
                        Ok((connection, true))
                    } else {
                        connection.close(1u32.into(), b"Control identity or proof rejected");
                        Err(DirectPeerError::VerifiedSession)
                    }
                });
            }
            if attempts.is_empty() && backlog.is_empty() {
                if Instant::now() >= expires {
                    return Err(DirectPeerError::QuicHandshake);
                }
                tokio::time::sleep(Duration::from_millis(180)).await;
                backlog.extend(dial_addrs.iter().copied());
                continue;
            }
            match tokio::time::timeout_at(expires, attempts.join_next()).await {
                Ok(Some(Ok(Ok(authenticated)))) => {
                    attempts.abort_all();
                    return Ok(authenticated);
                }
                Ok(Some(_)) => {}
                _ => return Err(DirectPeerError::QuicHandshake),
            }
        }
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

/// 对每个经过 ICE 验证的候选 UDP 端口尝试双向 QUIC，并完成证书指纹
/// 与会话 HMAC 认证。只有真正通过认证的 QUIC 才能成为当前连接。
async fn authenticate_on_path(
    mut path: ManagedPath,
    client_tls: quinn::ClientConfig,
    server_tls: quinn::ServerConfig,
    pairing: ManualPairing,
    advertised: IceDescription,
    role: IceRole,
    replay_guard: Arc<ReplayGuard>,
) -> Result<(ManagedPath, quinn::Endpoint, quinn::Connection, bool), DirectPeerError> {
    let remote = path.nominated().remote;
    let adapter = QuinnUdpAdapter::from_owner(&mut path.selected.owner)
        .map_err(|_| DirectPeerError::UdpAdapter)?;
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        demux_endpoint_config(), Some(server_tls), Arc::new(adapter),
        quinn::default_runtime().ok_or(DirectPeerError::QuicEndpoint)?,
    ).map_err(|_| DirectPeerError::QuicEndpoint)?;
    endpoint.set_default_client_config(client_tls);
    let (control, outbound) = race_authenticated_control(
        &endpoint, remote, &advertised, &pairing, role, replay_guard,
    ).await?;
    let actual_remote = control.remote_address();
    if outbound && actual_remote != remote
        && !advertised.candidates.iter().any(|candidate| candidate.address == actual_remote)
    {
        control.close(1u32.into(), b"unadvertised remote address");
        return Err(DirectPeerError::LiveSession);
    }
    // 外部 Punch/对端 NAT 可能使实际来源与最初 ICE 地址不同。
    // 只有 mTLS 指纹与当前会话 HMAC 都通过才更新选中的实际 QUIC 路径。
    path.selected.path.remote = actual_remote;
    // 创建方最终决定使用哪条已认证路径；加入方只有收到该
    // QUIC 内的选择消息才返回同一条 Control，防止多路竞速两端各选一条。
    if role == IceRole::Controlled {
        let selected = timeout(QUIC_ACCEPT, async {
            let mut stream = control.accept_uni().await
                .map_err(|_| DirectPeerError::QuicHandshake)?;
            let packet = stream.read_to_end(48).await
                .map_err(|_| DirectPeerError::QuicHandshake)?;
            if packet != CONTROL_PATH_SELECTED {
                return Err(DirectPeerError::VerifiedSession);
            }
            Ok::<(), DirectPeerError>(())
        }).await.map_err(|_| DirectPeerError::QuicHandshake)?;
        if selected.is_err() {
            control.close(1u32.into(), b"invalid path choice");
        }
        selected?;
    }
    Ok((path, endpoint, control, outbound))
}

/// 仅对双方已经通过 ICE+mTLS+HMAC 的网络路径进行评分。
/// 相同 192.168.x.x 前缀不能证明在同一个 LAN；没有实际认证绝不入选。
fn nominated_address_priority(
    local: std::net::IpAddr, remote: std::net::IpAddr,
    kind: Option<IceCandidateType>,
) -> u8 {
    match (local, remote, kind) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b),
            Some(IceCandidateType::Host)) if a.is_private() && b.is_private() => 5,
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b),
            Some(IceCandidateType::Host))
            if (a.is_unique_local() && b.is_unique_local())
                || (a.is_unicast_link_local() && b.is_unicast_link_local()) => 5,
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b),
            Some(IceCandidateType::Host))
            if !a.is_unique_local() && !b.is_unique_local()
                && !a.is_unicast_link_local() && !b.is_unicast_link_local()
                && !a.is_loopback() && !b.is_loopback() => 4,
        (_, _, Some(IceCandidateType::Host)) => 3,
        (_, _, Some(IceCandidateType::PortMapped)) => 2,
        (_, _, Some(IceCandidateType::PeerReflexive)) => 1,
        _ => 0,
    }
}

fn authenticated_path_priority(path: &ManagedPath, remote: &IceDescription) -> u8 {
    let nominated = path.nominated();
    let kind = remote.candidates.iter()
        .find(|candidate| candidate.address == nominated.remote)
        .map(|candidate| candidate.kind);
    nominated_address_priority(nominated.local.ip(), nominated.remote.ip(), kind)
}

/// 多接口 ICE 和 QUIC 相互认证同时推进。首个 ICE 路径如果完成不了
/// QUIC，并不会让备用端口/地址立即被丢弃。所有尝试共用总截止时间。
async fn connect_authenticated_transport(
    ready: ReadyBase,
    confirmed: &ManualConfirmation,
    now: u64,
    role: IceRole,
) -> Result<ConnectedTransportPeer, DirectPeerError> {
    let ReadyBase {
        identity, mut gathered, pairing, remote, remote_certificate,
    } = ready;
    confirmed.ensure_pairing_confirmed(
        pairing.credentials.session_id(), pairing.comparison_code,
    ).map_err(|_| DirectPeerError::Confirmation)?;
    if now >= pairing.expires_at {
        return Err(DirectPeerError::ManualSignal);
    }
    let offered_host_candidates = gathered.candidates.combined.candidates.iter()
        .filter(|candidate| candidate.kind == IceCandidateType::Host)
        .map(|candidate| candidate.address).collect::<Vec<_>>();
    if role == IceRole::Controlled {
        wait_for_authenticated_creator(&mut gathered, &pairing, &remote).await?;
    }
    let sender = if role == IceRole::Controlling {
        Some(ConnectPunchSender::start(&gathered, &pairing, &remote))
    } else {
        None
    };
    let mut candidates = gathered.start_authenticated_path_race(
        &remote, pairing.credentials.clone(), ICE_CHECK,
    ).map_err(|_| DirectPeerError::IceCheck)?;

    let trusted = trusted_certificate(remote_certificate)?;
    let cert = vec![identity.cert.der().clone()];
    let private_key = || rustls::pki_types::PrivateKeyDer::Pkcs8(
        identity.signing_key.serialize_der().into()
    );
    let client_tls = authenticated_client_config(
        cert.clone(), private_key(), trusted.clone(),
    ).map_err(|_| DirectPeerError::TlsConfig)?;
    let server_tls = authenticated_server_config(
        cert, private_key(), trusted,
    ).map_err(|_| DirectPeerError::TlsConfig)?;
    let replay_guard = Arc::new(ReplayGuard::new(4096)
        .map_err(|_| DirectPeerError::VerifiedSession)?);
    let mut in_flight = JoinSet::new();
    let mut ice_exhausted = false;
    let limit = Instant::now() + ICE_CHECK + QUIC_ACCEPT;
    let mut last_failure = DirectPeerError::IceCheck;
    let mut best: Option<(ManagedPath, quinn::Endpoint, quinn::Connection, bool)> = None;
    let mut best_score = 0_u8;
    let mut preference_deadline: Option<Instant> = None;
    let result = loop {
        // 仅创建方选择路径；加入方必须等待选中 QUIC 内的认证后通知。
        if ice_exhausted && in_flight.is_empty() {
            if let Some(verified) = best.take() {
                break Ok(verified);
            }
            break Err(last_failure);
        }
        tokio::select! {
            path = candidates.next(), if !ice_exhausted => {
                match path {
                    Some(path) => {
                        let cert = client_tls.clone();
                        let server = server_tls.clone();
                        let binding = ManualPairing {
                            credentials: pairing.credentials.clone(),
                            remote_tls_cert_sha256: pairing.remote_tls_cert_sha256,
                            expires_at: pairing.expires_at,
                            comparison_code: pairing.comparison_code,
                        };
                        let guard = Arc::clone(&replay_guard);
                        let offered = remote.clone();
                        in_flight.spawn(async move {
                            authenticate_on_path(
                                path, cert, server, binding, offered, role, guard,
                            ).await
                        });
                    }
                    None => ice_exhausted = true,
                }
            }
            result = in_flight.join_next(), if !in_flight.is_empty() => {
                match result {
                    Some(Ok(Ok(authenticated))) => {
                        if role == IceRole::Controlled {
                            break Ok(authenticated);
                        }
                        let score = authenticated_path_priority(&authenticated.0, &remote);
                        if score > best_score || best.is_none() {
                            if let Some((_, endpoint, loser, _)) = best.replace(authenticated) {
                                loser.close(0u32.into(), b"higher priority path selected");
                                endpoint.close(0u32.into(), b"higher priority path selected");
                            }
                            best_score = score;
                        } else {
                            authenticated.2.close(0u32.into(), b"lower priority path");
                            authenticated.1.close(0u32.into(), b"lower priority path");
                        }
                        if best_score >= 5 {
                            break Ok(best.take().expect("authenticated path present"));
                        }
                        preference_deadline.get_or_insert(
                            Instant::now() + PATH_PREFERENCE_GRACE,
                        );
                    }
                    Some(Ok(Err(error))) => last_failure = error,
                    _ => last_failure = DirectPeerError::QuicHandshake,
                }
            }
            _ = tokio::time::sleep_until(
                preference_deadline.unwrap_or(limit)
            ), if preference_deadline.is_some() => {
                break Ok(best.take().expect("a verified QUIC candidate started grace"));
            }
            _ = tokio::time::sleep_until(limit) => {
                if let Some(verified) = best.take() {
                    break Ok(verified);
                }
                break Err(DirectPeerError::QuicHandshake);
            }
        }
    };
    // 连接成功或失败均应等待 QUIC/ICE 任务取消完成，以及网关租约撤销。
    in_flight.abort_all();
    while in_flight.join_next().await.is_some() {}
    drop(sender);
    candidates.cleanup().await;
    let winner = result?;
    if role == IceRole::Controlling {
        let selected = async {
            let mut stream = winner.2.open_uni().await
                .map_err(|_| DirectPeerError::QuicHandshake)?;
            stream.write_all(CONTROL_PATH_SELECTED).await
                .map_err(|_| DirectPeerError::QuicHandshake)?;
            stream.finish().map_err(|_| DirectPeerError::QuicHandshake)?;
            Ok::<(), DirectPeerError>(())
        }.await;
        if let Err(error) = selected {
            let (mut path, endpoint, control, _) = winner;
            control.close(1u32.into(), b"Control path select failed");
            endpoint.close(1u32.into(), b"Control path select failed");
            path.shutdown_gateway().await;
            return Err(error);
        }
    }
    let (mut path, endpoint, control, control_outbound) = winner;
    let nominated = path.nominated();
    let remote_candidate_kind = remote.candidates.iter()
        .find(|candidate| candidate.address == nominated.remote)
        .map(|candidate| candidate.kind);
    let punch = match PunchLoop::start_for_control(
        &mut path.selected.owner,
        AuthenticatedPunch::new(pairing.credentials.clone(), role),
        remote, PUNCH_CADENCE, control.clone(),
    ) {
        Ok(punch) => punch,
        Err(_) => {
            control.close(1u32.into(), b"Punch owner startup failed");
            endpoint.close(1u32.into(), b"Punch owner startup failed");
            path.shutdown_gateway().await;
            return Err(DirectPeerError::LiveSession);
        }
    };
    Ok(ConnectedTransportPeer {
        endpoint, control, path, punch: Some(punch),
        credentials: pairing.credentials,
        remote_pin: pairing.remote_tls_cert_sha256,
        role, client_tls: Some(client_tls), replay_guard,
        control_outbound, remote_candidate_kind, offered_host_candidates,
    })
}

impl ReadyCreator {
    pub async fn connect_transport_now(
        self, confirmed: &ManualConfirmation,
    ) -> Result<ConnectedTransportPeer, DirectPeerError> {
        self.connect_transport(confirmed, current_unix_seconds()?).await
    }

    pub async fn connect_transport(
        self, confirmed: &ManualConfirmation, now: u64,
    ) -> Result<ConnectedTransportPeer, DirectPeerError> {
        connect_authenticated_transport(
            self.inner, confirmed, now, IceRole::Controlling,
        ).await
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
        connect_authenticated_transport(
            self.inner, confirmed, now, IceRole::Controlled,
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachable_host_priority_prefers_lan_then_public_ipv6_over_nat_mapping() {
        let lan_a = "192.168.1.100".parse().unwrap();
        let lan_b = "192.168.1.200".parse().unwrap();
        let ipv6_a = "2001:4860:1::1".parse().unwrap();
        let ipv6_b = "2606:4700::1111".parse().unwrap();
        assert_eq!(nominated_address_priority(
            lan_a, lan_b, Some(IceCandidateType::Host),
        ), 5);
        assert_eq!(nominated_address_priority(
            ipv6_a, ipv6_b, Some(IceCandidateType::Host),
        ), 4);
        assert_eq!(nominated_address_priority(
            lan_a, lan_b, Some(IceCandidateType::PortMapped),
        ), 2);
        // 仅在 ICE 与 QUIC 都真实通过认证之后调用评分，
        // 不能因不同城市的两端同为 192.168.1.x 就直接判定 LAN 可达。
    }

    #[test]
    fn quic_destinations_try_ice_nominated_address_then_other_signaled_hosts() {
        use crate::ice_signaling::IceCandidate;
        let primary: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let backup: SocketAddr = "127.0.0.1:30000".parse().unwrap();
        let offer = IceDescription {
            role: IceRole::Controlled,
            ufrag: "offer-ufrag".into(),
            password: "offer-pass".into(),
            candidates: vec![
                IceCandidate {
                    address: backup, kind: IceCandidateType::Host, priority: 100,
                },
                IceCandidate {
                    address: backup, kind: IceCandidateType::Host, priority: 99,
                },
                IceCandidate {
                    address: "[::1]:30000".parse().unwrap(),
                    kind: IceCandidateType::Host, priority: 1000,
                },
            ],
        };
        assert_eq!(quic_candidate_destinations(primary, &offer), vec![primary, backup]);
    }

    #[tokio::test]
    async fn authenticated_control_dials_second_remote_when_first_quic_port_is_dead() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let now = 1_800_000_000;
            let (pending, invite) = begin_creator(&[bind], &[], now, 1200).await.unwrap();
            let (joiner, reply) = begin_joiner(&invite, &[bind], &[], now).await.unwrap();
            let creator = pending.receive_reply(&reply, now).unwrap();
            let offer = creator.inner.remote.clone();
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (a, b) = tokio::join!(
                creator.connect_transport(&cc, now),
                joiner.connect_transport(&jc, now),
            );
            let a = a.unwrap();
            let b = b.unwrap();
            let actual = b.diagnostic().actual_local_udp;
            assert!(offer.candidates.iter().any(|candidate| candidate.address == actual));
            let invalid: SocketAddr = "127.0.0.1:9".parse().unwrap();
            let binding = ManualPairing {
                credentials: a.credentials.clone(),
                remote_tls_cert_sha256: a.remote_pin,
                comparison_code: 123456,
                expires_at: u64::MAX,
            };
            let recv_proof = b.credentials.clone();
            let recv_pin = b.remote_pin;
            let (dialed, accepted) = tokio::join!(
                race_authenticated_control(
                    &a.endpoint, invalid, &offer, &binding,
                    IceRole::Controlling,
                    Arc::new(ReplayGuard::new(4096).unwrap()),
                ),
                async {
                    let connection = b.endpoint.accept().await.unwrap().await.unwrap();
                    PeerCertificatePin::new(recv_pin).unwrap()
                        .verify_connection(&connection).unwrap();
                    authenticate_responder(
                        connection.clone(), &recv_proof, ChannelRole::Control,
                        &ReplayGuard::new(4096).unwrap(), AUTH_DEADLINE,
                    ).await.unwrap();
                    connection
                },
            );
            let (connection, outbound) = dialed.unwrap();
            assert!(outbound);
            assert_eq!(connection.remote_address(), actual);
            connection.close(0u32.into(), b"test complete");
            accepted.close(0u32.into(), b"test complete");
            a.shutdown().await;
            b.shutdown().await;
        }).await.unwrap();
    }

    #[tokio::test]
    async fn overlapping_private_candidates_cannot_replace_verified_reachable_path() {
        // 两个远端可能都公布 192.168.1.0/24，但该前缀不能作为
        // 位于同一物理 LAN 的证据：虚假高优先级私网候选不允许阻塞有效路径。
        tokio::time::timeout(Duration::from_secs(65), async {
            let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let now = 1_800_000_000;
            let (pending, invite) = begin_creator(&[bind], &[], now, 1200).await.unwrap();
            let (joiner, reply) = begin_joiner(&invite, &[bind], &[], now).await.unwrap();
            let mut creator = pending.receive_reply(&reply, now).unwrap();
            let mut joiner = joiner;
            creator.inner.remote.candidates.push(crate::ice_signaling::IceCandidate {
                address: "192.168.1.200:57001".parse().unwrap(),
                kind: IceCandidateType::Host,
                priority: u32::MAX,
            });
            joiner.inner.remote.candidates.push(crate::ice_signaling::IceCandidate {
                address: "192.168.1.100:57002".parse().unwrap(),
                kind: IceCandidateType::Host,
                priority: u32::MAX,
            });
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (left, right) = tokio::join!(
                creator.connect_transport(&cc, now),
                joiner.connect_transport(&jc, now),
            );
            let left = left.unwrap();
            let right = right.unwrap();
            assert!(left.diagnostic().actual_remote_udp.ip().is_loopback());
            assert!(right.diagnostic().actual_remote_udp.ip().is_loopback());
            assert!(left.diagnostic().control_connected);
            assert!(right.diagnostic().control_connected);
            left.shutdown().await;
            right.shutdown().await;
        }).await.unwrap();
    }

    #[tokio::test]
    async fn unreachable_ipv6_family_does_not_block_authenticated_ipv4_control() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let v6: SocketAddr = "[::1]:0".parse().unwrap();
            let now = 1_800_000_000;
            // 创建方拥有两个地址族；加入方只提供 IPv4，因此不允许
            // 被创建方的 IPv6 地址拖住/失败而忽略真实可达的 IPv4。
            let (pending, invite) =
                begin_creator(&[v6, v4], &[], now, 1200).await.unwrap();
            let (joiner, reply) =
                begin_joiner(&invite, &[v4], &[], now).await.unwrap();
            let creator = pending.receive_reply(&reply, now).unwrap();
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (a, b) = tokio::join!(
                creator.connect_transport(&cc, now),
                joiner.connect_transport(&jc, now),
            );
            let a = a.unwrap();
            let b = b.unwrap();
            assert!(a.diagnostic().actual_remote_udp.is_ipv4());
            assert!(b.diagnostic().actual_remote_udp.is_ipv4());
            a.shutdown().await;
            b.shutdown().await;
        }).await.unwrap();
    }

    #[tokio::test]
    async fn quic_path_race_shutdown_releases_all_advertised_udp_ports() {
        tokio::time::timeout(Duration::from_secs(70), async {
            let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let now = 1_800_000_000;
            let (pending, invite) = begin_creator(&[bind, bind], &[], now, 1200).await.unwrap();
            let (joiner, reply) = begin_joiner(&invite, &[bind, bind], &[], now).await.unwrap();
            let creator = pending.receive_reply(&reply, now).unwrap();
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&creator.comparison_code()).unwrap();
            jc.confirm(&joiner.comparison_code()).unwrap();
            let (a, b) = tokio::join!(
                creator.connect_transport(&cc, now),
                joiner.connect_transport(&jc, now),
            );
            let a = a.unwrap();
            let b = b.unwrap();
            let mut all_ports = a.diagnostic().offered_host_candidates;
            all_ports.extend(b.diagnostic().offered_host_candidates);
            assert_eq!(all_ports.len(), 4);
            a.shutdown().await;
            b.shutdown().await;
            for addr in all_ports {
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if tokio::net::UdpSocket::bind(addr).await.is_ok() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }).await.expect("all ICE/QUIC loser sockets must be released");
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn creator_accepts_manual_reply_after_two_hour_human_delay() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let now = 1_800_000_000;
        let (pending, invite) =
            begin_creator(&[bind], &[], now, UNLIMITED_INVITE_LIFETIME).await.unwrap();
        let two_hours_later = now + 7200;
        let (joiner, reply) =
            begin_joiner(&invite, &[bind], &[], two_hours_later).await.unwrap();
        let creator = pending.receive_reply(&reply, two_hours_later).unwrap();
        assert_eq!(creator.comparison_code(), joiner.comparison_code());
        assert!(creator.confirmation().is_ok());
        assert!(joiner.confirmation().is_ok());
    }

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
        let waiting = tokio::spawn(async move { joiner.connect_transport(&jc, now).await });
        // An authenticated REPLY alone must never start the joiner's ICE
        // deadline. A missing creator remains a pending, not failed, session.
        tokio::time::sleep(Duration::from_millis(1400)).await;
        assert!(!waiting.is_finished(), "joiner started ICE before creator activity");
        let connected = creator.connect_transport(&cc, now);
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
            // 额外连接由实际 Control 拨号方发起，不由邀请码创建/加入角色决定。
            assert_ne!(creator.control_outbound, joiner.control_outbound);
            let (dialer, listener) = if creator.control_outbound {
                (&creator, &joiner)
            } else {
                (&joiner, &creator)
            };
            assert!(matches!(
                listener.open_authenticated_data(Duration::from_secs(1)).await,
                Err(crate::transport_session::TransportError::WrongRole)
            ));
            assert!(matches!(
                dialer.accept_authenticated_data(Duration::from_secs(1)).await,
                Err(crate::transport_session::TransportError::WrongRole)
            ));
            assert!(matches!(
                dialer.open_authenticated_data(Duration::ZERO).await,
                Err(crate::transport_session::TransportError::Timeout)
            ));
            assert!(matches!(
                listener.accept_authenticated_data(Duration::ZERO).await,
                Err(crate::transport_session::TransportError::Timeout)
            ));
            let (mut tx, _) = creator.control.open_bi().await.unwrap();
            tx.write_all(b"generic control").await.unwrap();
            tx.finish().unwrap();
            let (_, mut rx) = joiner.control.accept_bi().await.unwrap();
            assert_eq!(rx.read_to_end(64).await.unwrap(), b"generic control");

            // No Data QUIC was created until this explicit application call.
            let (outgoing, incoming) = tokio::join!(
                dialer.open_authenticated_data(Duration::from_secs(12)),
                listener.accept_authenticated_data(Duration::from_secs(12)),
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


}
