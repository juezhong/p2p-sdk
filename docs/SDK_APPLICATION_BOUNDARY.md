# SDK / application boundary for authenticated direct networking

The Rust SDK is a **reusable peer-to-peer transport**, not a file-transfer
implementation. Compatibility with Go `p2p-friend v0.16.4` is judged by
observable network and session behavior, not by duplicating Go's application
file-pipeline internals.

## SDK responsibilities

- Enumerate local IPv4/IPv6 interfaces and public candidate observations, including
  STUN, verified router mappings and authenticated peer-reflexive sources.
- Exchange session-bound manual signaling, explicitly verify SAS, perform secure
  connectivity checks and nominate an actual UDP socket/path.
- Establish mutually authenticated QUIC sessions and new independently
  authenticated connections, validate remote certificate pins and replay guards.
- Detect unreachable or dead connections, maintain healthy NAT mappings,
  retry permitted connections and report actual shutdown/failure status.
- Expose sanitized networking diagnostics, candidate/mapping state and connection
  state changes. Never pretend an interrupted connection is healthy.

## Responsibilities of an SDK consumer

- Start a generic network session with `ReadyCreator::connect_transport()`
  or `ReadyJoiner::connect_transport()`: exactly one authenticated Control
  QUIC is established. No Data QUIC is created by default.
- The application may call `ConnectedTransportPeer::open_authenticated_data()`
  on the creator and `accept_authenticated_data()` on the joiner for each
  additional independently authenticated transport. No fixed four-lane
  scheduling, file framing or retransmission belongs to the SDK.
- If stable auxiliary QUIC connectivity is needed, wrap the transport peer in
  `Arc` and call `peer.manage_authenticated_data()` **once for each
  application-requested connection**. Its `ManagedAuthenticatedLink` publishes
  `Connecting / Connected / Reconnecting / ControlLost / Stopped` and a
  generation counter. The SDK automatically retries failed links with bounded
  backoff, per-link TLS PIN / session HMAC verification and source-port
  preference / fallback. An unverified or closed connection is never advertised
  as healthy. Call `manager.shutdown().await` before consuming the peer with
  `Arc::try_unwrap(peer).ok().unwrap().shutdown().await`.
- The managed link API does not create files, streams or data-lane indexes. It
  reconnects over the already nominated UDP path; after **Control loss** it
  stops instead of inventing ICE Restart or pretending a QUIC session survived
  network failure. Physical NAT/IPv6 firewall success still requires field tests.
- The legacy dual-QUIC convenience facade and fixed 1..=4 pool are physically
  removed in SDK #58, once Transfer #28 has migrated to its own Data lane
  dispatcher and passed CI. Both sides must merge before treating this as
  released; SDK has no fixed per-application connection count.
- Define application channel and stream semantics. In particular, Transfer owns
  the exact `4-lane` business strategy, file chunk assignment, ACK, ordering,
  cancellation and resumable transmission. The SDK must not transmit any file
  metadata or bytes without an application supplying them.
- If application-level recovery after a Control QUIC loss is desired, establish
  a new verified session using a safe renewal mechanism. Go v0.16.4 itself
  terminates its logical session on Control loss; seamless ICE Restart is a
  distinct enhancement, not a prerequisite to claiming Go-equivalent behavior.

## Critical parity gates

An SDK release must not be called Go-parity-complete while any of the following
is missing: delayed joiner readiness; live IPv4/IPv6 path nomination; dynamic
NAT candidate handling; independent UDP-port preference with shared-path
fallback; mutual reauthentication of every repaired connection; router mapping
renewal/cleanup; unambiguous Control-lost status; reproducible native
Linux/macOS/Windows/ARM-musl and real-network fault tests.

A green localhost CI run checks only software invariants. It cannot validate
router, CGNAT, mobile network or long-running firewall behavior.
