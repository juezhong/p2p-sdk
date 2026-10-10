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
  additional independently authenticated transport; there is no fixed four-lane
  scheduler or file semantics in this API. The SDK tracks lifetime, connection
  pin and session HMAC; applications select their message streams.
- The earlier dual-QUIC convenience facade `connect()` remains available for
  compatibility and starts one initial Data connection.
  `connect_with_data_connections(..., n)` opts into a supervised connection
  pool (currently 1..=4). New non-Transfer consumers should prefer the generic
  transport-only facade.
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
