# SDK / application boundary: generic authenticated P2P links

The SDK is a reusable network library. It does not understand file transfer,
SSH, tunnel, pipe, or application-defined Control/Data lanes.

## SDK owns

- ICE candidate gathering/nomination and the actual UDP Owner, QUIC Endpoint,
  authenticated dial/accept, certificate PIN, session HMAC and replay protection.
- Connection state and error reporting for each authenticated QUIC Link.
- Explicit lifecycle: new link construction on application request, bounded
  retry and reauthentication for managed links, and orderly release.
- The first successfully authenticated connection is a **bootstrap link**:
  it binds the manually verified peer session and serves as a rendezvous basis
  for optional later connections. **Bootstrap is not an application Control
  channel.** Subsequent links have the generic `Additional` proof class,
  independent of any application payload or stream semantics.
- The independent bootstrap/additional proof tags preserve the existing 1/2
  domain separation on the wire. Never remove or ignore link authentication to
  achieve API neutrality.

## Application owns

- Whether to start a peer session and when to request or stop each link.
- How many managed links to request: zero, one, four, or other bounded values
  that the application decides; SDK has no four-link Transfer policy.
- Interpreting the bootstrap and additional links as any application purpose.
  Transfer maps bootstrap to its Control and requests four additional Data
  connections as an **application policy**.
- Application stream scheduling, retry of interrupted streams, file hash,
  cancellation, acknowledgements, and task/session semantics.

## Current API in the generic-link transition

1. The application calls `begin_creator/begin_joiner` and then
   `ReadyCreator/ReadyJoiner::connect_transport()`; the SDK performs actual
   ICE and QUIC connection establishment and yields
   `ConnectedTransportPeer { bootstrap, ... }`.
2. The application explicitly requests a managed additional QUIC using
   `Arc<ConnectedTransportPeer>::manage_link()`. Each invocation creates one
   manager and no implicit extra connections.
3. `ManagedAuthenticatedLink::subscribe()`, `current()`, and `shutdown()`
   observe, use, and release that independently reauthenticated link. SDK
   chooses actual network dial/listen direction; it is not necessarily the
   invitation creator.
4. The application may use explicit `open_link()/accept_link()` for manual
   low-level lifecycle when appropriate, but must not bypass certificate PIN,
   session HMAC, or replay validation.

## Limits and compatibility

- Breaking the initial QUIC does **not** itself mark every additional link
  closed. A managed link can continue on its own physical QUIC until explicitly
  stopped or its own transport fails. The SDK retains a peer-session context
  and uses bootstrap's last known authenticated remote address for subsequent
  attempts; ongoing NAT reachability after bootstrap disconnect is **not**
  proven and needs dedicated real-network validation.
- Generic link physical repair is not automatic recovery of interrupted
  application QUIC streams, file blocks, or logical sessions. The consuming
  application decides recovery and resumption.
- API migration is cross-repository and intentionally staged: **SDK PR #73
  first**, then a new Transfer PR pinned to that exact SDK commit. During
  migration the last released Transfer stays pinned to the preceding SDK.
- If a new public API or wire format becomes incompatible, publish coordinated
  upgrades and explicitly state cross-version support.
- Do not claim NAT/CGNAT/IPv6 real-world parity from localhost CI results.
