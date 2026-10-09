//! Ongoing session-authenticated UDP punch on the selected real UDP socket.
//! A discovered source is a potential prflx candidate, never a QUIC route
//! until separately checked by authenticated ICE.

use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::{sync::{mpsc, watch}, task::JoinHandle, time::{Instant, MissedTickBehavior}};
use crate::{ice_signaling::{IceDescription, MAX_CANDIDATES},
    punch::{AuthenticatedPunch, unix_seconds},
    udp_owner::{UdpOwner, UdpOwnerError}};

const PRFLX_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PunchStatus {
    pub discovered: Vec<SocketAddr>,
    pub generation: u64,
}

pub struct PunchLoop {
    status: watch::Receiver<PunchStatus>,
    stop: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

fn publish(tx: &watch::Sender<PunchStatus>,
    known: &HashMap<SocketAddr, Instant>) {
    let mut discovered = known.keys().copied().collect::<Vec<_>>();
    discovered.sort();
    let generation = tx.borrow().generation.wrapping_add(1);
    tx.send_replace(PunchStatus { discovered, generation });
}

impl PunchLoop {
    /// Take exclusive ownership of the bounded punch inbox, leaving Quinn
    /// and authenticated ICE traffic on the original UdpOwner unchanged.
    pub fn start(owner: &mut UdpOwner, peer: AuthenticatedPunch,
        remote: IceDescription, cadence: Duration) -> Result<Self, UdpOwnerError>
    {
        if cadence < Duration::from_millis(100)
            || cadence > Duration::from_secs(60)
            || remote.validate().is_err()
        { return Err(UdpOwnerError::Io); }
        let handle = owner.handle.clone();
        let (tx, empty) = mpsc::channel(1);
        drop(tx);
        let mut packets = std::mem::replace(&mut owner.punch_packets, empty);
        let (changes, status) = watch::channel(PunchStatus {
            discovered: Vec::new(), generation: 0,
        });
        let (stop, mut stopping) = watch::channel(false);
        let worker = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(cadence);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut sources = HashMap::<SocketAddr, Instant>::new();
            loop {
                tokio::select! {
                    changed = stopping.changed() => {
                        if changed.is_err() || *stopping.borrow() { break; }
                    }
                    _ = ticker.tick() => {
                        tokio::select! {
                            _ = stopping.changed() => break,
                            _ = peer.send_to_candidates(&handle, &remote) => {}
                        }
                        let old = sources.len();
                        sources.retain(|_, at| at.elapsed() < PRFLX_TTL);
                        if old != sources.len() { publish(&changes, &sources); }
                    }
                    incoming = packets.recv() => {
                        let Some(packet) = incoming else { break };
                        let Ok(now) = unix_seconds() else { continue };
                        let Ok(addr) = peer.authenticate(&packet.bytes, packet.source, now)
                            else { continue };
                        if addr.is_ipv4() != handle.local_address().is_ipv4() {
                            continue;
                        }
                        let fresh = !sources.contains_key(&addr);
                        if fresh && sources.len() >= MAX_CANDIDATES { continue; }
                        sources.insert(addr, Instant::now());
                        if fresh {
                            publish(&changes, &sources);
                            // Reply once per discovered endpoint; protect
                            // against amplification with the verified HMAC.
                            if let Ok(reply) = peer.make_packet(now) {
                                let _ = handle.send_punch(addr, &reply).await;
                            }
                        }
                    }
                }
            }
            sources.clear();
            publish(&changes, &sources);
        });
        Ok(Self { status, stop, worker: Some(worker) })
    }

    pub fn subscribe(&self) -> watch::Receiver<PunchStatus> {
        self.status.clone()
    }

    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(worker) = self.worker.take() { let _ = worker.await; }
    }
}

impl Drop for PunchLoop {
    fn drop(&mut self) { self.stop.send_replace(true); }
}
