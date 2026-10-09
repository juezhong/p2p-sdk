//! SDK-only connectivity diagnostics: no file, disk-transfer or tunnel logic.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use p2p_sdk::{
    ice_agent::{new_ice_credentials, nominate_host_pair},
    quinn_socket::{demux_endpoint_config, QuinnUdpAdapter},
    stun_client::{discover_mapping, ProbeOptions},
    udp_owner::UdpOwner,
};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("selftest") if args.next().is_none() => selftest().await,
        Some("stun") => match (args.next(), args.next()) {
            (Some(addr), None) => match addr.parse::<SocketAddr>() {
                Ok(server) => match discover_mapping(server, ProbeOptions::default()).await {
                    Ok(report) => {
                        println!("STUN observation: socket={} server={} mapped={} attempts={}; NOT an ICE/QUIC path validation",
                            report.local_address, report.stun_server, report.mapped_address, report.attempts_used);
                        Ok(())
                    }
                    Err(err) => Err(format!("STUN probe failed: {err:?}")),
                },
                Err(_) => Err("invalid IP:port; resolve DNS separately".to_owned()),
            },
            _ => Err("usage: p2p-sdk-debug stun <IPv4:port|[IPv6]:port>".to_owned()),
        },
        _ => {
            eprintln!("p2p-sdk-debug: SDK-only experimental network diagnostics\n  selftest   local ICE nomination -> shared UDP -> dual QUIC TLS Echo\n  stun IP:PORT   STUN-only mapping observation (not P2P path validation)");
            std::process::exit(2);
        }
    };
    if let Err(err) = result {
        eprintln!("FAIL: {err}");
        std::process::exit(1);
    }
}

async fn selftest() -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut a = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.map_err(|e| e.to_string())?;
        let mut b = UdpOwner::bind("127.0.0.1:0".parse().unwrap()).await.map_err(|e| e.to_string())?;
        let aa = a.handle.local_address();
        let bb = b.handle.local_address();
        let ac = new_ice_credentials();
        let bc = new_ice_credentials();
        let (ar, br) = tokio::join!(
            nominate_host_pair(&mut a, bb, ac.clone(), bc.clone(), false, Duration::from_secs(5)),
            nominate_host_pair(&mut b, aa, bc, ac, true, Duration::from_secs(5))
        );
        if ar.map_err(|e| format!("{e:?}"))?.remote != bb ||
            br.map_err(|e| format!("{e:?}"))?.remote != aa {
            return Err("ICE nominated unexpected peer".into());
        }
        println!("PASS: RFC8445 ICE host candidate checks and nomination on localhost");

        // Selftest-only ephemeral certificate, never disable TLS validation.
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| e.to_string())?;
        let cert = generated.cert.der().clone();
        let private = rustls::pki_types::PrivateKeyDer::Pkcs8(
            generated.signing_key.serialize_der().into(),
        );
        let server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], private)
            .map_err(|e| e.to_string())?;
        let server_socket = QuinnUdpAdapter::from_owner(&mut a).map_err(|e| e.to_string())?;
        let server = quinn::Endpoint::new_with_abstract_socket(
            demux_endpoint_config(), Some(server_config),
            Arc::new(server_socket), quinn::default_runtime().unwrap(),
        ).map_err(|e| e.to_string())?;
        let client_socket = QuinnUdpAdapter::from_owner(&mut b).map_err(|e| e.to_string())?;
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            demux_endpoint_config(), None, Arc::new(client_socket),
            quinn::default_runtime().unwrap(),
        ).map_err(|e| e.to_string())?;
        let mut trust = rustls::RootCertStore::empty();
        trust.add(cert).map_err(|e| e.to_string())?;
        client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(trust))
                .map_err(|e| e.to_string())?
        );
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            let mut held = Vec::new();
            for want in [b"control".as_slice(), b"data".as_slice()] {
                let conn = server.accept().await.ok_or("server endpoint closed")?
                    .await.map_err(|_| "TLS handshake failed")?;
                let (mut tx, mut rx) = conn.accept_bi().await.map_err(|_| "stream accept failed")?;
                let payload = rx.read_to_end(128).await.map_err(|_| "stream read failed")?;
                if payload != want { return Err("unexpected stream payload"); }
                tx.write_all(b"ack").await.map_err(|_| "stream write failed")?;
                tx.finish().map_err(|_| "stream finish failed")?;
                held.push(conn);
            }
            done_rx.await.map_err(|_| "client dropped")?;
            Ok::<(), &str>(())
        });
        let control = client.connect(aa, "localhost").map_err(|e| e.to_string())?
            .await.map_err(|e| e.to_string())?;
        for (idx, value) in [b"control".as_slice(), b"data".as_slice()].into_iter().enumerate() {
            let conn = if idx == 0 {
                control.clone()
            } else {
                client.connect(aa, "localhost").map_err(|e| e.to_string())?
                    .await.map_err(|e| e.to_string())?
            };
            if idx == 1 && conn.stable_id() == control.stable_id() {
                return Err("QUIC lanes are not independent".into());
            }
            let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| e.to_string())?;
            tx.write_all(value).await.map_err(|e| e.to_string())?;
            tx.finish().map_err(|e| e.to_string())?;
            if rx.read_to_end(16).await.map_err(|e| e.to_string())? != b"ack" {
                return Err("invalid echo".into());
            }
            if idx == 0 { println!("PASS: Control QUIC TLS Stream Echo"); }
            else { println!("PASS: independent Data QUIC TLS Stream Echo"); }
        }
        done_tx.send(()).map_err(|_| "server completion channel lost")?;
        server_task.await.map_err(|e| e.to_string())?.map_err(str::to_owned)?;
        client.close(0u32.into(), b"selftest");
        println!("PASS: ICE-nominated shared UDP port={} / {}; localhost only; NOT a NAT penetration test", aa.port(), bb.port());
        Ok(())
    }).await.map_err(|_| "selftest timed out".to_owned())?
}
