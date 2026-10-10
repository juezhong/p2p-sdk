//! 手动信令 → 认证 ICE → 双向 QUIC 竞速 → 通用附属 QUIC 的完整环回回归。
//! 不依赖 Transfer 四路 Data lane 或旧连接池。
#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use crate::{begin_creator, begin_joiner};
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn confirmed_manual_pairing_builds_one_control_and_optional_authenticated_data() {
        tokio::time::timeout(Duration::from_secs(55), async {
            let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let (pending, invite) = begin_creator(&[local], &[], 100, 1200)
                .await.unwrap();
            let (joiner, reply) = begin_joiner(&invite, &[local], &[], 101)
                .await.unwrap();
            let creator = pending.receive_reply(&reply, 102).unwrap();
            let code = creator.comparison_code();
            assert_eq!(code, joiner.comparison_code());
            let mut cc = creator.confirmation().unwrap();
            let mut jc = joiner.confirmation().unwrap();
            cc.confirm(&code).unwrap();
            jc.confirm(&code).unwrap();

            let (c, j) = tokio::join!(
                creator.connect_transport(&cc, 103),
                joiner.connect_transport(&jc, 103),
            );
            let creator = Arc::new(c.unwrap());
            let joiner = Arc::new(j.unwrap());
            assert!(creator.diagnostic().control_connected);
            assert!(joiner.diagnostic().control_connected);
            // 网络认证使两端可独立使用真正的 QUIC Stream。
            let (mut tx, _) = creator.control.open_bi().await.unwrap();
            tx.write_all(b"hello").await.unwrap();
            tx.finish().unwrap();
            let (_, mut rx) = joiner.control.accept_bi().await.unwrap();
            assert_eq!(rx.read_to_end(16).await.unwrap(), b"hello");

            let outgoing = creator.manage_authenticated_data();
            let incoming = joiner.manage_authenticated_data();
            let mut c_updates = outgoing.subscribe();
            let mut j_updates = incoming.subscribe();
            let (client_data, server_data) = tokio::time::timeout(
                Duration::from_secs(20),
                async {
                    tokio::join!(
                        async {
                            loop {
                                let snapshot = c_updates.borrow().clone();
                                if let Some(c) = snapshot.connection {
                                    if c.close_reason().is_none() { break c; }
                                }
                                c_updates.changed().await.unwrap();
                            }
                        },
                        async {
                            loop {
                                let snapshot = j_updates.borrow().clone();
                                if let Some(c) = snapshot.connection {
                                    if c.close_reason().is_none() { break c; }
                                }
                                j_updates.changed().await.unwrap();
                            }
                        }
                    )
                },
            ).await.unwrap();
            let mut send = client_data.open_uni().await.unwrap();
            send.write_all(b"authenticated data").await.unwrap();
            send.finish().unwrap();
            let mut recv = server_data.accept_uni().await.unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), b"authenticated data");
            outgoing.shutdown().await;
            incoming.shutdown().await;
            Arc::try_unwrap(creator).ok().unwrap().shutdown().await;
            Arc::try_unwrap(joiner).ok().unwrap().shutdown().await;
        }).await.unwrap();
    }
}
