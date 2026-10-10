# p2p-sdk

Rust/Tokio 的通用 P2P 安全网络连接 SDK，供 Transfer、聊天、隧道等应用复用。使用 Quinn/QUIC、ICE、认证 UDP Punch、IPv4/IPv6、多网卡、Multi-STUN 和可选 PCP/NAT-PMP/UPnP。**无文件协议、UI、TURN、业务数据中继**。

> **当前状态（2026-10-10）**：SDK 统一连接入口、Control-only 认证 QUIC、应用按需辅助 QUIC、动态候选与诊断已有可运行代码并通过跨平台 CI。**尚未完成 Go `p2p-friend v0.16.4` 网络/会话全部行为对等验收**；不能把 localhost 与 GitHub Actions 通过视为真实 CGNAT、家庭路由器、防火墙的实测通过。

## 推荐 SDK 使用流程

1. 创建方 `begin_creator_auto()` 得到 INVITE；加入方 `begin_joiner_auto(invite)` 得到 REPLY。
2. 创建方调用 `PendingCreator::receive_reply_now()`；两端分别验证配对码并显式完成 `ManualConfirmation`。
3. 双方调用 `ReadyCreator::connect_transport_now()` / `ReadyJoiner::connect_transport_now()`，得到**一条经过认证的 Control QUIC**。所有 ICE/UDP Owner/证书与会话凭据由 SDK 管理。
4. 应用需要额外连接时，可使用 `open_authenticated_data()` / `accept_authenticated_data()`，或使用 **可选** `manage_authenticated_data()` 为各条认证 QUIC 提供故障检测、重拨、退避及状态订阅。
5. 应用自己管理每条 QUIC 上的 Stream、业务调度与协议；SDK 暴露真实连接故障与诊断，Control QUIC 真正丢失后终止当前会话，不伪造逻辑会话无缝续接。

## 应用边界

- **SDK**：网卡、STUN、NAT、网关端口映射、ICE、认证 Punch、QUIC/mTLS、会话 HMAC、连接保活和恢复、诊断。
- **Transfer**：是否建立四条 Data QUIC，以及应用的 Data lane 编号、Stream 调度、文件分片、ACK、重传、断点续传、访问控制和 UI。
- **其他应用**：可只用 Control QUIC，无须创建四条数据连接。
- 固定四路 `ResilientDataLanes` 已从 SDK 当前开发分支物理删除（SDK #59）；由 Transfer #29 自己维护业务连接池、选择 Stream。两个 PR 必须 CI 通过后才能进入主分支。

详细 API 与迁移见 [SDK / application boundary](docs/SDK_APPLICATION_BOUNDARY.md)，架构长期决策记录在 [SDK 文档 PR #2](https://github.com/juezhong/p2p-sdk/pull/2)。

## 尚未完成的 Go 对等门槛

Go `quic_connect.go` 的同时 Dial/Accept 与候选竞速仲裁、STUN/网关并行采集及优先策略，仍需逐条核对并达到行为对等。多网卡、真实 NAT、IPv6 有状态防火墙、网关续租/失败撤销、UDP 阻断、长期运行及故障注入，仍需要真实设备验收。详情参见 [Go v0.16.4 对等验收](docs/GO_V0164_PARITY_ACCEPTANCE.md)。

## 开发检查

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

## License

GPL-2.0-only。请按仓库 LICENSE 与依赖许可证条款使用。
