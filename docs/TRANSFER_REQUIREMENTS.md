# p2p-transfer 对 SDK 的需求契约（草案 v0.1）

> **状态：开发指导/待实现，不是 API 已稳定的声明。**
>
> 首个消费者是 [p2p-transfer](https://github.com/juezhong/p2p-transfer)。参考实现固定为 [p2p-friend/main@78c6b72](https://github.com/juezhong/p2p-friend/commit/78c6b72cd1024211db3cfc91af08b161f3a5b46d)（Go v0.16.4，2026-10-09）。**只参考旧功能、测试、优化与失败经验；Rust 新版不追求与 Go 旧版线协议兼容。** 不得修改旧仓库以适配新实现。

## 1. 所有权与依赖方向

```text
p2p-transfer (transfer-core + cli/tui/gui)
   |     文件 RPC、任务/目录、块调度、ACK、SHA-256、.part、UI
   v
p2p-sdk (identity + signaling + ICE + QUIC + diagnostics)
         对端身份、候选/打洞/选路、通道/连接生命周期、诊断
   v
Tokio UDP Socket / IPv4 / IPv6
```

- SDK 不理解文件名、路径、Entry、PUT/GET、文件 SHA-256、传输块 ACK、目录浏览或进度条。
- Transfer 不自行实现 STUN、ICE、NAT、PCP/NAT-PMP/UPnP、TLS 或 QUIC 握手；所有网络诊断来自 SDK。
- Rust 工作空间可跨仓库依赖 Git tag/revision；后续发布使用经过兼容性验证的版本。开发期间可用 Cargo `patch` 或 git rev 锁定。
- SDK 内使用 Rust + Tokio + Quinn（QUIC 为第一实现），但 *connectivity* 不依赖 Quinn；其余 UDP 安全传输预留扩展边界。

## 2. 连通性与配对：既定约束

- IPv4/IPv6 LAN 直连，优先可用 IPv6，同时及时测试可用 IPv4 候选；IPv6 stateful firewall 通过 ICE 主动检查尝试建立状态，不能绕过显式阻断。
- IPv4 host/STUN srflx/peer-reflexive、UDP 打洞及可选 PCP/NAT-PMP/UPnP 映射；严禁 TURN、任意代理或服务器业务中继。
- 手动 INVITE/REPLY（可以完全不使用自建 signaling server）和可选 Rendezvous（只交换认证的会话/ICE 信息）共享同一个 ICE 连接引擎。
- ICE 不能保证任意 NAT 都连通；无直连返回 `NoDirectPath` 或等效的可诊断错误。
- ICE 凭据不是可信设备身份。QUIC 必须实施端到端身份认证与加密；不允许“调试时关闭证书验证”作为生产连接选项。
- Quinn 与 ICE 的 UDP Socket/外部 NAT 映射一致性是必须先通过的设计实验；不要把两个独立 socket 的结果当作同一条可达路径。

## 3. 对上层暴露的能力（语义契约，不是当前已存在的 Rust API）

| 能力 | Transfer 使用场景 | 验收性质 |
| --- | --- | --- |
| 节点创建与优雅停止 | CLI/TUI/GUI 创建端点、退出 | 必需 |
| create/join + 双模式 signaling | 新建/加入安全会话 | 必需（手动先行） |
| 已认证的 Session | 连接到受信任对端、确定身份 | 必需 |
| 可靠、双向、独立 Stream | 控制帧、RPC 和文件数据 | 必需 |
| 多 Stream 并发 + 反压 | 不让大块传输阻塞控制消息 | 必需 |
| 超时/取消/半关闭/关闭事件 | 取消传输但保持控制面可用 | 必需 |
| 链路事件、RTT、候选/映射等诊断 | 所有界面的 status/diagnose | 必需 |
| 多条独立 QUIC data connection（可控生命周期） | 复现 v0.16.4 四条 data-only QUIC | 最终功能必需；可在后续里程碑交付 |
| 链路单独损坏/重建与状态回调 | 数据连接修复，主会话不终止 | 最终功能必需 |
| QUIC DATAGRAM | 将来 `p2p-net` 使用，Transfer 当前不用 | SDK 后续按里程碑提供 |

**连接数约束**：旧版 v0.16.4 是 1 条 control-only QUIC + 最多 4 条 data-only QUIC（不是「1 主 + 最多 3 数据」）。每个独立 UDP 端口/Socket 都可能拥有不同 NAT 映射；需要自己的可达性验证或协议明确安全的复用方案。此层 SDK 承担网络建连/身份/链路修复，Transfer 决定使用几条数据连接、chunk 分配、ACK 和重传。

**可靠性约束**：QUIC Stream 的发送成功不等于对端文件已完成写入，更不等于已 fsync 持久化；文件级 ACK 仍由 Transfer 实现。应用级 ACK 的准确含义（已顺序写入、何时 fsync）由 Transfer 协议定义。

## 4. 目标公共接口的方向（伪代码，仅用于讨论）

```rust
// 这段代码是示意，不可直接复制为现有 API。
let node = P2pNode::new(config).await?;
let invitation = node.create_invite().await?;
let session = node.join_or_accept(peer_signaling).await?;
let control = session.open_bi().await?;
let events = session.subscribe_events();
let snapshot = session.diagnostics().snapshot();

// 后续：data_connection = session.open_authenticated_data_connection(...)
// SDK 不包含 send_file、ack_chunk、browse_directory 等方法。
```

错误应可区分 `SignalingUnavailable`、`NoDirectPath`、`IdentityMismatch`、`IceTimeout`、`TransportHandshakeFailure`、`OperationCancelled`、`UnsupportedCapability`；具体类型名待定。不允许把所有失败简化为“连接超时”。

## 5. 版本与兼容决策

- 新 Rust SDK/Transfer 构成新的协议世代：不提供兼容旧 `P2PF-INVITE-`/`P2PF-REPLY-`、旧 QUIC ALPN、旧 RPC 帧和旧数据流的兼容层。
- Rust 新协议需有显式版本、capability negotiation、拒绝未知/不支持能力及可扩展字段，避免每次发版都破坏新 Rust 客户端之间互通。
- 旧 Go 项目仅作为只读参考、测试对照和可回退工具；不迁移 Go 代码到新的业务 runtime。
- 所有对客户端可观察到的旧功能和安全约束由 Rust 测试重新证明，不以测试文件名相似代替行为一致。
- 迁移版权和 LICENSE 需独立审查；不要在没有许可依据时更换 SPDX/许可证。

## 6. SDK 提供的诊断基础

统一输出 Connection State、ICE 候选检查结果、selected pair、地址族、实际 QUIC 远端/本地 UDP 端口、STUN 和网关映射、握手结果、链路恢复、错误根因。采用可脱敏 JSON 快照/事件，不记录完整密钥/连接码。Transfer UI 负责展示具体的文件信息。

## 7. 与 Transfer 的验收门槛

- G1：同机/同 LAN 两个 Rust 进程手动配对，TLS 对端认证、独立 control stream 与 data stream 互不堵塞。
- G2：真实 IPv4 NAT/IPv6 双栈验证；必要情况下明确 `NoDirectPath`，抓包证明直连、无 relay。
- G3：主控制会话保持、单个数据连接失败时状态通知与重建；实际 UDP 映射重新验证。
- G4：取消任务仅取消应用操作，SDK 主会话仍可执行控制 RPC。
- G5：所有 SDK 诊断输出不泄露完整 token、密钥和 ICE password。
- G6：Rust Transfer 功能回归矩阵和手测大纲见其 `docs/TEST_PLAN.md`。

关联：[SDK 架构](ARCHITECTURE.md)、[连通性](CONNECTIVITY.md)、[安全](SECURITY.md)、[路线图](ROADMAP.md)。
