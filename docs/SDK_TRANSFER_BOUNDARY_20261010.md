# SDK 与 Transfer 的唯一职责边界（2026-10-10 更新）

> 本文为架构决策与验收约束，不等同于代码已经实现或现场测试通过。
> 行为基准：Go `p2p-friend v0.16.4`（`78c6b72`），以**用户可感知网络行为**对等为目标。

## 1. SDK 负责什么

SDK 是所有程序共享的 P2P **连接、连接稳定性、安全和诊断**基础层：

- 本机 IPv4/IPv6、多网卡探测，Multi-STUN、公网映射类型判定，PCP/NAT-PMP/UPnP 映射和续租。
- 手动 INVITE/REPLY、会话身份、配对校验、认证 UDP Punch、ICE 候选检查/提名。
- QUIC/mTLS、证书指纹校验、会话 HMAC、防重放、认证连接重建。
- 控制 QUIC 与应用按需创建的辅助 QUIC；连接故障状态、重拨/回退、KeepAlive、网关映射生命周期与脱敏诊断。
- 提供认证成功的 `quinn::Connection` / Stream 使用入口；**不预先创建四条 Data QUIC**、不为应用分配流或执行文件消息调度。

在 Go v0.16.4 已有的故障语义下，**Control QUIC 真正断开会终止当前会话**；不伪报无缝重连。ICE Restart、原逻辑会话恢复是单独增强，不能冒充 Go 已有行为。

## 2. Transfer 负责什么

Transfer 自己决定是否使用 **四条 Data QUIC**，并定义其业务 `Data lane`、连接选择、文件块共享队列和流分配策略。其余包括文件目录协议、ACK、重传、断点续传、取消、权限和一致性校验，均由 Transfer 实现。

- `Data QUIC` 是通用加密传输连接，由 SDK 创建、认证、监测和可选托管重建。
- `Data lane` 是 Transfer 将这些连接/流组织为并行文件传输工作的**业务概念**；不会成为 SDK 公开的固定四路模型。
- 其它程序（聊天、隧道、远程控制）可以只使用一条认证 Control QUIC，也可以按自己业务需求申请辅助连接。

## 3. 当前迁移状态与删除时机

截至 PR #49 合并，`ReadyCreator/ReadyJoiner::connect_transport()` 是不创建 Data QUIC 的通用入口；`ConnectedTransportPeer::open_authenticated_data()/accept_authenticated_data()` 是按需新建的认证连接，但在当时需要应用自己监听断开并重建。

`ResilientDataLanes` 为兼容旧 Transfer 的 1–4 路托管连接池，混有轮询开流的旧设计。**不要把它当作新 SDK 应用必须使用的接口。**

迁移顺序：
1. 在 SDK 增加通用、与四路无关的**可选**托管连接生命周期 API：检测 Data QUIC 失效、按需重建、重新 mTLS/HMAC 验证、发布状态；Control 失效停止恢复且标明终止。
2. 由 Transfer 的适配层自行保有并发四路策略，调用该通用 SDK API；文件 ACK、chunk、补传不下沉到 SDK。
3. 只有在 Transfer 与其他调用方迁移、跨平台/异常回归全部通过后，才能移除 `ResilientDataLanes`、重复会话封装以及业务特定上限。**不要在迁移前删除旧 API，避免破坏现有调用方。**

## 4. 去过度设计约束

- 默认只给一个安全直连入口和最小可观测连接对象；不要出现要求用户自行拼接 UDP Owner/ICE/QUIC 的 API。
- 不为了概念拆更多 crate、transport trait、多种可插拔后端或第三套 lane pool。
- `ConnectedTransportPeer` 只返回已认证 QUIC；原始 Quinn `Endpoint` 不对外公开，以防绕过会话 HMAC。
- 内部认证、候选检查和套接字所有权不允许为了代码减少而降低安全约束。
- 重复连接生命周期与遗留文档随迁移删除，不做与 Go 网络行为无关的增强。

## 5. 最新代码实施记录（2026-10-10）

- SDK #47–#55、[#56](https://github.com/juezhong/p2p-sdk/pull/56)、[#57](https://github.com/juezhong/p2p-sdk/pull/57) 已合并，后两者 7/7 Actions 通过。Go 的**双方双向 QUIC Dial+Accept/方向仲裁**与**STUN + 网关映射同 socket 并行收集**现已有 Rust 代码。
- SDK [#54](https://github.com/juezhong/p2p-sdk/pull/54) 已合并，通用 `ManagedAuthenticatedLink` 为每条连接负责断链探测、重新 mTLS/HMAC、重拨和真实状态，不包含固定四路调度。
- Transfer [#28](https://github.com/juezhong/p2p-transfer/pull/28) **正在 CI 验证**：把文件四路调度搬进 `transfer-core::transport_lanes`，CLI 彻底改为 SDK `connect_transport` 统一入口，不再自己拼装 UDP/ICE/TLS/QUIC；当前尚未合并。
- SDK [#58](https://github.com/juezhong/p2p-sdk/pull/58) 已在单独 PR **实际删除** `src/resilient_data.rs`、旧 `ConnectedDirectPeer` 四路高层入口及 `LiveSdkSession` 重复生命周期包装；须等 Transfer #28 回归成功并合并，才能安全合并 SDK #58。两条均未宣称稳定版本。

## 6. Go v0.16.4 仍未证明完全对等的项目

1. **确认的功能差异**：Go 在多个候选/UDP socket 上持续尝试并竞速 QUIC；Rust 当前首先由 ICE 提名单条路径、丢弃其他 Owner，然后在这一条路径上进行双向 QUIC 竞速。若 ICE 首个提名路径随后 QUIC 失败，不能完整重试原来的其他路径。Go 对同网段 Host 候选提供短优先窗口，Rust 路径排序行为也未逐条证明一致。
2. **发现时间行为差异**：Go 的 STUN/网关同时发现还具有 soft deadline 和 grace；Rust #57 完成并行，但候选的软截止动态预算尚未复刻。
3. **未完成真实网络验收**：不同运营商、对称 NAT/CGNAT、多网卡 VPN、IPv6 有状态防火墙、真实路由器 PCP/NAT-PMP/UPnP 续租与回收、断网后真实状态/修复、长时间 2h/24h 持续连接。GitHub CI 仅能证明测试环境内的软件行为，不能代替这些场景。
4. Go Control 断开也结束本逻辑会话，因此 ICE Restart/换网后原逻辑会话保持应列为**独立增强**，不是 Go 已有行为。

**禁止在 1–3 项完成代码对等与真实验收前宣传 Rust SDK 与 Go v0.16.4 完全一致；不以“基础已实现”“部分完成”作为验收状态。**

> 相关代码：SDK `src/direct_peer.rs`, `src/transport_session.rs`；SDK #58 删除中的历史 `src/resilient_data.rs`；Go `quic_connect.go`, `quic_signal.go`, `resilient_data.go`, `portmap.go`。
