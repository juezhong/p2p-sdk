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

## 6. 代码实施记录（以 PR 当前状态为准）

- **#47–#53**：SDK 统一连接入口、Go 对照的动态 ICE、默认 Control-only、按需额外 QUIC、诊断、双栈与安全 API 已逐步合并；跨平台 CI 成功不代替公网 NAT/故障现场。
- **[#54](https://github.com/juezhong/p2p-sdk/pull/54)**：七组跨平台 CI 全部通过，已合并（`361b535`）。新增 `ManagedAuthenticatedLink`，为**单条应用按需申请的 Data QUIC**提供监测、退避重拨、重新 mTLS/Session HMAC、可订阅的 `Connected/Reconnecting/ControlLost` 状态。可以创建多个实例，没有 SDK 四路调度或文件协议。
- **Transfer**：仍锁定旧 SDK revision，文件传输逻辑尚未迁移到通用 API；不能把新 SDK 接口等同于 Transfer 已升级。只有 Transfer 单独完成迁移并验收后，才移除旧 `ResilientDataLanes` 兼容层。

## 5. 尚未宣称 Go 对等的硬条件

尽管 SDK #47–#53 改进统一入口、动态 prflx、双栈、公网映射、诊断、认证与超时，仍须继续对照 Go 的双向 QUIC 竞速、候选排序与动态更新、STUN/网关并行采集时序，并完成物理多网卡/NAT/IPv6 防火墙/映射变化和 2h/24h 保活及断网故障注入。

绿色 GitHub Actions **仅证明对应代码在 CI 测试环境通过**，不能替代真实运营商和路由器验收，也不能把尚未运行的测试写成“已完成”。

> 相关代码：SDK `src/direct_peer.rs`, `src/transport_session.rs`；兼容层 `src/resilient_data.rs`；Go `quic_connect.go`, `quic_signal.go`, `resilient_data.go`, `portmap.go`。
