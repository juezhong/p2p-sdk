# 开发代理与贡献约束

本文档适用于本仓库。当前为**设计与初始开发阶段**：除 `LICENSE` 与文档外没有已验收的 SDK 功能，不得根据规划文档虚构完成状态。

## 目标和不变量

- 使用 **Rust** 实现 P2P 连通性与安全通信 SDK；以 **Tokio** 为首选 runtime。
- ICE 承担候选管理、STUN 连通性检查和路径选择；可选 PCP/NAT-PMP/UPnP 给 ICE 补充候选。
- IPv6 可达时优先，IPv4/IPv6 LAN 可直连，IPv4 NAT 打洞与候选回退可用。
- 必须支持手动 INVITE/REPLY 和可选 Rendezvous 两类信令；两类信令不能分叉成两套穿透算法。
- **绝不实施 TURN/Relay 或经服务器转发业务数据**；直连不可达必须明确失败。
- 业务数据必须端到端认证和加密；ICE STUN 凭据不能当作应用身份认证。
- 诊断、状态和错误原因属于 SDK 核心公共能力。

## 模块边界

- 不在 SDK 内开发文件传输、SSH 服务、TUN 网络设备、CLI/TUI/GUI。
- 应用仓库独立实现业务，**必须**各自提供 CLI/TUI/GUI，统一调用业务 core 和本 SDK。
- 传输适配器可以用 Quinn/QUIC，但不能把 ICE/NAT 核心绑死在 QUIC。
- 任何高层传输都必须使用经过验证的路径，并确保探测与数据传输的 UDP 映射一致或重新验证。
- 不要重复实现已有 RFC 状态机而没有测试依据；不要声称 ICE 可以保证任何 NAT 成功。

## 代码与文档

- 新代码以 Rust stable 为目标；遵循 rustfmt、clippy、`cargo test`，避免不必要的 unsafe。
- 网络协议与异步并发代码要明确超时、取消、资源生命周期和错误返回。
- 安全/网络不变量变化时，同时更新 `docs/ARCHITECTURE.md`、`docs/CONNECTIVITY.md`、`docs/SECURITY.md`、`docs/TESTING.md`。
- 功能未实现写“计划/待验证”；有测试、构建与真实网络证据后才能标记“已完成”。
- 迁移原 Go 代码或调整许可证前，检查协议兼容性、版权与依赖许可证。
- 优先查官方规范与上游实现；验证版本和 API 后再写生产代码。

## 首个里程碑

先用最小测试程序验证：两端交换候选 -> ICE 通过 -> Quinn 经同一有效 UDP 映射完成身份验证和双向 Stream echo。原型不通过，不扩展成多应用框架。
