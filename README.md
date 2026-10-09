# p2p-sdk

面向 `p2p-transfer`、`p2p-tunnel`、`p2p-net` 的 Rust 点对点连通性与安全通信 SDK。

> **状态：架构规划中。** 目前仓库尚未提供可运行的 SDK、稳定 Rust API 或已验证的 ICE/QUIC 集成。本文档定义目标与约束，不代表功能已实现。

## 目标

- 选择可达的 **IPv6/IPv4 直连路径**；优先使用可用 IPv6，同时支持 IPv4/IPv6 局域网直连与 IPv4 NAT 打洞。
- 通过 **ICE（RFC 8445）** 收集候选、执行基于 STUN 的连通性检查与选路；可选 PCP、NAT-PMP、UPnP 网关端口映射。
- **严格 Direct-only：永不把业务数据转发到服务器；没有直连路径时明确失败。** ICE 不能保证任何两台机器一定直连。
- 兼容两种信令方式：无需自建信令服务的手动邀请码/回传码，以及可选的纯信息交换 Rendezvous 服务器。
- 业务数据端到端认证与加密；信令服务不得充当业务数据代理。
- 传输层可插拔：QUIC 是第一版的候选后端，不把 ICE/NAT 核心设计成依赖 QUIC。
- 内置可在所有应用中复用的网络诊断、状态快照与脱敏报告导出。

## 技术方向（待原型验证）

- 语言：**Rust**；异步运行时：**Tokio**。
- ICE：优先评估独立 Sans-I/O ICE 状态机（例如 `is`），备选其他成熟实现。
- QUIC：优先评估 `quinn`；需通过 ICE/QUIC **同一有效 UDP 映射**与收包分发的集成验证。
- 应用 UI：`p2p-transfer` / `p2p-tunnel` / `p2p-net` 各自必须提供 CLI、TUI、GUI；SDK 本身是无 UI 的库。

## 文档导航

- [架构与模块边界](docs/ARCHITECTURE.md)
- [ICE、IPv6/IPv4、NAT 穿透策略](docs/CONNECTIVITY.md)
- [手动/服务器信令协议设计](docs/SIGNALING.md)
- [安全模型与不使用中继的约束](docs/SECURITY.md)
- [实施路线](docs/ROADMAP.md)
- [测试与验收](docs/TESTING.md)
- [AI 开发与贡献约束](AGENTS.md)

## 范围边界

SDK **不实现**文件传输、远程 SSH 业务、虚拟网卡或 GUI；这些由独立应用仓库实现。可选纯信令服务器属于独立服务，不构成 SDK 离线手动连接模式的运行依赖。

## 许可

仓库已有 `LICENSE`（GPL v2 文本）。在审查既有代码版权、依赖兼容性和再许可权利之前，不变更许可证。