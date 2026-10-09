# 开发交接状态 — p2p-sdk

> 状态应随每次开发 PR 更新。**本文件不是运行测试的证据。** 新 Agent 必须重新读取当前分支、打开的 PR 和实际源码。

## 已确定需求

- Rust + Tokio；ICE 直连（IPv6 优先、IPv4 回退、LAN 优先检查、可选网关端口映射），Quinn 为第一版默认安全传输后端。
- 手动双向邀请码/回传码 + 可选纯信令服务器；无业务数据中继。
- 身份认证与加密、SDK 统一诊断。Go 旧版不需线协议兼容。
- 为 Transfer 提供 QUIC Stream/Session、数据通道、链路重建及诊断；具体见未合并文档 PR #2。

## 重要 PR 和参考

- [SDK PR #2 — 设计记录，不合并](https://github.com/juezhong/p2p-sdk/pull/2)
- [Transfer PR #1 — 设计记录，不合并](https://github.com/juezhong/p2p-transfer/pull/1)
- [只读旧项目基线](https://github.com/juezhong/p2p-friend/commit/78c6b72cd1024211db3cfc91af08b161f3a5b46d)

## 当前代码进度（请检查分支/PR）

- M0：Rust crate、基础领域数据类型、基本测试与 CI —— 开发启动阶段。
- M1：两端真实 ICE + Quinn + 身份验证的端到端连接 —— **未完成**。
- M2：IPv6/IPv4 NAT/防火墙和网关映射真实网络验证 —— **未完成**。
- M3：两类完整信令 —— **未完成**。
- M4：稳定会话、多 QUIC 数据连接与诊断 —— **未完成**。

## 下一步

1. 核对当前最新的功能开发 PR 和 CI；如果只是基础 Rust 数据结构，不能声称 SDK 已能穿透。
2. 优先完成 UDP socket 所有权和报文分发原型，确保 ICE 检查与 Quinn 使用一致且可验证的公网 NAT 映射。
3. 实现真实 ICE、加密握手、两机 Stream Echo，记录可复现的测试环境。


## 已创建的功能 PR（2026-10-09）

- [SDK 开发 PR #3 — M0 Rust 基础类型、配置、连接状态机和测试](https://github.com/juezhong/p2p-sdk/pull/3)，**Draft，未合并**。
- 代码包括 `Cargo.toml`、`src/{lib,config,candidate,state}.rs` 与 Rust CI。候选优先级仅用于策略表示，不是 ICE 选路或连通性证明。
- **未实现**：Tokio UDP、ICE/STUN、Quinn、TLS、真实端到端通信。
- **未运行本地 Rust 测试**：当前执行环境没有 rustc/cargo；后续 Agent 首先查看 PR CI（fmt/clippy/test），有失败先修复。
- 下一项：M1 UDP Socket/ICE/Quinn 实验性安全 Stream Echo，不能提前自称“打洞成功”。


## CI 故障处理记录（2026-10-09）

- [功能 PR #3](https://github.com/juezhong/p2p-sdk/pull/3) 初始 CI 失败：`cargo fmt --all -- --check` 提示 `src/config.rs`、`src/state.rs` 格式差异；已在开发分支修复。
- 后续 CI `cargo fmt` 成功，但 `cargo clippy` 报测试代码 `field_reassign_with_default`；已在开发分支将配置初始化改为结构体更新语法。
- 最新 SDK CI 结果须查看 PR Checks；若状态仍是 queued/in_progress，不可声称测试已通过。M1 ICE/Quinn 尚未实现。
- Agent 应先核对 PR 最新 commit、CI 是否成功，再判断是否进入下一开发阶段。
