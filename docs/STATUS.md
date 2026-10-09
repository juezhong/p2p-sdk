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

## 开发更新：M0 合并与 M1 STUN 编解码（2026-10-09）

- SDK M0 [PR #3](https://github.com/juezhong/p2p-sdk/pull/3) 已合并到 main（180007cb）；Transfer M0 [PR #2](https://github.com/juezhong/p2p-transfer/pull/2) 已合并到对应 main（99ecfe0）。
- 本分支 [SDK PR #4](https://github.com/juezhong/p2p-sdk/pull/4) 增加 RFC 8489 STUN Binding request/response 的**纯 Rust 编解码**，覆盖 IPv4/IPv6 XOR-MAPPED-ADDRESS、事务 ID、Cookie 与长度错误单元测试。
- 该代码尚未执行 STUN UDP 网络请求；不代表 ICE 或 NAT 穿透可用。应当通过 PR #4 CI 核实 fmt/clippy/test，并修复后再合并。
- 下一个任务：为 STUN 加入 Tokio UDP 请求/超时/事务响应源匹配，继而验证 ICE agent 的 Socket 所有权与 Quinn 复用；不得把测试用文档地址视作公网连接。


## 进展（2026-10-09）：M1 STUN 报文编解码

- 已合并的 M0 基础：SDK [PR #3](https://github.com/juezhong/p2p-sdk/pull/3)，main squash commit `180007cb`。
- 开发中：[PR #4](https://github.com/juezhong/p2p-sdk/pull/4)：纯 Rust STUN Binding 请求/响应编解码；IPv4/IPv6 XOR-MAPPED-ADDRESS、Cookie、事务 ID、长度边界测试。
- **注意：STUN 编解码不等于网络请求、ICE Agent 或 NAT 穿透。** 当前无真实端到端连接；若未合并 PR #4，main 不具备该模块。
- 下一步：Tokio UDP 请求/响应源地址校验、事务重试和取消，再验证 ICE/Quinn UDP 映射共享与加密 QUIC Echo。


## 已完成并合并（2026-10-09）

- M0: [PR #3](https://github.com/juezhong/p2p-sdk/pull/3) 已合并，Rust crate、Direct-only 策略数据模型、连接阶段与单元测试；合并提交 `180007cb`。
- M1 的**第一个纯编解码子任务**：[PR #4](https://github.com/juezhong/p2p-sdk/pull/4) 已合并，RFC 8489 STUN Binding request / response 与 IPv4/IPv6 XOR-MAPPED-ADDRESS 解码、边界/事务标识测试；合并提交 `dbd0d7b`。PR 最新 GitHub Actions fmt/Clippy/test 已通过。
- 仍**没有**真正的 STUN UDP Client、ICE candidate pair 检查、Quinn/TLS 安全连接、实际 NAT 穿透、自动信令。编解码模块本身不认证 peer；其解析结果不可单独视为可信路径。
- 下一项：Tokio UDP STUN 收发（随机 Transaction ID、服务端源地址验证、退避重试、超时/取消/脱敏诊断），接着验证 ICE Agent + Quinn 同一有效 UDP 映射；再开展真实双机 NAT 测试。
