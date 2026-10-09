# Agent 开发交接流程（p2p-sdk）

> 本文件位于默认分支，新的会话/Agent 无需依赖聊天历史即可恢复上下文。每次开始工作先读 `/AGENTS.md` 和本文件。

## 新会话标准步骤

1. 检查仓库 `main`、所有打开的 PR、当前开发分支和近期提交，**不要假设一个 PR 已经合并**。
2. 读取 `AGENTS.md`、`docs/STATUS.md`、`docs/ARCHITECTURE.md`、`docs/CONNECTIVITY.md`、`docs/SIGNALING.md`、`docs/SECURITY.md`、`docs/ROADMAP.md`、`docs/TESTING.md`。
3. **单独阅读仍打开的设计记录 PR**：[SDK PR #2：Transfer 依赖与集成测试](https://github.com/juezhong/p2p-sdk/pull/2)；以及跨仓库 [Transfer PR #1：迁移方案、26 项手工测试](https://github.com/juezhong/p2p-transfer/pull/1)。用户已明确要求这两个**记录用 PR 不必合并**，不要替用户合并它们。
4. 对照 `docs/STATUS.md` 的“已实现/未实现/待验证”，通过阅读当前源码和运行可执行的测试重新验证；不相信过期状态记录。
5. 按 M0 → M1 → M2 开发。初期风险最大的是 ICE/Quinn 共用有效 UDP 映射且接收报文不冲突；明确区分原型、已通过的自动测试、实际双机 NAT 手测。
6. 在新的 `feat/` 分支提交范围可控的改动，新建中文 PR，PR 中写明测试/未测试和下一个可接续任务。
7. 更新 `docs/STATUS.md`（所完成的里程碑、SHA、阻塞、测试证据、下一项任务）。如涉及网络架构变动，同时更新对应文档。

## 强约束

- Rust / Tokio；ICE/STUN/NAT/IPv6 优先、IPv4 回退；默认 QUIC/Quinn 安全传输；无 TURN/Relay、无服务器业务数据转发；强制身份认证与端到端加密。
- 保留手动 INVITE/REPLY 和可选的纯信息交换信令服务。任何服务器只是信令，并非数据路径。
- SDK 只负责连通性、传输、身份、诊断；文件传输/SSH/TUN/UI 均属于应用仓库。
- ICE 不保证连通性；无可达直连路径必须明确失败。
- 新 Rust 协议无需和旧 Go `p2p-friend` 线协议互通。只将其作为只读参考（`main@78c6b72`）。
- 三个应用最后必须都具有 CLI/TUI/GUI；SDK 无需 GUI。
- 先核实当前分支和源码，不直接在 `main` 做功能试验。

## 新会话可直接使用的指令

> 请读取本仓库 AGENTS.md 和 docs/WORKFLOW.md、docs/STATUS.md，并检查打开的 PR；同时读取 p2p-sdk PR #2 和 p2p-transfer PR #1 的设计记录。以实际源码与 CI 作为已完成证据，继续 STATUS.md 的首个未完成里程碑，在独立分支提交中文 PR 并更新 STATUS.md。不得合并记录 PR、不得修改旧 Go p2p-friend，也不得声称 ICE 一定能直连。
