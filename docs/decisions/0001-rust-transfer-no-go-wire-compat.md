# ADR-0001：Rust Transfer 独立协议世代；Go 仅作参考

- **状态：已确认的开发决策**
- **日期：2026-10-09**
- **适用范围：p2p-sdk / p2p-transfer**
- **参考基线：** `p2p-friend` `main@78c6b72cd1024211db3cfc91af08b161f3a5b46d`，Go v0.16.4

## 决策

1. `p2p-transfer` 使用 Rust 重写，`p2p-sdk` 使用 Rust 实现 ICE/信令/QUIC/身份与诊断。
2. 不实现 Rust 客户端与旧 Go `p2p-friend` 客户端的线协议兼容，不承诺旧 INVITE/REPLY、ALPN、RPC、data wire 与新协议互通。
3. `p2p-friend` 保留为只读行为参考、测试向量来源、故障回归与性能对照；**不修改旧仓库**以配合迁移，也不把 Go runtime/服务强制加入新产品。
4. 功能层保留：双向文件与目录传输、目录浏览、Unicode 路径、取消、单会话仲裁、SHA-256、临时文件、有界内存、应用级 ACK/重传、最多四条 data-only QUIC 的最终能力。
5. Rust 新一代线协议应具有独立版本号、能力协商、长度和权限边界，从首版开始约束自身向后兼容行为。
6. 三个 Rust 应用须交付 CLI、TUI、GUI；UI 实现与 SDK 解耦。

## 选择原因

继续兼容旧 Go 自定义 NAT punch 和信令封装，会限制 ICE + Quinn 的正确实现及通用 SDK 的演进。保持用户可见功能与可靠性，而非保留全部旧二进制细节，是当前工程目标。

## 后果与风险

- 旧 Go 客户端无法直接连接新的 Rust Transfer；两个版本会并存一段时间。
- 旧版已修复过的可靠性/安全缺陷必须变为新 Rust 的回归用例；不得因为新协议而降低可靠性。
- 跨语言测试可以比较文件 SHA-256、相同输入下功能表现和资源/吞吐，但**不以 Go/Rust 建立同一个协议会话为测试目标**。
- 若未来真有旧端兼容需求，必须重新发起独立设计评审，不能私下加入隐式兼容代码。

## 关联文档

- `docs/TRANSFER_REQUIREMENTS.md`
- `docs/TRANSFER_INTEGRATION_TESTS.md`
