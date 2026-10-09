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

## 当前进行中：STUN UDP 探针（2026-10-09）

- 用户确认：Transfer 专用 `P2PT` 20 字节控制帧**不是 RFC 标准**，不应仅为假想复用提升到 SDK。保持在 Transfer 项目；独立 `feat/shared-control-framing` 实验分支不合并、无 PR。
- [SDK PR #5](https://github.com/juezhong/p2p-sdk/pull/5)：新增 Tokio UDP 独立 STUN 地址探针、随机事务 ID、来源校验、重试/超时及 mock server 测试；请以最新 CI 的结果判定是否可合并。
- **限制**：探针 socket 并非 ICE/Quinn 的正式 socket，不可把其映射视为直连通路；ICE Agent、Quinn TLS 和真实双机通信都尚未完成。
- 下一个优先事项：选择/验证 ICE 实现并证明 ICE 与 Quinn 同一有效 UDP 映射的所有权和分包逻辑，随后进行加密双向 Stream Echo。

## 最新继续开发（2026-10-09）

- SDK [PR #5](https://github.com/juezhong/p2p-sdk/pull/5) 通过 CI 并合并，提交 `645050e`：Tokio 独立 STUN UDP 探针（不是 ICE/QUIC 共享 Socket）。
- SDK 原 [PR #6](https://github.com/juezhong/p2p-sdk/pull/6) 因 PR #5 合并后的 `lib.rs` 和 `STATUS.md` 冲突，内容重建在 [PR #7](https://github.com/juezhong/p2p-sdk/pull/7)；不得把 #6 覆盖回 main。
- PR #7 实现 RFC 9443 STUN/QUIC 报文预分类，新增 Control/Data 角色策略值类型与 `docs/CONTROL_DATA_PLAN.md`；**控制面和数据面逻辑分离**，同时允许同一有效 UDP Socket 承载网络协议分流。
- 暂未实现真实 Quinn `AsyncUdpSocket` 适配、ICE 连通性检查/提名、数据和控制 Stream 开流 API、TLS 握手及真实双机验证。下一阶段优先选型并测试 ICE/Quinn 同一 UDP I/O Owner 的安全握手原型。

## 开发检查点（2026-10-09，最新）

- SDK [PR #5](https://github.com/juezhong/p2p-sdk/pull/5) 已通过 CI 并合并，新增 Tokio STUN UDP 映射探针，提交 `645050e`。
- SDK [PR #7](https://github.com/juezhong/p2p-sdk/pull/7) 已通过 CI 并合并，提交 `58c8fe1`：RFC 9443 STUN/QUIC 报文预分类、逻辑 Control/Data 角色与 ADR-0002；原 PR #6 因与 #5 冲突而关闭、未合并。
- **控制面和数据面继续分离**：一个已验证的 UDP 数据端点可以承载 STUN/ICE/QUIC，但应用的 Control RPC/ACK/取消与 bulk Data Stream 必须逻辑分离；将来最多四条额外 data-only QUIC 的 UDP 端口必须重新验证连通性。当前仅有角色策略模型，没有真实 Stream API。
- 尚未完成 ICE agent、Quinn UDP 适配和 TLS 身份认证、真实控制/数据 Stream 及真实两机 NAT 验证。下一阶段优先实现共享 UDP I/O Owner + ICE/Quinn 安全 Stream Echo，证明路径和报文分流稳定性。

## 本轮 M1 开发：双 QUIC 控制/数据隔离（2026-10-09）

- 已决定首版使用独立 Control QUIC + Data QUIC，**共用实际 ICE 验证的 UDP Endpoint**，两条连接具有各自生命周期；控制和数据 Stream 不是同一 QUIC 下仅逻辑分离。完整要求见 `docs/decisions/0003-dual-quic-control-data.md`。
- 新增 `src/dual_quic.rs` Quinn 双连接句柄内部模型（构造函数仅 crate 内部可访问，**尚不执行 Peer Identity / Session ID 绑定**）；接入 Quinn 依赖。当前仍不是真实的安全 P2P Session。
- 新增数据链接上限语义说明：默认 1 Control + 1 Data，额外 Data QUIC 的 0–4 配置不包括基础 Data。
- 核心下一步：真实单 Quinn Endpoint 同 UDP Socket 双 QUIC 测试，Data 连接单独关闭后 Control RPC 成功；再引入双连接共同身份/会话绑定、ICE 路径与数据链接重建。
- 即使 Control 和 Data 独立 QUIC，也不能抵抗同一 UDP Socket 或 NAT/物理路径故障，需有重连；高吞吐共用带宽须做控制延迟实测。

## 双 QUIC 故障隔离验证（2026-10-09）

- [PR #8](https://github.com/juezhong/p2p-sdk/pull/8) 已经通过 Actions 并 squash 合并到 `main`（`291224ff`）；其中 `DualQuic` 仍是内部句柄模型，不负责真实 ICE 或配对身份绑定。
- [PR #9](https://github.com/juezhong/p2p-sdk/pull/9) 正开发 Quinn loopback 双 QUIC 集成测试：同一客户端 Endpoint/UDP 端口两条连接、测试专用证书验证、先控制 RPC、关闭数据连接、后控制 RPC。
- 本测试只验证 Quinn Connection 级隔离；不是 ICE/共享 STUN I/O、真实 NAT/IPv6、防火墙、身份 Session 绑定或 Data 重连测试。以 PR #9 GitHub Actions 最新结果为准，未通过不合并。
- 下一任务：控制/数据连接的设备身份与会话 ID 绑定，然后 ICE/QUIC 共 UDP I/O Owner、真实双机连通性和数据故障重建。

## M1 会话绑定开发（2026-10-09）

- [SDK PR #9](https://github.com/juezhong/p2p-sdk/pull/9) 已通过完整 Rust CI 并合并，提交 `c5eecd4`：同一 Quinn Endpoint 两条独立 QUIC 连接，关闭数据连接后控制 RPC 仍能成功的 loopback 验证。
- [SDK PR #10](https://github.com/juezhong/p2p-sdk/pull/10) 当前待验收：应用 Session ID + HMAC-SHA256 双向随机挑战、Control/Data 角色证明、共享有界 nonce replay guard；双连接组合需验证角色和 Session 一致。
- **尚未完成**：真实设备公钥与两个 QUIC TLS 连接绑定、会话凭据发行/过期撤销、ICE/QUIC 共底层 Socket、NAT 测试、data lane 重连。因此不能认为 PR #10 是完整的认证 Session。
- 下一步：PR #10 CI 通过并合并后，补齐真实双连接握手端到端测试、TLS 设备身份绑定及 ICE/Quinn I/O Owner。独立设计 PR SDK #2、Transfer #1 继续保持不合并。

## M1 最近完成（2026-10-09）

- [SDK PR #10](https://github.com/juezhong/p2p-sdk/pull/10) 已经通过最后一次 GitHub Actions 完整检查并合并（commit `a8f497d`）。新增双向 HMAC-SHA256 会话挑战证明、Control/Data 角色和 Session ID 校验、共享 nonce 防重放缓存与双 QUIC 的真实 loopback 握手测试；先前测试因服务器过早关闭/丢弃连接句柄失败，现已修复并通过。
- **验证边界**：这些是共享 Session Secret 的应用层证明，Quinn 测试使用明确的 TLS 信任根。尚不能代替设备长期公钥身份、Session 凭据生成/过期/撤销、真实 ICE 路径与跨 NAT 验证，不是可直接投入生产的完整认证 Session。
- **下一个首要任务**：实现 TLS 设备身份验证与双 QUIC 设备身份一致性检查，随后真实 ICE + Quinn 同 UDP I/O Owner、IPv4/IPv6 连通性检查。继续分离 Control QUIC 与 Data QUIC。

## 手动配对 M1（2026-10-09）

- 在新功能分支 `feat/m1-manual-invite-reply` 研发单纯 INVITE/REPLY 不依赖消息服务器的临时 X25519 + HKDF-SHA256 会话密钥派生；6 位人工比较码；身份 TLS 指纹记录。用户无需另输 Session Secret。
- 消息服务器将来只替代人工传递信令，不参与业务数据/密钥派生。
- **当前限制**：连接码还不包含 ICE 候选，未实现真实 TLS 指纹绑定、人工验证码确认门禁、设备信任、真实网络连接；不能声称手动配对已完整可用。
- 下一步：检查 CI、修复构建与测试；继续 ICE offer/answer、绑定真实证书、比较码确认及跨平台安全测试。

## M1 手动配对已合并（2026-10-09）

- [SDK PR #11](https://github.com/juezhong/p2p-sdk/pull/11) 已通过最新 GitHub Actions 的 Rust fmt/Clippy/单元测试并合并至 main（`e0ac6579`）。
- 用户输入仍只有手动 INVITE/REPLY 识别码，无需额外人工发送 Session Secret，也无需部署消息服务器。两个识别码仅载临时公钥、会话 ID、有效期、TLS 证书指纹声明与随机元数据；双方使用 X25519 + HKDF-SHA256 本地推导内部会话绑定密钥与 6 位比较码。
- CI 覆盖双方派生结果一致、配对码过期、跨会话回复、坏版本、无效公钥及篡改拒绝。
- **安全尚未完成**：实际 Quinn TLS 证书与连接码声明的指纹绑定、独立人工比较码确认门禁、身份/信任管理、会话撤销以及 ICE 候选的 OFFER/ANSWER 信令交换。因此不能把 PR #11 称为“完整手动直连可用”。
- 下一步优先：TLS 对端证书指纹核验 + 两条 QUIC 设备身份一致性；为手动配对加入 ICE 候选与完整的交换码，并进行 LAN 双机加密连接验证。

## 本轮安全基础开发（2026-10-09）

- [SDK PR #12](https://github.com/juezhong/p2p-sdk/pull/12) 已通过完整 GitHub Actions 并合并至 main（`60af368f`）。新增 `src/peer_pin.rs`，通过 Quinn 实际 `peer_identity` 证书链比对叶证书 SHA-256、拒绝缺失/错误指纹；还有独立 ManualConfirmation 状态与真实 TLS loopback 测试。
- **尚未与正式 P2P Session 流程强制连接**：低层 `authenticate_initiator/responder` 仍可独立调用，用户确认状态未作为完整 Session 构造门槛。QUIC 服务端默认仍无客户端证书，缺少可靠双方设备身份；不可视为生产安全配对。
- [长期 SDK 设计 PR #2 的服务器讨论评论](https://github.com/juezhong/p2p-sdk/pull/2#issuecomment-6078101303) 记录可选公网 Rust signaling server：密码验证、在线设备登记、可选持久连接与自动配对信令，**仅待讨论、不实施业务中继**。
- 下一阶段优先做 TLS 双向设备身份、ManualConfirmation 不可绕过地绑定完整 Session 构造，再将 ICE candidate/密码加入手动 INVITE/REPLY，推进共享 UDP Socket 的 Quinn 直连原型。

## M1 双向 TLS 认证开发（2026-10-09）

- 新开发分支 `feat/m1-mutual-tls-verified-session`：新增 `tls_identity.rs`，在 Quinn 服务端强制客户端证书，在客户端强制服务器证书验证，并增加两条连接的 loopback 双向证书检查与无证书客户端拒绝测试。
- 注意：当前只实现双向 TLS 配置基础，仍未将 ManualConfirmation/证书 Pin 与应用 Session 构造接口统一为不可绕过的高层 API；未实现 ICE/Quinn 同 UDP I/O Owner、真实 NAT 穿透、密钥撤销。CI 完整通过之前不合并。
- 下一任务：将手工配对的明确确认、两条 QUIC 的双向 TLS 身份和 Session Secret 证明组合成不可绕过的 Session 构造状态机，然后开展真实双机 ICE/Quinn 验证。
