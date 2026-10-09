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

## 本轮 M1 双向 TLS 证书校验（2026-10-09）

- [SDK PR #13](https://github.com/juezhong/p2p-sdk/pull/13) 已通过 [GitHub Actions #37912246917](https://github.com/juezhong/p2p-sdk/actions/runs/37912246917) 的自动格式化/Clippy/全部单元测试，并 squash 合并至 main（commit `e9e2cf8d`）。
- 新增 `tls_identity.rs`：Quinn 服务端明确要求并验证客户端 TLS 证书，客户端也验证服务端证书，使用明确选择的 rustls `ring` CryptoProvider、独立信任根、ALPN 及禁止 0-RTT。
- 自动测试覆盖 localhost 上两条独立 Control/Data QUIC 的双向证书指纹校验、错误指纹拒绝、无客户端证书拒绝，以及缺少证书或信任根的配置拒绝。**这是 loopback 测试，不等于真实 NAT 测试。**
- 尚未将 `ManualConfirmation`、临时密钥派生、两条 QUIC mTLS/Pin 校验和 HMAC 会话绑定合并为不可绕过的高层已授权 Session。生产级设备证书持久化/轮换/撤销和 ICE/Quinn 共 UDP I/O Owner、跨平台/双机网络验证仍未完成。
- 下一开发重点：高层经验证双连接 Session 构造门禁；随后真实 ICE offer/answer 与 Quinn 共端口、两机 Stream Echo 测试。

## SDK 与 Transfer 分工及手动安全会话（2026-10-09）

- **SDK 不实现文件上传、文件下载、文件协议、磁盘 I/O 或 GUI。** 这些属于 `juezhong/p2p-transfer`。SDK 提供身份、手动/可选服务器信令、ICE/NAT、独立 Control QUIC 与 Data QUIC 及网络诊断。
- 本开发分支提供 `VerifiedManualSession`：过期拒绝、人工验证码与本次配对绑定、实际两条 QUIC TLS 叶证书指纹验证、Control/Data 会话 HMAC 证明，并将原始会话组装函数收紧到 crate 内部。
- 尚缺少真正 ICE 选路、网络路径共 UDP 接收复用，以及 QUIC 身份长期轮换/凭据撤销；SDK API 仍允许低层 `quinn::Connection` 处理，不应误认为应用无法自行绕开 SDK 的高层授权。正式安全会话需要强制走 `VerifiedManualSession` 门禁。
- 以后开发完成和 CI 结果优先同步评论到 SDK 长期文档 PR #2；Transfer 相关依赖与业务状态同步评论到 Transfer 长期文档 PR #1，**两个记录 PR 不合并**。

## M1 安全手动会话入口已合并（2026-10-09）

- [SDK PR #14](https://github.com/juezhong/p2p-sdk/pull/14) 已通过 [GitHub Actions #37912990238](https://github.com/juezhong/p2p-sdk/actions/runs/37912990238) 并 squash 合并到 main（commit `954246f`）。
- 新增 `VerifiedManualSession` 高层构造入口：在绑定独立 Control/Data QUIC 前验证配对未过期、用户明确确认的比较码属于**同一次** Session、两条实际 TLS 叶证书指纹一致、双向会话 HMAC 认证；缩小低层 `DualQuic::from_authenticated_links`/`authenticate_*` 公开范围。
- 目前仅证明了已有单元/loopback 集成测试通过；**没有**全链路生产级手动连接体验、真实双机 ICE/Quinn 共 Socket/NAT 穿透，且高层会话函数还需要单独的端到端 mTLS 双连接回归测试。不能称为已可发布 SDK。
- **职责提醒**：文件上传/下载及落盘、文件块与业务 UI 都属于 `p2p-transfer`，不是 SDK。进度和后续任务定期评论到 SDK 记录 PR #2 及 Transfer 记录 PR #1，两份记录 PR 均不合并。
- 下一步首要任务：将 ICE candidates/credentials 纳入 INVITE/REPLY，设计一个实际 UDP Socket Owner 使 ICE 检查与 Quinn 共用映射，完成真实 Stream Echo 和双机测试。

## 2026-10-09 合并式 M1 网络基础开发（进行中）

- 功能分支 `feat/m1-ice-signaling-udp-router-multistun` 同时开发：有界 ICE 描述+Session HMAC、同一 UDP 端口 Multi-STUN 一致性观察、单一 `recv_from` UDP Owner 与 STUN/ICE/QUIC 有界分包队列。详见 `docs/M1_NETWORK_INTEGRATION.md`。CI 未成功前不能声称已验证。
- **尚未实现完整 ICE Agent、ICE/Quinn 共真实 Socket 适配、ICE 检查/提名、手动 v2 携带候选、真实 NAT/IPv6/端口映射**。这些仍是首要阻塞。
- SDK 没有任何上传/下载/目录/文件块等 Transfer 业务模块。两份长期设计 PR 继续保持开放且不合并，重要状态评论到 SDK #2 / Transfer #1。

## M1 共 Socket 的真实 Quinn 适配（2026-10-09 进行中）

- 上一批 [SDK PR #15](https://github.com/juezhong/p2p-sdk/pull/15) 已通过 fmt/Clippy/测试并合并（`862eeb21`），新增有界 ICE 认证描述、Multi-STUN 和单 UDP `recv_from()` Owner。
- 新批次 `feat/m1-quinn-shared-udp-adapter` 将 Quinn `AsyncUdpSocket` 与该 Owner 的 QUIC 队列及**相同的真实 UDP Socket 发送路径**相接，禁用 QUIC bit greasing；增加同源端口 STUN 发现和真正 Quinn TLS Stream Echo 并发的 localhost 集成测试。以对应 CI 结果为准。
- **未完成**：ICE Agent、经过 STUN MESSAGE-INTEGRITY 认证的 ICE 检查/提名、真实 NAT 穿透/端口映射/公网双机测试；adapter 当前不支持 ECN/源 IP 附加信息/GSO-GRO，跨平台性能与可靠性仍待检验。
- SDK 不实现文件业务，文件/目录/上传下载均在 Transfer。长期记录 PR 的评论是跨会话开发索引。

## M1 网络核心双批次已验证（2026-10-09）

- [SDK PR #15](https://github.com/juezhong/p2p-sdk/pull/15) 合并 `862eeb21`，CI 全绿：带 Session HMAC 的有限 ICE 候选编解码、同端口 Multi-STUN 并发/映射差异报告、单 `recv_from` 的真实 UDP I/O Owner。
- [SDK PR #16](https://github.com/juezhong/p2p-sdk/pull/16) 合并 `726ad563`，[CI 成功](https://github.com/juezhong/p2p-sdk/actions/runs/37914763174)：真正 Quinn `AsyncUdpSocket` Adapter，在同一个 UDP Socket 上同时实现 STUN 探测与 Quinn TLS 双端 Stream Echo（**localhost**）。已禁止 QUIC bit greasing；首轮 Quinn API 编译错误已修复。
- **已解决的关键原型风险**：STUN/QUIC 不必使用分离的 UDP 源端口，已在单台 Linux CI 机器的环回环境证明共享实际 Socket 具备基本收发能力；但尚未证明不同 NAT/多网卡上的真实 ICE 穿透可靠性。
- **仍缺少**：标准 ICE agent 的短期 MESSAGE-INTEGRITY、双端 candidate-pair 检查/提名/consent、主机网卡候选收集、手动 INVITE/REPLY 中实际交换候选的 v2 协议、IPv6 防火墙及 PCP/NAT-PMP/UPnP、实际跨运营商/路由器的手工测试。
- **下一批开发应优先**评估并接入 Sans-I/O 标准 ICE agent（可评估 `is` crate），由现有 UDP Owner 驱动收包、发送和定时器，实现真实双方认证的 pair nomination，再让 Quinn 仅使用该 nominated address 与相同 Socket。验证 Control QUIC/Data QUIC 独立，增加高负载背压和跨平台测试。
- SDK 仍不包含文件上传、下载、文件协议、落盘或界面；这些全部属于 Transfer。两份记录型 PR 不合并，优先在 PR 评论中持续交接。

## M1 标准 ICE 连通性检查（2026-10-09）

- 新分支 `feat/m1-ice-agent-direct-checks` 引入第三方独立 Sans-I/O `is` ICE Agent（0.11.1，MSRV 1.85），通过原 UDP Owner 同端口进行真实 RFC 8445 检查；有 host↔host 双 Agent 授权提名的 localhost 测试，超时应为 NoDirectPath。
- 此模块暂只针对一个 IPv4/IPv6 同族 host candidate；需要 CI 成功后才算验证。ICE 候选收集、srflx/prflx 映射整合、多网卡、真正跨 NAT、双 QUIC 控制/数据 Session 与 ICE nominated pair 一体化、consent 保活与 restart 仍未完成。
- 继续保持 SDK 与 Transfer 业务独立，记录 PR #2/#1 不合并。

## 四批 M1 网络能力已合并：ICE 正式提名 + Quinn 同 Socket（2026-10-09）

**完成并有 GitHub Actions 证据**：
- PR [#15](https://github.com/juezhong/p2p-sdk/pull/15) `862eeb21`：ICE 候选/凭据会话 HMAC 编解码、多 STUN、单 UDP Owner，CI 通过。
- PR [#16](https://github.com/juezhong/p2p-sdk/pull/16) `726ad563`：真实 Quinn AsyncUdpSocket 共享 STUN UDP Socket、Quinn TLS Echo，CI [#37914763174](https://github.com/juezhong/p2p-sdk/actions/runs/37914763174) 通过。
- PR [#17](https://github.com/juezhong/p2p-sdk/pull/17) `a9b0265f`：标准 Sans-I/O `is` ICE Agent 连接单 UDP Owner，运行 RFC 8445 双端 host candidate integrity/check/nomination，NoDirectPath 测试，CI [#37915693838](https://github.com/juezhong/p2p-sdk/actions/runs/37915693838) 通过；最低 Rust 版本更新至 1.85。
- PR [#18](https://github.com/juezhong/p2p-sdk/pull/18) `fcb48d16`：**跨模块集成测试**两端正式 ICE nominated pair 后使用**完全相同 UDP Socket**完成独立 Control/Data Quinn TLS QUIC Stream Echo，CI [#37915984880](https://github.com/juezhong/p2p-sdk/actions/runs/37915984880) 通过。

**绝不可误报**：
- 上述仍是 Linux Actions 127.0.0.1 loopback 两端模拟，不是复杂 NAT 的真实公网直连成功率验证，也不是可用完整 SDK 产品。
- 当前 ICE 流程针对单个 host/IPv4 或 IPv6 同族候选；未把 ICE 凭据/候选编码真正整合进手动 INVITE/REPLY v2。还缺主机多网卡发现、srflx/prflx 收集与加入 candidate pairs、持续 consent/freshness、ICE restart/恢复、IPv6 有状态防火墙验证以及 PCP/NAT-PMP/UPnP。
- 当前 ICE/QUIC 实验测试中还需与正式的 mTLS 双向设备认证、确认状态和 HMAC VerifiedManualSession 统一组成不可绕过的完整用户配对 API；不能把独立模块通过分别的测试当成完整产品验收。
- Quinn AsyncUdpSocket 的 ECN/多网卡源 IP/GSO 等实现及高负载控制优先级需要专门验证。
- SDK 不实现上传下载、磁盘文件操作、Transfer 业务帧或 UI；这些只属于 p2p-transfer。

**下一批优先任务**：
1. 设计并实现不会让用户额外步骤的完整 Manual INVITE/REPLY v2：交换经过认证且大小有界的 ICE credentials/candidates，兼顾隐私/重放/过期；需要真实用户一次邀请一次回复完成配对和 ICE 启动。
2. 从真正本机网卡收集 host + 多 STUN srflx 候选并加入 ICE candidate pairs；独立 IPv4/IPv6 UDP owner 路径。
3. 保活、撤销、ICE restart 与双 QUIC 恢复；持续 Nomination 路径有效性验证。基于网络环境和性能数据补充可选 PCP/NAT-PMP/UPnP。
4. 开发 SDK CLI 联机 Echo/诊断测试工具（不是 Transfer），实现真实两台机器 LAN/跨 NAT 测试，并按文档登记 Windows/macOS/Linux 手测结果；无直连路径必须 NoDirectPath，不允许中继。

## 手动配对 ICE INVITE/REPLY v2（2026-10-09，开发中）

- 功能分支 `feat/m1-manual-ice-v2` 新增离线 V2 配对信令：完整带限额的 ICE credentials/candidates 随 INVITE/REPLY 一来一回交换；REPLY 绑定整份原始 INVITE 摘要，并以双方 X25519/HKDF 派生的会话密钥为 REPLY 完整性提供 HMAC。
- 测试覆盖 IPv4/IPv6 候选交换、会话一致、INVITE 候选替换检测、REPLY 候选篡改检测、过期与错误角色；待 CI 验证，不提前标记完成。
- 仍没有真实两机用户 CLI、候选发现、身份确认 UI 与完整经 mTLS 的 Session 一体化；v2 会包含 ICE 短期密码/本地 IP，不能安全公开分享，终端与日志不应自动打印原始连接码。配对仍必须独立核对六位比较码。
- 调整发布策略：SDK 仅作为库，正式跨平台用户测试/发布由 `p2p-transfer` 承担，SDK Debug PR #19 不合并。

## M1 Host/srflx 候选收集与标准 ICE 多候选对检查（2026-10-09 开发中）

- 新分支 `feat/m1-host-srflx-gather-and-ice-checks`：在原 UdpOwner 的同一真实端口收集 host 及 Multi-STUN server-reflexive 地址，区分诊断性映射与已提名直连路径；添加 LAN-only、本地绑定限制和候选安全边界测试。
- 新增标准 ICE Agent 对多个 Host/ServerReflexive 候选检查、选中实际可达地址的逻辑；屏蔽 TURN relay，拒绝错误 ICE 角色和没有相同基础 UDP Socket 的描述。测试将包含两个 UDP Owner 加入不可达公网候选时仍通过可达 LAN host pair 提名。
- **限制**：目前只允许绑定明确本机 IP 的 UDP Owner；对 `0.0.0.0`/`::` 的真实多网卡候选需要 pktinfo/源地址选择后再开放。srflx 仅由 STUN 观察，不代表公网成功。缺少真实跨 NAT、防火墙、持续 consent/ICE restart 和安全配对的一体化用户入口。
- SDK 仍仅是网络库；最终用户可执行 Debug/Release 都通过 Transfer 提供。开发完成进展记录到两份长期文档 PR 评论。

## 手动 v2 → 标准 ICE → 双向 mTLS → 双 QUIC 安全会话完整环回门槛（2026-10-09 开发中）

- 此分支新增 `manual_full_integration.rs`，模拟用户显式确认六位校验码：同一实际 UDP Owner Gather → v2 INVITE/REPLY 交换 ICE 描述并验证 → 双端标准 ICE nominated pair → 原 UDP Socket 上分别建立 Control/Data QUIC → 双向 TLS 证书验证、双连接 Session HMAC → Control/Data 双 Stream Echo → 单独关闭 Data 后 Control 继续 Echo。
- 自动化测试在 localhost Linux 上运行；通过只表示完整模块链路本地可用，不等于真实双机跨 NAT 或证明自动用户确认 UI 安全。证书在测试中由代码生成和显式信任，真实使用需匹配配对安全信任与长期身份机制。
- 下一阶段：候选端点/网卡发现、真实 Internet NAT 路径、STUN 暴露的地址是否可达、ICE consent/restart、Transfer CLI 全链路连接/文件传输及五平台用户验证。

## 手动连接码携带 TLS 实际证书信任根（2026-10-09，开发 PR）

- 因用户不应另行拷贝证书/密钥，`manual_ice_v2.rs` 新增包含**公开 X.509 DER 证书**的 INVITE/REPLY API（证书长度上限 2KiB，整个识别码有界）。原先仅有证书指纹无法让初次使用者配置标准 rustls 信任根；本改进让收到完整 V2 并核对配对码后可把严格匹配的对端 DER 放入 RootStore，而不跳过 TLS 验证。
- 回复仍绑定邀请全文哈希并附 HMAC，X.509 DER 与 v1 指纹不一致时 fail closed；扩展完整集成测试从**交换码提取证书**构建双向 TLS 信任，而不再由测试直接共享证书对象。
- 实际用户必须独立核对六位配对码；连接码泄露公开证书/局域网 IP/短期 ICE 密码，不宜在日志/不可信渠道分发。未做真实双机、持久设备证书生命周期、过期撤销、Web UI。
- 最终用户 Debug/Release 仍在 Transfer；SDK 只负责库与自动化测试。

## SDK → Transfer 联合开发与发版策略（2026-10-09）

- SDK 仅作为 Rust 库，不独立发布给用户的 Debug/Release；内部保留自动化网络测试。用户五平台下载及跨 NAT 验收统一走 `p2p-transfer`（Windows x86_64，macOS x86_64/aarch64，Linux x86_64/aarch64）。
- 当前 #20、#21、#22 已合并；[PR #23](https://github.com/juezhong/p2p-sdk/pull/23) 最新 CI [#37920087927](https://github.com/juezhong/p2p-sdk/actions/runs/37920087927) 通过并合并（`b09f7e0`），完善手动配对 TLS 身份交换。
- 优先 LAN host 直连和经同一 Socket 的 Quinn，随后 IPv6/IPv4 STUN/NAT 候选，绝不实现数据 Relay/TURN；不可达路径返回 NoDirectPath。**真实跨 NAT 和两机打洞还没有经过用户验收。**
- 下一任务：SDK 生产会话的握手/ICE consent/restart/路径恢复及真实双机通信入口，与 Transfer CLI 端到端接线；用户从 Transfer 验证，不需要独立 SDK Debug。细节持续追加评论到长期记录 PR #2。

## M2 网关端口映射的 SDK 基础（功能 PR 进行中，2026-10-09）

- 开发分支 `feat/m2-nat-pmp-portmapping` 同批实现 RFC 6886 NAT-PMP / RFC 6887 PCP MAP 的 UDP 网关事务、严格 gateway/nonce/端口关联、防伪装回复和模拟网关测试；实现只有匹配当前真实 ICE/Quinn UDP Owner 端口时才允许添加 port-mapped ICE candidate。见 `docs/GATEWAY_PORTMAP.md`。
- 仍没实现 UPnP、网关自动发现、映射 lease 续期/删除、真实路由器/跨 NAT 测试；API 仅为显式网关的低层组件，暂不在 Transfer UI 默认启用。最新 Actions 未成功前不能标已验收。
- 完整 Transfer 发行继续以 CLI Go 行为对照和五架构 CI + 用户两台机器实际 NAT 穿透验证为门槛；SDK 不开发文件业务。
