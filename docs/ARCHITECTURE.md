# 架构设计（草案 v0.3）

> 状态：目标架构；模块和 API 尚未实现。任何库选型、类型命名、Socket 方案都以原型验证为准。

## 设计原则

1. **Connectivity 与 Transport 解耦**：ICE 负责 UDP 直连路径选择；QUIC/其他 UDP 加密协议负责业务传输。
2. **信令与连接解耦**：手动双向连接码、自动 Rendezvous 共享协议模型与同一 ICE 引擎。
3. **Direct-only**：无 TURN、无应用数据中继，也不允许在“无法直连”时悄悄经信令服务转发。
4. **安全默认开启**：绑定对端身份、会话凭据与连接结果，所有业务数据端到端加密。
5. **可观测与可测**：诊断在 SDK 内，应用共享事件、状态与报告结构。

## 目标模块

```text
p2p-sdk (Rust crate)
├── identity/        本地身份、对端指纹/密钥绑定、信任策略
├── signaling/       INVITE/REPLY、会话封装、Rendezvous 消息抽象
├── discovery/       IPv4/IPv6 host、STUN srflx、网关端口映射
├── connectivity/    ICE Agent、候选/优先级、路径检查与恢复
├── netio/           UDP Socket 管理、报文区分/分发
├── transport/       QUIC adapter；未来其他加密 UDP adapter
├── session/         统一会话、状态机、超时、取消和资源回收
└── diagnostics/     路径事件、连通性状态与脱敏报告
```

上述模块先作为一个 crate 内的模块实现；不要在尚无稳定 API 时拆成多个发布 crate。

## 连接生命周期

```text
Created -> Gathering -> Signaling -> Checking -> Selected
                                                   |
                                            Authenticated
                                                   |
                                                Connected
                                                   |
                                           Degraded / Restart
                                                   |
                                               Closed / Failed
```

- 收集 host、STUN server-reflexive 候选，按配置叠加端口映射可达入口。
- 交换 ICE 凭据、候选与临时/持久设备身份资料；会话须绑定防重放的随机标识。
- ICE 检查成功并 nomination 后才能认为存在可用的 **UDP 路径**；之后还需验证传输后端完成认证加密握手。
- 网络切换、映射失效后应触发路径重新检查/ICE restart（确切策略待验证），不承诺永久连通。
- 无可达路径时返回显式错误与诊断原因，**不发起中继**。

## UDP Socket 所有权：必须先通过原型

ICE 对候选对进行 STUN 检查时使用的本地 UDP 映射和 QUIC 后续收发的映射必须一致或经过重新验证。不能分别创建互不相关的探测 Socket 与 QUIC Socket，再假定公网映射相同。

待评估方式：
1. 由 NetIO 独占底层 UDP Socket，按 STUN/QUIC 报文类型分发到 ICE 和 QUIC（需要研究 Quinn 的 `AsyncUdpSocket`）。
2. 在 ICE 检查结束后将相同已绑定 UDP Socket 的所有权交给 QUIC；明确连接监测、保活、ICE restart 的局限。

不能让两个不协调的任务同时 `recv_from` 同一个 Socket。IPv4/IPv6 可能需要分别绑定 Socket；双栈行为必须按 OS 测试，而不是默认所有平台一致。

## 传输接口与应用边界

第一阶段仅承诺一个经过认证、加密、可用的 QUIC 会话原型及 Stream/Datagram 验证。最终公开 API、错误模型、trait 设计需要在原型后确定。

- `p2p-transfer`：消费可靠 Stream，管理文件协议、校验与传输恢复。
- `p2p-tunnel`：消费可靠双向 Stream，对接 TCP/SSH 字节流；SSH 认证仍由 OpenSSH 完成。
- `p2p-net`：消费经认证的包通道；QUIC DATAGRAM 和其他加密 UDP 后端待基准测试。TUN 和路由属于应用。
- 三个应用都必须交付 CLI/TUI/GUI 三种入口，但共享单一业务内核；SDK 不含 UI 依赖。

## 不在第一版范围

TCP ICE、完整 Mesh 路由、强制账号服务、TURN/其他业务中继、VPN、文件系统、桌面 GUI、未经验证的“最优吞吐”声明。

## 参考

- ICE: https://www.rfc-editor.org/rfc/rfc8445
- Trickle ICE: https://www.rfc-editor.org/rfc/rfc8838
- Quinn: https://docs.rs/quinn/latest/quinn/
- 独立 Sans-I/O ICE 候选: https://docs.rs/is/latest/is/


## 2026-10-10：被动 QUIC / ICE 共 socket 生命周期（SDK PR #70 待 CI）

JOIN 人工等待期间在每个已绑定 UdpOwner 上创建 Quinn Endpoint，先于有限 ICE timeout 接纳入站 QUIC。所有 QUIC 仍由唯一 recv loop 分包。若先收到经过 ICE MESSAGE-INTEGRITY 或 HMAC Punch 的流量，进入常规认证 ICE 竞速，并复用已有 Endpoint（严禁二次接管 QUIC 队列）。若先完成 QUIC 双向 mTLS、Session HMAC 与创建方的 Control-path 选择消息，可使用实际 QUIC 验证过的同一 UDP Owner 建立 Control，不再伪称发生过 ICE nomination。失败/取消关闭所有落选 Endpoint 和 UDP Owner，显式清理网关租约。
