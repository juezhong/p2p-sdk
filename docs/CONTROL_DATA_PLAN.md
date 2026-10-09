# 控制面与数据面分离：SDK 与 Transfer 实施约束

## 三种分离不能混淆

1. **网络层复用**：每个经过验证的 ICE 数据候选使用统一 UDP I/O Owner，让 STUN、ICE 和 QUIC 的实际本地 IP/端口一致，按 RFC 9443 分包。这是共享 UDP 端点，并不是共享文件业务协议。
2. **应用控制面**：连接/身份/会话管理、业务 RPC、任务取消、ACK、状态与诊断使用专门的控制 Stream 或控制 QUIC 连接；不发送文件块作为控制消息。
3. **业务数据面**：文件块经专用数据 Stream；未来可增加独立认证 data-only QUIC connections。SSH 的双向字节流以及 Net 的 Datagram 是各自应用的数据面，不复用 Transfer 的控制帧。

## 一期行为

SDK 首版优先一条经过 ICE 验证、TLS 身份认证的 QUIC 连接，提供互不混淆的 Control/Data Stream。即便二者共用 QUIC 连接和底层 UDP Socket，也属于*逻辑分离*；需要实施流量背压和控制消息延迟测试，不能仅凭 Stream 独立声称控制面不会被总连接拥塞影响。

## 后续多连接

Transfer 最终需要保持旧版控制面独立与最多四条独立 data-only QUIC 通道的能力。SDK 应让每个额外 UDP 数据端口独立进行有效连通性验证或设计经过检验的同端口复用机制；主连接的映射不能直接外推。应用负责文件分块调度、ACK、文件事务；SDK 负责认证 QUIC 连接和网络路径。

`src/channel.rs` 目前仅提供角色与上限约束值类型，**不代表开流、并行连接或优先级调度已经实现**。

## 最低验收

- 大文件多 Stream 发送同时周期性执行 RPC、取消和状态查询。
- 单数据 Stream 或 data-only QUIC 故障不静默终止可用的主控制会话。
- 确认数据通道的身份绑定和 NAT 映射真实性，抓包不经过 relay。
- 统计控制 RPC P95 延迟、吞吐、应用 ACK 推进、队列和连接内存。
- 真实 SDK ICE/Quinn 原型尚未完成，这些验收均为后续任务。

参见 [ADR-0002](decisions/0002-ice-quic-udp-endpoint.md)。
