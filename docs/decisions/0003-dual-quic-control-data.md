# ADR-0003：控制 QUIC 与数据 QUIC 从首版起独立

- 状态：**目标架构已确认，具体网络集成和故障隔离测试未完成**
- 日期：2026-10-09
- 适用：SDK 所有应用，尤其 p2p-transfer

## 为什么不只使用不同 Stream？

QUIC 单条连接内，不同 Stream 可以独立关闭、取消和使用流量控制；但 Connection Close、传输错误与对端整个 QUIC 会话中断会影响其上**所有** Stream。因此要满足用户的“文件数据连接故障不使控制会话中断”，Transfer 从第一版起采用至少两条相互独立的 QUIC Connection。

## 正式最小拓扑

```text
authenticated P2P application session (same peer + session binding)
├── Control QUIC connection  [RPC, ACK, cancel, session, status]
└── Data QUIC connection     [bulk file data streams]
    └── optional extra independently authenticated data QUIC links (0–4)
                  ↓
          one Quinn Endpoint / UDP data socket
                  ↓
        ICE-validated UDP candidate pair
```

- **默认 1 Control + 1 Data**，额外 Data 连接由性能和实际容错测试决定，配置计数不包含首条 Data。
- Quinn 支持同一个 Endpoint/UDP Socket 复用多个 QUIC Connection；使用不同 Connection ID 做分流。不需要为了区分 Control/Data 强行额外占用 UDP 源端口。
- 共用 UDP Socket/ICE 路径降低 NAT 映射不匹配风险，但**两条连接并不抵抗 UDP Socket、NAT 映射、主机或公网路径整体故障**；此时由 SDK 重新 ICE/连接并恢复应用会话。
- 多条 QUIC 连接各自维护拥塞控制，但共享网络瓶颈。必须引入数据限速/优先级和控制延迟约束，避免数据传输压满网络造成取消/RPC 饥饿。
- 数据连接断开时，控制连接继续有效；SDK 提供 data-lane degraded/recovering/recovered 事件，Transfer 使用独立 ACK/重传保证内容正确。
- 不能把数据连接“只要 TLS 证书一致”就视为可信，需要双方握手之后绑定**应用 Session ID、双方设备身份、角色和新鲜度**，防止跨会话数据注入或旧连接误加入。绑定消息、能力协商和防重放另行设计。
- SDK 负责两个连接的建连、身份绑定、关闭与修复；Transfer 负责文件块调度、校验、应用 ACK，不在 SDK 里写入文件帧协议。

## 真实验收条件（必须实现，不可用类型检查代替）

1. 同一个本地 Quinn Endpoint 与底层 UDP Socket 发起两条不同 QUIC Connection；服务端正确识别、绑定并允许各自的 Stream。
2. 关闭 Data QUIC，仅 Data Stream 失败；连续运行的 Control QUIC RPC/heartbeat 成功；换新的已认证 Data QUIC 后恢复文件传输。
3. Data QUIC 在流量压满时，Control RPC P95、取消延迟保持在测试阈值内；对带宽和丢包做基准和对照。阈值需根据网络类型确定，不能编造结果。
4. 在 UDP Socket 被关闭、网络断开、NAT 映射变化时，两条连接都可能断开；正确触发重建，而不是虚假宣称隔离。
5. 经同一个 ICE-validated path 传输，IPv4/IPv6 且**无业务中继**，已验证的 UDP 映射与实际 QUIC 通路一致。
6. 故障注入：乱序、丢包、数据 lane 超时、用户取消、控制连接故障；无应用数据越权或流入错误 Session。

## 实现状态

当前 `src/dual_quic.rs` 只是 Quinn Connection 对的**早期内部表示**，尚无两端 Session 身份绑定、路径选取/ICE/数据 lane 恢复，也未完成真实双连接网络测试，不能直接向应用暴露为安全 SDK API。下一迭代优先完成同端点双 QUIC 连接的身份验证实验与故障注入。

参考：
- RFC 9000，QUIC connection/stream lifecycle: https://www.rfc-editor.org/rfc/rfc9000
- RFC 9002，QUIC loss/congestion: https://www.rfc-editor.org/rfc/rfc9002
- Quinn Endpoint/Connection: https://docs.rs/quinn/latest/quinn/
- UDP 与 ICE 同端口边界：`docs/decisions/0002-ice-quic-udp-endpoint.md`
