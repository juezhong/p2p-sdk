# ADR-0002：ICE / STUN / QUIC 共用数据 UDP 端点，控制协议独立

- 状态：**架构决策已确定；实际共 Socket 适配与跨 NAT 性能尚未完成验证**
- 日期：2026-10-09
- 适用：p2p-sdk；p2p-transfer、p2p-tunnel、p2p-net 均使用统一 SDK

## 需求范围：六项都要实现

| 能力 | 目标 | 预计阶段 |
| --- | --- | --- |
| Multi-STUN 并发请求 | 可配置多服务端，使用数据通路对应 UDP Socket 收集 srflx 观测 | M1 |
| 映射一致性诊断 | 多服务端同一个本地 Socket 查询；报告同/异映射，仅为启发式诊断，不推断保证穿透 | M1 |
| STUN/ICE 与 QUIC 端口一致 | **强约束**：ICE 检查的发送/接收 UDP IP:port 即用于同一候选对的 QUIC 业务 | M1 首要阻塞 |
| PCP、NAT-PMP、UPnP | 可选网关主动 UDP 映射，验证映射端口指向选定**数据** Socket，管理续租、删除与错误回退 | M2 |
| 双端 UDP 打洞 | 标准 ICE candidate pair 连通性检查、提名、prflx 与保活；不复制 Go 自定义 HMAC punch | M1/M2 |
| IPv6 有状态防火墙打开返回路径 | IPv6 host candidate 双端主动检查，在路由/防火墙允许时直连；失败及时回退 IPv4 | M1/M2 |

这些是**目标及验收事项**，不是 2026-10-09 已实现能力。完全无可达直连路径必须清晰失败，不能使用 TURN 或任何应用数据中继。

## 决策：复用哪些部分？

- 每个*数据候选对应的实际 IP/端口*由一个 **UDP I/O Owner** 独占管理，STUN 服务器探测、ICE 同伴检查、Quinn QUIC 共享其实际绑定端口与 UDP NAT/firewall 状态。
- IPv4 与 IPv6 **可使用各自 Socket**；多网卡、多候选也可有多个已明确管理的 Socket。**不是要求所有设备、项目、网络接口永远只能有一个 Socket。**
- 报文仅由统一 I/O Owner 从底层 Socket 接收，再根据 RFC 9443 分发 STUN → ICE、QUIC → Quinn，未知报文丢弃。网络发送亦由它协调。**绝不让两个无协调的 `recv_from` 任务抢同一个 Socket。**
- 实际多 QUIC connection 若确实需要不同 UDP 源端口，**每一条源端口都应独立建立/验证候选**；不能拿主连接的 STUN 结果证明新五元组可用。MVP 优先一个经过验证的 QUIC Endpoint 的多 Stream。
- **PCP/NAT-PMP/UPnP 的控制报文可以用独立的 UDP/TCP 控制通道**，但映射的 internal UDP port **必须对应正在监听数据的 Socket**。信令 HTTPS/WebSocket 可以独立；这些独立控制通道绝不转发业务数据。
- STUN 独立诊断探针可以保留，但须明确返回的是该临时 Socket 的 srflx 观测，**不得当成实际 QUIC/ICE 地址有效性证明**。

## 为什么这样更稳定？

- RFC 8445 §2.2 指定 STUN 连通性检查应使用与媒体/应用数据**相同**的 IP/端口；不同端口的 NAT 映射和过滤可能不同（RFC 4787）。
- 共用 Socket/端口避免“STUN 测通端口 A，QUIC 尝试端口 B”的路径错配，降低 NAT 资源消耗与候选数。
- 但共享并不保证所有 NAT 可穿透；单个 I/O Owner 也可能成为实现 bug 的集中风险：必须测试队列背压、唤醒、取消、流量公平性及 Windows/macOS/Linux。
- Multi-STUN 在相同端口向不同 STUN 目标发包，观察映射稳定性；两个服务器看到一致外部端点**不是**对真实对端可达性的保证。

## QUIC/STUN 复用的一个关键配置

- RFC 9443 定义 STUN 与 QUIC 等协议同 UDP 端口的分流。
- **使用此分流方案时，所有 Quinn 端点必须关闭 `EndpointConfig::grease_quic_bit(false)`。RFC 9443 明确禁止在此场景协商 RFC 9287 `grease_quic_bit`。**
- SDK 的 `packet_demux::classify_datagram` 仅做轻量级预分流。STUN 必须由 ICE Agent 校验消息完整性与事务、候选/对端；QUIC 必须交由 Quinn 进行 TLS 和包级认证。不可将分类成功当成认证成功。
- RFC 9443 的第一字节分类适用于指定扩展条件。未来如果选择其他 QUIC 扩展/版本或启用 Bit Greasing，必须重新评估分包可行性。
- Quinn 当前提供 `AsyncUdpSocket` 与 `Endpoint::new_with_abstract_socket` 自定义 I/O 接口；仍需实际原型验证跨平台接收/写入/唤醒适配，不能只看 API 就声称方案已完成。

## ICE 实现方向

优先对 Sans-I/O `is` ICE agent 做小型原型评估：它负责 candidate pair、STUN 双向检查/提名；地址收集和 socket 收发由 SDK 层承担。仍须审查 API、依赖安全、候选类型兼容、ICE restart/consent freshness；必要时比较 `webrtc-ice`。目前**未完成选型验证**。

## 通过标准

在单个本地 UDP Socket 上完成：多个 STUN 查询、双方真实 ICE 连通性检查、Quinn TLS 1.3 对端身份认证、双向 Stream echo、ICE 持续收包/保活。不能以 mock 分类测试、一个公网 STUN 查询或 localhost echo 声称完成此项。

## 参考标准与实现

- RFC 8445 ICE: https://www.rfc-editor.org/rfc/rfc8445
- RFC 4787 NAT Mapping: https://www.rfc-editor.org/rfc/rfc4787
- RFC 9443 QUIC/STUN Demux: https://www.rfc-editor.org/rfc/rfc9443
- RFC 9287 QUIC Bit Greasing: https://www.rfc-editor.org/rfc/rfc9287
- RFC 6887 PCP MAP: https://www.rfc-editor.org/rfc/rfc6887
- RFC 7675 ICE Consent: https://www.rfc-editor.org/rfc/rfc7675
- Quinn AsyncUdpSocket: https://docs.rs/quinn/latest/quinn/trait.AsyncUdpSocket.html
- Quinn EndpointConfig: https://docs.rs/quinn/latest/quinn/struct.EndpointConfig.html
- is Sans-I/O ICE: https://docs.rs/is/latest/is/
