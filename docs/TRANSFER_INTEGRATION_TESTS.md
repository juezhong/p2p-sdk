# p2p-transfer × p2p-sdk 集成验证清单（草案）

## 测试目标与证据

本文件仅描述 SDK 必须为 Rust Transfer 提供的可验证能力；文件业务详测由 p2p-transfer/docs/TEST_PLAN.md 管理。所有能力都是**计划**，文档写入不代表已测试通过。

每次测试记录：SDK commit/tag、Transfer commit、OS/CPU、网络场景、STUN/网关配置、选中地址族和候选对、连接事件、结果、脱敏日志、必要的 pcap。

## SDK-001：同机两进程独立会话

前提：两个 Rust 进程，独立身份与 UDP Socket。
步骤：创建 INVITE -> 加入并生成 REPLY -> 创建方确认 -> ICE 完成 -> 对端身份校验 -> control stream echo。
通过：可复现已认证的 stream 双向数据；status 能显示实际地址；关闭后释放 Socket。失败：任何隐式关闭 TLS 校验或请求 relay。

## SDK-002：IPv4 与 IPv6 双栈优先级

前提：真实可路由 IPv6 + IPv4 双栈。
步骤：交换候选并记录检查时间线，允许双方主动探测。
通过：存在可达 IPv6 时优先验证 IPv6；IPv6 不可达时有界时间内检查并选择 IPv4；不得因相似前缀误判 LAN。

## SDK-003：IPv4 NAT 直连与不可能直连的处理

前提：独立 NAT/CGNAT、不同防火墙策略。
步骤：记录 STUN srflx、prflx、候选检查、建链和失败原因。
通过：可打洞的环境直连；不能直连的环境明确报 `NoDirectPath` 且没有应用数据 relay。不能承诺所有 NAT 成功。

## SDK-004：控制与数据通道并发

前提：控制 RPC 在进行数据 Stream 持续发送。
步骤：周期调用诊断/status，再主动取消数据发送。
通过：不会因为大流量而永久饿死 control；取消任务后会话继续可用。

## SDK-005：单条 data-only QUIC 故障

前提：后续多连接能力已完成。
步骤：在 Transfer 正在传输中主动关闭一条 data connection，检查控制会话及其他 lane；尝试创建替代连接。
通过：连接状态正确报告、主会话仍可 RPC；新 UDP 五元组经过合规的验证；交由 Transfer 应用 ACK/重传保证最终文件完整。

## SDK-006：身份错误、过期/重放信令、无中继

步骤：提供错误指纹、过期邀请码、重复 nonce、伪造候选、不可用 STUN、不可达直连；抓取服务端网络流量。
通过：身份错误立即拒绝，错误原因结构化，凭据脱敏；服务器没有业务数据代理，直连失败不降级为明文或 relay。

## SDK-007：双信令模式

前提：手动模式与可选纯信令服务就绪。
步骤：断开信令服务测试手动模式；重新运行，测试自动交换 ICE 信息和 Trickle ICE。
通过：两种模式进入相同的 ICE 与身份验证流程；信令仅交换结构化控制消息。

## SDK-008：异常结束与平台覆盖

步骤：Linux amd64/arm64、Windows amd64、macOS amd64/arm64 上测试退出、取消、休眠/恢复、网卡变化；监控 Socket、任务和端口映射残留。
通过：不存在长期悬挂资源，错误分类稳定；不能通过 localhost/CI 环回来代替实际 NAT 覆盖。

## 与开发阶段对应

- SDK M1：SDK-001、基础 SDK-006。
- SDK M2：SDK-002、003、008。
- SDK M3：SDK-007。
- SDK M4 + Transfer 多数据通道阶段：SDK-004、005、全部回归。

参见：[Transfer SDK 契约](TRANSFER_REQUIREMENTS.md)。
