# 连通性、安全与性能验收（草案 v0.3）

## 测试方法

- 单元测试：candidate 解析、IPv4/IPv6 优先级、信令大小/版本限制、凭据过期与重放、资源回收。
- 集成测试：两个独立进程，双端协同检查，完成对端身份验证及加密 Stream echo；Datagram 路径另测。
- 网络真实环境或网络命名空间 + NAT/firewall 测试；localhost 成功不能代表 NAT 穿透成功。
- 所有测试保存脱敏日志、选中 candidate pair、连接耗时、错误分类；必要时使用抓包佐证。
- CI 不依赖易变公共 STUN 服务来宣称全网成功率；公共网络测试可独立运行。

## 核心场景矩阵

| 场景 | 预期结果 |
| --- | --- |
| 双方可路由 IPv6 且防火墙允许 | 首选 IPv6 直连 |
| 双方 IPv6 有状态防火墙 | 双端主动 ICE 检查；允许时直连，否则 IPv4 fallback |
| 仅单方 IPv6、双方 IPv4 | 正常验证 IPv4 路径 |
| IPv4/IPv6 同 LAN | 本地 host 直连成功 |
| 不同 LAN 使用重叠私网网段 | 不误选无效 LAN 候选 |
| IPv4 双端普通 NAT | 尝试 srflx/prflx 打洞，成功与否按实测 |
| 支持 PCP/NAT-PMP/UPnP 的网关 | 验证创建、使用、撤销显式映射及失败回退 |
| 对称/严格过滤 NAT、CGNAT | 尽最大可能检查；无直连时明确 NoDirectPath |
| 双方 UDP 被封锁 | 有界时限内失败，绝不使用隐式 relay |
| STUN 服务不可达 | 能使用的 host/显式映射路径仍应检查；报告 STUN 错误 |
| 信令服务器下线 | 手动模式不依赖它；自动模式提供明确错误 |
| DNS/IPv6/接口变更 | 触发适当重新检查或重连，且身份认证不降级 |
| 异常退出/取消 | Socket/映射/任务按设计回收，避免资源泄漏 |

## Direct-only 与 E2EE 证明

- 配置禁用 TURN relay candidate；对连接候选进行类型检查。
- 使用抓包/流量审计，确认没有业务 payload 被发送给 Rendezvous 服务。
- 用错误身份/伪造指纹连接，必须拒绝；不得跳过 TLS/端到端加密。
- 报告不得泄露完整邀请码、会话密码或长期私钥。
- 服务端提供任何非 schema 白名单消息的转发接口都应视为安全设计违规。

## 指标（先建基线，不预设伪造指标）

连通率、候选检查耗时、QUIC 握手时间、RTT、CPU、RSS、丢包/重传、网络切换恢复时间。记录 OS/网络/路由器/防火墙配置与测试时间；保持与旧 Go 基线可比较。

## 报告结构（计划）

```json
{
  "mode": "manual",
  "status": "direct_path_validated",
  "selected_family": "ipv6",
  "candidate_type": "host",
  "transport": "quic",
  "relay_used": false,
  "warnings": []
}
```

这是结构示意，真正的报告应包含结构化错误、时间戳、观测来源与隐私分级。
