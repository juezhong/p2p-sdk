# ICE 与 Direct-only 连通性策略（草案 v0.3）

## ICE 能解决什么、不能解决什么

ICE (RFC 8445) 负责候选收集、形成候选对、使用 STUN 进行连通性检查、提名并选择直连路径。**ICE 并不保证两台终端一定能互通**：防火墙严格阻断、NAT 映射行为不匹配、UDP 被封锁时可能检查全部失败。禁用 TURN 意味着没有可用直连路径就必须失败。

STUN 是 ICE 使用的协议，既可通过服务器发现映射（srflx），也用于双方的连通性检查。UPnP、PCP、NAT-PMP **不是 ICE 自动包含的功能**，由独立端口映射模块实现并为候选收集提供补充入口；这类入口如何登记为 ICE 候选需明确基础 Socket/相关地址关系并实测互操作性。

## 确定的连接要求

1. 双方有可用 IPv6 时优先尝试 IPv6 直接通信；有状态 IPv6 防火墙可尝试双向主动检查，不能绕过显式 deny。
2. IPv4 和 IPv6 的可用局域网直连均应支持。重叠的私有 IP 网段或 IPv6 前缀 **不能** 单凭相似性判断为同一 LAN，必须连通性检查确认。
3. 任一方无可用 IPv6 或 IPv6 检查失败时自动选择已验证的 IPv4 可达路径。
4. IPv4 依次考虑 host（含 LAN）、STUN srflx、peer-reflexive 与可选网关端口映射入口；连通性检查应协调/并发调度，**不采用长时间串行阻塞等待某地址族**。
5. 只允许 host / server-reflexive / peer-reflexive 等直连候选及经验证的显式映射入口；禁止 TURN relay candidate 与业务流量中继。
6. 优先级属于选路 **策略**，不能先于真实连通性验证宣布成功。选路偏好应可配置，避免不良 IPv6 路径长期阻塞可用 IPv4。

## 候选路径与能力边界

| 情况 | 预期行为 |
| --- | --- |
| IPv6 全球可路由且双方防火墙允许 | 优先验证 IPv6 直连 |
| IPv6 有状态防火墙 | 双向发起检查，尝试建立允许的回程状态；可能失败 |
| IPv4/IPv6 局域网 | 使用 host candidate 进行连通性检查 |
| IPv4 NAT | STUN + ICE 检查 + UDP hole punching，含 prflx 发现 |
| 网关允许 PCP / NAT-PMP / UPnP | 可选创建 UDP 映射，登记并验证候选 |
| UDP 全封锁或所有候选均不可达 | 显示 `NoDirectPath` 类诊断，**不提供偷偷中继的 fallback** |

## 通路保持与切换

- 选择成功的地址对不是永久保证：NAT 超时、休眠、地址更换、IPv6 前缀变化都可能失效。
- ICE consent freshness / keepalive、应用会话心跳、ICE restart 的具体配合需选定实现后验证。
- 重新连接必须重新验证可达性，不能仅以旧映射地址复用作为成功依据。
- TCP 应用经 QUIC Stream 运行；**UDP 打洞结果并不能直接拿来做独立 TCP 打洞**。
- 对外区分 `Checking`、`DirectPathValidated`、`TransportAuthenticated`、`Failed` 等状态。

## 验收准则

在真实网络或受控 NAT 测试拓扑中覆盖双栈 IPv6、IPv6 防火墙、IPv4-only、同局域网、双 NAT、CGNAT、网络切换与 UDP 封锁；不能只在 localhost 上验证。

## 规范依据

- RFC 8445 ICE: https://www.rfc-editor.org/rfc/rfc8445
- RFC 8489 STUN: https://www.rfc-editor.org/rfc/rfc8489
- RFC 8838 Trickle ICE: https://www.rfc-editor.org/rfc/rfc8838
- RFC 8863 ICE PAC: https://www.rfc-editor.org/rfc/rfc8863
