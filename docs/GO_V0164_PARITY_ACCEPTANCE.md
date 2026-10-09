# Go p2p-friend v0.16.4 → Rust SDK / Transfer 能力对等验收（阻塞稳定发布）

目标：实现与 [Go p2p-friend v0.16.4](https://github.com/juezhong/p2p-friend/blob/main/README.md) 一致的**用户可感知行为**，无需兼容 Go 线协议，也不要求 Rust 完全采用 Go 网络算法。支持离线双机手动配对，不使用 TURN/文件中继。不能用本机环回 CI 代替真实网络验收。

## 三层边界

- **SDK（网络基础）**：单 UDP Owner、IPv4/IPv6、多网卡候选、Multi-STUN、网关映射、安全打洞/ICE、QUIC/mTLS/会话身份、Control+Data lane 组网、链路保活、故障检测、ICE restart/应用会话重新认证和重建、网络诊断。不能把状态机重新放到 Transfer 中。
- **Transfer Core（业务传输）**：单任务仲裁、协议 RPC、最多四条经 SDK 认证的数据连接上的 chunk 分配与重排、ACK、重传与原子提交、取消、进度、权限控制。
- **Transfer CLI（表现）**：无参数连接菜单、Unicode/空格/绝对路径与 Tab、status/help、目录导航、友好提示。GUI/TUI 独立完整界面暂缓，不能让 UI 决定网络可靠性。

## SDK 必须逐项通过的能力（缺任何一项不得宣称 Go 对等）

| 能力 | Go v0.16.4 实际行为 | Rust SDK 当前状态（2026-10-10） | 验收门槛 |
| --- | --- | --- | --- |
| QUIC 长时间空闲连接 | 15s PING / 60s max idle；健康连接无限期刷新 | **已配置**：双端 10s PING / 120s 有限 timeout，38s 控制+数据环回通过（SDK PR #27） | 同 LAN 2h/24h idle soak、失联时正确超时与无 CPU busy loop |
| 多网卡与 IPv4/IPv6 | 多 endpoint + 全部候选持续竞争、IPv6 优先但 IPv4 不饥饿 | 当前 Transfer 只自动选单一 UDP 本地接口 | 多 NIC、跨地址族候选同时 CHECK，选中连接实际源地址与提名一致 |
| STUN / IPv4 NAT | 多 STUN 映射发现；安全 UDP punch、动态 prflx | Multi-STUN / 同 UDP Owner / ICE Host+srflx 基础，未完成动态 prflx 或现场验证 | 不同路由器、CGNAT、端点依赖映射、UDP 封锁；无直连时报告 NoDirectPath |
| IPv6 有状态防火墙 | 双向 UDP 安全探测，全球路由 IPv6 优先 | 单地址族 ICE 基础，无全路由策略 | 双栈下 Stateful firewall 允许回程时 IPv6 直连、否则快速尝试 IPv4 |
| 网关显式映射 | PCP/NAT-PMP/UPnP 可用则尝试、失败仍保留其它有效路径 | PCP/NAT-PMP 编解码/查询原型，尚无自动网关发现/UPnP/续租 | 真实网关发起/续租/撤销，合法映射加入候选且与实际绑定 UDP 一致 |
| 多独立 QUIC | 主 Control 和最多四条 DATA 连接；可用 lane 数减少不退出会话 | 目前仅固定独立 Control QUIC + Data QUIC 两条 | 1~4 lane 独立认证、按需建立、Data 单链断开不影响 Control |
| Data 失效恢复 | 背景修复 loop + authenticated re-dial + 5-tuple 独立源端口优先 | **已新增** typed Data/Control 断链观察接口；尚未重新拨号/认证/替换 data slot | 单 lane 断开期间继续 status，补回 lane 且不丢未确认业务数据 |
| Control/网络路径失效 | 主控制断链 Go 现有实现也会结束会话；Rust 对等目标可进一步提供重连会话 | 尚无 ICE restart/路径切换和 Session 重新认证 | 故障显式状态、路径变化后仅经重新 ICE 和 mTLS/会话鉴权恢复；不伪报同一原始 QUIC |
| SDK 诊断 | candidate、映射类型、UDP 源端口、QUIC lane 数/方向、传输状态 | 只提供基础 endpoint / close_reason | 稳定脱敏诊断 API / status 数据；日志不泄露邀请码/HMAC/私钥 |
| 安全身份约束 | Go TLS + token/证书指纹；离线手工信令 | Rust 手动 v2 + 双向 TLS/HMAC + 人工 SAS，当前配对码较长 | 无可认证路径时拒绝；每条重连 lane 重新认证；明文文件传输禁止 |

## Transfer 尚需通过的能力

Go v0.16.4 的 1 MiB pooled chunk、4-way 动态共享队列、64/128/256 MiB 上限内的有界重排、LAN/WAN 拥塞/ACK 自适应、Data lane 随时故障替换、远程 CANCEL、文件/目录双向、Windows/Linux/macOS 中文路径 Tab、2GiB 双向验证与 checksum，分别在 Transfer 测试与性能 PR 里证明。当前仅具备基础 PUT/GET/目录/RPC/安全落盘及单 Data QUIC；不能声称传输模型已对等。

## 连接生命周期状态机（目标）

```text
Discovering -> Checking -> Authenticated -> Healthy
                                        | 
                                        +--(Data QUIC lost)--> Degraded
                                        |     | retry authenticated Data lane
                                        |     +----------------------> Healthy
                                        |
                                        +--(selected ICE path lost)--> Reconnecting
                                              | ICE restart / signal refresh
                                              | QUIC + mTLS + session proof
                                              +----------------------> Healthy
                                              +---- budget exhausted -> Failed
```

用户主动执行 quit/对端明确 bye 才标记正常关闭；物理断网可造成暂时失联，但不应静默当作用户退出。若无法在可信边界内恢复，清晰报错和会话恢复入口，而不是永远卡住的假“已连接”。

**注意**：QUIC keepalive 的计时是不断重置的健康路径空闲计时，不是会话最大寿命；QoS/UDP 阻断/进程停止时无法保证物理连接永不失效。RFC 7675 ICE consent freshness 是与 QUIC PING **不同**的持续对端授权，需要实现并在失去许可时阻止后续应用数据。

## 实际验证证据

每一项必须保留对应 commit / CI、测试平台、内核、网络拓扑和失败阶段。真实 NAT 场景由用户在 [Transfer NAT_FIELD_TEST_RESULTS.md](https://github.com/juezhong/p2p-transfer/blob/main/docs/NAT_FIELD_TEST_RESULTS.md) 脱敏反馈。双方配对的完整 INVITE/REPLY 绝不能写入公开日志。

- 2h/24h 静置与连续 status/远端目录：控制连接保活；
- 家庭 LAN、不同 NAT、手机热点/CGNAT、IPv6 Stateful firewall；
- 拔网线/临时 UDP 封禁/路由器重启/切换 Wi-Fi/IPv4 地址变化；
- 部分 Data lane 断开后续传与 SHA-256、一方主动退出、故障未能恢复的明确告警；
- ARM64-musl RK3568、x86_64 GNU、Windows/macOS 中文路径；
- 2 GiB 文件 PUT/GET 双方向性能与一致性（单独手动性能 CI）。

对等验收以行为为准，不以 Rust crate 数量、协议名字或 PR 数量为准。
