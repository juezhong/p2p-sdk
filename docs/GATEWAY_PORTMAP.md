# M2 可选网关端口映射：NAT-PMP / PCP（RFC 6886 / RFC 6887）

## 设计约束

SDK only。Transfer 不能实现 NAT 协议，也不得暴露文件中继；网络候选仍统一交给标准 ICE Agent 认证检查和提名。

此阶段采用**调用者明确提供的受信任 LAN 网关地址**：端口映射请求通过同一个本地 IP 的临时 UDP 管理 Socket 发出，但请求映射的内部 UDP 端口等于 SDK/Quinn 实际正在使用的 UDP Owner 端口。管理 Socket 自身不承载 QUIC 数据、也不共享 ICE 收包循环，因此不会错误地映射一个与 QUIC 无关的内部端口。

### 已实现的低层能力

- `nat_pmp::request_udp_mapping`：先按 RFC 6886 获取网关外部 IPv4，再创建 UDP 映射；检查网关 source IP/port、回复 opcode、internal port、granted external port/lifetime；错误/拒绝/超时均 fail closed。
- `pcp::request_udp_mapping`：按 RFC 6887 构建 IPv4-mapped IPv6 / native IPv6 的 MAP 请求，使用随机 96 位 nonce，验证来源、nonce、UDP protocol number、internal port、external address 与寿命，并拒绝错误回复。
- `ice_gather::add_portmapped_candidate`：只有网关返回的映射确实匹配当前 ICE host/Quinn UDP Owner local IP/port 才加入 port-mapped candidate，防止错误把另一个 UDP source port 的映射用于 QUIC。
- 模拟网关 UDP 测试包括正确映射、错误来源、错误 nonce、超时、重复候选、错误本地 IP/port 和 IPv4/IPv6 地址编码。

### 尚未完成，不能算真实网关穿透可用

- 还没有自动、安全地发现默认网关、配置受信任路由器以及映射续租/删除/网关重启检测（短期映射不能假设永久有效）。
- 当前 API 是**显式网关低层构件**，尚未在 Transfer 无参交互 CLI 中自动启用。
- 未支持 SSDP/UPnP IGD；无法保证每台路由器或运营商支持 PCP/NAT-PMP，也不能解决 CGNAT 的所有情况。
- 映射地址仍必须和 HOST、STUN srflx 等候选一起交给标准 ICE 带认证 connectivity checks；不成功必须输出 `NoDirectPath`，无 TURN/data relay。

## 后续验收

1. 跨 Windows/macOS/Linux 自动验证这两个 SDK 构件与 gateway 模拟器；
2. 安全网关发现、并发 PCP→NAT-PMP→UPnP 策略和租约续期；PCP/NAT-PMP 的成功映射加入同一个真实 UDP Owner 的 ICE candidate list；
3. 通过 Transfer 的五架构应用包进行用户双设备 LAN/公网实际验证（SDK 不单独发布用户 Debug）。
