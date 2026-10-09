# STUN UDP 网络探针：范围与安全边界

## 当前实现

`src/stun_client.rs` 的 `discover_mapping(server, options)` 使用 Tokio 临时 UDP Socket、OS CSPRNG 提供的 96-bit Transaction ID、RFC 8489 STUN Binding 编解码，查询服务器观察到的映射地址。支持 IPv4/IPv6 服务器地址、带上限的重试/超时、检查回包源地址与事务 ID。

**这不是 ICE Agent，不执行 NAT 打洞或 QUIC 连接；返回值不是直连保证。**

## 关键网络限制

该探针创建并销毁独立的临时 UDP Socket。NAT 绑定通常与 Socket、端口、远端地址有关，因此查询得到的外部映射不能被后续另一个 QUIC Socket 直接当作已验证候选。它只供地址发现/诊断实验和测试；未来 ICE/QUIC 必须由同一网络 I/O 所有者协调，或验证新 Socket 的连通性。

`stun_client` 独占该 Socket 的接收端，不与 Quinn/ICE 并行从同一个 Socket 读取，不会吞掉二者报文。正式集成前不能把临时探针复制为共享 Socket 上的接收循环。

## 安全边界

- STUN 服务器不是受信任的 P2P 身份提供者；响应仅是地址观测。
- 校验 96-bit 随机事务 ID 和精确返回源 SocketAddr，拒绝匹配失败或格式错误的回应。
- UDP 源地址可能被伪造；结果不能用作用户认证或唯一连接安全判断。
- 限制本地内存（固定接收缓冲区）、每次尝试超时、总重传数。
- 不使用 TURN/relay；不转发用户业务数据。
- 日志默认不得记录长期密钥、ICE 密码或邀请码；公共 STUN 服务器能观察到查询者的公网端点。

## 自动测试

本地 mock STUN 服务器覆盖：IPv4 查询成功、伪造来源和错误事务忽略、使用相同 ID 重试、超时、参数拒绝。其他 IPv6 编解码测试位于 `src/stun.rs`。

## 后续

- ICE Agent 和 QUIC 同 UDP 映射集成实验。
- 在可控网络中覆盖 IPv6/IPv4 双栈、NAT 和防火墙。
- 独立完成 TLS/QUIC 对端身份验证与 Stream Echo。
