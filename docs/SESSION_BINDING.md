# QUIC 双连接应用会话绑定（M1 开发记录）

## 本轮实现

- `src/session_binding.rs`：在已完成 TLS 认证的 QUIC 连接上，独立绑定 Control 或 Data 角色、16 字节 Session ID 与双方持有的 32 字节会话密钥。
- 通过随机 client/server challenge 和双向 HMAC-SHA256 验证；两个方向使用不同域标签，避免反射。
- Responder 的共享 `ReplayGuard` 只接受校验成功的 nonce，保留有界历史；角色、Session、密钥、方向或 MAC 不匹配时拒绝。
- `DualQuic::from_authenticated_links` 只组合通过应用层握手、角色正确、会话 ID 一致且不是同一 Connection 的两个链接。

## 安全与接口限制

**这不是设备的长期身份认证，也不是可投入生产的完整 Session。** 需要上层在两个 QUIC 连接上分别验证 TLS 对端设备身份，且**与预期的同一设备公钥/证书绑定**。拥有会话密钥的另一个参与者仍可完成 HMAC，应当将会话密钥安全交换给单一授权设备、保证随机性并限制有效期；不能使用固定示例密钥或未经核验的 signaling 消息。

当前不支持：凭据自动生成/安全销毁、长期设备密钥、会话过期与撤销、TLS 身份到应用 Session ID 的绑定、控制面权限授权、数据重建/ICE、跨平台压测。

HMAC 提供应用层链路占有证明，不代替 Quinn TLS 1.3、ICE integrity 或实际路径验证。所有凭据和 nonce 不记录到普通日志。

## 下一阶段 Gate

- 两端 Quinn loopback 的 Control/Data 两条独立连接分别完成握手，并用共享 ReplayGuard 证明同一 Session。
- 错误会话 ID/角色/密钥、重复 nonce、握手超时和数据连接恢复时旧凭据的拒绝测试。
- 实现永久设备身份绑定、Session 发放/过期/撤销、密钥轮换，随后才开放生产级 Session API。
- 单 UDP Socket 的 ICE/Quinn 共端口、真实两机 IPv4/IPv6、NAT 和无中继证明。

相关：`docs/decisions/0003-dual-quic-control-data.md` 和 `docs/SECURITY.md`。
