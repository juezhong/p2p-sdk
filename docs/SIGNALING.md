# 信令与配对设计（草案 v0.3）

## 信令不是中继

信令只负责配对、交换身份材料、ICE 凭据、候选地址和能力协商；应用数据必须经已验证的 P2P 直连路径传送。信令服务器不承担通用字节流、TCP/UDP 代理、TURN、文件或 VPN 数据中继。

## 双模式

### Manual：离线手动 INVITE / REPLY

1. A 收集候选和身份材料，生成含 session ID、时效、ICE 凭据、能力与指纹绑定的 INVITE。
2. B 校验 INVITE、生成本地候选和 REPLY；用户将 REPLY 交回 A。
3. 双方依据完整候选、凭据、ICE 角色和认证材料执行检查；选路成功后建立经对端身份验证的加密传输。
4. 不依赖自建 Rendezvous 服务。STUN 地址发现仍可能请求第三方 STUN 服务；完全离线场景应可使用 LAN host candidate。

手动模式优先采用非 Trickle 的完整候选交换；若一方候选后续变化，可能需要再次交换新码或重新协商。INVITE/REPLY 格式、长度、认证字段以及旧 `p2p-friend` 协议互通均待设计，不能假定现有 P2PF 连接码兼容 ICE。

### Rendezvous：可选纯信息交换服务器

1. A/B 连接信令服务器，进行设备/会话认证与对端定位。
2. 服务器投递候选、ICE 凭据、连接状态；可使用 Trickle ICE 随发现随发送。
3. 选路与业务连接仍由双方端点直接完成。
4. 信令中断后既有直连是否保持由端点状态机决定；不得切换到服务器转发。

## 两种模式共用的协议概念

```text
SessionId / Nonce / Expiry
PeerIdentity / Fingerprint / TrustProof
IceParameters: ufrag + password + role
Candidates: family / protocol / type / address / port / priority / related address
Capabilities / Version
Messages: Offer, Answer, CandidateUpdate, EndOfCandidates, Abort
```

这是概念模型，不是已确定的 wire format；最终格式必须定义长度上限、解析规则、防重放、版本协商与错误处理。手动连接码可选择一次性会话密钥/指纹绑定；不应把公开可分享的“设备 ID”当作秘密认证因子。

## 身份和 ICE 的不同职责

- 设备公钥/会话指纹：回答“对方是不是预期的人”。
- ICE `ufrag/password`：保护连通性检查消息，不自动证明长期设备身份。
- Candidate：描述“可以尝试从哪里连接”。
- Signaling：负责“把上述信息安全送到对端”。

## 服务端边界和验证

- 使用严格的消息 schema；拒绝任何任意 payload 转发的代理通道。
- 消息大小、频率、连接数、TTL 受限；日志不得保留密钥。
- 服务器不可解密最终业务数据；若还需保护候选/IP 元数据，另行设计信令 E2EE。
- 端到端测试抓包确认业务传输不经过服务器。
- server 不在线时手动模式继续工作。

参考：https://www.rfc-editor.org/rfc/rfc8838
