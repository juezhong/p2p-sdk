# M1 网络集成批次：ICE 描述、同端口 Multi-STUN、UDP I/O Owner

## 本批次实际实现

1. **ICE 描述编解码**：带角色的 ICE ufrag/password，最多 32 个 host/srflx/prflx/port-mapped UDP 候选，IPv4/IPv6、priority、端口，严格长度/版本/地址校验。此模块只产生和解析描述对象，不是真实 ICE Agent。
2. **会话 MAC 的 ICE 元数据封装**：使用原来的 `SessionCredentials` 作为 HMAC-SHA256 密钥，域分离，将 Session ID / ICE role / payload 绑定并验证。错误密钥、角色、session、截断或篡改 fail closed。ICE 密码与 IP 不加密，传输媒介必须考虑隐私；此封装尚未编码到现有 Manual INVITE/REPLY v1 码之中。
3. **Multi-STUN**：同一绑定 UDP Socket 向多个 STUN 服务器并发发送 Binding Request，按远端地址+随机 Transaction ID 核验回复，对映射是否一致作观察。仅是诊断信号，不保证 NAT 可达；支持 IPv4 或 IPv6 同地址族，拒绝重复及畸形输入。
4. **统一 UDP 收包 Owner**：真正绑定 Tokio UDP Socket，仅一个后台循环调用 `recv_from`，按现有 RFC 9443 分类将 STUN 事务答复/待交 ICE 报文/QUIC 报文送至有界队列。多个 STUN 请求共用该 Socket/本地端口，并有超时/最大事务数限制。
5. **集成测试**：localhost 模拟两台 STUN Server 返回不同/相同 NAT 映射；测试源端口共享、UDP Owner 上的并发 STUN、转发 ICE/QUIC 样本、过期/错误/坏角色/错误密钥/异常长度。

## 仍未完成的关键连接组件

- Quinn 目前**没有**从 UDP Owner 队列取走真实 QUIC 报文的 `quinn::AsyncUdpSocket` 适配器，也没有接入 Quinn 发包路径。所谓 UDP Owner 只是部分网络 I/O 原型，尚不能把 QUIC 流量送入真实 Quinn。
- STUN 事务仍是 Binding discovery，不包含 RFC 8445 的 ICE MESSAGE-INTEGRITY、角色冲突、checklist / pair nomination / consent freshness / retry；未实现真正 UDP 打洞。
- 旧 Manual INVITE/REPLY v1 还不包含 ICE 描述；后续需要在认证 transcript 内实现完整非 Trickle Offer/Answer 编码（可用 v2 版本号），才能让用户一来一回完成真正的连接。
- `multi_stun::query_same_socket` 只用于独占该 Socket 的诊断场景；当 UDP Owner 正在运行时，必须使用 `query_via_owner`，不可另开 `recv_from` 与 Owner 竞争。
- 还没实现 PCP/NAT-PMP/UPnP、IPv6 防火墙实测、QUIC 多通道实际 NAT 路径认证、跨 Windows/macOS/Linux 的真实互联网测试。
- 此批次没有任何文件业务代码：文件上传/下载严格属于 p2p-transfer。

## 下一阶段的整体 Gate

1. 基于目前 Owner 编写真实 Quinn AsyncUdpSocket 适配，并在 localhost 证明 STUN/ICE 检查与独立 Control/Data QUIC 能在同一 IPv4/IPv6 UDP 路径上共存，禁用 QUIC bit greasing。
2. 选定并接入标准 ICE agent：Gather、candidate pairs、connectivity checks、nomination、consent freshness。确保同一 UDP 端点实际通信，不存在“STUN 用 A 端口，Quinn 用 B 端口”。
3. 把 ICE 元数据装入手动 INVITE/REPLY v2，明确限制大小、加密/认证隐私与比较码绑定；执行双机 direct-only Stream Echo。
4. 再推进网关端口映射、ICE restart、跨 NAT 性能和错误码，并使用真实双机手工测试验收。

整个批次的验收以该功能 PR 最终 GitHub Actions 结果为准。文档不代表已运行真实 ICE/Quinn NAT 测试。
