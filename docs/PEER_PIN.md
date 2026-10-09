# 手动配对的真实 QUIC 证书指纹与用户确认门禁（M1）

## 已实现的基础

- `PeerCertificatePin::verify_connection` 在 Quinn TLS 握手成功后，从 `Connection::peer_identity()` 提取 Rustls 实际对端证书链中的叶证书，计算 SHA-256 并与手动 INVITE/REPLY 声明的证书摘要比较；缺失、未知类型、空证书链、不匹配均拒绝。
- `ManualConfirmation` 保存 Session ID 和 6 位人工比较码，默认未确认；只有 UI 让用户从独立可信渠道核对并显式确认相同数字后，才能通过 `ensure_confirmed` 检查。
- 真实 Quinn loopback 测试校验服务端证书的实际指纹，并拒绝错误指纹；另有用户确认、跨会话和输入格式测试。

## 严格限制（非常重要）

1. 这里仍是**分开的工具/API**，未与 `manual_pairing::respond/finish`、`session_binding::authenticate_*` 或任何文件流开放操作组成生产级握手状态机。调用者尚可绕过这两个检查直接调用旧的 `authenticate_*` 函数，所以**不能称作目前已强制执行的安全门禁**。在完整集成完成前，不应对不可信真实设备开放应用数据。
2. Quinn 服务端默认的 `ServerConfig::with_single_cert` 不要求客户端证书，因此服务端的 `peer_identity()` 通常为空。**必须**后续配置/验证双向客户端证书或等效的设备密钥认证，不能通过允许空证书或“先建立会话再补验证”绕过。
3. 客户端的证书摘要检查发生在 TLS 握手之后；它是额外的绑定检查，不能取代 Rustls 在握手期间的 TLS 证书验证。
4. 指纹证明对端证书与识别码一致，但如果攻击者同时替换完整 INVITE/REPLY 仍可能进行中间人攻击。人工独立渠道比较码与可信持久设备密钥校验是必须设计的确认流程。
5. 后续应以不可绕过的高层 API 收敛认证路径，封闭公开的底层凭据/未确认连接构造，考虑统一握手失败时立即关闭相关 QUIC Connection。

## 下一步

- 真实两端双向 TLS 身份证明，绑定同一 Session 的 Control/Data 两条 QUIC；
- 将 `ManualPairing` 与 `ManualConfirmation` 和真实证书指纹校验组合为状态机，未确认不能构造已授权 P2P Session；
- 将 ICE 候选和凭据加入手动 INVITE/REPLY，打通真实直连；
- 界面确认流程和安全回归/真实两机手测。
