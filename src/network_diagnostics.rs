//! SDK 诊断枚举；运行态诊断由通用 TransportDiagnostic 提供。
//! 不携带短期 ICE 凭据、配对码或 QUIC 会话密钥。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayMethod {
    Pcp,
    NatPmp,
    Upnp,
}
