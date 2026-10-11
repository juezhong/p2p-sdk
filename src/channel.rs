//! Domain-separated authentication classes for QUIC links in one peer session.
//! These tags identify bootstrap and additional authenticated links, never an
//! application's Control, Data, Pipe, RPC, or other stream semantics.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LinkProofClass {
    /// Initial authenticated QUIC used to establish the peer session.
    Bootstrap,
    /// Any subsequent authenticated QUIC in the same peer session.
    Additional,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_classes_are_distinct_but_business_agnostic() {
        assert_ne!(LinkProofClass::Bootstrap, LinkProofClass::Additional);
    }
}
