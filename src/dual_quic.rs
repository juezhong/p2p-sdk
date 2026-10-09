//! A pair of authenticated QUIC connections with independent lifetimes.
//!
//! These are two QUIC connections, NOT two streams of one connection.
//! The surrounding session must authenticate and bind both connections to
//! the same peer/session before constructing this type.
//! This is an experimental transport building block; ICE is not wired up.

use quinn::Connection;

#[derive(Clone)]
#[allow(dead_code)]
pub struct DualQuic {
    control: Connection,
    data: Connection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualQuicError {
    SameConnection,
}

#[allow(dead_code)]
impl DualQuic {
    /// Caller must verify that both connections refer to the same authenticated
    /// peer and negotiated application session. This is not done here yet.
    pub(crate) fn new(control: Connection, data: Connection) -> Result<Self, DualQuicError> {
        if control.stable_id() == data.stable_id() {
            return Err(DualQuicError::SameConnection);
        }
        Ok(Self { control, data })
    }

    pub fn control(&self) -> &Connection {
        &self.control
    }

    pub fn data(&self) -> &Connection {
        &self.data
    }

    /// Close the bulk-data QUIC connection without closing control QUIC.
    /// Replacing it requires a freshly authenticated session-bound connection.
    pub fn close_data(&self) {
        self.data.close(0u32.into(), b"data connection reset");
    }
}
