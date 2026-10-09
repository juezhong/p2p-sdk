//! Logical separation of application control and bulk data.
//!
//! This is an API policy model, not a Quinn transport implementation.
//! Both classes may use the same validated UDP endpoint; the application
//! protocol must keep its control RPCs separate from bulk payload streams.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ChannelRole {
    Control,
    Data,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    InvalidParallelDataLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelPolicy {
    /// Maximum number of extra, independently connected data-only QUIC links.
    /// A single authenticated QUIC link can still carry many data streams.
    pub max_extra_data_connections: u8,
}

impl Default for ChannelPolicy {
    fn default() -> Self {
        Self {
            max_extra_data_connections: 0,
        }
    }
}

impl ChannelPolicy {
    pub fn validate(&self) -> Result<(), ChannelError> {
        if self.max_extra_data_connections > 4 {
            return Err(ChannelError::InvalidParallelDataLimit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_control_and_data_roles() {
        assert_ne!(ChannelRole::Control, ChannelRole::Data);
    }

    #[test]
    fn defaults_to_one_transport_without_extra_data_links() {
        let policy = ChannelPolicy::default();
        assert_eq!(policy.max_extra_data_connections, 0);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn limits_extra_data_connections() {
        assert!(ChannelPolicy {
            max_extra_data_connections: 4
        }
        .validate()
        .is_ok());
        assert_eq!(
            ChannelPolicy {
                max_extra_data_connections: 5
            }
            .validate(),
            Err(ChannelError::InvalidParallelDataLimit)
        );
    }
}
