//! Direct-only connectivity policy.

/// Configuration is intentionally direct-only. There is no relay flag to toggle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub prefer_ipv6: bool,
    pub enable_stun: bool,
    pub enable_port_mapping: bool,
    pub candidate_limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            prefer_ipv6: true,
            enable_stun: true,
            enable_port_mapping: false,
            candidate_limit: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidCandidateLimit,
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.candidate_limit == 0 || self.candidate_limit > 1024 {
            return Err(ConfigError::InvalidCandidateLimit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_ipv6_preferred_and_explicitly_direct_only() {
        let config = Config::default();
        assert!(config.prefer_ipv6);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_unbounded_candidate_configuration() {
        let mut config = Config::default();
        config.candidate_limit = 0;
        assert_eq!(config.validate(), Err(ConfigError::InvalidCandidateLimit));
        config.candidate_limit = 1025;
        assert_eq!(config.validate(), Err(ConfigError::InvalidCandidateLimit));
    }
}
