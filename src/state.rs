//! Diagnostic connection phases. State changes do not cause network activity.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPhase {
    Created,
    Gathering,
    Signaling,
    Checking,
    DirectPathValidated,
    Authenticated,
    Connected,
    Failed,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    InvalidTransition {
        from: ConnectionPhase,
        to: ConnectionPhase,
    },
}

#[derive(Clone, Debug)]
pub struct ConnectionState {
    phase: ConnectionPhase,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            phase: ConnectionPhase::Created,
        }
    }
}

impl ConnectionState {
    pub fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub fn transition(&mut self, next: ConnectionPhase) -> Result<(), StateError> {
        use ConnectionPhase::*;
        let valid = matches!(
            (self.phase, next),
            (Created, Gathering)
                | (Gathering, Signaling)
                | (Signaling, Checking)
                | (Checking, DirectPathValidated)
                | (DirectPathValidated, Authenticated)
                | (Authenticated, Connected)
                | (Connected, Checking)
        ) || !matches!(self.phase, Closed | Failed) && matches!(next, Closed | Failed);
        if !valid {
            return Err(StateError::InvalidTransition {
                from: self.phase,
                to: next,
            });
        }
        self.phase = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cannot_claim_authenticated_without_verified_path() {
        let mut state = ConnectionState::default();
        assert!(state.transition(ConnectionPhase::Authenticated).is_err());
        assert_eq!(state.phase(), ConnectionPhase::Created);
        for next in [
            ConnectionPhase::Gathering,
            ConnectionPhase::Signaling,
            ConnectionPhase::Checking,
            ConnectionPhase::DirectPathValidated,
            ConnectionPhase::Authenticated,
            ConnectionPhase::Connected,
        ] {
            state.transition(next).unwrap();
        }
        assert_eq!(state.phase(), ConnectionPhase::Connected);
    }

    #[test]
    fn failed_and_closed_are_terminal() {
        let mut state = ConnectionState::default();
        state.transition(ConnectionPhase::Failed).unwrap();
        assert!(state.transition(ConnectionPhase::Gathering).is_err());
    }
}
