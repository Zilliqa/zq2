use crate::credits::RateLimitState;
use anyhow::Result;
use parking_lot::RwLock;
use std::time::Instant;

/// Abstraction for managing global rate limits and user-specific rate limits.
#[derive(Debug)]
pub struct RpcCreditStore {
    // this is the glocal state, that is used in testing w/o needing a redis server.
    null_state: RwLock<RateLimitState>,
}

impl RpcCreditStore {
    // Implement methods here
    pub fn new() -> Self {
        RpcCreditStore {
            // sane default, immediately expires and passes.
            null_state: RwLock::new(RateLimitState::Deny {
                until: Instant::now(),
            }),
        }
    }

    pub fn get_user_state(&self, key: &str) -> Result<RateLimitState> {
        tracing::info!("GET {key}");
        if key.is_empty() {
            // this is a special case for empty key, which is treated as a global rate-limit.
            return Ok(self.null_state.read().clone());
        }

        // sane default, immediately expires and passes.
        Ok(RateLimitState::Deny {
            until: Instant::now(),
        })
    }

    pub fn update_user_state(&self, key: &str, state: &RateLimitState) -> Result<()> {
        tracing::info!("SET {key} {state:?}");
        if key.is_empty() {
            // this is a special case for empty key, which is treated as a global rate-limit.
            *self.null_state.write() = state.clone();
        }

        // Implement logic to update user state
        Ok(())
    }
}

impl Default for RpcCreditStore {
    fn default() -> Self {
        Self::new()
    }
}
