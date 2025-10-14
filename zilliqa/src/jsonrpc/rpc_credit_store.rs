use std::time::{Duration, Instant};

use anyhow::Result;

/// Abstraction for managing global rate limits and user-specific rate limits.
#[derive(Debug, Clone)]
pub struct RpcCreditStore {
    // Define fields here
}

impl RpcCreditStore {
    // Implement methods here
    pub fn new() -> Self {
        RpcCreditStore {
            // Initialize fields here
        }
    }

    pub fn get_user_state(&self, _key: &str) -> Result<RateLimitState> {
        tracing::info!("GET {_key}");
        Ok(RateLimitState::Allow {
            until: Instant::now() + Duration::from_secs(5),
            rem: 10000,
        })
    }

    pub fn update_user_state(&self, _key: &str, _state: &RateLimitState) -> Result<()> {
        tracing::info!("SET {_key}");
        // Implement logic to update user state
        Ok(())
    }
}

impl Default for RpcCreditStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct RateLimit {
    pub balance: u64,
    pub period: Duration,
}

impl RateLimit {
    pub fn new(balance: u64, period: Duration) -> Self {
        Self { balance, period }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum RateLimitState {
    Deny { until: Instant },
    Allow { until: Instant, rem: u64 },
}
