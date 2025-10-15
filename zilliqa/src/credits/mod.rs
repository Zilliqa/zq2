mod rpc_credit_limit;
mod rpc_credit_rate;
mod rpc_credit_store;
mod rpc_extension_layer;

use std::time::{Duration, SystemTime};

pub use rpc_credit_limit::*;
pub use rpc_credit_rate::*;
pub use rpc_credit_store::*;
pub use rpc_extension_layer::*;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct RateLimit {
    pub balance: u64,
    #[serde(deserialize_with = "deserialize_duration")]
    pub period: Duration,
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let x = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(x))
}

impl RateLimit {
    pub fn new(balance: u64, period: Duration) -> Self {
        Self { balance, period }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum RateLimitState {
    Deny { until: SystemTime },
    Allow { until: SystemTime, balance: u64 },
}

impl Default for RateLimitState {
    #[inline]
    fn default() -> Self {
        Self::Deny {
            until: SystemTime::UNIX_EPOCH,
        }
    }
}
