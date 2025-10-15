mod rpc_credit_store;
mod rpc_extension_layer;
mod rpc_price_list;
mod rpc_rate_limit;

pub use rpc_credit_store::*;
pub use rpc_extension_layer::*;
pub use rpc_price_list::*;
pub use rpc_rate_limit::*;

use serde::{Deserialize, Deserializer, Serialize};
use std::time::{Duration, Instant};

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

#[derive(Debug, Copy, Clone)]
pub enum RateLimitState {
    Deny { until: Instant },
    Allow { until: Instant, balance: u64 },
}
