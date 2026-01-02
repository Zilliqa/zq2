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

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
// Currently supports time-based rate-limiting
pub struct RateQuota {
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

impl RateQuota {
    pub fn new(balance: u64, period: Duration) -> Self {
        Self { balance, period }
    }
}

impl Default for RateQuota {
    fn default() -> Self {
        Self::new(u64::MAX, Duration::from_secs(60))
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
// Can be extended to support more features
pub enum RateState {
    Deny { until: SystemTime },
    Allow { until: SystemTime, balance: u64 },
}

impl Default for RateState {
    #[inline]
    // sane default - immediately expires and switches to allow.
    fn default() -> Self {
        Self::Deny {
            until: SystemTime::UNIX_EPOCH,
        }
    }
}
