use std::time::SystemTime;

use anyhow::Result;
use r2d2::Pool;
use redis::{Client, Commands};
use url::Url;

use crate::credits::RateState;

/// Abstraction for managing global rate limits and user-specific rate limits.
#[derive(Debug)]
pub struct RpcCreditStore {
    ns: String,
    pool: Option<Pool<Client>>,
}

impl RpcCreditStore {
    const REDIS_BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
    // URI e.g. "redis://[<username>][:<password>@]<hostname>[:port][/[<db>][?protocol=<protocol>]]"
    pub fn new(uri: Option<Url>) -> Self {
        // spin up redis connection pool
        let num_workers = tokio::runtime::Handle::try_current()
            .map(|h| h.metrics().num_workers().max(4))
            .unwrap_or(4);
        let pool = uri.as_ref().and_then(|url| {
            Pool::builder()
                .max_size(2 * num_workers as u32)
                .build(Client::open(url.to_string()).unwrap())
                .ok()
        });

        // get namespace
        let ns = uri
            .as_ref()
            .and_then(|url| url.fragment().map(|s| s.to_string()))
            .unwrap_or_default();

        RpcCreditStore { ns, pool }
    }

    pub fn get_user_state(&self, key: &str) -> Result<RateState> {
        let key = format!("{}#{key}", self.ns);
        tracing::debug!("GET {key}");
        // get from redis pool, if one is configured
        if let Some(pool) = self.pool.as_ref() {
            let mut conn = pool.get()?;
            let bin: Vec<u8> = conn.get(&key)?;
            let state = bincode::serde::decode_from_slice::<RateState, _>(
                bin.as_slice(),
                Self::REDIS_BINCODE_CONFIG,
            )
            .map_or_else(|_e| RateState::default(), |bin| bin.0);
            return Ok(state);
        }
        Err(anyhow::anyhow!("State not found"))
    }

    pub fn update_user_state(&self, key: &str, state: &RateState) -> Result<()> {
        let key = format!("{}#{key}", self.ns);
        tracing::debug!(?state, "SET {key}");
        // set to redis pool, if one is configured
        if let Some(pool) = self.pool.as_ref() {
            let until = match state {
                RateState::Allow { until, .. } => until,
                RateState::Deny { until } => until,
            };
            let secs = until
                .duration_since(SystemTime::now())
                .unwrap_or_default()
                .as_secs();
            let bin = bincode::serde::encode_to_vec(state, Self::REDIS_BINCODE_CONFIG)?;
            let mut conn = pool.get()?;
            // set key expiry, to avoid stale data
            let _: () = conn.set_ex(&key, bin, secs)?;
            return Ok(());
        }
        Err(anyhow::anyhow!("State not updated"))
    }
}

impl Default for RpcCreditStore {
    fn default() -> Self {
        Self::new(None)
    }
}
