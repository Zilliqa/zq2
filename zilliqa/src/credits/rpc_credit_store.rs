use std::time::SystemTime;

use anyhow::Result;
use parking_lot::RwLock;
use r2d2::Pool;
use redis::{Client, TypedCommands};

use crate::credits::RateState;

/// Abstraction for managing global rate limits and user-specific rate limits.
#[derive(Debug)]
pub struct RpcCreditStore {
    pool: Option<Pool<Client>>,
    // this is the glocal state, that is used in testing w/o needing a redis server.
    null_state: RwLock<RateState>,
}

impl RpcCreditStore {
    const REDIS_BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
    // uri e.g. "redis://localhost:6379"
    pub fn new(uri: Option<String>) -> Self {
        let num_workers = tokio::runtime::Handle::try_current()
            .map(|h| h.metrics().num_workers().max(4))
            .unwrap_or(4);

        RpcCreditStore {
            pool: uri.and_then(|uri| {
                Pool::builder()
                    .max_size(2 * num_workers as u32)
                    .build(Client::open(uri).unwrap())
                    .ok()
            }),
            null_state: RwLock::new(RateState::default()),
        }
    }

    pub fn get_user_state(&self, key: &str) -> Result<RateState> {
        tracing::trace!(%key, "GET");
        if key.is_empty() {
            // this is a special case for empty key, which is treated as a global rate-limit.
            return Ok(*self.null_state.read());
        }

        // get from redis pool, if one is configured
        if let Some(pool) = self.pool.as_ref() {
            let mut conn = pool.get()?;
            let bin = conn.get(key)?.unwrap_or_default();
            let state = bincode::serde::decode_from_slice::<RateState, _>(
                bin.as_bytes(),
                Self::REDIS_BINCODE_CONFIG,
            )?;
            return Ok(state.0);
        }
        Ok(RateState::default())
    }

    pub fn update_user_state(&self, key: &str, state: &RateState) -> Result<()> {
        tracing::trace!(%key, ?state, "SET");
        if key.is_empty() {
            // this is a special case for empty key, which is treated as a global rate-limit.
            *self.null_state.write() = *state;
            return Ok(());
        }

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
            conn.set_ex(key, bin, secs)?; // set expiry, helps to manage redis size
        }
        Ok(())
    }
}

impl Default for RpcCreditStore {
    fn default() -> Self {
        Self::new(None)
    }
}
