use std::time::SystemTime;

use anyhow::Result;
use r2d2::Pool;
use redis::{Client, Commands};
use url::Url;
use uuid::Uuid;

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

    pub fn acquire_state(&self, key: &str) -> Result<(String, RateState)> {
        let token = self.acquire(key)?;
        let state = self.get_user_state(key)?;
        Ok((token, state))
    }

    pub fn update_release(&self, key: &str, state: RateState, token: String) -> Result<()> {
        self.update_user_state(key, &state)?;
        self.release(key, token)?;
        Ok(())
    }

    pub fn release(&self, key: &str, token: String) -> Result<()> {
        tracing::debug!("UNLOCK {key}");
        let key = format!("{}#{key}.lock", self.ns);
        // get from redis pool, if one is configured
        if let Some(pool) = self.pool.as_ref() {
            let mut conn = pool.get()?;
            let val = conn.get::<_, String>(&key)?;
            // delete the key if the token matches
            if val == token {
                conn.del::<_, ()>(&key)?;
            }
            return Ok(());
        }
        Err(anyhow::anyhow!("Redis pool not configured"))
    }

    // Waits until the lock is acquired.
    // Returns the token used to release the lock.
    pub fn acquire(&self, key: &str) -> Result<String> {
        tracing::debug!("LOCK {key}");
        let key = format!("{}#{key}.lock", self.ns);
        if let Some(pool) = self.pool.as_ref() {
            let opts = redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX) // set-if-not-exist
                .with_expiration(redis::SetExpiry::EX(55)); // set lock-expiration
            let mut conn = pool.get()?;
            let val = Uuid::new_v4();
            loop {
                match conn.set_options::<_, _, String>(&key, val.to_string(), opts) {
                    Ok(rv) if rv == "OK" => return Ok(val.to_string()), // successfully acquired lock
                    _ => continue, // wait until lock is acquired
                };
            }
        }
        Err(anyhow::anyhow!("Redis pool not configured"))
    }

    pub fn get_user_state(&self, key: &str) -> Result<RateState> {
        tracing::debug!("GET {key}");
        let key = format!("{}#{key}", self.ns);
        // get from redis pool, if one is configured
        let Some(pool) = self.pool.as_ref() else {
            return Err(anyhow::anyhow!("Redis not found not found"));
        };

        let mut conn = pool.get()?;
        let bin: Vec<u8> = conn.get(&key)?;
        let state = bincode::serde::decode_from_slice::<RateState, _>(
            bin.as_slice(),
            Self::REDIS_BINCODE_CONFIG,
        )
        .map_or_else(|_e| RateState::default(), |bin| bin.0);
        Ok(state)
    }

    pub fn update_user_state(&self, key: &str, state: &RateState) -> Result<()> {
        tracing::debug!(?state, "SET {key}");
        let key = format!("{}#{key}", self.ns);
        // set to redis pool, if one is configured
        let Some(pool) = self.pool.as_ref() else {
            return Err(anyhow::anyhow!("State not updated"));
        };

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
        conn.set_ex::<_, _, ()>(&key, bin, secs)?;
        Ok(())
    }
}

impl Default for RpcCreditStore {
    fn default() -> Self {
        Self::new(None)
    }
}
