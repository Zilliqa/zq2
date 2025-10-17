use std::time::{Duration, UNIX_EPOCH};

use anyhow::Result;
use r2d2::Pool;
use rand::{RngCore, thread_rng};
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
                .min_idle(Some(1))
                .connection_timeout(Duration::from_secs(1)) // fail fast
                .build(Client::open(url.to_string()).unwrap())
                .map_or_else(
                    |e| {
                        tracing::error!("REDIS {e}");
                        None
                    },
                    |p| {
                        tracing::debug!("REDIS {p:?}");
                        Some(p)
                    },
                )
        });

        // get namespace
        let ns = uri
            .as_ref()
            .and_then(|url| url.fragment().map(|s| s.to_string()))
            .unwrap_or_default();

        RpcCreditStore { ns, pool }
    }

    pub fn release(&self, key: &str, token: u64) -> Result<()> {
        tracing::debug!("UNLOCK {key}");
        let key = format!("{}#{key}.lock", self.ns);
        // get from redis pool, if one is configured
        if let Some(pool) = self.pool.as_ref() {
            let mut conn = pool.get()?;
            let val = conn.get::<_, u64>(&key)?;
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
    pub fn acquire(&self, key: &str) -> Result<u64> {
        tracing::debug!("LOCK {key}");
        let key = format!("{}#{key}.lock", self.ns);
        if let Some(pool) = self.pool.as_ref() {
            // since the state computation is done before the rpc call is made, the lock does not need to be acquired for a long time.
            // set lock-expiration to 5-secs. it should practically, be under 1s.
            let opts = redis::SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(5));
            let token = thread_rng().next_u64(); // random token

            let mut conn = pool.get()?;
            loop {
                match conn.set_options::<_, _, String>(&key, token, opts) {
                    // locked
                    Ok(rv) if rv == "OK" => return Ok(token),
                    // !nil, we throw the error.
                    Err(err) if err.kind() != redis::ErrorKind::TypeError => {
                        tracing::error!(%err, "REDIS");
                        return Err(err.into());
                    }
                    _ => {}
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

        // compute expiration time
        let until_at = match state {
            RateState::Allow { until, .. } => until
                .duration_since(UNIX_EPOCH)
                .expect("time travel")
                .as_secs(),
            RateState::Deny { until } => until
                .duration_since(UNIX_EPOCH)
                .expect("time travel")
                .as_secs(),
        };
        let opts = redis::SetOptions::default().with_expiration(redis::SetExpiry::EXAT(until_at));

        // set the key-value
        let bin = bincode::serde::encode_to_vec(state, Self::REDIS_BINCODE_CONFIG)?;
        let mut conn = pool.get()?;
        conn.set_options::<_, _, ()>(&key, bin, opts)?;
        Ok(())
    }
}

impl Default for RpcCreditStore {
    fn default() -> Self {
        Self::new(None)
    }
}
