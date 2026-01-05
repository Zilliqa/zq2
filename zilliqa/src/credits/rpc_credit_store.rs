use std::time::{Duration, UNIX_EPOCH};

use anyhow::Result;
use jsonrpsee::client_transport::ws::Url;
use r2d2::Pool;
use rand::{RngCore, thread_rng};
use redis::{Client, Commands};

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
    pub fn new() -> Self {
        // Use REDIS_ENDPOINT value to configure redis connection pool.
        let uri =
            std::env::var("REDIS_ENDPOINT").map_or_else(|_| None, |uri| Url::parse(&uri).ok());

        // spin up redis connection pool
        let pool = uri.as_ref().and_then(|url| {
            let num_workers = crate::tokio_worker_count().max(4) as u32;
            Pool::builder()
                .max_size(num_workers * 2)
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

    // Only deletes the lock if the token matches.
    pub fn release(&self, key: &str, token: u64) -> Result<()> {
        tracing::trace!("RELEASE {key}");
        let Some(pool) = self.pool.as_ref() else {
            return Err(anyhow::anyhow!("Redis pool missing"));
        };
        let key = format!("{}#{key}.lock", self.ns);

        let mut conn = pool.get()?;
        // https://redis.io/docs/latest/commands/set/#patterns
        redis::cmd("EVAL")
            .arg("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end")
            .arg(1)
            .arg(key)
            .arg(token)
            .exec(&mut conn)?;
        Ok(())
    }

    // Waits until the lock is acquired.
    // Returns the token used to release the lock.
    pub fn acquire(&self, key: &str) -> Result<u64> {
        tracing::trace!("ACQUIRE {key}");
        let Some(pool) = self.pool.as_ref() else {
            return Err(anyhow::anyhow!("Redis pool missing"));
        };
        let key = format!("{}#{key}.lock", self.ns);

        // Since the state computation is done before the rpc call is made,
        // the lock does not need to be acquired for a long time.
        // Set lock-expiration to 3-secs - it should be under 1s.
        let opts = redis::SetOptions::default()
            .conditional_set(redis::ExistenceCheck::NX)
            .with_expiration(redis::SetExpiry::EX(3));
        let token = thread_rng().next_u64(); // random token

        let mut conn = pool.get()?;
        // the loop will either acquire a lock; or return a redis error.
        // it is not infinite.
        loop {
            match conn.set_options::<_, _, String>(&key, token, opts) {
                // locked
                Ok(rv) if rv == "OK" => return Ok(token),
                // !nil, we throw the error.
                Err(err) if err.kind() != redis::ErrorKind::TypeError => {
                    tracing::error!(%err, "REDIS");
                    return Err(err.into());
                }
                _ => {} // spin
            };
        }
    }

    // Returns the stored user state, or default state if non exists.
    pub fn get_user_state(&self, key: &str) -> Result<RateState> {
        tracing::trace!("GET {key}");
        let Some(pool) = self.pool.as_ref() else {
            return Err(anyhow::anyhow!("Redis pool missing"));
        };
        let key = format!("{}#{key}", self.ns);
        let mut conn = pool.get()?;
        let bin: Vec<u8> = conn.get(&key)?;
        let state = bincode::serde::decode_from_slice::<RateState, _>(
            bin.as_slice(),
            Self::REDIS_BINCODE_CONFIG,
        )
        // returns default state, if there is none in redis
        .map_or_else(|_e| RateState::default(), |bin| bin.0);
        Ok(state)
    }

    // Update the user state, or create a new one if it doesn't exist.
    pub fn update_user_state(&self, key: &str, state: &RateState) -> Result<()> {
        tracing::trace!(?state, "SET {key}");
        let Some(pool) = self.pool.as_ref() else {
            return Err(anyhow::anyhow!("Redis pool missing"));
        };
        let key = format!("{}#{key}", self.ns);

        // compute expiration time
        // we exploit redis's internal expiration mechanism so that:
        // 1. the state storage does not grow infinitely; and
        // 2. the quota gets reset upon expiry
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
        Self::new()
    }
}
