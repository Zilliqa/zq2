use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use jsonrpsee::{
    MethodResponse,
    core::middleware::{
        Batch, BatchEntry, BatchEntryErr, Notification, ResponseFuture, RpcServiceT,
    },
    types::{ErrorObject, Request},
};

/// Based on https://github.com/paritytech/jsonrpsee/blob/master/examples/examples/rpc_middleware_rate_limiting.rs
///
use crate::credits::{RateLimit, RateLimitState, RpcCreditRate, RpcCreditStore, RpcHeaderExt};

const RPC_ERROR_CODE: i32 = -32000;
const RPC_ERROR_MESSAGE: &str = "RPC_RATE_LIMIT";

#[derive(Clone)]
pub struct RpcCreditLimit<S> {
    service: S,
    default_limit: RateLimit,
    credit_store: Arc<RpcCreditStore>,
    credit_list: Arc<RpcCreditRate>,
}

impl<S> RpcCreditLimit<S> {
    pub fn new(
        service: S,
        credit_store: Arc<RpcCreditStore>,
        price_list: Arc<RpcCreditRate>,
        default_limit: Option<RateLimit>,
    ) -> Self {
        Self {
            service,
            // default rate-limit is unlimited
            default_limit: default_limit.unwrap_or(RateLimit {
                balance: u64::MAX,
                period: Duration::default(),
            }),
            credit_store: credit_store.clone(),
            credit_list: price_list.clone(),
        }
    }

    fn check_credit_limit(
        &self,
        state: RateLimitState,
        quota: &RateLimit,
        method: &str,
    ) -> Option<RateLimitState> {
        // simplifies the code by allowing the case where:
        // as long as balance > 0, we can always make at least one request.
        // TODO: make this strict, if so desired.
        let next_state = match state {
            RateLimitState::Deny { until } => {
                let now = SystemTime::now();
                if now < until {
                    // continue to deny
                    RateLimitState::Deny { until }
                } else {
                    // refresh quota
                    let cost = self.credit_list.get_credit(method);
                    RateLimitState::Allow {
                        until: now + quota.period,
                        balance: quota.balance.saturating_sub(cost),
                    }
                }
            }
            RateLimitState::Allow { until, balance } => {
                let now = SystemTime::now();
                if now > until {
                    // refresh quota
                    let cost = self.credit_list.get_credit(method);
                    RateLimitState::Allow {
                        until: now + quota.period,
                        balance: quota.balance.saturating_sub(cost),
                    }
                } else if balance > 0 {
                    // reduce balance
                    let cost = self.credit_list.get_credit(method);
                    RateLimitState::Allow {
                        until,
                        balance: balance.saturating_sub(cost),
                    }
                } else {
                    // block
                    RateLimitState::Deny {
                        until: now + quota.period,
                    }
                }
            }
        };

        Some(next_state)
    }
}

impl<S> RpcServiceT for RpcCreditLimit<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    // Single calls
    fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let ext = req
            .extensions()
            .get::<RpcHeaderExt>()
            .expect("RpcHeaderExt must be present");
        tracing::info!("CALL {ext:?}");

        // identify by IP
        let key = ext.remote_ip.map(|ip| ip.to_string()).unwrap_or_default();

        // Get the user state
        let state = self
            .credit_store
            .get_user_state(&key)
            .expect("Failed to get user state");

        if let Some(balance) =
            self.check_credit_limit(state, &self.default_limit, req.method_name())
        {
            self.credit_store
                .update_user_state(&key, &balance)
                .expect("Failed to update user state");

            if matches!(balance, RateLimitState::Allow { .. }) {
                return ResponseFuture::future(self.service.call(req));
            }
        }
        ResponseFuture::ready(MethodResponse::error(
            req.id,
            ErrorObject::borrowed(RPC_ERROR_CODE, RPC_ERROR_MESSAGE, None),
        ))
    }

    // Batch calls
    fn batch<'a>(
        &self,
        mut batch: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        let ext = batch
            .extensions()
            .get::<RpcHeaderExt>()
            .expect("RpcHeaderExt must be present");
        tracing::info!("BATCH {ext:?}");

        // identify by IP
        let key = ext.remote_ip.map(|ip| ip.to_string()).unwrap_or_default();

        // Get the user state
        let mut state = self
            .credit_store
            .get_user_state(&key)
            .expect("Failed to get user state");

        for entry in batch.iter_mut() {
            match entry {
                Ok(BatchEntry::Call(req)) => {
                    if let Some(balance) =
                        self.check_credit_limit(state, &self.default_limit, req.method_name())
                    {
                        state = balance;
                        if matches!(state, RateLimitState::Allow { .. }) {
                            continue;
                        }
                    }
                    *entry = Err(BatchEntryErr::new(
                        req.id.clone(),
                        ErrorObject::borrowed(RPC_ERROR_CODE, RPC_ERROR_MESSAGE, None),
                    ));
                }
                Ok(BatchEntry::Notification(_)) => continue,
                Err(_) => continue,
            }
        }

        self.credit_store
            .update_user_state(&key, &state)
            .expect("Failed to update user state");

        self.service.batch(batch)
    }

    // Notifications
    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        // TODO: implement notification rate-limits
        // ResponseFuture::ready(MethodResponse::notification())
        ResponseFuture::future(self.service.notification(n))
    }
}
