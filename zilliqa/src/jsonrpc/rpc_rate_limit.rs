use std::time::{Duration, Instant};

/// Based on https://github.com/paritytech/jsonrpsee/blob/master/examples/examples/rpc_middleware_rate_limiting.rs
///
use jsonrpsee::{
    MethodResponse,
    core::middleware::{
        Batch, BatchEntry, BatchEntryErr, Notification, ResponseFuture, RpcServiceT,
    },
    types::{ErrorObject, Request},
};

use crate::jsonrpc::{
    rpc_credit_list::RpcCreditList,
    rpc_credit_store::{RateLimit, RateLimitState, RpcCreditStore},
    rpc_extension_layer::RpcHeaderExt,
};

#[derive(Clone)]
pub struct RpcRateLimit<S> {
    service: S,
    credit_store: RpcCreditStore,
    credit_list: RpcCreditList,
}

impl<S> RpcRateLimit<S> {
    pub fn new(service: S, credit_store: RpcCreditStore, credit_list: RpcCreditList) -> Self {
        Self {
            service,
            credit_store,
            credit_list,
        }
    }

    fn check_rate_limit(
        &self,
        state: RateLimitState,
        limit: RateLimit,
        method: &str,
    ) -> Option<RateLimitState> {
        // accuracy for simplicity trade-off.
        let next_state = match state {
            RateLimitState::Deny { until } => {
                let now = Instant::now();
                if now < until {
                    // continue to deny
                    RateLimitState::Deny { until }
                } else {
                    // change to allow, with new credit balance
                    let cost = self.credit_list.get_credit(method);
                    RateLimitState::Allow {
                        until: now + limit.period,
                        rem: limit.balance.saturating_sub(cost),
                    }
                }
            }
            RateLimitState::Allow { until, rem } => {
                if rem > 0 {
                    // update credit balance
                    let cost = self.credit_list.get_credit(method);
                    RateLimitState::Allow {
                        until: until + limit.period,
                        rem: rem.saturating_sub(cost),
                    }
                } else {
                    // block now
                    let now = Instant::now();
                    RateLimitState::Deny {
                        until: now + limit.period,
                    }
                }
            }
        };

        // Some(balance)
        Some(next_state)
    }
}

impl<S> RpcServiceT for RpcRateLimit<S>
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
        let key = ext.remote_ip.to_string();

        // Get the user state
        let state = self
            .credit_store
            .get_user_state(&key)
            .expect("Failed to get user state");

        // TODO: Extract limit from Authorization header
        let limit = RateLimit::new(10000, Duration::from_secs(5));

        if let Some(balance) = self.check_rate_limit(state, limit, req.method_name()) {
            self.credit_store
                .update_user_state(&key, &balance)
                .expect("Failed to update user state");

            if matches!(balance, RateLimitState::Allow { .. }) {
                return ResponseFuture::future(self.service.call(req));
            }
        }
        ResponseFuture::ready(MethodResponse::error(
            req.id,
            ErrorObject::borrowed(-32000, "RPC rate limit", None),
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
        let key = ext.remote_ip.to_string();

        // Get the user state
        let mut state = self
            .credit_store
            .get_user_state(&key)
            .expect("Failed to get user state");

        // TODO: Extract limit from Authorization header
        let limit = RateLimit::new(10000, Duration::from_secs(5));

        for entry in batch.iter_mut() {
            match entry {
                Ok(BatchEntry::Call(req)) => {
                    if let Some(balance) = self.check_rate_limit(state, limit, req.method_name()) {
                        state = balance;
                        if matches!(state, RateLimitState::Allow { .. }) {
                            continue;
                        }
                    }
                    *entry = Err(BatchEntryErr::new(
                        req.id.clone(),
                        ErrorObject::borrowed(-32000, "RPC rate limit", None),
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
