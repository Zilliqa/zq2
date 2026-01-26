use std::{sync::Arc, time::SystemTime};

use anyhow::Result;
use jsonrpsee::{
    MethodResponse,
    core::middleware::{
        Batch, BatchEntry, BatchEntryErr, Notification, ResponseFuture, RpcServiceT,
    },
    types::{ErrorObject, Request},
};
use tower::Layer;

use crate::credits::{RateQuota, RateState, RpcCreditRate, RpcCreditStore, RpcHeaderExt};

const RPC_ERROR_CODE: i32 = -32000;
const RPC_ERROR_MESSAGE: &str = "RPC_RATE_LIMIT";

/// Credit limit layer for JSON-RPC requests.
#[derive(Debug, Clone)]
pub struct RpcLimitLayer {
    credit_store: Arc<RpcCreditStore>,
    credit_rate: RpcCreditRate,
    default_quota: Option<RateQuota>,
}

impl RpcLimitLayer {
    pub fn new(
        credit_store: Arc<RpcCreditStore>,
        credit_rate: RpcCreditRate,
        default_quota: Option<RateQuota>,
    ) -> Self {
        Self {
            credit_store,
            credit_rate,
            default_quota,
        }
    }
}

impl<S> Layer<S> for RpcLimitLayer {
    type Service = RpcCreditLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcCreditLimit::new(
            inner,
            self.credit_store.clone(),
            self.credit_rate.clone(),
            self.default_quota,
        )
    }
}

/// Based on https://github.com/paritytech/jsonrpsee/blob/master/examples/examples/rpc_middleware_rate_limiting.rs

#[derive(Clone)]
pub struct RpcCreditLimit<S> {
    inner: S,
    default_quota: RateQuota,
    credit_store: Arc<RpcCreditStore>,
    credit_rate: RpcCreditRate,
}

impl<S> RpcCreditLimit<S> {
    pub fn new(
        inner: S,
        credit_store: Arc<RpcCreditStore>,
        credit_rate: RpcCreditRate,
        default_quota: Option<RateQuota>,
    ) -> Self {
        Self {
            inner,
            // default rate-limit is unlimited
            default_quota: default_quota.unwrap_or_default(),
            credit_store,
            credit_rate,
        }
    }

    #[inline]
    fn acquire_state(&self, key: &str) -> Result<(u64, RateState)> {
        let token = self.credit_store.acquire(key)?;
        // acquire before getting state
        let state = self.credit_store.get_user_state(key)?;
        Ok((token, state))
    }

    #[inline]
    fn update_release(&self, key: &str, state: RateState, token: u64) -> Result<()> {
        self.credit_store.update_user_state(key, &state)?;
        // release after updating state
        self.credit_store.release(key, token)?;
        Ok(())
    }

    fn check_credit_limit(&self, state: RateState, quota: &RateQuota, method: &str) -> RateState {
        // simplifies the code by allowing the case where:
        // as long as balance > 0, we can always make at least one request.
        // TODO: make this strict, if so desired.
        let now = SystemTime::now();
        match state {
            RateState::Deny { until } => {
                if now < until {
                    // continue to deny
                    RateState::Deny { until }
                } else {
                    // refresh quota
                    let cost = self.credit_rate.get_credit(method);
                    RateState::Allow {
                        until: now + quota.period,
                        balance: quota.balance.saturating_sub(cost),
                    }
                }
            }
            RateState::Allow { until, balance } => {
                if now > until {
                    // refresh quota
                    let cost = self.credit_rate.get_credit(method);
                    RateState::Allow {
                        until: now + quota.period,
                        balance: quota.balance.saturating_sub(cost),
                    }
                } else if balance > 0 {
                    // reduce balance
                    let cost = self.credit_rate.get_credit(method);
                    RateState::Allow {
                        until,
                        balance: balance.saturating_sub(cost),
                    }
                } else {
                    // block
                    RateState::Deny {
                        until: now + quota.period,
                    }
                }
            }
        }
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

        if ext.remote_key.is_some() || ext.remote_ip.is_none() {
            return ResponseFuture::future(self.inner.call(req)); // Bypass by KEY/IP
        };
        let key = ext
            .remote_ip
            .map(|ip| ip.to_string())
            .expect("remote_ip must be Some(ip)");

        // compute credits **before** executing the request.
        // this simplifies the error handling and ensures that the credit is always deducted.
        let (token, state) = self
            .acquire_state(&key)
            .map_err(|err| {
                tracing::error!(%err, "Failed to acquire state");
                err
            })
            .unwrap_or_default();
        let state = self.check_credit_limit(state, &self.default_quota, req.method_name());
        self.update_release(&key, state, token)
            .map_err(|err| {
                tracing::error!(%err, "Failed to update release");
                err
            })
            .ok(); // ignore errors

        if matches!(state, RateState::Deny { .. }) {
            tracing::warn!(ip=%key, id=%req.id, method=%req.method, "RPC limited");
            return ResponseFuture::ready(MethodResponse::error(
                req.id,
                ErrorObject::borrowed(RPC_ERROR_CODE, RPC_ERROR_MESSAGE, None),
            ));
        }

        // underlying service handler
        ResponseFuture::future(self.inner.call(req))
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

        if ext.remote_key.is_some() || ext.remote_ip.is_none() {
            return self.inner.batch(batch); // Bypass by KEY/IP
        };
        let key = ext
            .remote_ip
            .map(|ip| ip.to_string())
            .expect("remote_ip must be Some(ip)");

        // due to the way limits are applied, call ordering is irrelevant.
        // compute the credit budget and immediately mutate/fail any that are denied.
        // the denied calls are skipped by the underlying service handler.
        let (token, mut state) = self
            .acquire_state(&key)
            .map_err(|err| {
                tracing::error!(%err, "Failed to acquire state");
                err
            })
            .unwrap_or_default();
        for entry in batch.iter_mut() {
            match entry {
                Ok(BatchEntry::Call(req)) => {
                    let balance =
                        self.check_credit_limit(state, &self.default_quota, req.method_name());
                    state = balance;
                    if matches!(state, RateState::Deny { .. }) {
                        tracing::warn!(ip=%key, id=%req.id, method=%req.method, "RPC limited");
                        *entry = Err(BatchEntryErr::new(
                            req.id.clone(),
                            ErrorObject::borrowed(RPC_ERROR_CODE, RPC_ERROR_MESSAGE, None),
                        ));
                    }
                }
                Ok(BatchEntry::Notification(_)) => continue,
                Err(_) => continue,
            }
        }
        self.update_release(&key, state, token)
            .map_err(|err| {
                tracing::error!(%err, "Failed to update release");
                err
            })
            .ok(); // only save the final state, skipping intermediate states.

        // underlying service handler
        self.inner.batch(batch)
    }

    // Notifications
    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        // TODO: implement notification rate-limits
        // ResponseFuture::ready(MethodResponse::notification())
        ResponseFuture::future(self.inner.notification(n))
    }
}
