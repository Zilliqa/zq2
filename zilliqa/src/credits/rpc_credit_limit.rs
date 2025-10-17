use std::{sync::Arc, time::SystemTime};

use anyhow::Result;
use jsonrpsee::{
    MethodResponse,
    core::middleware::{
        Batch, BatchEntry, BatchEntryErr, Notification, ResponseFuture, RpcServiceT,
    },
    types::{ErrorObject, Request},
};

/// Based on https://github.com/paritytech/jsonrpsee/blob/master/examples/examples/rpc_middleware_rate_limiting.rs
///
use crate::credits::{RateQuota, RateState, RpcCreditRate, RpcCreditStore, RpcHeaderExt};

const RPC_ERROR_CODE: i32 = -32000;
const RPC_ERROR_MESSAGE: &str = "RPC_RATE_LIMIT";

#[derive(Clone)]
pub struct RpcCreditLimit<S> {
    service: S,
    default_quota: RateQuota,
    credit_store: Arc<RpcCreditStore>,
    credit_rate: RpcCreditRate,
}

impl<S> RpcCreditLimit<S> {
    pub fn new(
        service: S,
        credit_store: Arc<RpcCreditStore>,
        credit_rate: RpcCreditRate,
        default_quota: Option<RateQuota>,
    ) -> Self {
        Self {
            service,
            // default rate-limit is unlimited
            default_quota: default_quota.unwrap_or_default(),
            credit_store: credit_store.clone(),
            credit_rate,
        }
    }

    fn acquire_state(&self, key: &str) -> Result<(u64, RateState)> {
        let token = self.credit_store.acquire(key)?;
        let state = self.credit_store.get_user_state(key)?;
        Ok((token, state))
    }

    fn update_release(&self, key: &str, state: RateState, token: u64) -> Result<()> {
        self.credit_store.update_user_state(key, &state)?;
        self.credit_store.release(key, token)?;
        Ok(())
    }

    fn check_credit_limit(
        &self,
        state: RateState,
        quota: &RateQuota,
        method: &str,
    ) -> Option<RateState> {
        // simplifies the code by allowing the case where:
        // as long as balance > 0, we can always make at least one request.
        // TODO: make this strict, if so desired.
        let now = SystemTime::now();
        match state {
            RateState::Deny { until } => {
                if now < until {
                    // continue to deny
                    Some(RateState::Deny { until })
                } else {
                    // refresh quota
                    let cost = self.credit_rate.get_credit(method);
                    Some(RateState::Allow {
                        until: now + quota.period,
                        balance: quota.balance.saturating_sub(cost),
                    })
                }
            }
            RateState::Allow { until, balance } => {
                if now > until {
                    // refresh quota
                    let cost = self.credit_rate.get_credit(method);
                    Some(RateState::Allow {
                        until: now + quota.period,
                        balance: quota.balance.saturating_sub(cost),
                    })
                } else if balance > 0 {
                    // reduce balance
                    let cost = self.credit_rate.get_credit(method);
                    Some(RateState::Allow {
                        until,
                        balance: balance.saturating_sub(cost),
                    })
                } else {
                    // block
                    Some(RateState::Deny {
                        until: now + quota.period,
                    })
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

        // identify by IP
        let key = ext.remote_ip.map(|ip| ip.to_string()).unwrap_or_default();

        // R-M-W mechanism
        let (token, state) = self.acquire_state(&key).unwrap_or_default(); // sane default
        let state = self
            .check_credit_limit(state, &self.default_quota, req.method_name())
            .expect("Never None");
        self.update_release(&key, state, token).ok(); // ignore errors

        if matches!(state, RateState::Deny { .. }) {
            return ResponseFuture::ready(MethodResponse::error(
                req.id,
                ErrorObject::borrowed(RPC_ERROR_CODE, RPC_ERROR_MESSAGE, None),
            ));
        }

        ResponseFuture::future(self.service.call(req))
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

        // identify by IP
        let key = ext.remote_ip.map(|ip| ip.to_string()).unwrap_or_default();

        // R-M-W mechanism
        let (token, mut state) = self.acquire_state(&key).unwrap_or_default();
        for entry in batch.iter_mut() {
            match entry {
                Ok(BatchEntry::Call(req)) => {
                    let balance = self
                        .check_credit_limit(state, &self.default_quota, req.method_name())
                        .expect("Never None");
                    state = balance;
                    if matches!(state, RateState::Deny { .. }) {
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
        self.update_release(&key, state, token).ok();

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
