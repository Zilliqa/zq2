/// Based on https://github.com/paritytech/jsonrpsee/blob/master/examples/examples/rpc_middleware_rate_limiting.rs
///
use jsonrpsee::{
    MethodResponse,
    core::middleware::{
        Batch, BatchEntry, BatchEntryErr, Notification, ResponseFuture, RpcServiceT,
    },
    types::{ErrorObject, Request},
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Copy, Clone)]
pub struct RateLimit {
    num: u64,
    period: Duration,
}

impl RateLimit {
    pub fn new(num: u64, period: Duration) -> Self {
        Self { num, period }
    }
}

#[derive(Debug, Copy, Clone)]
enum State {
    Deny { until: Instant },
    Allow { until: Instant, rem: u64 },
}

#[derive(Clone)]
pub struct RpcRateLimit<S> {
    service: S,
    state: Arc<Mutex<State>>,
    rate: RateLimit,
}

impl<S> RpcRateLimit<S> {
    pub fn new(service: S, rate: RateLimit) -> Self {
        let period = rate.period;
        let num = rate.num;

        Self {
            service,
            rate,
            state: Arc::new(Mutex::new(State::Allow {
                until: Instant::now() + period,
                rem: num + 1,
            })),
        }
    }

    fn rate_limit_deny(&self) -> bool {
        let now = Instant::now();
        let mut lock = self.state.lock().unwrap();
        let next_state = match *lock {
            State::Deny { until } => {
                if now > until {
                    State::Allow {
                        until: now + self.rate.period,
                        rem: self.rate.num - 1,
                    }
                } else {
                    State::Deny { until }
                }
            }
            State::Allow { until, rem } => {
                if now > until {
                    State::Allow {
                        until: now + self.rate.period,
                        rem: self.rate.num - 1,
                    }
                } else {
                    let n = rem - 1;
                    if n > 0 {
                        State::Allow {
                            until: now + self.rate.period,
                            rem: n,
                        }
                    } else {
                        State::Deny { until }
                    }
                }
            }
        };

        *lock = next_state;
        matches!(next_state, State::Deny { .. })
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
        if let Some(ext) = req
            .extensions()
            .get::<crate::jsonrpc::rpc_extension_layer::RpcHeaderExt>()
        {
            tracing::info!("CALL {ext:?}");
        }

        if self.rate_limit_deny() {
            ResponseFuture::ready(MethodResponse::error(
                req.id,
                ErrorObject::borrowed(-32000, "RPC rate limit", None),
            ))
        } else {
            ResponseFuture::future(self.service.call(req))
        }
    }

    // Batch calls
    fn batch<'a>(
        &self,
        mut batch: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        if let Some(ext) = batch
            .extensions()
            .get::<crate::jsonrpc::rpc_extension_layer::RpcHeaderExt>()
        {
            tracing::info!("BATCH {ext:?}");
        }

        // If the rate limit is reached then we modify each entry
        // in the batch to be a request with an error.
        //
        // This makes sure that the client will receive an error
        // for each request in the batch.
        if self.rate_limit_deny() {
            for entry in batch.iter_mut() {
                let id = match entry {
                    Ok(BatchEntry::Call(req)) => req.id.clone(),
                    Ok(BatchEntry::Notification(_)) => continue,
                    Err(_) => continue,
                };

                // This will create a new error response for batch and replace the method call
                *entry = Err(BatchEntryErr::new(
                    id,
                    ErrorObject::borrowed(-32000, "RPC rate limit", None),
                ));
            }
        }

        self.service.batch(batch)
    }

    // Notifications
    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        if self.rate_limit_deny() {
            // Notifications are not expected to return a response so just ignore
            // if the rate limit is reached.
            ResponseFuture::ready(MethodResponse::notification())
        } else {
            ResponseFuture::future(self.service.notification(n))
        }
    }
}
