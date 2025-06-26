use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use jsonrpsee::{
    MethodResponse,
    server::middleware::rpc::{ResponseFuture, RpcServiceT},
    types::{ErrorObject, Request},
};

/// Derived from
/// https://github.com/paritytech/jsonrpsee/blob/master/examples/examples/rpc_middleware_rate_limiting.rs

#[derive(Debug, Copy, Clone)]
pub struct Rate {
    num: u64,
    period: Duration,
}

impl Rate {
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
pub struct RateLimit<S> {
    service: S,
    state: Arc<Mutex<State>>,
    rate: Rate,
}

impl<S> RateLimit<S> {
    pub fn new(service: S, rate: Rate) -> Self {
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
}

impl<'a, S> RpcServiceT<'a> for RateLimit<S>
where
    S: Send + RpcServiceT<'a>,
{
    type Future = ResponseFuture<S::Future>;

    // Currently, does a naive calls/time limit
    // It can be improved by using a more sophisticated algorithm
    // such as using per-method based weights e.g.
    // https://docs.metamask.io/services/get-started/pricing/credit-cost/

    fn call(&self, req: Request<'a>) -> Self::Future {
        // disable rate limiting if rate is 0
        if self.rate.num == 0 {
            return ResponseFuture::future(self.service.call(req));
        }

        let now = Instant::now();

        let is_denied = {
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
        };

        if is_denied {
            ResponseFuture::ready(MethodResponse::error(
                req.id,
                ErrorObject::borrowed(-32005, "Limit exceeded", None),
            ))
        } else {
            ResponseFuture::future(self.service.call(req))
        }
    }
}
