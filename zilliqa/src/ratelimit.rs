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

/// Depending on how the rate limit is instantiated
/// it's possible to select whether the rate limit
/// is be applied per connection or shared by
/// all connections.
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
    // Instead of `Boxing` the future in this example
    // we are using a jsonrpsee's ResponseFuture future
    // type to avoid those extra allocations.
    type Future = ResponseFuture<S::Future>;

    fn call(&self, req: Request<'a>) -> Self::Future {
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
                ErrorObject::borrowed(-32000, "RPC_RATE_LIMIT", None),
            ))
        } else {
            ResponseFuture::future(self.service.call(req))
        }
    }
}
