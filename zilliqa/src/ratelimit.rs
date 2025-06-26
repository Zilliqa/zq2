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
    num: u16,
    period: Duration,
}

impl Rate {
    pub fn new(num: u16, period: Duration) -> Self {
        Self { num, period }
    }
}

#[derive(Debug, Copy, Clone)]
enum State {
    Deny { until: Instant },
    Allow { until: Instant, rem: u16 },
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
                rem: num,
            })),
        }
    }
}

impl<'a, S> RpcServiceT<'a> for RateLimit<S>
where
    S: Send + RpcServiceT<'a>,
{
    type Future = ResponseFuture<S::Future>;

    // Uses a credits-based rate limiting algorithm
    //
    // Each connection is assigned a certain number of credits
    // which are consumed when a call is made. If the number of credits
    // is insufficient, the request is denied.

    fn call(&self, req: Request<'a>) -> Self::Future {
        // disable rate limiting if rate is 0
        if self.rate.num == 0 {
            return ResponseFuture::future(self.service.call(req));
        }

        let now = Instant::now();

        let is_denied = {
            let price = *RPC_CREDITS
                .get(req.method_name())
                .unwrap_or(&DEFAULT_CREDIT);

            let mut lock = self.state.lock().unwrap();
            let next_state = match *lock {
                State::Deny { until } => {
                    if now < until {
                        State::Deny { until }
                    } else if price > self.rate.num {
                        State::Deny {
                            until: now + self.rate.period,
                        }
                    } else {
                        State::Allow {
                            until: now + self.rate.period,
                            rem: self.rate.num - price,
                        }
                    }
                }
                State::Allow { until, rem } => {
                    if now < until {
                        if price > rem {
                            State::Deny { until }
                        } else {
                            State::Allow {
                                until: now + self.rate.period,
                                rem: rem - price,
                            }
                        }
                    } else if price > self.rate.num {
                        State::Deny {
                            until: now + self.rate.period,
                        }
                    } else {
                        State::Allow {
                            until: now + self.rate.period,
                            rem: self.rate.num - price,
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

use std::{collections::HashMap, sync::LazyLock};

// Pricing should be derived based on the typical/average timing of the RPC calls.
// The conversion rate should be around 1ms:1credit such that a 5ms call costs 5 credits.
// Unless otherwise listed below, the default pricing allows for 1 call/period
static RPC_CREDITS: LazyLock<HashMap<&'static str, u16>> = LazyLock::new(|| {
    // Initial pricing derived from https://docs.metamask.io/services/get-started/pricing/credit-cost/
    let mut map = HashMap::new();
    map.insert("eth_accounts", 80);
    map.insert("eth_blobBaseFee", 300);
    map.insert("eth_blockNumber", 80);
    map.insert("eth_call", 80);
    map.insert("eth_chainId", 80);
    map.insert("eth_estimateGas", 300);
    map.insert("eth_feeHistory", 80);
    map.insert("eth_gasPrice", 80);
    map.insert("eth_getBalance", 80);
    map.insert("eth_getBlockByHash", 80);
    map.insert("eth_getBlockByNumber", 80);
    map.insert("eth_getBlockReceipts", 1000);
    map.insert("eth_getBlockTransactionCountByHash", 150);
    map.insert("eth_getBlockTransactionCountByNumber", 150);
    map.insert("eth_getCode", 80);
    map.insert("eth_getLogs", 255);
    map.insert("eth_getProof", 150);
    map.insert("eth_getStorageAt", 80);
    map.insert("eth_getTransactionByBlockHashAndIndex", 150);
    map.insert("eth_getTransactionByBlockNumberAndIndex", 150);
    map.insert("eth_getTransactionByHash", 150);
    map.insert("eth_getTransactionCount", 150);
    map.insert("eth_getTransactionReceipt", 150);
    map.insert("eth_hashrate", 5);
    map.insert("eth_maxPriorityFeePerGas", 80);
    map.insert("eth_mining", 5);
    map.insert("eth_protocolVersion", 5);
    map.insert("eth_sendRawTransaction", 80);
    map.insert("eth_simulateV1", 300);
    map.insert("eth_submitWork", 80);
    map.insert("eth_syncing", 5);
    map.insert("eth_getFilterChanges", 140);
    map.insert("eth_getFilterLogs", 255);
    map.insert("eth_newBlockFilter", 80);
    map.insert("eth_newFilter", 80);
    map.insert("eth_uninstallFilter", 80);

    map.insert("net_version", 5);
    map.insert("net_peerCount", 5);
    map.insert("net_listening", 5);

    map.insert("web3_clientVersion", 5);

    map.insert("trace_block", 300);
    map.insert("trace_call", 300);
    map.insert("trace_callMany", 300);
    map.insert("trace_filter", 300);
    map.insert("trace_rawTransaction", 300);
    map.insert("trace_replayBlockTransactions", 300);
    map.insert("trace_replayTransaction", 300);
    map.insert("trace_transaction", 300);

    map.insert("debug_getBadBlocks", 1000);
    map.insert("debug_getTrieFlushInterval", 1000);
    map.insert("debug_storageRangeAt", 1000);
    map.insert("debug_traceBlock", 1000);
    map.insert("debug_traceBlockByHash", 1000);
    map.insert("debug_traceBlockByNumber", 1000);
    map.insert("debug_traceCall", 1000);
    map.insert("debug_traceTransaction", 1000);

    map
});

// the default allows 1 call/period
pub static DEFAULT_CREDIT: u16 = 500;
