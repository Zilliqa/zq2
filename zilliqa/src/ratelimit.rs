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
    // let mut map = HashMap::new();
    let map: HashMap<&'static str, u16> = [
        // Empirical estimates
        ("CreateTransaction", 80),
        ("GetContractAddressFromTransactionID", 250),
        ("GetBlockchainInfo", 500),
        ("GetNumTxBlocks", 250),
        ("GetSmartContractState", 1000),
        ("GetSmartContractCode", 50),
        ("GetSmartContractInit", 250),
        ("GetTransaction", 150),
        ("GetBalance", 250),
        ("GetCurrentMiniEpoch", 250),
        ("GetLatestTxBlock", 250),
        ("GetMinimumGasPrice", 250),
        ("GetNetworkId", 5),
        ("GetVersion", 5),
        ("GetTransactionsForTxBlock", 300),
        ("GetTxBlock", 250),
        ("GetTxBlockVerbose", 300),
        ("GetSmartContracts", 300),
        // ("GetDSBlock", 500u16),
        // ("GetDSBlockVerbose", 500u16),
        ("GetLatestDSBlock", 250),
        // ("GetCurrentDSComm", 500u16),
        ("GetCurrentDSEpoch", 250),
        ("DSBlockListing", 80),
        ("GetDSBlockRate", 80),
        ("GetTxBlockRate", 80),
        ("TxBlockListing", 50),
        ("GetNumPeers", 80),
        // ("GetTransactionRate", 500u16),
        // ("GetTransactionsForTxBlockEx", 500u16),
        ("GetTxnBodiesForTxBlock", 250),
        ("GetTxnBodiesForTxBlockEx", 80),
        // ("GetNumDSBlocks", 500u16),
        ("GetRecentTransactions", 500),
        // ("GetNumTransactions", 500u16),
        // ("GetNumTxnsTXEpoch", 500u16),
        // ("GetNumTxnsDSEpoch", 500u16),
        ("GetTotalCoinSupply", 5),
        ("GetTotalCoinSupplyAsInt", 5),
        ("GetMinerInfo", 5),
        // ("GetNodeType", 500u16),
        ("GetPrevDifficulty", 5),
        ("GetPrevDSDifficulty", 5),
        // ("GetShardingStructure", 500u16),
        ("GetSmartContractSubState", 80),
        // ("GetSoftConfirmedTransaction", 500u16),
        // ("GetStateProof", 500u16),
        ("GetTransactionStatus", 250),
        // RPC rate-limit can be disabled for the admin port, to enable all these calls
        ("admin_consensusInfo", 10000),
        ("admin_generateCheckpoint", 10000),
        ("admin_blockRange", 80),
        ("admin_forceView", 10000),
        ("admin_getPeers", 80),
        ("admin_votesReceived", 10000),
        ("admin_clearMempool", 10000),
        ("admin_getLeaders", 10000),
        // RPC rate-limit can be disabled for the admin port, to enable all these calls
        ("debug_getBadBlocks", 10000),
        ("debug_getTrieFlushInterval", 10000),
        ("debug_storageRangeAt", 10000),
        ("debug_traceBlock", 10000),
        ("debug_traceBlockByHash", 10000),
        ("debug_traceBlockByNumber", 10000),
        ("debug_traceCall", 10000),
        ("debug_traceTransaction", 10000),
        // Estimated from similar eth_* calls
        ("erigon_blockNumber", 80),
        ("erigon_forks", 80),
        ("erigon_getBlockByTimestamp", 150),
        ("erigon_getBlockReceiptsByBlockHash", 1000),
        ("erigon_getHeaderByHash", 80),
        ("erigon_getHeaderByNumber", 80),
        ("erigon_getLatestLogs", 250),
        ("erigon_getLogsByHash", 250),
        // Derived from https://docs.metamask.io/services/get-started/pricing/credit-cost/
        ("net_version", 5),
        ("net_peerCount", 80),
        ("net_listening", 5),
        ("web3_clientVersion", 80),
        // Empirical estimate
        ("ots_getApiLevel", 5),
        ("ots_getBlockDetails", 80),
        ("ots_getBlockDetailsByHash", 80),
        ("ots_getBlockTransactions", 250),
        ("ots_getContractCreator", 500),
        ("ots_getInternalOperations", 80),
        ("ots_getTransactionBySenderAndNonce", 50),
        ("ots_getTransactionError", 50),
        ("ots_hasCode", 5),
        ("ots_searchTransactionsAfter", 500),
        ("ots_searchTransactionsBefore", 500),
        ("ots_traceTransaction", 80),
        // Derived from https://docs.metamask.io/services/get-started/pricing/credit-cost/
        ("trace_block", 300),
        ("trace_call", 300),
        ("trace_callMany", 300),
        ("trace_filter", 300),
        ("trace_rawTransaction", 300),
        ("trace_replayBlockTransactions", 300),
        ("trace_replayTransaction", 300),
        ("trace_transaction", 300),
        // Empirical estimate
        ("txpool_content", 300),
        ("txpool_contentFrom", 300),
        ("txpool_inspect", 300),
        ("txpool_status", 300),
        // Derived from https://docs.metamask.io/services/get-started/pricing/credit-cost/
        ("eth_accounts", 80),
        ("eth_blobBaseFee", 300),
        ("eth_blockNumber", 80),
        ("eth_call", 80),
        ("eth_chainId", 80),
        ("eth_estimateGas", 300),
        ("eth_feeHistory", 80),
        ("eth_gasPrice", 80),
        ("eth_getAccount", 80),
        ("eth_getBalance", 80),
        ("eth_getBlockByHash", 80),
        ("eth_getBlockByNumber", 80),
        ("eth_getBlockReceipts", 1000),
        ("eth_getBlockTransactionCountByHash", 150),
        ("eth_getBlockTransactionCountByNumber", 150),
        ("eth_getCode", 80),
        ("eth_getFilterChanges", 140),
        ("eth_getFilterLogs", 250),
        ("eth_getLogs", 250),
        ("eth_getProof", 150),
        ("eth_getStorageAt", 80),
        ("eth_getTransactionByBlockHashAndIndex", 150),
        ("eth_getTransactionByBlockNumberAndIndex", 150),
        ("eth_getTransactionByHash", 150),
        ("eth_getTransactionCount", 150),
        ("eth_getTransactionReceipt", 150),
        ("eth_getUncleByBlockHashAndIndex", 150),
        ("eth_getUncleByBlockNumberAndIndex", 150),
        ("eth_getUncleCountByBlockHash", 150),
        ("eth_getUncleCountByBlockNumber", 150),
        ("eth_hashrate", 5),
        ("eth_maxPriorityFeePerGas", 80),
        ("eth_mining", 5),
        ("eth_newBlockFilter", 80),
        ("eth_newFilter", 80),
        ("eth_uninstallFilter", 80),
        ("eth_protocolVersion", 5),
        ("eth_sendRawTransaction", 80),
        ("eth_signTransaction", 80),
        ("eth_simulateV1", 300),
        ("eth_submitWork", 80),
        ("eth_syncing", 5),
    ]
    .into_iter()
    .collect();

    map
});

// default config allows 1 call/period.
pub static DEFAULT_CREDIT: u16 = 500;
