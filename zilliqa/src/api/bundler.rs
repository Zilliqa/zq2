use std::sync::Arc;

use jsonrpsee::RpcModule;

use crate::{
    api::{
        HandlerType, disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook,
        rpc_base_attributes,
    },
    cfg::EnabledApi,
    node::Node,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            (
                "debug_traceCall",
                super::debug::debug_trace_call,
                HandlerType::Slow
            ),
            (
                "debug_traceTransaction",
                super::debug::debug_trace_transaction,
                HandlerType::Slow
            ),
            ("eth_call", super::eth::call, HandlerType::Fast),
            ("eth_feeHistory", super::eth::fee_history, HandlerType::Fast),
            ("eth_getBalance", super::eth::get_balance, HandlerType::Fast),
            ("eth_getLogs", super::eth::get_logs, HandlerType::Fast),
        ],
    )
}
