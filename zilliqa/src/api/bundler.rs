use std::sync::Arc;

use alloy::{
    eips::BlockId,
    rpc::types::{TransactionRequest, state::StateOverride},
};
use anyhow::Result;
use jsonrpsee::{RpcModule, core::traits::ToRpcParams, types::Params};

use crate::{
    api::{
        HandlerType, disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook,
        rpc_base_attributes,
    },
    cfg::EnabledApi,
    node::Node,
};

/// Bundler API
///
/// Provides bundler-specific API alternatives and implementations.
pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    let mut module = RpcModule::new(node.clone());
    module
        .merge(super::eth::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(super::debug::rpc_module(node.clone(), enabled_apis))
        .unwrap();

    // Overrides
    let overrides = super::declare_module!(
        node,
        enabled_apis,
        [("eth_call", eth_call, HandlerType::Fast),],
    );
    for method_name in overrides.method_names() {
        module.remove_method(method_name);
    }
    module.merge(overrides).unwrap();

    module
}

fn eth_call(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: TransactionRequest = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();
    let _overrides: StateOverride = params.optional_next()?.unwrap_or_default();

    let array_params = jsonrpsee::rpc_params!(call_params, block_id);
    let string_params = array_params.to_rpc_params()?.unwrap().get().to_owned();
    let params = Params::new(Some(&string_params));
    super::eth::call(params, node)
}
