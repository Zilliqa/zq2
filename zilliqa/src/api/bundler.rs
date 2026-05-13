use std::sync::Arc;

use alloy::{
    eips::BlockId,
    rpc::types::{
        TransactionRequest,
        state::{AccountOverride, StateOverride},
    },
};
use anyhow::{Result, anyhow};
use eth_trie::{EthTrie, Trie as _};
use jsonrpsee::{
    RpcModule,
    types::{ErrorObjectOwned, Params},
};

use crate::{
    api::{
        HandlerType, disabled_err, eth::build_errored_response_for_missing_block,
        format_panic_as_error, into_rpc_error, make_panic_hook, rpc_base_attributes,
        to_hex::ToHex as _,
    },
    cfg::EnabledApi,
    error::ensure_success,
    node::Node,
    state::Code,
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

/// Geth compatible eth_call()
///
/// Takes 3 parameters including the optional state overrides.
pub fn eth_call(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: TransactionRequest = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();
    let overrides: StateOverride = params.optional_next()?.unwrap_or_default();

    let (mut evm_state, block) = {
        let block = node.get_block(block_id)?;
        let block = build_errored_response_for_missing_block(block_id, block)?;
        let state = node.get_state(&block)?;
        (state, block)
    };
    if evm_state.is_empty() {
        return Err(anyhow!("State required to execute request does not exist"));
    }

    tracing::trace!("call_contract: block={block:?} overrides={overrides:?}");

    // override state - skipped if empty
    // TODO: Do not commit changes to disk - simulation only.
    for (
        address,
        AccountOverride {
            balance,
            nonce,
            code,
            state,
            state_diff,
            move_precompile_to,
        },
    ) in overrides.into_iter()
    {
        // The fake balance to set for the account before executing the call
        if let Some(balance) = balance {
            evm_state.mutate_account(address, |a| {
                a.balance = balance.to::<u128>();
                Ok(())
            })?;
        }
        // The fake nonce to set for the account before executing the call
        if let Some(nonce) = nonce {
            evm_state.mutate_account(address, |a| {
                a.nonce = nonce;
                Ok(())
            })?;
        }
        // The fake EVM bytecode to inject into the account before executing the call
        if let Some(code) = code {
            evm_state.mutate_account(address, |a| {
                a.code = Code::Evm(code.into());
                Ok(())
            })?;
        }
        // The fake key-value mapping to override all slots in the account storage before executing the call
        if let Some(state) = state {
            let state_trie = Arc::new(node.db.state_trie()?);
            let mut trie = EthTrie::new(state_trie);
            for (k, v) in state.iter() {
                trie.insert(k.0.as_slice(), v.0.as_slice())?;
            }
            let storage_root = trie.root_hash()?;
            evm_state.mutate_account(address, |a| {
                a.storage_root = storage_root;
                Ok(())
            })?;
        }
        // The fake key-value mapping to override individual slots in the account storage before executing the call
        if let Some(state) = state_diff {
            let mut trie = evm_state.get_account_trie(address)?;
            for (k, v) in state.iter() {
                trie.insert(k.0.as_slice(), v.0.as_slice())?;
            }
            let storage_root = trie.root_hash()?;
            evm_state.mutate_account(address, |a| {
                a.storage_root = storage_root;
                Ok(())
            })?;
        }
        if let Some(_move_precompile_to) = move_precompile_to {
            unimplemented!()
        }
    }

    let result = evm_state.call_contract(
        call_params.from.unwrap_or_default(),
        call_params.to.and_then(|to| to.into_to()),
        call_params.input.into_input().unwrap_or_default().to_vec(),
        u128::try_from(call_params.value.unwrap_or_default())?,
        block.header,
    )?;

    match ensure_success(result) {
        Ok(output) => Ok(output.to_hex()),
        Err(err) => Err(ErrorObjectOwned::from(err).into()),
    }
}
