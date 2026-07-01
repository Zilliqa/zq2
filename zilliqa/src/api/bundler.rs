use std::{sync::Arc, time::Duration};

use alloy::{
    consensus::TxLegacy,
    eips::BlockId,
    network::TxSignerSync as _,
    primitives::{Address, B256, TxKind},
    rpc::types::{
        BlockOverrides, TransactionRequest,
        state::{AccountOverride, StateOverride},
        trace::geth::{GethDebugTracingCallOptions, GethTrace},
    },
};
use anyhow::{Context, Result, anyhow};
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
    crypto::Hash,
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
        .merge(super::web3::rpc_module(node.clone(), enabled_apis))
        .unwrap();
    module
        .merge(super::net::rpc_module(node.clone(), enabled_apis))
        .unwrap();
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
        [
            ("eth_call", eth_call, HandlerType::Fast),
            ("eth_accounts", eth_accounts, HandlerType::Fast),
            (
                "eth_sendTransaction",
                eth_send_transaction,
                HandlerType::Fast
            ),
            ("debug_traceCall", debug_trace_call, HandlerType::Slow),
        ],
    );
    for method_name in overrides.method_names() {
        module.remove_method(method_name);
    }
    module.merge(overrides).unwrap();

    module
}

fn eth_accounts(_params: Params, node: &Arc<Node>) -> Result<Vec<Address>> {
    let address = node.secret_key.to_evm_address();
    Ok(vec![address])
}

// FIXME: DO NOT EXPOSE THIS TO THE PUBLIC
// This is only for local development use.
fn eth_send_transaction(params: Params, node: &Arc<Node>) -> Result<String> {
    let txn = params.one::<alloy::rpc::types::TransactionRequest>()?;

    let address = node.secret_key.to_evm_address();
    let block = node.get_block(BlockId::latest())?.context("must exist")?;
    let nonce = node.get_state(&block)?.get_account(address)?.nonce;

    let mut tx_legacy = TxLegacy {
        chain_id: Some(node.chain_id.eth),
        gas_price: node.config.consensus.gas_price.0,
        gas_limit: txn.gas.unwrap_or_default(),
        to: txn.to.unwrap_or(TxKind::Create),
        value: txn.value.unwrap_or_default(),
        input: txn.input.into_input().unwrap_or_default(),
        nonce,
    };

    let signer = alloy::signers::local::PrivateKeySigner::from_bytes(&B256::from_slice(
        node.secret_key.as_bytes().as_slice(),
    ))?;
    let sig = signer.sign_transaction_sync(&mut tx_legacy)?;

    let stx = crate::transaction::SignedTransaction::Legacy { tx: tx_legacy, sig };
    let vtx = stx.verify_bypass(Hash::ZERO)?;

    let (txn_hash, _result) = node.create_transaction(vtx)?;
    Ok(txn_hash.0.to_hex())
}

pub fn debug_trace_call(params: Params, node: &Arc<Node>) -> Result<GethTrace> {
    let mut params = params.sequence();
    let call_params: TransactionRequest = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();
    let options: GethDebugTracingCallOptions = params.optional_next()?.unwrap_or_default();
    crate::api::eth::expect_end_of_params(&mut params, 1, 3)?;

    anyhow::ensure!(
        options.block_overrides.is_none(),
        "block_overrides unexpected"
    );
    anyhow::ensure!(options.tx_index.is_none(), "tx_index unexpected");

    let (mut evm_state, block) = {
        let block = node.get_block(block_id)?;
        let block = build_errored_response_for_missing_block(block_id, block)?;
        let state = node.get_state(&block)?;
        (state, block)
    };
    anyhow::ensure!(
        !evm_state.is_empty(),
        "State required to execute request does not exist"
    );

    let state_overrides = options.state_overrides.clone().unwrap_or_default();
    let block_overrides = options.block_overrides.clone().unwrap_or_default();

    tracing::trace!(?state_overrides, ?block_overrides, ?block, "debug contract");

    apply_state_overrides(&mut evm_state, &node.clone(), state_overrides)?;

    // run the trace with timeout
    let timeout = options.tracing_options.timeout.as_ref().map_or_else(
        || Duration::from_secs(10),
        |s| duration_str::parse_std(s).unwrap_or_default(),
    );

    let handle = tokio::runtime::Handle::current();

    let result = handle.block_on(async {
        let task = tokio::task::spawn_blocking({
            let node = node.clone();
            move || node.debug_trace_call(&mut evm_state, &block, call_params, options)
        });

        tokio::time::timeout(timeout, task)
            .await
            .map_err(|_| anyhow::anyhow!("timed out"))?
            .map_err(|e| anyhow::anyhow!("panicked: {e}"))?
    })?;

    Ok(result)
}

/// Geth compatible eth_call()
///
/// Takes 3 parameters including the optional state overrides.
pub fn eth_call(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: TransactionRequest = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();
    let state_overrides: StateOverride = params.optional_next()?.unwrap_or_default();
    let block_overrides: BlockOverrides = params.optional_next()?.unwrap_or_default();
    crate::api::eth::expect_end_of_params(&mut params, 1, 4)?;

    let (mut evm_state, block) = {
        let block = node.get_block(block_id)?;
        let block = build_errored_response_for_missing_block(block_id, block)?;
        let state = node.get_state(&block)?;
        (state, block)
    };
    if evm_state.is_empty() {
        return Err(anyhow!("State required to execute request does not exist"));
    }

    tracing::trace!(?block, ?state_overrides, ?block_overrides, "call_contract");

    apply_state_overrides(&mut evm_state, &node.clone(), state_overrides)?;

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

fn apply_state_overrides(
    evm_state: &mut crate::state::State,
    node: &Arc<Node>,
    state_overrides: StateOverride,
) -> Result<()> {
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
    ) in state_overrides.into_iter()
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
    Ok(())
}
