//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::{collections::HashMap, sync::Arc};

use alloy::{
    consensus::{TxEip1559, TxEip2930, TxLegacy, transaction::RlpEcdsaDecodableTx},
    eips::{BlockId, BlockNumberOrTag, RpcBlockHash},
    primitives::{Address, B256, U64, U256},
    rpc::types::{
        FeeHistory, FilteredParams, TransactionRequest,
        pubsub::{self, SubscriptionKind},
    },
};
use anyhow::{Result, anyhow};
use http::Extensions;
use jsonrpsee::{
    PendingSubscriptionSink, RpcModule,
    core::SubscriptionError,
    types::{
        Params,
        error::{ErrorObject, ErrorObjectOwned},
        params::ParamsSequence,
    },
};
use parking_lot::RwLock;
use revm::primitives::keccak256;
use serde_json::json;
use tracing::*;

use super::{
    HandlerType,
    to_hex::ToHex,
    types::{
        eth::{self, ErrorCode, HashOrTransaction, SyncingResult, TransactionReceipt},
        filters::{BlockFilter, FilterKind, LogFilter, PendingTxFilter},
    },
};
use crate::{
    api::{
        disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook, rpc_base_attributes,
        types::eth::GetAccountResult, zilliqa::ZilAddress,
    },
    cfg::EnabledApi,
    constants::BASE_FEE_PER_GAS,
    crypto::Hash,
    data_access,
    db::Db,
    error::ensure_success,
    exec::{ExecType::Estimate, ExtraOpts, zil_contract_address},
    message::Block,
    node::Node,
    pool::{TransactionPool, TxAddResult},
    state::Code,
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, VerifiedTransaction},
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    let mut module = super::declare_module!(
        node,
        enabled_apis,
        [
            ("eth_accounts", accounts, HandlerType::Fast),
            ("eth_blobBaseFee", blob_base_fee, HandlerType::Fast),
            ("eth_blockNumber", block_number, HandlerType::Fast),
            ("eth_call", call, HandlerType::Fast),
            ("eth_callMany", call_many, HandlerType::Fast),
            ("eth_chainId", chain_id, HandlerType::Fast),
            ("eth_estimateGas", estimate_gas, HandlerType::Fast),
            ("eth_feeHistory", fee_history, HandlerType::Fast),
            ("eth_gasPrice", get_gas_price, HandlerType::Fast),
            ("eth_getAccount", get_account, HandlerType::Fast),
            ("eth_getBalance", get_balance, HandlerType::Fast),
            ("eth_getBlockByHash", get_block_by_hash, HandlerType::Fast),
            (
                "eth_getBlockByNumber",
                get_block_by_number,
                HandlerType::Fast
            ),
            (
                "eth_getBlockReceipts",
                get_block_receipts,
                HandlerType::Fast
            ),
            (
                "eth_getBlockTransactionCountByHash",
                get_block_transaction_count_by_hash,
                HandlerType::Fast
            ),
            (
                "eth_getBlockTransactionCountByNumber",
                get_block_transaction_count_by_number,
                HandlerType::Fast
            ),
            ("eth_getCode", get_code, HandlerType::Fast),
            (
                "eth_getFilterChanges",
                get_filter_changes,
                HandlerType::Fast
            ),
            ("eth_getFilterLogs", get_filter_logs, HandlerType::Fast),
            ("eth_getLogs", get_logs, HandlerType::Fast),
            ("eth_getProof", get_proof, HandlerType::Fast),
            ("eth_getStorageAt", get_storage_at, HandlerType::Fast),
            (
                "eth_getTransactionByBlockHashAndIndex",
                get_transaction_by_block_hash_and_index,
                HandlerType::Fast
            ),
            (
                "eth_getTransactionByBlockNumberAndIndex",
                get_transaction_by_block_number_and_index,
                HandlerType::Fast
            ),
            (
                "eth_getTransactionByHash",
                get_transaction_by_hash,
                HandlerType::Fast
            ),
            (
                "eth_getTransactionCount",
                get_transaction_count,
                HandlerType::Fast
            ),
            (
                "eth_getTransactionReceipt",
                get_transaction_receipt,
                HandlerType::Fast
            ),
            (
                "eth_getUncleByBlockHashAndIndex",
                get_uncle,
                HandlerType::Fast
            ),
            (
                "eth_getUncleByBlockNumberAndIndex",
                get_uncle,
                HandlerType::Fast
            ),
            (
                "eth_getUncleCountByBlockHash",
                get_uncle_count,
                HandlerType::Fast
            ),
            (
                "eth_getUncleCountByBlockNumber",
                get_uncle_count,
                HandlerType::Fast
            ),
            ("eth_hashrate", hashrate, HandlerType::Fast),
            (
                "eth_maxPriorityFeePerGas",
                max_priority_fee_per_gas,
                HandlerType::Fast
            ),
            ("eth_mining", mining, HandlerType::Fast),
            ("eth_newBlockFilter", new_block_filter, HandlerType::Fast),
            ("eth_newFilter", new_filter, HandlerType::Fast),
            (
                "eth_newPendingTransactionFilter",
                new_pending_transaction_filter,
                HandlerType::Fast
            ),
            ("eth_protocolVersion", protocol_version, HandlerType::Fast),
            (
                "eth_sendRawTransaction",
                send_raw_transaction,
                HandlerType::Fast
            ),
            ("eth_signTransaction", sign_transaction, HandlerType::Fast),
            ("eth_simulateV1", simulate_v1, HandlerType::Fast),
            ("eth_submitWork", submit_work, HandlerType::Fast),
            ("eth_syncing", syncing, HandlerType::Fast),
            ("eth_uninstallFilter", uninstall_filter, HandlerType::Fast),
        ],
    );

    module
        .register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            subscribe,
        )
        .unwrap();

    module
}

// See https://eips.ethereum.org/EIPS/eip-1898
fn build_errored_response_for_missing_block(
    request: BlockId,
    result: Option<Block>,
) -> Result<Block> {
    // Block has been found
    if let Some(block) = result {
        return Ok(block);
    }

    const INVALID_INPUT: i32 = -32000;
    let resource_not_found = ErrorObjectOwned::owned(
        INVALID_INPUT,
        "Invalid input".to_string(),
        Option::<String>::None,
    );

    let BlockId::Hash(RpcBlockHash {
        require_canonical, ..
    }) = request
    else {
        return Err(resource_not_found.into());
    };

    let require_canonical = require_canonical.unwrap_or_default();

    match require_canonical {
        true => {
            const INVALID_INPUT: i32 = -32000;
            let response = ErrorObjectOwned::owned(
                INVALID_INPUT,
                "Invalid input".to_string(),
                Option::<String>::None,
            );
            Err(response.into())
        }
        false => Err(resource_not_found.into()),
    }
}

fn expect_end_of_params(seq: &mut ParamsSequence, min: u32, max: u32) -> Result<()> {
    // Styled after the geth error message.
    let msg = if min != max {
        format!("too many arguments, want at most {max}")
    } else {
        format!("too many arguments, want {max}")
    };
    match seq.next::<serde_json::Value>() {
        Ok(_) => Err(ErrorObjectOwned::owned(
            jsonrpsee::types::error::INVALID_PARAMS_CODE,
            msg,
            Option::<String>::None,
        )
        .into()),
        _ => Ok(()),
    }
}

fn accounts(params: Params, _: &Arc<Node>) -> Result<[(); 0]> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok([])
}

fn block_number(params: Params, node: &Arc<Node>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    let db = node.db.clone();
    Ok(data_access::get_highest_canonical_block_number(db).to_hex())
}

fn call_many(_params: Params, _node: &Arc<Node>) -> Result<()> {
    // TODO: disable_eip3607 for this call.
    Err(anyhow!("API method eth_callMany is not implemented yet"))
}

fn call(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: TransactionRequest = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();
    expect_end_of_params(&mut params, 1, 2)?;

    let (state, block) = {
        let block = node.get_block(block_id)?;
        let block = build_errored_response_for_missing_block(block_id, block)?;
        let state = node.get_state(&block)?;
        (state, block)
    };
    if state.is_empty() {
        return Err(anyhow!("State required to execute request does not exist"));
    }

    trace!("call_contract: block={:?}", block);

    let result = state.call_contract(
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

fn chain_id(params: Params, node: &Arc<Node>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.config.eth_chain_id.to_hex())
}

fn estimate_gas(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: TransactionRequest = params.next()?;
    let block_number: BlockNumberOrTag = params.optional_next()?.unwrap_or_default();
    expect_end_of_params(&mut params, 1, 2)?;

    let (block, parent, state) = {
        let block = node
            .get_block(block_number)?
            .ok_or_else(|| anyhow!("missing block: {block_number}"))?;
        let parent = node
            .get_block(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing parent block"))?;

        let state = node.get_state(&block)?;
        if state.is_empty() {
            return Err(anyhow!("State required to execute request does not exist"));
        }
        (block, parent, state)
    };

    let return_value = state.estimate_gas(
        call_params.from.unwrap_or_default(),
        call_params.to.and_then(|to| to.into_to()),
        call_params.input.input().unwrap_or_default().to_vec(),
        block.header,
        call_params.gas.map(EvmGas),
        call_params.fee_cap(),
        call_params.max_priority_fee_per_gas,
        u128::try_from(call_params.value.unwrap_or_default())?,
        call_params.access_list,
        ExtraOpts {
            tx_type: call_params.transaction_type.unwrap_or_default().into(),
            disable_eip3607: true,
            exec_type: Estimate,
            randao_mix_hash: parent.header.mix_hash.unwrap_or(Hash::ZERO),
        },
    )?;

    Ok(return_value.to_hex())
}

fn get_balance(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let address: ZilAddress = params.next()?;
    let address: Address = address.into();

    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let state = {
        let block = node.get_block(block_id)?;

        let block = build_errored_response_for_missing_block(block_id, block)?;
        node.get_state(&block)?
    };

    Ok(state.get_account(address)?.balance.to_hex())
}

pub fn brt_to_eth_receipts(
    btr: crate::db::BlockAndReceiptsAndTransactions,
) -> Vec<TransactionReceipt> {
    let block = btr.block;

    let base_receipts = btr.receipts;
    let transactions: HashMap<Hash, VerifiedTransaction> =
        btr.transactions.into_iter().map(|x| (x.hash, x)).collect();

    let mut log_index = 0;
    let mut receipts = Vec::new();

    for (transaction_index, receipt_retrieved) in base_receipts.iter().enumerate() {
        let transaction = transactions.get(&receipt_retrieved.tx_hash).unwrap();

        // Required workaround for incorrectly converted nonces for zq1 scilla transactions
        let contract_address = match &transaction.tx {
            SignedTransaction::Zilliqa { tx, .. } => {
                if tx.to_addr.is_zero() && receipt_retrieved.success {
                    Some(zil_contract_address(
                        transaction.signer,
                        transaction.tx.nonce().unwrap(),
                    ))
                } else {
                    receipt_retrieved.contract_address
                }
            }
            _ => receipt_retrieved.contract_address,
        };

        let mut logs_bloom = [0; 256];

        let mut logs = Vec::new();
        for log in receipt_retrieved.logs.iter() {
            let log = match log {
                Log::Evm(log) => log.clone(),
                Log::Scilla(log) => log.clone().into_evm(),
            };
            let log = eth::Log::new(
                log,
                log_index,
                transaction_index,
                receipt_retrieved.tx_hash,
                block.number(),
                block.hash(),
            );
            log_index += 1;
            log.bloom(&mut logs_bloom);
            logs.push(log);
        }

        let from = transaction.signer;
        let v = transaction.tx.sig_v();
        let r = transaction.tx.sig_r();
        let s = transaction.tx.sig_s();
        let transaction = transaction.tx.clone().into_transaction();

        let receipt = TransactionReceipt {
            transaction_hash: receipt_retrieved.tx_hash.into(),
            transaction_index: transaction_index as u64,
            block_hash: block.hash().into(),
            block_number: block.number(),
            from,
            to: transaction.to_addr(),
            cumulative_gas_used: receipt_retrieved.cumulative_gas_used,
            effective_gas_price: transaction.max_fee_per_gas(),
            gas_used: receipt_retrieved.gas_used,
            contract_address,
            logs,
            logs_bloom,
            ty: 0,
            status: receipt_retrieved.success,
            v,
            r,
            s,
        };

        receipts.push(receipt);
    }

    receipts
}

pub fn old_get_block_transaction_receipts_inner(
    db: Arc<Db>,
    block: &Block,
) -> Result<Vec<TransactionReceipt>> {
    let mut log_index = 0;
    let mut receipts = Vec::new();

    let receipts_retrieved =
        data_access::get_transaction_receipts_in_block(db.clone(), block.header.hash)?;

    for (transaction_index, receipt_retrieved) in receipts_retrieved.iter().enumerate() {
        // This could maybe be a bit faster if we had a db function that queried transactions by
        // block hash, joined on receipts, but this would be quite a bit of new code.
        let Some(verified_transaction) =
            data_access::get_transaction_by_hash(db.clone(), None, receipt_retrieved.tx_hash)?
        else {
            warn!(
                "Failed to get TX by hash when getting TX receipt! {}",
                receipt_retrieved.tx_hash
            );
            continue;
        };

        // Required workaround for incorrectly converted nonces for zq1 scilla transactions
        let contract_address = match &verified_transaction.tx {
            SignedTransaction::Zilliqa { tx, .. } => {
                if tx.to_addr.is_zero() && receipt_retrieved.success {
                    Some(zil_contract_address(
                        verified_transaction.signer,
                        verified_transaction
                            .tx
                            .nonce()
                            .ok_or_else(|| anyhow!("Unable to extract nonce!"))?,
                    ))
                } else {
                    receipt_retrieved.contract_address
                }
            }
            _ => receipt_retrieved.contract_address,
        };

        let mut logs = Vec::new();
        for log in receipt_retrieved.logs.iter() {
            let log = match log {
                Log::Evm(log) => log.clone(),
                Log::Scilla(log) => log.clone().into_evm(),
            };
            let log = eth::Log::new(
                log,
                log_index,
                transaction_index,
                receipt_retrieved.tx_hash,
                block.number(),
                block.hash(),
            );
            log_index += 1;
            logs.push(log);
        }

        let from = verified_transaction.signer;
        let v = verified_transaction.tx.sig_v();
        let r = verified_transaction.tx.sig_r();
        let s = verified_transaction.tx.sig_s();
        let transaction = verified_transaction.tx.into_transaction();

        let receipt = TransactionReceipt {
            transaction_hash: receipt_retrieved.tx_hash.into(),
            transaction_index: transaction_index as u64,
            block_hash: block.hash().into(),
            block_number: block.number(),
            from,
            to: transaction.to_addr(),
            cumulative_gas_used: receipt_retrieved.cumulative_gas_used,
            effective_gas_price: transaction.max_fee_per_gas(),
            gas_used: receipt_retrieved.gas_used,
            contract_address,
            logs,
            logs_bloom: [0; 256],
            ty: transaction.transaction_type(),
            status: receipt_retrieved.success,
            v,
            r,
            s,
        };

        receipts.push(receipt);
    }

    Ok(receipts)
}

// This has to iterate through a whole block, so get_block_transaction_receipts_inner is more efficient for multiple receipts
pub fn get_transaction_receipt_inner_slow(
    node: &Node,
    block_id: impl Into<BlockId>,
    txn_hash: Hash,
) -> Result<Option<TransactionReceipt>> {
    let (db, block) = {
        let Some(block) = node.get_block(block_id)? else {
            return Err(anyhow!("Block not found"));
        };
        (node.db.clone(), block)
    };
    let receipts = old_get_block_transaction_receipts_inner(db, &block)?;
    Ok(receipts
        .into_iter()
        .find(|r| r.transaction_hash == txn_hash.as_bytes()))
}

fn get_block_receipts(params: Params, node: &Arc<Node>) -> Result<Vec<TransactionReceipt>> {
    let block_id: BlockId = params.one()?;

    let (db, block) = {
        let Some(block) = node.get_block(block_id)? else {
            return Err(anyhow!("Block not found"));
        };
        (node.db.clone(), block)
    };

    old_get_block_transaction_receipts_inner(db, &block)
}

fn get_code(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let state = {
        let block = node.get_block(block_id)?;

        let block = build_errored_response_for_missing_block(block_id, block)?;
        node.get_state(&block)?
    };

    // For compatibility with Zilliqa 1, eth_getCode also returns Scilla code if any is present.
    let code = state.get_account(address)?.code;

    // do it this way so the compiler will tell us when another option inevitably
    // turns up and we have to deal with it ..
    let return_code = if code.is_eoa() {
        vec![].to_hex()
    } else {
        match code {
            Code::Evm(val) => val.to_hex(),
            Code::Scilla { code, .. } => code.to_hex(),
        }
    };

    Ok(return_code)
}

fn get_storage_at(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let position: U256 = params.next()?;
    let position = B256::new(position.to_be_bytes());
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 3, 3)?;

    let state = {
        let block = node.get_block(block_id)?;
        let block = build_errored_response_for_missing_block(block_id, block)?;
        node.get_state(&block)?
    };

    let value = state.get_account_storage(address, position)?;

    Ok(value.to_hex())
}

fn get_transaction_count(params: Params, node: &Arc<Node>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 3, 3)?;

    let block = node.get_block(block_id)?;
    let block = build_errored_response_for_missing_block(block_id, block)?;

    let nonce = node.get_state(&block)?.get_account(address)?.nonce;

    if matches!(block_id, BlockId::Number(BlockNumberOrTag::Pending)) {
        Ok(node
            .consensus
            .read()
            .pending_transaction_count(address)
            .to_hex())
    } else {
        Ok(nonce.to_hex())
    }
}

fn get_gas_price(params: Params, node: &Arc<Node>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.get_gas_price().to_hex())
}

fn get_block_by_number(params: Params, node: &Arc<Node>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let full: bool = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    // Pending blocks are not queried from db
    // TODO: add transactions
    if matches!(block_number, BlockNumberOrTag::Pending) {
        let block = node
            .get_block(block_number)?
            .ok_or_else(|| anyhow!("Block not found"))?;
        let miner = node.get_proposer_reward_address(block.header)?;
        let block_gas_limit = block.gas_limit();
        let result = eth::Block::from_block(&block, miner.unwrap_or_default(), block_gas_limit);
        return Ok(Some(result));
    }

    get_eth_block(node, block_number.into(), full)
}

fn get_block_by_hash(params: Params, node: &Arc<Node>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let hash: B256 = params.next()?;
    let full: bool = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    get_eth_block(node, crate::db::BlockFilter::Hash(hash.into()), full)
}

pub fn get_eth_block(
    node: &Arc<Node>,
    block_id: crate::db::BlockFilter,
    full: bool,
) -> Result<Option<eth::Block>> {
    let block = match node.db.get_block(block_id)? {
        Some(block) => block,
        None => return Ok(None),
    };

    let miner = node.get_proposer_reward_address(block.header)?;
    let block_gas_limit = block.gas_limit();
    let mut result = eth::Block::from_block(&block, miner.unwrap_or_default(), block_gas_limit);

    if let Some(max_txns) = node.config.api_limits.max_txns_in_block_to_fetch
        && full
        && block.transactions.len() as u64 > max_txns
    {
        return Err(anyhow!(
            "Block has too many transactions to fetch. Max: {max_txns}, got: {}",
            block.transactions.len()
        ));
    }

    if full {
        let transactions = node.db.get_transactions(&block.transactions)?;
        result.transactions = transactions
            .iter()
            .map(|x| eth::Transaction::new(x.clone(), Some(block.clone())))
            .map(HashOrTransaction::Transaction)
            .collect();
    }
    Ok(Some(result))
}

fn get_block_transaction_count_by_hash(params: Params, node: &Arc<Node>) -> Result<Option<String>> {
    let mut params = params.sequence();
    let hash: B256 = params.next()?;
    expect_end_of_params(&mut params, 1, 1)?;

    let block = node.get_block(hash)?;

    Ok(block.map(|b| b.transactions.len().to_hex()))
}

fn get_block_transaction_count_by_number(
    params: Params,
    node: &Arc<Node>,
) -> Result<Option<String>> {
    let mut params = params.sequence();
    // The ethereum RPC spec says this is optional, but it is mandatory in geth and erigon.
    let block_number: BlockNumberOrTag = params.next()?;
    expect_end_of_params(&mut params, 1, 1)?;

    let block = node.get_block(block_number)?;

    Ok(Some(
        block.map_or(0, |block| block.transactions.len()).to_hex(),
    ))
}

fn get_logs(params: Params, node: &Arc<Node>) -> Result<Vec<eth::Log>> {
    let mut seq = params.sequence();
    let params: alloy::rpc::types::Filter = seq.next()?;
    expect_end_of_params(&mut seq, 1, 1)?;
    get_logs_inner(&params, node)
}

fn get_logs_inner(params: &alloy::rpc::types::Filter, node: &Arc<Node>) -> Result<Vec<eth::Log>> {
    let filter_params = FilteredParams::new(Some(params.clone()));

    // Find the range of blocks we care about. This is an iterator of blocks.
    let blocks = match params.block_option {
        alloy::rpc::types::FilterBlockOption::AtBlockHash(block_hash) => {
            vec![
                node.get_block(block_hash)?
                    .ok_or_else(|| anyhow!("block not found"))?,
            ]
        }
        alloy::rpc::types::FilterBlockOption::Range {
            from_block,
            to_block,
        } => {
            let Some(from) = node
                .resolve_block_number(from_block.unwrap_or(BlockNumberOrTag::Latest))?
                .as_ref()
                .map(Block::number)
            else {
                return Ok(vec![]);
            };

            let to = node.resolve_block_number(to_block.unwrap_or(BlockNumberOrTag::Latest))?;

            let to = match to {
                Some(block) => block.number(),
                None => node
                    .resolve_block_number(BlockNumberOrTag::Latest)?
                    .unwrap()
                    .number(),
            };

            if from > to {
                return Err(anyhow!("`from` is greater than `to` ({from} > {to})"));
            }

            if let Some(max_blocks) = node.config.api_limits.max_blocks_to_fetch
                && to - from > max_blocks
            {
                return Err(anyhow!("Range of blocks exceeds {max_blocks}"));
            }

            let db = node.db.clone();
            db.get_blocks_by_height_range(from..=to)?
        }
    };

    let mut logs = vec![];

    let db = node.db.clone();

    let blocks_and_receipts = db.get_transaction_receipts_in_blocks(blocks)?;

    for (block, receipts) in blocks_and_receipts {
        for (index, receipt) in receipts.into_iter().enumerate() {
            for (log_index, log) in receipt.logs.into_iter().enumerate() {
                let log = match log {
                    Log::Evm(l) => l,
                    Log::Scilla(l) => l.into_evm(),
                };

                if !filter_params.filter_address(&log.address) {
                    continue;
                }

                if !filter_params.filter_topics(&log.topics) {
                    continue;
                }

                logs.push(eth::Log::new(
                    log,
                    log_index,
                    index,
                    receipt.tx_hash,
                    block.number(),
                    block.hash(),
                ));
            }
        }
    }

    Ok(logs)
}

fn get_transaction_by_block_hash_and_index(
    params: Params,
    node: &Arc<Node>,
) -> Result<Option<eth::Transaction>> {
    let mut params = params.sequence();
    let block_hash: B256 = params.next()?;
    let index: U64 = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let (pool, db, txn_hash) = {
        let Some(block) = node.get_block(block_hash)? else {
            return Ok(None);
        };
        let Some(txn_hash) = block.transactions.get(index.to::<usize>()).copied() else {
            return Ok(None);
        };
        (
            node.consensus.read().transaction_pool.clone(),
            node.db.clone(),
            txn_hash,
        )
    };

    get_transaction_inner(txn_hash, pool, db)
}

fn get_transaction_by_block_number_and_index(
    params: Params,
    node: &Arc<Node>,
) -> Result<Option<eth::Transaction>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let index: U64 = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let (pool, db, txn_hash) = {
        let Some(block) = node.get_block(block_number)? else {
            return Ok(None);
        };
        let Some(txn_hash) = block.transactions.get(index.to::<usize>()).copied() else {
            return Ok(None);
        };
        (
            node.consensus.read().transaction_pool.clone(),
            node.db.clone(),
            txn_hash,
        )
    };

    get_transaction_inner(txn_hash, pool, db)
}

fn get_transaction_by_hash(params: Params, node: &Arc<Node>) -> Result<Option<eth::Transaction>> {
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let (pool, db) = {
        (
            node.consensus.read().transaction_pool.clone(),
            node.db.clone(),
        )
    };

    get_transaction_inner(hash, pool, db)
}

pub(super) fn get_transaction_inner(
    hash: Hash,
    pool: Arc<RwLock<TransactionPool>>,
    db: Arc<Db>,
) -> Result<Option<eth::Transaction>> {
    let Some(tx) = data_access::get_transaction_by_hash(db.clone(), Some(pool), hash)? else {
        return Ok(None);
    };

    // The block can either be null or some based on whether the tx exists
    let block = if let Some(receipt) = data_access::get_transaction_receipt(db.clone(), hash)? {
        data_access::get_block_by_hash(db.clone(), &receipt.block_hash)?
    } else {
        // Even if it has not been mined, the tx may still be in the mempool and should return
        // a correct tx, with pending/null fields
        None
    };

    Ok(Some(eth::Transaction::new(tx, block)))
}

fn get_transaction_receipt(params: Params, node: &Arc<Node>) -> Result<Option<TransactionReceipt>> {
    let hash: B256 = params.one()?;
    let hash: Hash = hash.into();
    let block_hash = match node.get_transaction_receipt(hash)? {
        Some(receipt) => receipt.block_hash,
        None => return Ok(None),
    };
    get_transaction_receipt_inner_slow(node, block_hash, hash)
}

fn send_raw_transaction(params: Params, node: &Arc<Node>) -> Result<String> {
    let transaction: String = params.one()?;
    let transaction = transaction
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let transaction = hex::decode(transaction)?;
    let transaction = parse_transaction(&transaction)?;

    let transaction = transaction.verify()?;

    let (hash, result) = node.create_transaction(transaction)?;
    match result {
        TxAddResult::AddedToMempool
        | TxAddResult::Duplicate(_)
        | TxAddResult::SameNonceButLowerGasPrice => Ok(()),
        TxAddResult::CannotVerifySignature => Err(ErrorObject::owned::<String>(
            ErrorCode::TransactionRejected as i32,
            "Cannot verify signature".to_string(),
            None,
        )),
        TxAddResult::ValidationFailed(reason) => Err(ErrorObject::owned::<String>(
            ErrorCode::InvalidParams as i32,
            reason.to_msg_string(),
            None,
        )),
        TxAddResult::NonceTooLow(got, expected) => Err(ErrorObject::owned::<String>(
            ErrorCode::InvalidParams as i32,
            format!("Nonce ({got}) lower than current ({expected})"),
            None,
        )),
    }?;
    let transaction_hash = B256::from(hash);

    Ok(transaction_hash.to_hex())
}

fn parse_transaction(bytes: &[u8]) -> Result<SignedTransaction> {
    // https://eips.ethereum.org/EIPS/eip-2718#backwards-compatibility
    // "Clients can differentiate between the legacy transactions and typed transactions by looking at the first byte.
    // If it starts with a value in the range [0, 0x7f] then it is a new transaction type, if it starts with a value in
    // the range [0xc0, 0xfe] then it is a legacy transaction type."
    match bytes[0] {
        0xc0..=0xfe => parse_legacy_transaction(bytes),
        0x01 => parse_eip2930_transaction(&bytes[1..]),
        0x02 => parse_eip1559_transaction(&bytes[1..]),
        _ => Err(anyhow!(
            "invalid transaction with starting byte {}",
            bytes[0]
        )),
    }
}

fn parse_legacy_transaction(mut buf: &[u8]) -> Result<SignedTransaction> {
    let (tx, sig) = TxLegacy::rlp_decode_with_signature(&mut buf)?;
    Ok(SignedTransaction::Legacy { tx, sig })
}

fn parse_eip2930_transaction(mut buf: &[u8]) -> Result<SignedTransaction> {
    let (tx, sig) = TxEip2930::rlp_decode_with_signature(&mut buf)?;
    Ok(SignedTransaction::Eip2930 { tx, sig })
}

fn parse_eip1559_transaction(mut buf: &[u8]) -> Result<SignedTransaction> {
    let (tx, sig) = TxEip1559::rlp_decode_with_signature(&mut buf)?;
    Ok(SignedTransaction::Eip1559 { tx, sig })
}

fn get_uncle_count(_: Params, _: &Arc<Node>) -> Result<String> {
    Ok("0x0".to_string())
}

fn get_uncle(_: Params, _: &Arc<Node>) -> Result<Option<String>> {
    Ok(None)
}

fn mining(_: Params, _: &Arc<Node>) -> Result<bool> {
    Ok(false)
}

fn protocol_version(_: Params, _: &Arc<Node>) -> Result<String> {
    Ok("0x41".to_string())
}

fn syncing(params: Params, node: &Arc<Node>) -> Result<SyncingResult> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    let db = node.db.clone();
    if let Some(result) = node.consensus.read().get_sync_data(db)? {
        Ok(SyncingResult::Struct(result))
    } else {
        Ok(SyncingResult::Bool(false))
    }
}

#[allow(clippy::redundant_allocation, clippy::await_holding_lock)]
async fn subscribe(
    params: Params<'_>,
    pending: PendingSubscriptionSink,
    node: Arc<Arc<Node>>,
    _: Extensions,
) -> Result<(), SubscriptionError> {
    let mut params = params.sequence();
    let kind: SubscriptionKind = params.next()?;
    let params: Option<pubsub::Params> = params.optional_next()?;
    let params = params.unwrap_or_default();

    let sink = pending.accept().await?;

    match kind {
        SubscriptionKind::NewHeads => {
            let mut new_blocks = node.subscribe_to_new_blocks();

            while let Ok(header) = new_blocks.recv().await {
                let block = node
                    .consensus
                    .read()
                    .db
                    .get_transactionless_block(header.hash.into())?
                    .ok_or("Block not found")?;
                let miner = node.get_proposer_reward_address(block.header)?;
                let block_gas_limit = block.gas_limit();
                let eth_block =
                    eth::Block::from_block(&block, miner.unwrap_or_default(), block_gas_limit);
                let header = eth_block.header;
                let _ = sink.send(serde_json::value::to_raw_value(&header)?).await;
            }
        }
        SubscriptionKind::Logs => {
            let filter = match params {
                pubsub::Params::None => None,
                pubsub::Params::Logs(f) => Some(*f),
                pubsub::Params::Bool(_) => {
                    return Err("invalid params for logs".into());
                }
            };
            let filter = FilteredParams::new(filter);

            let mut receipts = node.subscribe_to_receipts();

            'outer: while let Ok((receipt, transaction_index)) = receipts.recv().await {
                if !filter.filter_block_hash(receipt.block_hash.into()) {
                    continue;
                }
                let block = node
                    .get_block(receipt.block_hash)?
                    .ok_or("Block not found")?;

                // We track log index plus one because we have to increment before we use the log index, and log indexes are 0-based.
                let mut log_index_plus_one: i64 =
                    old_get_block_transaction_receipts_inner(node.db.clone(), &block)?
                        .iter()
                        .take_while(|x| x.transaction_index < receipt.index)
                        .map(|x| x.logs.len())
                        .sum::<usize>() as i64;

                let mut logs = Vec::new();
                for log in receipt.logs.into_iter() {
                    log_index_plus_one += 1;
                    // Only consider EVM logs
                    let Log::Evm(log) = log else {
                        continue;
                    };
                    if !filter.filter_address(&log.address) {
                        continue;
                    }
                    if !filter.filter_topics(&log.topics) {
                        continue;
                    }

                    // We defer this check to later to avoid querying the block if the log was already filtered out by
                    // something else.
                    let block = node
                        .get_block(receipt.block_hash)?
                        .ok_or_else(|| anyhow!("missing block"))?;
                    if !filter.filter_block_range(block.number()) {
                        continue 'outer;
                    }

                    logs.push(alloy::rpc::types::Log {
                        inner: alloy::primitives::Log {
                            address: log.address,
                            data: alloy::primitives::LogData::new_unchecked(
                                log.topics,
                                log.data.into(),
                            ),
                        },
                        block_hash: Some(block.hash().into()),
                        block_number: Some(block.number()),
                        block_timestamp: Some(
                            block
                                .timestamp()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        ),
                        transaction_hash: Some(receipt.tx_hash.into()),
                        transaction_index: Some(transaction_index as u64),
                        log_index: Some((log_index_plus_one - 1) as u64),
                        removed: false,
                    });
                }
                for log in logs {
                    let _ = sink.send(serde_json::value::to_raw_value(&log)?).await;
                }
            }
        }
        SubscriptionKind::NewPendingTransactions => {
            let full = match params {
                pubsub::Params::None => false,
                pubsub::Params::Bool(b) => b,
                pubsub::Params::Logs(_) => {
                    return Err("invalid params for newPendingTransactions".into());
                }
            };

            if full {
                let mut txns = node.subscribe_to_new_transactions();

                while let Ok(txn) = txns.recv().await {
                    let txn = eth::Transaction::new(txn, None);
                    let _ = sink.send(serde_json::value::to_raw_value(&txn)?).await;
                }
            } else {
                let mut txns = node.subscribe_to_new_transaction_hashes();

                while let Ok(txn) = txns.recv().await {
                    let _ = sink
                        .send(serde_json::value::to_raw_value(&B256::from(txn))?)
                        .await;
                }
            }
        }
        _ => {
            return Err("invalid subscription kind".into());
        }
    }

    Ok(())
}

/// eth_blobBaseFee
/// Returns the expected base fee for blobs in the next block
fn blob_base_fee(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!("API method eth_blobBaseFee is not implemented yet"))
}

/// eth_feeHistory
/// Returns the collection of historical gas information
fn fee_history(params: Params, node: &Arc<Node>) -> Result<FeeHistory> {
    let mut params = params.sequence();
    let block_count: String = params.next()?;
    let block_count = if let Some(block_count) = block_count.strip_prefix("0x") {
        u64::from_str_radix(block_count, 16)?
    } else {
        block_count.parse::<u64>()?
    };

    let mut block_count = block_count.min(1024);

    if block_count == 0 {
        return Ok(FeeHistory::default());
    }

    let newest_block: BlockNumberOrTag = params.next()?;
    let reward_percentiles: Option<Vec<f64>> = params.optional_next()?;
    if let Some(ref percentiles) = reward_percentiles
        && (!percentiles.windows(2).all(|w| w[0] <= w[1])
            || percentiles.iter().any(|&p| !(0.0..=100.0).contains(&p)))
    {
        return Err(anyhow!(
            "reward_percentiles must be in ascending order and within the range [0, 100]"
        ));
    }
    expect_end_of_params(&mut params, 2, 3)?;

    let (newest_block_number, gas_price, db) = {
        let number = node
            .resolve_block_number(newest_block)?
            .ok_or_else(|| anyhow!("block not found"))?
            .number();
        (number, node.config.consensus.gas_price, node.db.clone())
    };
    if newest_block_number < block_count {
        warn!("block_count is greater than newest_block");
        block_count = newest_block_number;
    }

    let oldest_block = newest_block_number - block_count + 1;
    let (reward, gas_used_ratio) = (oldest_block..=newest_block_number)
        .map(|block_number| {
            let block = data_access::get_block_by_number(db.clone(), block_number)?
                .ok_or_else(|| anyhow!("block not found"))?;

            let reward = if let Some(reward_percentiles) = reward_percentiles.as_ref() {
                let mut effective_gas_prices = block
                    .transactions
                    .iter()
                    .map(|tx_hash| {
                        let tx = data_access::get_transaction_by_hash(db.clone(), None, *tx_hash)?
                            .ok_or_else(|| anyhow!("transaction not found: {tx_hash}"))?;
                        Ok(tx.tx.effective_gas_price(BASE_FEE_PER_GAS))
                    })
                    .collect::<Result<Vec<_>>>()?;

                effective_gas_prices.sort_unstable();

                let fees_len = effective_gas_prices.len() as f64;
                if fees_len == 0.0 {
                    effective_gas_prices.push(*gas_price);
                }

                reward_percentiles
                    .iter()
                    .map(|x| {
                        // Calculate the index in the sorted effective priority fees based on the percentile
                        let i = ((x / 100_f64) * fees_len) as usize;

                        // Get the fee at the calculated index, or default to 0 if the index is out of bounds
                        effective_gas_prices.get(i).cloned().unwrap_or_default()
                    })
                    .collect()
            } else {
                vec![]
            };

            let gas_limit = block.gas_limit().0 as f64;
            if gas_limit == 0.0 {
                return Err(anyhow!("gas limit is zero"));
            }

            Ok((reward, (block.gas_used().0 as f64) / gas_limit))
        })
        .collect::<Result<(Vec<Vec<_>>, Vec<_>)>>()?;

    let res = FeeHistory {
        oldest_block,
        reward: reward_percentiles.map(|_| reward),
        gas_used_ratio,
        base_fee_per_gas: vec![0; (block_count + 1) as usize],
        base_fee_per_blob_gas: vec![0; (block_count + 1) as usize],
        blob_gas_used_ratio: vec![0.0; block_count as usize],
    };
    Ok(res)
}

/// eth_getAccount
/// Retrieve account details by specifying an address and a block number/tag.
fn get_account(params: Params, node: &Arc<Node>) -> Result<GetAccountResult> {
    let mut params = params.sequence();
    let address: ZilAddress = params.next()?;
    let address: Address = address.into();
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let state = {
        let block = node.get_block(block_id)?;
        let block = build_errored_response_for_missing_block(block_id, block)?;
        node.get_state(&block)?
    };

    let account = state.get_account(address)?;
    let return_code = if account.code.is_eoa() {
        vec![].to_hex_no_prefix()
    } else {
        match account.code {
            Code::Evm(val) => val.to_hex_no_prefix(),
            Code::Scilla { code, .. } => code.to_hex_no_prefix(),
        }
    };
    Ok(GetAccountResult {
        balance: account.balance,
        nonce: account.nonce,
        storage_root: account.storage_root,
        code_hash: keccak256(return_code),
    })
}

/// eth_getFilterChanges
/// Polling method for a filter, which returns an array of events that have occurred since the last poll.
fn get_filter_changes(params: Params, node: &Arc<Node>) -> Result<serde_json::Value> {
    let filter_id: u128 = params.one()?;

    let filters = { node.filters.clone() };
    let mut filter = filters.get(filter_id).ok_or(anyhow!("filter not found"))?;

    match &mut filter.kind {
        FilterKind::Block(block_filter) => {
            let headers = block_filter.poll()?;

            let results: Vec<_> = headers
                .into_iter()
                .map(|header| B256::from(header.hash).to_hex())
                .collect();

            Ok(json!(results))
        }

        FilterKind::PendingTx(pending_tx_filter) => {
            let pending_txns = pending_tx_filter.poll()?;
            let result: Vec<_> = pending_txns
                .into_iter()
                .map(|txn| B256::from(txn.hash).to_hex())
                .collect();
            Ok(json!(result))
        }

        FilterKind::Log(log_filter) => {
            // If necessary, adjust the filter so it ignores already returned blocks
            let last_block = log_filter.last_block_number; // exclusive
            let criteria_last_block = log_filter.criteria.get_from_block(); // inclusive
            let adjusted_criteria = *log_filter.criteria.clone();
            let adjusted_criteria = match (last_block, criteria_last_block) {
                (None, None) => adjusted_criteria,
                (None, Some(y)) => adjusted_criteria.from_block(y),
                (Some(x), None) => adjusted_criteria.from_block(x + 1),
                (Some(x), Some(y)) => adjusted_criteria.from_block(std::cmp::max(x + 1, y)),
            };

            // Get the logs
            let logs = get_logs_inner(&adjusted_criteria, node)?;

            // Set the last recorded block in the filter to the most recent block in the returned logs
            let last_block = logs.iter().fold(None, |acc, x| {
                Some(std::cmp::max(x.block_number, acc.unwrap_or(0)))
            });
            log_filter.last_block_number = last_block;

            Ok(json!(logs))
        }
    }
}

/// eth_getFilterLogs
/// Returns an array of all logs matching filter with given id.
fn get_filter_logs(params: Params, node: &Arc<Node>) -> Result<serde_json::Value> {
    let filter_id: u128 = params.one()?;

    if let Some(filter) = node.filters.get(filter_id) {
        match &filter.kind {
            FilterKind::Block(_) => Err(anyhow!("pending tx filter not supported")),
            FilterKind::PendingTx(_) => Err(anyhow!("pending tx filter not supported")),
            FilterKind::Log(log_filter) => {
                let result = get_logs_inner(&log_filter.criteria, node)?;
                Ok(json!(result))
            }
        }
    } else {
        Err(anyhow!("filter not found"))
    }
}

/// eth_getProof
/// Returns the account and storage values of the specified account including the Merkle-proof.
fn get_proof(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!("API method eth_getProof is not implemented yet"))
}

/// eth_hashrate
/// Returns the number of hashes per second that the node is mining with.
fn hashrate(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!("API method eth_hashrate is not implemented yet"))
}

/// eth_maxPriorityFeePerGas
/// Get the priority fee needed to be included in a block.
fn max_priority_fee_per_gas(params: Params, node: &Arc<Node>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.get_gas_price().to_hex())
}

/// eth_newBlockFilter
/// Creates a filter in the node, to notify when a new block arrives. To check if the state has changed, call eth_getFilterChanges
fn new_block_filter(params: Params, node: &Arc<Node>) -> Result<u128> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;

    let filter = BlockFilter {
        block_receiver: node.subscribe_to_new_blocks(),
    };
    let id = node.filters.add(FilterKind::Block(filter));
    Ok(id)
}

/// eth_newFilter
/// Creates a filter object, based on filter options, to notify when the state changes (logs). To check if the state has changed, call eth_getFilterChanges.
fn new_filter(params: Params, node: &Arc<Node>) -> Result<u128> {
    let criteria: alloy::rpc::types::Filter = params.one()?;

    let id = node.filters.add(FilterKind::Log(LogFilter {
        criteria: Box::new(criteria),
        last_block_number: None,
    }));
    Ok(id)
}

/// eth_newPendingTransactionFilter
/// Creates a filter in the node to notify when new pending transactions arrive. To check if the state has changed, call eth_getFilterChanges.
fn new_pending_transaction_filter(params: Params, node: &Arc<Node>) -> Result<u128> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;

    let filter = PendingTxFilter {
        pending_txn_receiver: node.subscribe_to_new_transactions(),
    };
    let id = node.filters.add(FilterKind::PendingTx(filter));
    Ok(id)
}

/// eth_signTransaction
/// Signs a transaction that can be submitted to the network later using eth_sendRawTransaction
fn sign_transaction(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!(
        "API method eth_signTransaction is not implemented yet"
    ))
}

/// eth_simulateV1
/// Simulates a series of transactions at a specific block height with optional state overrides. This method allows you to test transactions with custom block and state parameters without actually submitting them to the network.
fn simulate_v1(_params: Params, _node: &Arc<Node>) -> Result<()> {
    // TODO: disable_eip3607 for this call.
    Err(anyhow!("API method eth_simulateV1 is not implemented yet"))
}

/// eth_submitWork
/// Used for submitting a proof-of-work solution.
fn submit_work(_params: Params, _node: &Arc<Node>) -> Result<()> {
    Err(anyhow!("API method eth_submitWork is not implemented yet"))
}

/// eth_uninstallFilter
/// It uninstalls a filter with the given filter id.
fn uninstall_filter(params: Params, node: &Arc<Node>) -> Result<bool> {
    let filter_id: u128 = params.one()?;
    Ok(node.filters.remove(filter_id))
}
