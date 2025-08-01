//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::{collections::HashMap, sync::Arc};

use alloy::{
    consensus::{TxEip1559, TxEip2930, TxLegacy, transaction::RlpEcdsaDecodableTx},
    eips::{BlockId, BlockNumberOrTag, RpcBlockHash},
    primitives::{Address, B256, U64, U256},
    rpc::types::{
        FeeHistory, FilteredParams,
        pubsub::{self, SubscriptionKind},
    },
};
use anyhow::{Result, anyhow};
use http::Extensions;
use itertools::Either;
use jsonrpsee::{
    PendingSubscriptionSink, RpcModule, SubscriptionMessage,
    core::StringError,
    types::{
        Params,
        error::{ErrorObject, ErrorObjectOwned},
        params::ParamsSequence,
    },
};
use parking_lot::{RwLock, RwLockReadGuard};
use revm::primitives::keccak256;
use serde_json::json;
use tracing::*;

use super::{
    to_hex::ToHex,
    types::{
        eth::{self, CallParams, ErrorCode, HashOrTransaction, SyncingResult, TransactionReceipt},
        filters::{BlockFilter, FilterKind, LogFilter, PendingTxFilter},
    },
};
use crate::{
    api::{types::eth::GetAccountResult, zilliqa::ZilAddress},
    cfg::EnabledApi,
    constants::BASE_FEE_PER_GAS,
    crypto::Hash,
    error::ensure_success,
    exec::zil_contract_address,
    message::Block,
    node::Node,
    pool::TxAddResult,
    state::Code,
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, VerifiedTransaction},
};

pub fn rpc_module(
    node: Arc<RwLock<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<RwLock<Node>>> {
    let mut module = super::declare_module!(
        node,
        enabled_apis,
        [
            ("eth_accounts", accounts),
            ("eth_blobBaseFee", blob_base_fee),
            ("eth_blockNumber", block_number),
            ("eth_call", call),
            ("eth_callMany", call_many),
            ("eth_chainId", chain_id),
            ("eth_estimateGas", estimate_gas),
            ("eth_feeHistory", fee_history),
            ("eth_gasPrice", get_gas_price),
            ("eth_getAccount", get_account),
            ("eth_getBalance", get_balance),
            ("eth_getBlockByHash", get_block_by_hash),
            ("eth_getBlockByNumber", get_block_by_number),
            ("eth_getBlockReceipts", get_block_receipts),
            (
                "eth_getBlockTransactionCountByHash",
                get_block_transaction_count_by_hash
            ),
            (
                "eth_getBlockTransactionCountByNumber",
                get_block_transaction_count_by_number
            ),
            ("eth_getCode", get_code),
            ("eth_getFilterChanges", get_filter_changes),
            ("eth_getFilterLogs", get_filter_logs),
            ("eth_getLogs", get_logs),
            ("eth_getProof", get_proof),
            ("eth_getStorageAt", get_storage_at),
            (
                "eth_getTransactionByBlockHashAndIndex",
                get_transaction_by_block_hash_and_index
            ),
            (
                "eth_getTransactionByBlockNumberAndIndex",
                get_transaction_by_block_number_and_index
            ),
            ("eth_getTransactionByHash", get_transaction_by_hash),
            ("eth_getTransactionCount", get_transaction_count),
            ("eth_getTransactionReceipt", get_transaction_receipt),
            ("eth_getUncleByBlockHashAndIndex", get_uncle),
            ("eth_getUncleByBlockNumberAndIndex", get_uncle),
            ("eth_getUncleCountByBlockHash", get_uncle_count),
            ("eth_getUncleCountByBlockNumber", get_uncle_count),
            ("eth_hashrate", hashrate),
            ("eth_maxPriorityFeePerGas", max_priority_fee_per_gas),
            ("eth_mining", mining),
            ("eth_newBlockFilter", new_block_filter),
            ("eth_newFilter", new_filter),
            (
                "eth_newPendingTransactionFilter",
                new_pending_transaction_filter
            ),
            ("eth_protocolVersion", protocol_version),
            ("eth_sendRawTransaction", send_raw_transaction),
            ("eth_signTransaction", sign_transaction),
            ("eth_simulateV1", simulate_v1),
            ("eth_submitWork", submit_work),
            ("eth_syncing", syncing),
            ("eth_uninstallFilter", uninstall_filter),
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

fn accounts(params: Params, _: &Arc<RwLock<Node>>) -> Result<[(); 0]> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok([])
}

fn block_number(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    let node = node.read();
    Ok(node.consensus.get_highest_canonical_block_number().to_hex())
}

fn call_many(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<()> {
    // TODO: disable_eip3607 for this call.
    Err(anyhow!("API method eth_callMany is not implemented yet"))
}

fn call(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: CallParams = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();
    expect_end_of_params(&mut params, 1, 2)?;

    let node = node.read();
    let block = node.get_block(block_id)?;
    let block = build_errored_response_for_missing_block(block_id, block)?;

    let result = node.call_contract(
        &block,
        call_params.from,
        call_params.to,
        call_params
            .data
            .try_into_unique_input()?
            .unwrap_or_default()
            .to_vec(),
        call_params.value.to(),
    )?;

    match ensure_success(result) {
        Ok(output) => Ok(output.to_hex()),
        Err(err) => Err(ErrorObjectOwned::from(err).into()),
    }
}

fn chain_id(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.read().config.eth_chain_id.to_hex())
}

fn estimate_gas(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: CallParams = params.next()?;
    let block_number: BlockNumberOrTag = params.optional_next()?.unwrap_or_default();
    expect_end_of_params(&mut params, 1, 2)?;

    let return_value = node.read().estimate_gas(
        block_number,
        call_params.from,
        call_params.to,
        call_params
            .data
            .try_into_unique_input()?
            .unwrap_or_default()
            .to_vec(),
        call_params.gas.map(|g| EvmGas(g.to())),
        call_params.gas_price.map(|g| g.to()),
        call_params.value.to(),
        call_params.access_list,
    )?;

    Ok(return_value.to_hex())
}

fn get_balance(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: ZilAddress = params.next()?;
    let address: Address = address.into();

    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.read();
    let block = node.get_block(block_id)?;

    let block = build_errored_response_for_missing_block(block_id, block)?;

    Ok(node
        .get_state(&block)?
        .get_account(address)?
        .balance
        .to_hex())
}

pub fn brt_to_eth_receipts(
    btr: crate::db::BlockAndReceiptsAndTransactions,
) -> Vec<eth::TransactionReceipt> {
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

        let receipt = eth::TransactionReceipt {
            transaction_hash: (receipt_retrieved.tx_hash).into(),
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
    node: &RwLockReadGuard<Node>,
    block_id: impl Into<BlockId>,
) -> Result<Vec<eth::TransactionReceipt>> {
    let Some(block) = node.get_block(block_id)? else {
        return Err(anyhow!("Block not found"));
    };

    let mut log_index = 0;
    let mut receipts = Vec::new();

    let receipts_retrieved = node.get_transaction_receipts_in_block(block.header.hash)?;

    for (transaction_index, receipt_retrieved) in receipts_retrieved.iter().enumerate() {
        // This could maybe be a bit faster if we had a db function that queried transactions by
        // block hash, joined on receipts, but this would be quite a bit of new code.
        let Some(signed_transaction) = node.get_transaction_by_hash(receipt_retrieved.tx_hash)?
        else {
            warn!(
                "Failed to get TX by hash when getting TX receipt! {}",
                receipt_retrieved.tx_hash
            );
            continue;
        };

        // Required workaround for incorrectly converted nonces for zq1 scilla transactions
        let contract_address = match &signed_transaction.tx {
            SignedTransaction::Zilliqa { tx, .. } => {
                if tx.to_addr.is_zero() && receipt_retrieved.success {
                    Some(zil_contract_address(
                        signed_transaction.signer,
                        signed_transaction
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

        let from = signed_transaction.signer;
        let v = signed_transaction.tx.sig_v();
        let r = signed_transaction.tx.sig_r();
        let s = signed_transaction.tx.sig_s();
        let transaction = signed_transaction.tx.into_transaction();

        let receipt = eth::TransactionReceipt {
            transaction_hash: (receipt_retrieved.tx_hash).into(),
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
            ty: 0,
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
    node: &RwLockReadGuard<Node>,
    block_id: impl Into<BlockId>,
    txn_hash: Hash,
) -> Result<Option<eth::TransactionReceipt>> {
    let receipts = old_get_block_transaction_receipts_inner(node, block_id)?;
    Ok(receipts
        .into_iter()
        .find(|r| r.transaction_hash == txn_hash.as_bytes()))
}

fn get_block_receipts(params: Params, node: &Arc<RwLock<Node>>) -> Result<Vec<TransactionReceipt>> {
    let block_id: BlockId = params.one()?;
    let node = node.read();

    old_get_block_transaction_receipts_inner(&node, block_id)
}

fn get_code(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.read();
    let block = node.get_block(block_id)?;

    let block = build_errored_response_for_missing_block(block_id, block)?;

    // For compatibility with Zilliqa 1, eth_getCode also returns Scilla code if any is present.
    let code = node.get_state(&block)?.get_account(address)?.code;

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

fn get_storage_at(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let position: U256 = params.next()?;
    let position = B256::new(position.to_be_bytes());
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 3, 3)?;

    let node = node.read();
    let block = node.get_block(block_id)?;
    let block = build_errored_response_for_missing_block(block_id, block)?;

    let value = node
        .get_state(&block)?
        .get_account_storage(address, position)?;

    Ok(value.to_hex())
}

fn get_transaction_count(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 3, 3)?;

    let node = node.read();

    let block = node.get_block(block_id)?;
    let block = build_errored_response_for_missing_block(block_id, block)?;

    let nonce = node.get_state(&block)?.get_account(address)?.nonce;

    if matches!(block_id, BlockId::Number(BlockNumberOrTag::Pending)) {
        Ok(node.consensus.pending_transaction_count(address).to_hex())
    } else {
        Ok(nonce.to_hex())
    }
}

fn get_gas_price(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.read().get_gas_price().to_hex())
}

fn get_block_by_number(params: Params, node: &Arc<RwLock<Node>>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let full: bool = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    get_eth_block(node, block_number.into(), full)
}

fn get_block_by_hash(params: Params, node: &Arc<RwLock<Node>>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let hash: B256 = params.next()?;
    let full: bool = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    get_eth_block(node, crate::db::BlockFilter::Hash(hash.into()), full)
}

pub fn get_eth_block(
    node: &Arc<RwLock<Node>>,
    block_id: crate::db::BlockFilter,
    full: bool,
) -> Result<Option<eth::Block>> {
    let node = node.read();
    let brt = match node
        .consensus
        .db
        .get_block_and_receipts_and_transactions(block_id)?
    {
        Some(btr) => btr,
        None => return Ok(None),
    };

    let miner = node.get_proposer_reward_address(brt.block.header)?;
    let block_gas_limit = brt.block.gas_limit();
    let mut result = eth::Block::from_block(&brt.block, miner.unwrap_or_default(), block_gas_limit);
    if full {
        result.transactions = brt
            .transactions
            .iter()
            .map(|x| eth::Transaction::new(x.clone(), Some(brt.block.clone())))
            .map(HashOrTransaction::Transaction)
            .collect();
    }
    Ok(Some(result))
}

fn get_block_transaction_count_by_hash(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<Option<String>> {
    let mut params = params.sequence();
    let hash: B256 = params.next()?;
    expect_end_of_params(&mut params, 1, 1)?;

    let node = node.read();
    let block = node.get_block(hash)?;

    Ok(block.map(|b| b.transactions.len().to_hex()))
}

fn get_block_transaction_count_by_number(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<Option<String>> {
    let mut params = params.sequence();
    // The ethereum RPC spec says this is optional, but it is mandatory in geth and erigon.
    let block_number: BlockNumberOrTag = params.next()?;
    expect_end_of_params(&mut params, 1, 1)?;

    let node = node.read();
    let block = node.get_block(block_number)?;

    Ok(Some(
        block.map_or(0, |block| block.transactions.len()).to_hex(),
    ))
}

fn get_logs(params: Params, node: &Arc<RwLock<Node>>) -> Result<Vec<eth::Log>> {
    let mut seq = params.sequence();
    let params: alloy::rpc::types::Filter = seq.next()?;
    expect_end_of_params(&mut seq, 1, 1)?;
    let node = node.read();
    get_logs_inner(&params, &node)
}

fn get_logs_inner(
    params: &alloy::rpc::types::Filter,
    node: &RwLockReadGuard<Node>,
) -> Result<Vec<eth::Log>> {
    let filter_params = FilteredParams::new(Some(params.clone()));

    // Find the range of blocks we care about. This is an iterator of blocks.
    let blocks = match params.block_option {
        alloy::rpc::types::FilterBlockOption::AtBlockHash(block_hash) => {
            Either::Left(std::iter::once(Ok(node
                .get_block(block_hash)?
                .ok_or_else(|| anyhow!("block not found"))?)))
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

            let to = match node
                .resolve_block_number(to_block.unwrap_or(BlockNumberOrTag::Latest))?
                .as_ref()
            {
                Some(block) => block.number(),
                None => node
                    .resolve_block_number(BlockNumberOrTag::Latest)?
                    .unwrap()
                    .number(),
            };

            if from > to {
                return Err(anyhow!("`from` is greater than `to` ({from} > {to})"));
            }

            Either::Right((from..=to).map(|number| {
                node.get_block(number)?
                    .ok_or_else(|| anyhow!("missing block: {number}"))
            }))
        }
    };

    let mut logs = vec![];

    for block in blocks {
        let block = block?;

        for (txn_index, txn_hash) in block.transactions.iter().enumerate() {
            let receipt = node
                .get_transaction_receipt(*txn_hash)?
                .ok_or(anyhow!("missing receipt"))?;

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
                    txn_index,
                    *txn_hash,
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
    node: &Arc<RwLock<Node>>,
) -> Result<Option<eth::Transaction>> {
    let mut params = params.sequence();
    let block_hash: B256 = params.next()?;
    let index: U64 = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;
    let node = node.read();

    let Some(block) = node.get_block(block_hash)? else {
        return Ok(None);
    };
    let Some(txn_hash) = block.transactions.get(index.to::<usize>()) else {
        return Ok(None);
    };

    get_transaction_inner(*txn_hash, &node)
}

fn get_transaction_by_block_number_and_index(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<Option<eth::Transaction>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let index: U64 = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.read();

    let Some(block) = node.get_block(block_number)? else {
        return Ok(None);
    };
    let Some(txn_hash) = block.transactions.get(index.to::<usize>()) else {
        return Ok(None);
    };

    get_transaction_inner(*txn_hash, &node)
}

fn get_transaction_by_hash(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<Option<eth::Transaction>> {
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let node = node.read();

    get_transaction_inner(hash, &node)
}

pub(super) fn get_transaction_inner(
    hash: Hash,
    node: &RwLockReadGuard<Node>,
) -> Result<Option<eth::Transaction>> {
    let Some(tx) = node.get_transaction_by_hash(hash)? else {
        return Ok(None);
    };

    // The block can either be null or some based on whether the tx exists
    let block = if let Some(receipt) = node.get_transaction_receipt(hash)? {
        node.get_block(receipt.block_hash)?
    } else {
        // Even if it has not been mined, the tx may still be in the mempool and should return
        // a correct tx, with pending/null fields
        None
    };

    Ok(Some(eth::Transaction::new(tx, block)))
}

fn get_transaction_receipt(
    params: Params,
    node: &Arc<RwLock<Node>>,
) -> Result<Option<eth::TransactionReceipt>> {
    let hash: B256 = params.one()?;
    let hash: Hash = hash.into();
    let node = node.read();
    let block_hash = match node.get_transaction_receipt(hash)? {
        Some(receipt) => receipt.block_hash,
        None => return Ok(None),
    };
    get_transaction_receipt_inner_slow(&node, block_hash, hash)
}

fn send_raw_transaction(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    let transaction: String = params.one()?;
    let transaction = transaction
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let transaction = hex::decode(transaction)?;
    let transaction = parse_transaction(&transaction)?;

    let transaction = transaction.verify()?;

    let (hash, result) = node.read().create_transaction(transaction)?;
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

fn get_uncle_count(_: Params, _: &Arc<RwLock<Node>>) -> Result<String> {
    Ok("0x0".to_string())
}

fn get_uncle(_: Params, _: &Arc<RwLock<Node>>) -> Result<Option<String>> {
    Ok(None)
}

fn mining(_: Params, _: &Arc<RwLock<Node>>) -> Result<bool> {
    Ok(false)
}

fn protocol_version(_: Params, _: &Arc<RwLock<Node>>) -> Result<String> {
    Ok("0x41".to_string())
}

fn syncing(params: Params, node: &Arc<RwLock<Node>>) -> Result<SyncingResult> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    if let Some(result) = node.read().consensus.get_sync_data()? {
        Ok(SyncingResult::Struct(result))
    } else {
        Ok(SyncingResult::Bool(false))
    }
}

#[allow(clippy::redundant_allocation, clippy::await_holding_lock)]
async fn subscribe(
    params: Params<'_>,
    pending: PendingSubscriptionSink,
    node: Arc<Arc<RwLock<Node>>>,
    _: Extensions,
) -> Result<(), StringError> {
    let mut params = params.sequence();
    let kind: SubscriptionKind = params.next()?;
    let params: Option<pubsub::Params> = params.optional_next()?;
    let params = params.unwrap_or_default();

    let sink = pending.accept().await?;

    let node_lock = node.read();

    match kind {
        SubscriptionKind::NewHeads => {
            let mut new_blocks = node_lock.subscribe_to_new_blocks();
            std::mem::drop(node_lock);

            while let Ok(header) = new_blocks.recv().await {
                let node_lock = node.read();
                let block = node_lock
                    .consensus
                    .db
                    .get_transactionless_block(header.hash.into())?
                    .ok_or("Block not found")?;
                let miner = node_lock.get_proposer_reward_address(block.header)?;
                std::mem::drop(node_lock);
                let block_gas_limit = block.gas_limit();
                let eth_block =
                    eth::Block::from_block(&block, miner.unwrap_or_default(), block_gas_limit);
                let header = eth_block.header;
                let _ = sink.send(SubscriptionMessage::from_json(&header)?).await;
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

            let mut receipts = node_lock.subscribe_to_receipts();
            std::mem::drop(node_lock);

            'outer: while let Ok((receipt, transaction_index)) = receipts.recv().await {
                let node_lock = node.read();
                if !filter.filter_block_hash(receipt.block_hash.into()) {
                    continue;
                }

                // We track log index plus one because we have to increment before we use the log index, and log indexes are 0-based.
                let mut log_index_plus_one: i64 =
                    old_get_block_transaction_receipts_inner(&node_lock, receipt.block_hash)?
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
                    let block = node_lock
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
                std::mem::drop(node_lock);
                for log in logs {
                    let _ = sink.send(SubscriptionMessage::from_json(&log)?).await;
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
                let mut txns = node_lock.subscribe_to_new_transactions();
                std::mem::drop(node_lock);

                while let Ok(txn) = txns.recv().await {
                    let txn = eth::Transaction::new(txn, None);
                    let _ = sink.send(SubscriptionMessage::from_json(&txn)?).await;
                }
            } else {
                let mut txns = node_lock.subscribe_to_new_transaction_hashes();
                std::mem::drop(node_lock);

                while let Ok(txn) = txns.recv().await {
                    let _ = sink
                        .send(SubscriptionMessage::from_json(&B256::from(txn))?)
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
fn blob_base_fee(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_blobBaseFee is not implemented yet"))
}

/// eth_feeHistory
/// Returns the collection of historical gas information
fn fee_history(params: Params, node: &Arc<RwLock<Node>>) -> Result<FeeHistory> {
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
    if let Some(ref percentiles) = reward_percentiles {
        if !percentiles.windows(2).all(|w| w[0] <= w[1])
            || percentiles.iter().any(|&p| !(0.0..=100.0).contains(&p))
        {
            return Err(anyhow!(
                "reward_percentiles must be in ascending order and within the range [0, 100]"
            ));
        }
    }
    expect_end_of_params(&mut params, 2, 3)?;

    let node = node.read();
    let newest_block_number = node
        .resolve_block_number(newest_block)?
        .ok_or_else(|| anyhow!("block not found"))?
        .number();
    if newest_block_number < block_count {
        warn!("block_count is greater than newest_block");
        block_count = newest_block_number;
    }

    let oldest_block = newest_block_number - block_count + 1;
    let (reward, gas_used_ratio) = (oldest_block..=newest_block_number)
        .map(|block_number| {
            let block = node
                .get_block(BlockNumberOrTag::Number(block_number))?
                .ok_or_else(|| anyhow!("block not found"))?;

            let reward = if let Some(reward_percentiles) = reward_percentiles.as_ref() {
                let mut effective_gas_prices = block
                    .transactions
                    .iter()
                    .map(|tx_hash| {
                        let tx = node
                            .get_transaction_by_hash(*tx_hash)?
                            .ok_or_else(|| anyhow!("transaction not found: {}", tx_hash))?;
                        Ok(tx.tx.effective_gas_price(BASE_FEE_PER_GAS))
                    })
                    .collect::<Result<Vec<_>>>()?;

                effective_gas_prices.sort_unstable();

                let fees_len = effective_gas_prices.len() as f64;
                if fees_len == 0.0 {
                    effective_gas_prices.push(*node.config.consensus.gas_price);
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
fn get_account(params: Params, node: &Arc<RwLock<Node>>) -> Result<GetAccountResult> {
    let mut params = params.sequence();
    let address: ZilAddress = params.next()?;
    let address: Address = address.into();
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.read();
    let block = node.get_block(block_id)?;
    let block = build_errored_response_for_missing_block(block_id, block)?;

    let account = node.get_state(&block)?.get_account(address)?;
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
fn get_filter_changes(params: Params, node: &Arc<RwLock<Node>>) -> Result<serde_json::Value> {
    let filter_id: u128 = params.one()?;

    let node = node.read();

    let mut filter = node
        .filters
        .get(filter_id)
        .ok_or(anyhow!("filter not found"))?;

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
            let logs = get_logs_inner(&adjusted_criteria, &node)?;

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
fn get_filter_logs(params: Params, node: &Arc<RwLock<Node>>) -> Result<serde_json::Value> {
    let filter_id: u128 = params.one()?;
    let node = node.read();

    if let Some(filter) = node.filters.get(filter_id) {
        match &filter.kind {
            FilterKind::Block(_) => Err(anyhow!("pending tx filter not supported")),
            FilterKind::PendingTx(_) => Err(anyhow!("pending tx filter not supported")),
            FilterKind::Log(log_filter) => {
                let result = get_logs_inner(&log_filter.criteria, &node)?;
                Ok(json!(result))
            }
        }
    } else {
        Err(anyhow!("filter not found"))
    }
}

/// eth_getProof
/// Returns the account and storage values of the specified account including the Merkle-proof.
fn get_proof(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_getProof is not implemented yet"))
}

/// eth_hashrate
/// Returns the number of hashes per second that the node is mining with.
fn hashrate(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_hashrate is not implemented yet"))
}

/// eth_maxPriorityFeePerGas
/// Get the priority fee needed to be included in a block.
fn max_priority_fee_per_gas(params: Params, node: &Arc<RwLock<Node>>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.read().get_gas_price().to_hex())
}

/// eth_newBlockFilter
/// Creates a filter in the node, to notify when a new block arrives. To check if the state has changed, call eth_getFilterChanges
fn new_block_filter(params: Params, node: &Arc<RwLock<Node>>) -> Result<u128> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;

    let node = node.read();

    let filter = BlockFilter {
        block_receiver: node.subscribe_to_new_blocks(),
    };
    let id = node.filters.add(FilterKind::Block(filter));
    Ok(id)
}

/// eth_newFilter
/// Creates a filter object, based on filter options, to notify when the state changes (logs). To check if the state has changed, call eth_getFilterChanges.
fn new_filter(params: Params, node: &Arc<RwLock<Node>>) -> Result<u128> {
    let criteria: alloy::rpc::types::Filter = params.one()?;
    let node = node.read();

    let id = node.filters.add(FilterKind::Log(LogFilter {
        criteria: Box::new(criteria),
        last_block_number: None,
    }));
    Ok(id)
}

/// eth_newPendingTransactionFilter
/// Creates a filter in the node to notify when new pending transactions arrive. To check if the state has changed, call eth_getFilterChanges.
fn new_pending_transaction_filter(params: Params, node: &Arc<RwLock<Node>>) -> Result<u128> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    let node = node.read();

    let filter = PendingTxFilter {
        pending_txn_receiver: node.subscribe_to_new_transactions(),
    };
    let id = node.filters.add(FilterKind::PendingTx(filter));
    Ok(id)
}

/// eth_signTransaction
/// Signs a transaction that can be submitted to the network later using eth_sendRawTransaction
fn sign_transaction(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method eth_signTransaction is not implemented yet"
    ))
}

/// eth_simulateV1
/// Simulates a series of transactions at a specific block height with optional state overrides. This method allows you to test transactions with custom block and state parameters without actually submitting them to the network.
fn simulate_v1(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<()> {
    // TODO: disable_eip3607 for this call.
    Err(anyhow!("API method eth_simulateV1 is not implemented yet"))
}

/// eth_submitWork
/// Used for submitting a proof-of-work solution.
fn submit_work(_params: Params, _node: &Arc<RwLock<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_submitWork is not implemented yet"))
}

/// eth_uninstallFilter
/// It uninstalls a filter with the given filter id.
fn uninstall_filter(params: Params, node: &Arc<RwLock<Node>>) -> Result<bool> {
    let filter_id: u128 = params.one()?;

    let node = node.read();

    Ok(node.filters.remove(filter_id))
}
