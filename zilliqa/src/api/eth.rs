//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::sync::{Arc, Mutex, MutexGuard};

use alloy::{
    consensus::{transaction::RlpEcdsaTx, TxEip1559, TxEip2930, TxLegacy},
    eips::{BlockId, BlockNumberOrTag, RpcBlockHash},
    primitives::{Address, B256, U256, U64},
    rpc::types::{
        pubsub::{self, SubscriptionKind},
        FilteredParams,
    },
};
use anyhow::{anyhow, Result};
use http::Extensions;
use itertools::{Either, Itertools};
use jsonrpsee::{
    core::StringError,
    types::{
        error::{ErrorObject, ErrorObjectOwned},
        params::ParamsSequence,
        Params,
    },
    PendingSubscriptionSink, RpcModule, SubscriptionMessage,
};
use revm::primitives::Bytecode;
use serde::Deserialize;
use tracing::*;

use super::{
    to_hex::ToHex,
    types::eth::{
        self, CallParams, ErrorCode, HashOrTransaction, OneOrMany, SyncingResult, SyncingStruct,
        TransactionReceipt,
    },
};
use crate::{
    api::zilliqa::ZilAddress,
    cfg::EnabledApi,
    crypto::Hash,
    error::ensure_success,
    message::Block,
    node::Node,
    pool::TxAddResult,
    state::Code,
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction},
};
use crate::api::types::eth::{Proof, StorageProof};

pub fn rpc_module(
    node: Arc<Mutex<Node>>,
    enabled_apis: &[EnabledApi],
) -> RpcModule<Arc<Mutex<Node>>> {
    let mut module = super::declare_module!(
        node,
        enabled_apis,
        [
            ("eth_accounts", accounts),
            ("eth_blobBaseFee", blob_base_fee),
            ("eth_blockNumber", block_number),
            ("eth_call", call),
            ("eth_chainId", chain_id),
            ("eth_estimateGas", estimate_gas),
            ("eth_feeHistory", fee_history),
            ("eth_gasPrice", get_gas_price),
            ("eth_getAccount", get_account),
            ("eth_getBalance", get_balance),
            ("eth_getProof", get_proof),
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

fn accounts(params: Params, _: &Arc<Mutex<Node>>) -> Result<[(); 0]> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok([])
}

fn block_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.lock().unwrap().number().to_hex())
}

fn call(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("call: params: {:?}", params);
    let mut params = params.sequence();
    let call_params: CallParams = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();
    expect_end_of_params(&mut params, 1, 2)?;

    let mut node = node.lock().unwrap();
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

fn chain_id(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.lock().unwrap().config.eth_chain_id.to_hex())
}

fn estimate_gas(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("estimate_gas: params: {:?}", params);
    let mut params = params.sequence();
    let call_params: CallParams = params.next()?;
    let block_number: BlockNumberOrTag = params.optional_next()?.unwrap_or_default();
    expect_end_of_params(&mut params, 1, 2)?;

    let return_value = node.lock().unwrap().estimate_gas(
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
    )?;

    Ok(return_value.to_hex())
}

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: ZilAddress = params.next()?;
    let address: Address = address.into();

    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.lock().unwrap();
    let block = node.get_block(block_id)?;

    let block = build_errored_response_for_missing_block(block_id, block)?;

    Ok(node
        .get_state(&block)?
        .get_account(address)?
        .balance
        .to_hex())
}

fn get_block_receipts(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<TransactionReceipt>> {
    let block_id: BlockId = params.one()?;

    let node = node.lock().unwrap();

    // Get the block
    let block = node
        .get_block(block_id)?
        .ok_or_else(|| anyhow!("block not found"))?;

    // Get receipts for all transactions in the block
    let mut receipts = Vec::new();
    for tx_hash in block.transactions {
        if let Some(receipt) = get_transaction_receipt_inner(tx_hash, &node)? {
            receipts.push(receipt);
        }
    }

    Ok(receipts)
}

fn get_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.lock().unwrap();
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

fn get_storage_at(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_storage_at: params: {:?}", params);
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let position: U256 = params.next()?;
    let position = B256::new(position.to_be_bytes());
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 3, 3)?;

    let node = node.lock().unwrap();
    let block = node.get_block(block_id)?;
    let block = build_errored_response_for_missing_block(block_id, block)?;

    let value = node
        .get_state(&block)?
        .get_account_storage(address, position)?;

    Ok(value.to_hex())
}

fn get_transaction_count(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_transaction_count: params: {:?}", params);
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 3, 3)?;

    let node = node.lock().unwrap();

    let block = node.get_block(block_id)?;
    let block = build_errored_response_for_missing_block(block_id, block)?;

    let nonce = node.get_state(&block)?.get_account(address)?.nonce;

    if matches!(block_id, BlockId::Number(BlockNumberOrTag::Pending)) {
        Ok(node.consensus.pending_transaction_count(address).to_hex())
    } else {
        Ok(nonce.to_hex())
    }
}

fn get_gas_price(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    Ok(node.lock().unwrap().get_gas_price().to_hex())
}

fn get_block_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let full: bool = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.lock().unwrap();
    let block = node.get_block(block_number)?;
    let block = block.map(|b| convert_block(&node, &b, full)).transpose()?;

    Ok(block)
}

fn get_block_by_hash(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let hash: B256 = params.next()?;
    let full: bool = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.lock().unwrap();
    let block = node
        .get_block(hash)?
        .map(|b| convert_block(&node, &b, full))
        .transpose()?;

    Ok(block)
}

pub fn get_block_logs_bloom(node: &MutexGuard<Node>, block: &Block) -> Result<[u8; 256]> {
    let mut logs_bloom = [0; 256];
    for txn_receipt in node.get_transaction_receipts_in_block(block.hash())?.iter() {
        // Ideally we'd implement a full blown bloom filter type but this'll do for now
        txn_receipt
            .logs
            .clone()
            .into_iter()
            .map(|log| match log {
                Log::Evm(log) => log,
                Log::Scilla(log) => log.into_evm(),
            })
            .enumerate()
            .map(|(log_index, log)| {
                let log = eth::Log::new(
                    log,
                    log_index,
                    txn_receipt.index as usize,
                    txn_receipt.tx_hash,
                    block.number(),
                    block.hash(),
                );

                log.bloom(&mut logs_bloom);

                log
            })
            .collect_vec();
    }
    Ok(logs_bloom)
}

fn convert_block(node: &MutexGuard<Node>, block: &Block, full: bool) -> Result<eth::Block> {
    let logs_bloom = get_block_logs_bloom(node, block)?;
    if !full {
        let miner = node.get_proposer_reward_address(block.header)?;
        let block_gas_limit = block.gas_limit();
        Ok(eth::Block::from_block(
            block,
            miner.unwrap_or_default(),
            block_gas_limit,
            logs_bloom,
        ))
    } else {
        let transactions = block
            .transactions
            .iter()
            .map(|h| {
                get_transaction_inner(*h, node)?
                    .ok_or_else(|| anyhow!("missing transaction: {}", h))
            })
            .map(|t| Ok(HashOrTransaction::Transaction(t?)))
            .collect::<Result<_>>()?;
        let miner = node.get_proposer_reward_address(block.header)?;
        let block_gas_limit = block.gas_limit();
        let block = eth::Block::from_block(
            block,
            miner.unwrap_or_default(),
            block_gas_limit,
            logs_bloom,
        );
        Ok(eth::Block {
            transactions,
            ..block
        })
    }
}

fn get_block_transaction_count_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<String>> {
    let mut params = params.sequence();
    let hash: B256 = params.next()?;
    expect_end_of_params(&mut params, 1, 1)?;

    let node = node.lock().unwrap();
    let block = node.get_block(hash)?;

    Ok(block.map(|b| b.transactions.len().to_hex()))
}

fn get_block_transaction_count_by_number(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<String>> {
    let mut params = params.sequence();
    // The ethereum RPC spec says this is optional, but it is mandatory in geth and erigon.
    let block_number: BlockNumberOrTag = params.next()?;
    expect_end_of_params(&mut params, 1, 1)?;

    let node = node.lock().unwrap();
    let block = node.get_block(block_number)?;

    Ok(Some(
        block.map_or(0, |block| block.transactions.len()).to_hex(),
    ))
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct GetLogsParams {
    from_block: Option<BlockNumberOrTag>,
    to_block: Option<BlockNumberOrTag>,
    address: Option<OneOrMany<Address>>,

    /// elements represent an alternative that matches any of the contained topics.
    ///
    /// Examples (from Erigon):
    /// * `[]`                          matches any topic list
    /// * `[[A]]`                       matches topic A in first position
    /// * `[[], [B]]` or `[None, [B]]`  matches any topic in first position AND B in second position
    /// * `[[A], [B]]`                  matches topic A in first position AND B in second position
    /// * `[[A, B], [C, D]]`            matches topic (A OR B) in first position AND (C OR D) in second position
    topics: Vec<OneOrMany<B256>>,
    block_hash: Option<B256>,
}

fn get_logs(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<eth::Log>> {
    let mut seq = params.sequence();
    let params: GetLogsParams = seq.next()?;
    expect_end_of_params(&mut seq, 1, 1)?;

    let node = node.lock().unwrap();

    // Find the range of blocks we care about. This is an iterator of blocks.
    let blocks = match (params.block_hash, params.from_block, params.to_block) {
        (Some(block_hash), None, None) => Either::Left(std::iter::once(Ok(node
            .get_block(block_hash)?
            .ok_or_else(|| anyhow!("block not found"))?))),
        (None, from, to) => {
            let Some(from) = node
                .resolve_block_number(from.unwrap_or(BlockNumberOrTag::Latest))?
                .as_ref()
                .map(Block::number)
            else {
                return Ok(vec![]);
            };

            let to = match node
                .resolve_block_number(to.unwrap_or(BlockNumberOrTag::Latest))?
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
        _ => {
            return Err(anyhow!(
                "only one of `blockHash` or (`fromBlock` and/or `toBlock`) are allowed"
            ));
        }
    };

    // Get the receipts for each transaction. This is an iterator of (receipt, txn_index, txn_hash, block_number, block_hash).
    let receipts = blocks
        .map(|block: Result<_>| {
            let block = block?;
            let block_number = block.number();
            let block_hash = block.hash();
            let receipts = node.get_transaction_receipts_in_block(block_hash)?;

            Ok(block
                .transactions
                .into_iter()
                .enumerate()
                .zip(receipts)
                .map(move |((txn_index, txn_hash), receipt)| {
                    (receipt, txn_index, txn_hash, block_number, block_hash)
                }))
        })
        .flatten_ok();

    // Get the logs from each receipt and filter them based on the provided parameters. This is an iterator of (log, log_index, txn_index, txn_hash, block_number, block_hash).
    let logs = receipts
        .map(|r: Result<_>| {
            let (receipt, txn_index, txn_hash, block_number, block_hash) = r?;
            Ok(receipt
                .logs
                .into_iter()
                .map(|log| match log {
                    Log::Evm(log) => log,
                    Log::Scilla(log) => log.into_evm(),
                })
                .enumerate()
                .map(move |(i, l)| (l, i, txn_index, txn_hash, block_number, block_hash)))
        })
        .flatten_ok()
        .filter_ok(|(log, _, _, _, _, _)| {
            params
                .address
                .as_ref()
                .map(|a| a.contains(&log.address))
                .unwrap_or(true)
        })
        .filter_ok(|(log, _, _, _, _, _)| {
            params
                .topics
                .iter()
                .zip(log.topics.iter())
                .all(|(filter_topic, log_topic)| {
                    filter_topic.is_empty() || filter_topic.contains(log_topic)
                })
        });

    // Finally convert the iterator to our response format.
    let logs = logs.map(|l: Result<_>| {
        let (log, log_index, txn_index, txn_hash, block_number, block_hash) = l?;
        Ok(eth::Log::new(
            log,
            log_index,
            txn_index,
            txn_hash,
            block_number,
            block_hash,
        ))
    });

    logs.collect()
}

fn get_transaction_by_block_hash_and_index(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::Transaction>> {
    let mut params = params.sequence();
    let block_hash: B256 = params.next()?;
    let index: U64 = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;
    let node = node.lock().unwrap();

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
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::Transaction>> {
    let mut params = params.sequence();
    let block_number: BlockNumberOrTag = params.next()?;
    let index: U64 = params.next()?;
    expect_end_of_params(&mut params, 2, 2)?;

    let node = node.lock().unwrap();

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
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::Transaction>> {
    trace!("get_transaction_by_hash: params: {:?}", params);
    let hash: B256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let node = node.lock().unwrap();

    get_transaction_inner(hash, &node)
}

pub(super) fn get_transaction_inner(
    hash: Hash,
    node: &MutexGuard<Node>,
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

pub(super) fn get_transaction_receipt_inner(
    hash: Hash,
    node: &MutexGuard<Node>,
) -> Result<Option<eth::TransactionReceipt>> {
    let Some(signed_transaction) = node.get_transaction_by_hash(hash)? else {
        warn!("Failed to get TX by hash when getting TX receipt! {}", hash);
        return Ok(None);
    };
    // TODO: Return error if receipt or block does not exist.

    let Some(receipt) = node.get_transaction_receipt(hash)? else {
        debug!("Failed to get TX receipt when getting TX receipt! {}", hash);
        return Ok(None);
    };

    debug!(
        "get_transaction_receipt_inner: hash: {:?} result: {:?}",
        hash, receipt
    );

    let Some(block) = node.get_block(receipt.block_hash)? else {
        warn!("Failed to get block when getting TX receipt! {}", hash);
        return Ok(None);
    };

    let transaction_index = block.transactions.iter().position(|t| *t == hash).unwrap();

    let mut logs_bloom = [0; 256];

    let logs = receipt
        .logs
        .into_iter()
        .map(|log| match log {
            Log::Evm(log) => log,
            Log::Scilla(log) => log.into_evm(),
        })
        .enumerate()
        .map(|(log_index, log)| {
            let log = eth::Log::new(
                log,
                log_index,
                transaction_index,
                hash,
                block.number(),
                block.hash(),
            );

            log.bloom(&mut logs_bloom);

            log
        })
        .collect();

    let from = signed_transaction.signer;
    let v = signed_transaction.tx.sig_v();
    let r = signed_transaction.tx.sig_r();
    let s = signed_transaction.tx.sig_s();
    let transaction = signed_transaction.tx.into_transaction();
    let receipt = eth::TransactionReceipt {
        transaction_hash: hash.into(),
        transaction_index: transaction_index as u64,
        block_hash: block.hash().into(),
        block_number: block.number(),
        from,
        to: transaction.to_addr(),
        cumulative_gas_used: receipt.cumulative_gas_used,
        effective_gas_price: transaction.max_fee_per_gas(),
        gas_used: receipt.gas_used,
        contract_address: receipt.contract_address,
        logs,
        logs_bloom,
        ty: 0,
        status: receipt.success,
        v,
        r,
        s,
    };

    Ok(Some(receipt))
}

fn get_transaction_receipt(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::TransactionReceipt>> {
    trace!("get_transaction_receipt: params: {:?}", params);
    let hash: B256 = params.one()?;
    let hash: Hash = hash.into();
    let node = node.lock().unwrap();
    get_transaction_receipt_inner(hash, &node)
}

fn send_raw_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("send_raw_transaction: params: {:?}", params);
    let transaction: String = params.one()?;
    let transaction = transaction
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let transaction = hex::decode(transaction)?;
    let transaction = parse_transaction(&transaction)?;

    let (hash, result) = node.lock().unwrap().create_transaction(transaction)?;
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

fn get_uncle_count(_: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok("0x0".to_string())
}

fn get_uncle(_: Params, _: &Arc<Mutex<Node>>) -> Result<Option<String>> {
    Ok(None)
}

fn mining(_: Params, _: &Arc<Mutex<Node>>) -> Result<bool> {
    Ok(false)
}

fn protocol_version(_: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok("0x41".to_string())
}

fn syncing(params: Params, node: &Arc<Mutex<Node>>) -> Result<SyncingResult> {
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    if let Some((starting_block, current_block, highest_block)) =
        node.lock().unwrap().consensus.get_sync_data()?
    {
        Ok(SyncingResult::Struct(SyncingStruct {
            starting_block,
            current_block,
            highest_block,
        }))
    } else {
        Ok(SyncingResult::Bool(false))
    }
}

fn get_proof(params: Params, node: &Arc<Mutex<Node>>) -> Result<Proof> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let storage_keys: Vec<U256> = params.next()?;
    let storage_keys = storage_keys
        .into_iter()
        .map(|key| B256::new(key.to_be_bytes()))
        .collect::<Vec<_>>();
    let block_id: BlockId = params.next()?;
    expect_end_of_params(&mut params, 3, 3)?;

    let node = node.lock().unwrap();

    let block = node.get_block(block_id)?;

    let block = build_errored_response_for_missing_block(block_id, block)?;

    let state = node.consensus.state().at_root(block.state_root_hash().into());

    let computed_proof = state.get_proof(address, &storage_keys)?;

    let acc_code = Bytecode::new_raw(computed_proof.account.code.evm_code().unwrap_or_default().into());

    info!("Block state root is: {:?}", block.state_root_hash());

    Ok(Proof {
        address,
        account_proof: computed_proof.account_proof,
        storage_proof: computed_proof.storage_proofs.into_iter().map(|single_item| StorageProof {
            proof: single_item.proof,
            key: single_item.key,
            value: single_item.value
        }).collect(),
        nonce: computed_proof.account.nonce,
        balance: computed_proof.account.balance,
        storage_hash: computed_proof.account.storage_root,
        code_hash: acc_code.hash_slow()
    })
}

#[allow(clippy::redundant_allocation)]
async fn subscribe(
    params: Params<'_>,
    pending: PendingSubscriptionSink,
    node: Arc<Arc<Mutex<Node>>>,
    _: Extensions,
) -> Result<(), StringError> {
    let mut params = params.sequence();
    let kind: SubscriptionKind = params.next()?;
    let params: Option<pubsub::Params> = params.optional_next()?;
    let params = params.unwrap_or_default();

    let sink = pending.accept().await?;

    match kind {
        SubscriptionKind::NewHeads => {
            let mut new_blocks = node.lock().unwrap().subscribe_to_new_blocks();

            while let Ok(header) = new_blocks.recv().await {
                let miner = node.lock().unwrap().get_proposer_reward_address(header)?;
                let block_gas_limit = node.lock().unwrap().config.consensus.eth_block_gas_limit;
                let header =
                    eth::Header::from_header(header, miner.unwrap_or_default(), block_gas_limit);
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

            let mut receipts = node.lock().unwrap().subscribe_to_receipts();

            'outer: while let Ok((receipt, transaction_index)) = receipts.recv().await {
                if !filter.filter_block_hash(receipt.block_hash.into()) {
                    continue;
                }
                for (log_index, log) in receipt.logs.into_iter().enumerate() {
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
                        .lock()
                        .unwrap()
                        .get_block(receipt.block_hash)?
                        .ok_or_else(|| anyhow!("missing block"))?;
                    if !filter.filter_block_range(block.number()) {
                        continue 'outer;
                    }

                    let log = alloy::rpc::types::Log {
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
                        log_index: Some(log_index as u64),
                        removed: false,
                    };
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
                let mut txns = node.lock().unwrap().subscribe_to_new_transactions();

                while let Ok(txn) = txns.recv().await {
                    let txn = eth::Transaction::new(txn, None);
                    let _ = sink.send(SubscriptionMessage::from_json(&txn)?).await;
                }
            } else {
                let mut txns = node.lock().unwrap().subscribe_to_new_transaction_hashes();

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
fn blob_base_fee(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_feeHistory
/// Returns the collection of historical gas information
fn fee_history(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_getAccount
/// Retrieve account details by specifying an address and a block number/tag.
fn get_account(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_getFilterChanges
/// Polling method for a filter, which returns an array of events that have occurred since the last poll.
fn get_filter_changes(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_getFilterLogs
/// Returns an array of all logs matching filter with given id.
fn get_filter_logs(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_hashrate
/// Returns the number of hashes per second that the node is mining with.
fn hashrate(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_maxPriorityFeePerGas
/// Get the priority fee needed to be included in a block.
fn max_priority_fee_per_gas(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_newBlockFilter
/// Creates a filter in the node, to notify when a new block arrives. To check if the state has changed, call eth_getFilterChanges
fn new_block_filter(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_newFilter
/// Creates a filter object, based on filter options, to notify when the state changes (logs). To check if the state has changed, call eth_getFilterChanges.
fn new_filter(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_newPendingTransactionFilter
/// Creates a filter in the node to notify when new pending transactions arrive. To check if the state has changed, call eth_getFilterChanges.
fn new_pending_transaction_filter(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_signTransaction
/// Signs a transaction that can be submitted to the network later using eth_sendRawTransaction
fn sign_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_simulateV1
/// Simulates a series of transactions at a specific block height with optional state overrides. This method allows you to test transactions with custom block and state parameters without actually submitting them to the network.
fn simulate_v1(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_submitWork
/// Used for submitting a proof-of-work solution.
fn submit_work(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}

/// eth_uninstallFilter
/// It uninstalls a filter with the given filter id.
fn uninstall_filter(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    todo!("Endpoint not implemented yet")
}
