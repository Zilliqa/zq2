//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::sync::{Arc, Mutex, MutexGuard};

use alloy::{
    consensus::{TxEip1559, TxEip2930, TxLegacy, transaction::RlpEcdsaDecodableTx},
    eips::{BlockId, BlockNumberOrTag, RpcBlockHash},
    primitives::{Address, B256, U64, U256},
    rpc::types::{
        FilteredParams,
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
    api::zilliqa::ZilAddress,
    cfg::EnabledApi,
    crypto::Hash,
    error::ensure_success,
    exec::zil_contract_address,
    message::Block,
    node::Node,
    pool::TxAddResult,
    state::Code,
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction},
};

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

pub fn get_block_transaction_receipts_inner(
    node: &MutexGuard<Node>,
    block_id: impl Into<BlockId>,
) -> Result<Vec<eth::TransactionReceipt>> {
    let Some(block) = node.get_block(block_id)? else {
        return Err(anyhow!("Block not found"));
    };

    let mut log_index = 0;
    let mut receipts = Vec::new();

    for (transaction_index, tx_hash) in block.transactions.iter().enumerate() {
        let Some(signed_transaction) = node.get_transaction_by_hash(*tx_hash)? else {
            warn!(
                "Failed to get TX by hash when getting TX receipt! {}",
                tx_hash
            );
            continue;
        };

        let Some(receipt) = node.get_transaction_receipt(*tx_hash)? else {
            debug!(
                "Failed to get TX receipt when getting TX receipt! {}",
                tx_hash
            );
            continue;
        };

        debug!(
            "get_block_transaction_receipts: hash: {:?} result: {:?}",
            tx_hash, receipt
        );

        // Required workaround for incorrectly converted nonces for zq1 scilla transactions
        let contract_address = match &signed_transaction.tx {
            SignedTransaction::Zilliqa { tx, .. } => {
                if tx.to_addr.is_zero() && receipt.success {
                    Some(zil_contract_address(
                        signed_transaction.signer,
                        signed_transaction
                            .tx
                            .nonce()
                            .ok_or_else(|| anyhow!("Unable to extract nonce!"))?,
                    ))
                } else {
                    receipt.contract_address
                }
            }
            _ => receipt.contract_address,
        };

        let mut logs_bloom = [0; 256];

        let mut logs = Vec::new();
        for log in receipt.logs {
            let log = match log {
                Log::Evm(log) => log,
                Log::Scilla(log) => log.into_evm(),
            };
            let log = eth::Log::new(
                log,
                log_index,
                transaction_index,
                *tx_hash,
                block.number(),
                block.hash(),
            );
            log_index += 1;
            log.bloom(&mut logs_bloom);
            logs.push(log);
        }

        let from = signed_transaction.signer;
        let v = signed_transaction.tx.sig_v();
        let r = signed_transaction.tx.sig_r();
        let s = signed_transaction.tx.sig_s();
        let transaction = signed_transaction.tx.into_transaction();

        let receipt = eth::TransactionReceipt {
            transaction_hash: (*tx_hash).into(),
            transaction_index: transaction_index as u64,
            block_hash: block.hash().into(),
            block_number: block.number(),
            from,
            to: transaction.to_addr(),
            cumulative_gas_used: receipt.cumulative_gas_used,
            effective_gas_price: transaction.max_fee_per_gas(),
            gas_used: receipt.gas_used,
            contract_address,
            logs,
            logs_bloom,
            ty: 0,
            status: receipt.success,
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
    node: &MutexGuard<Node>,
    block_id: impl Into<BlockId>,
    txn_hash: Hash,
) -> Result<Option<eth::TransactionReceipt>> {
    let receipts = get_block_transaction_receipts_inner(node, block_id)?;
    Ok(receipts
        .into_iter()
        .find(|r| r.transaction_hash == txn_hash.as_bytes()))
}

fn get_block_receipts(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<TransactionReceipt>> {
    let block_id: BlockId = params.one()?;
    let node = node.lock().unwrap();

    get_block_transaction_receipts_inner(&node, block_id)
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

#[allow(unreachable_code)]
#[allow(unused_variables)]
pub fn get_block_logs_bloom(node: &MutexGuard<Node>, block: &Block) -> Result<[u8; 256]> {
    let mut logs_bloom = [0; 256];
    return Ok(logs_bloom); // FIXME: test if it speeds eth_getBlockByNumber
    for txn_hash in &block.transactions {
        let txn_receipt = node
            .get_transaction_receipt(*txn_hash)?
            .ok_or_else(|| anyhow!("missing receipt"))?;
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
            .for_each(|(log_index, log)| {
                let log = eth::Log::new(
                    log,
                    log_index,
                    txn_receipt.index as usize,
                    txn_receipt.tx_hash,
                    block.number(),
                    block.hash(),
                );

                log.bloom(&mut logs_bloom);
            });
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

fn get_logs(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<eth::Log>> {
    let mut seq = params.sequence();
    let params: alloy::rpc::types::Filter = seq.next()?;
    expect_end_of_params(&mut seq, 1, 1)?;
    let node = node.lock().unwrap();
    get_logs_inner(&params, &node)
}

fn get_logs_inner(
    params: &alloy::rpc::types::Filter,
    node: &MutexGuard<Node>,
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

fn get_transaction_receipt(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::TransactionReceipt>> {
    trace!("get_transaction_receipt: params: {:?}", params);
    let hash: B256 = params.one()?;
    let hash: Hash = hash.into();
    let node = node.lock().unwrap();
    let block_hash = match node.get_transaction_receipt(hash)? {
        Some(receipt) => receipt.block_hash,
        None => return Ok(None),
    };
    get_transaction_receipt_inner_slow(&node, block_hash, hash)
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
    if let Some(result) = node.lock().unwrap().consensus.get_sync_data()? {
        Ok(SyncingResult::Struct(result))
    } else {
        Ok(SyncingResult::Bool(false))
    }
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
                let block = node
                    .lock()
                    .unwrap()
                    .get_block(header.hash)?
                    .ok_or_else(|| anyhow!("missing block"))?;
                let logs_bloom = get_block_logs_bloom(&node.lock().unwrap(), &block)?;
                let header = eth::Header::from_header(
                    header,
                    miner.unwrap_or_default(),
                    block_gas_limit,
                    logs_bloom,
                );
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

                // We track log index plus one because we have to increment before we use the log index, and log indexes are 0-based.
                let mut log_index_plus_one: i64 = get_block_transaction_receipts_inner(
                    &node.lock().unwrap(),
                    receipt.block_hash,
                )?
                .iter()
                .take_while(|x| x.transaction_index < receipt.index)
                .map(|x| x.logs.len())
                .sum::<usize>() as i64;

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
                        log_index: Some((log_index_plus_one - 1) as u64),
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
    Err(anyhow!("API method eth_blobBaseFee is not implemented yet"))
}

/// eth_feeHistory
/// Returns the collection of historical gas information
fn fee_history(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_feeHistory is not implemented yet"))
}

/// eth_getAccount
/// Retrieve account details by specifying an address and a block number/tag.
fn get_account(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_getAccount is not implemented yet"))
}

/// eth_getFilterChanges
/// Polling method for a filter, which returns an array of events that have occurred since the last poll.
#[allow(unreachable_code)]
#[allow(unused_variables)]
fn get_filter_changes(params: Params, node: &Arc<Mutex<Node>>) -> Result<serde_json::Value> {
    return Err(anyhow!("API method get_filter_changes is disabled"));
    let filter_id: u128 = params.one()?;

    let node = node.lock().unwrap();

    let mut filters = node.filters.lock().unwrap();

    let filter = filters
        .get_mut(&filter_id)
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
            let all_logs = get_logs_inner(&log_filter.criteria, &node)?;
            let result: Vec<eth::Log> = all_logs
                .iter()
                .filter(|log| !log_filter.seen_logs.contains(log))
                .cloned()
                .collect();
            log_filter.seen_logs = all_logs.into_iter().collect();
            Ok(json!(result))
        }
    }
}

/// eth_getFilterLogs
/// Returns an array of all logs matching filter with given id.
#[allow(unreachable_code)]
#[allow(unused_variables)]
fn get_filter_logs(params: Params, node: &Arc<Mutex<Node>>) -> Result<serde_json::Value> {
    return Err(anyhow!("API method get_filter_logs is disabled"));
    let filter_id: u128 = params.one()?;
    let node = node.lock().unwrap();
    let mut filters = node.filters.lock().unwrap();

    if let Some(filter) = filters.get_mut(&filter_id) {
        match &mut filter.kind {
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
fn get_proof(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_getProof is not implemented yet"))
}

/// eth_hashrate
/// Returns the number of hashes per second that the node is mining with.
fn hashrate(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_hashrate is not implemented yet"))
}

/// eth_maxPriorityFeePerGas
/// Get the priority fee needed to be included in a block.
fn max_priority_fee_per_gas(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method eth_maxPriorityFeePerGas is not implemented yet"
    ))
}

/// eth_newBlockFilter
/// Creates a filter in the node, to notify when a new block arrives. To check if the state has changed, call eth_getFilterChanges
#[allow(unreachable_code)]
#[allow(unused_variables)]
fn new_block_filter(params: Params, node: &Arc<Mutex<Node>>) -> Result<u128> {
    return Err(anyhow!("API method new_block_filter is disabled"));
    expect_end_of_params(&mut params.sequence(), 0, 0)?;

    let node = node.lock().unwrap();
    let mut filters = node.filters.lock().unwrap();

    let filter = BlockFilter {
        block_receiver: node.subscribe_to_new_blocks(),
    };
    let id = filters.add_filter(FilterKind::Block(filter));
    Ok(id)
}

/// eth_newFilter
/// Creates a filter object, based on filter options, to notify when the state changes (logs). To check if the state has changed, call eth_getFilterChanges.
#[allow(unreachable_code)]
#[allow(unused_variables)]
fn new_filter(params: Params, node: &Arc<Mutex<Node>>) -> Result<u128> {
    return Err(anyhow!("API method new_filter is disabled"));
    let criteria: alloy::rpc::types::Filter = params.one()?;
    let node = node.lock().unwrap();
    let mut filters = node.filters.lock().unwrap();

    let id = filters.add_filter(FilterKind::Log(LogFilter {
        criteria: Box::new(criteria),
        last_block_number: None,
        seen_logs: std::collections::HashSet::new(),
    }));
    Ok(id)
}

/// eth_newPendingTransactionFilter
/// Creates a filter in the node to notify when new pending transactions arrive. To check if the state has changed, call eth_getFilterChanges.
#[allow(unreachable_code)]
#[allow(unused_variables)]
fn new_pending_transaction_filter(params: Params, node: &Arc<Mutex<Node>>) -> Result<u128> {
    return Err(anyhow!(
        "API method new_pending_transaction_filter is disabled"
    ));
    expect_end_of_params(&mut params.sequence(), 0, 0)?;
    let node = node.lock().unwrap();
    let mut filters = node.filters.lock().unwrap();

    let filter = PendingTxFilter {
        pending_txn_receiver: node.subscribe_to_new_transactions(),
    };
    let id = filters.add_filter(FilterKind::PendingTx(filter));
    Ok(id)
}

/// eth_signTransaction
/// Signs a transaction that can be submitted to the network later using eth_sendRawTransaction
fn sign_transaction(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!(
        "API method eth_signTransaction is not implemented yet"
    ))
}

/// eth_simulateV1
/// Simulates a series of transactions at a specific block height with optional state overrides. This method allows you to test transactions with custom block and state parameters without actually submitting them to the network.
fn simulate_v1(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_simulateV1 is not implemented yet"))
}

/// eth_submitWork
/// Used for submitting a proof-of-work solution.
fn submit_work(_params: Params, _node: &Arc<Mutex<Node>>) -> Result<()> {
    Err(anyhow!("API method eth_submitWork is not implemented yet"))
}

/// eth_uninstallFilter
/// It uninstalls a filter with the given filter id.
#[allow(unreachable_code)]
#[allow(unused_variables)]
fn uninstall_filter(params: Params, node: &Arc<Mutex<Node>>) -> Result<bool> {
    return Err(anyhow!("API method uninstall_filter is disabled"));
    let filter_id: u128 = params.one()?;

    let node = node.lock().unwrap();
    let mut filters = node.filters.lock().unwrap();

    Ok(filters.remove_filter(filter_id))
}
