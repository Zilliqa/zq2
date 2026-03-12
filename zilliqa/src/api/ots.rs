use std::{borrow::Cow, sync::Arc};

use alloy::{
    eips::BlockId,
    primitives::{Address, B256},
};
use anyhow::{Result, anyhow};
use ethabi::Token;
use jsonrpsee::{RpcModule, types::Params};
use serde_json::{Value, json};

use super::{
    HandlerType,
    eth::{
        get_transaction_inner, get_transaction_receipt_inner_slow,
        old_get_block_transaction_receipts_inner,
    },
    types::ots::{self, Operation, TraceEntry},
};
use crate::{
    api::{
        disabled_err, format_panic_as_error, into_rpc_error, make_panic_hook, rpc_base_attributes,
        to_hex::ToHex,
    },
    cfg::EnabledApi,
    crypto::Hash,
    inspector::{self, CreatorInspector, OtterscanOperationInspector, OtterscanTraceInspector},
    node::Node,
    time::SystemTime,
};

pub fn rpc_module(node: Arc<Node>, enabled_apis: &[EnabledApi]) -> RpcModule<Arc<Node>> {
    super::declare_module!(
        node,
        enabled_apis,
        [
            (
                "ots_getApiLevel",
                get_otterscan_api_level,
                HandlerType::Fast
            ),
            ("ots_getBlockDetails", get_block_details, HandlerType::Fast),
            (
                "ots_getBlockDetailsByHash",
                get_block_details_by_hash,
                HandlerType::Fast
            ),
            (
                "ots_getBlockTransactions",
                get_block_transactions,
                HandlerType::Slow
            ),
            (
                "ots_getContractCreator",
                get_contract_creator,
                HandlerType::Slow
            ),
            (
                "ots_getInternalOperations",
                get_internal_operations,
                HandlerType::Slow
            ),
            (
                "ots_getTransactionBySenderAndNonce",
                get_transaction_by_sender_and_nonce,
                HandlerType::Slow
            ),
            (
                "ots_getTransactionError",
                get_transaction_error,
                HandlerType::Slow
            ),
            ("ots_hasCode", has_code, HandlerType::Fast),
            (
                "ots_searchTransactionsAfter",
                search_transactions_after,
                HandlerType::Slow
            ),
            (
                "ots_searchTransactionsBefore",
                search_transactions_before,
                HandlerType::Slow
            ),
            ("ots_traceTransaction", trace_transaction, HandlerType::Slow),
        ],
    )
}

pub fn get_otterscan_api_level(_: Params, _: &Arc<Node>) -> Result<u64> {
    // https://github.com/otterscan/otterscan/blob/0a819f3557fe19c0f47327858261881ec5f56d6c/src/params.ts#L1
    Ok(8)
}

fn get_block_details(params: Params, node: &Arc<Node>) -> Result<Option<ots::BlockDetails>> {
    let block_number: u64 = params.one()?;

    let Some(ref block) = node.get_block(block_number)? else {
        return Ok(None);
    };
    let miner = node.get_proposer_reward_address(block)?;

    let block_gas_limit = node.config.consensus.eth_block_gas_limit;
    Ok(Some(ots::BlockDetails::from_block(
        block,
        miner.unwrap_or_default(),
        block_gas_limit,
    )))
}

fn get_block_details_by_hash(
    params: Params,
    node: &Arc<Node>,
) -> Result<Option<ots::BlockDetails>> {
    let block_hash: B256 = params.one()?;

    let Some(ref block) = node.get_block(block_hash)? else {
        return Ok(None);
    };
    let miner = node.get_proposer_reward_address(block)?;
    let block_gas_limit = node.config.consensus.eth_block_gas_limit;
    Ok(Some(ots::BlockDetails::from_block(
        block,
        miner.unwrap_or_default(),
        block_gas_limit,
    )))
}

fn get_block_transactions(
    params: Params,
    node: &Arc<Node>,
) -> Result<Option<ots::BlockTransactions>> {
    let mut params = params.sequence();
    let block_number: u64 = params.next()?;
    let page_number: usize = params.next()?;
    let page_size: usize = params.next()?;

    let (pool, db, miner, block, block_gas_limit) = {
        let Some(block) = node.get_block(block_number)? else {
            return Ok(None);
        };
        let miner = node.get_proposer_reward_address(&block)?;
        (
            node.consensus.read().transaction_pool.clone(),
            node.db.clone(),
            miner,
            block,
            node.config.consensus.eth_block_gas_limit,
        )
    };

    let start = usize::min(page_number * page_size, block.transactions.len());
    let end = usize::min((page_number + 1) * page_size, block.transactions.len());

    let receipts = old_get_block_transaction_receipts_inner(db.clone(), &block)?;
    let transactions = block.transactions[start..end]
        .iter()
        .map(|hash| get_transaction_inner(*hash, pool.clone(), db.clone()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    let full_block = ots::BlockWithTransactions {
        transactions,
        block: ots::Block::from_block(&block, miner.unwrap_or_default(), block_gas_limit),
    };

    Ok(Some(ots::BlockTransactions {
        full_block,
        receipts,
    }))
}

fn get_contract_creator(params: Params, node: &Arc<Node>) -> Result<Option<Value>> {
    let address: Address = params.one()?;

    let touched = node.get_touched_transactions(address)?;

    // Perform a linear search over each transaction which touched this address. Replay each one to try and find the
    // transaction which created it.
    for txn_hash in touched {
        // Replay the creation transaction to work out the creator. This is important for contracts which are created
        // by other contracts, for which the creator is not the same as `txn.from_addr`.
        let mut inspector = CreatorInspector::new(address);

        Node::replay_transaction(node, txn_hash, &mut inspector)?;

        if let Some(creator) = inspector.creator() {
            return Ok(Some(json!({
                "hash": B256::from(txn_hash).to_hex(),
                "creator": creator.to_hex(),
            })));
        }
    }

    Ok(None)
}

fn get_internal_operations(params: Params, node: &Arc<Node>) -> Result<Vec<Operation>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let mut inspector = OtterscanOperationInspector::default();
    Node::replay_transaction(node, txn_hash, &mut inspector)?;

    Ok(inspector.entries())
}

fn get_transaction_by_sender_and_nonce(params: Params, node: &Arc<Node>) -> Result<Option<String>> {
    let mut params = params.sequence();
    let sender: Address = params.next()?;
    let nonce: u64 = params.next()?;

    let touched = { node.get_touched_transactions(sender)? };

    // Iterate over each transaction which touched the sender. This will include transactions which weren't sent by the
    // sender which we need to filter out.
    for txn_hash in touched {
        let txn = node
            .get_transaction_by_hash(txn_hash)?
            .ok_or_else(|| anyhow!("missing transaction: {txn_hash}"))?;
        if txn.signer == sender && txn.tx.nonce().map(|n| n == nonce).unwrap_or(false) {
            return Ok(Some(B256::from(txn_hash).to_hex()));
        }
    }

    Ok(None)
}

fn get_transaction_error(params: Params, node: &Arc<Node>) -> Result<Cow<'static, str>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let result = Node::replay_transaction(node, txn_hash, inspector::noop())?;

    if !result.exceptions().is_empty() {
        // If the transaction resulted in Scilla exceptions, concatenate them into a single string and ABI encode it.
        let error: String = itertools::intersperse_with(
            result.exceptions().iter().map(|e| e.message.as_str()),
            || ", ",
        )
        .collect();
        let error = ethabi::encode(&[Token::String(error)]);
        // Prefix the error with the function selector for 'Error'. This is how raw reverts are encoded in Solidity.
        let mut encoded = vec![0x08, 0xc3, 0x79, 0xa0];
        encoded.extend_from_slice(&error);
        Ok(encoded.to_hex().into())
    } else {
        match result.output() {
            Some(output) => Ok(output.to_hex().into()),
            _ => Ok("0x".into()),
        }
    }
}

fn has_code(params: Params, node: &Arc<Node>) -> Result<bool> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_id: BlockId = params.optional_next()?.unwrap_or_default();

    let state = {
        let block = node
            .get_block(block_id)?
            .ok_or_else(|| anyhow!("Unable to get the latest block!"))?;
        node.get_state(&block)?
    };
    let empty = state.get_account(address)?.code.is_eoa();

    Ok(!empty)
}

fn search_transactions_inner(
    node: &Arc<Node>,
    address: Address,
    block_number: u64,
    page_size: usize,
    reverse: bool,
) -> Result<ots::Transactions> {
    let mut touched = node.get_touched_transactions(address)?;

    // If searching in reverse, we should start with the most recent transaction and work backwards.
    if reverse {
        touched.reverse();
    }

    let mut transactions = Vec::with_capacity(page_size);
    let mut receipts = Vec::with_capacity(page_size);

    // Keep track of the current block number. Once we reach `page_size` transactions, we still need to continue adding
    // transactions from the current block.
    let mut current_block = u64::MAX;
    // This will be set to false if we break out of the loop, indicating to the caller there are further pages.
    let mut finished = true;

    let (pool, db) = {
        (
            node.consensus.read().transaction_pool.clone(),
            node.db.clone(),
        )
    };

    for hash in touched {
        let txn = get_transaction_inner(hash, pool.clone(), db.clone())
            .unwrap()
            .unwrap();

        let txn_block_number = match txn.block_number {
            Some(txn_block_number) => txn_block_number,
            None => continue,
        };

        let cmp = if !reverse {
            PartialOrd::le
        } else {
            PartialOrd::ge
        };
        if cmp(&txn_block_number, &block_number) {
            continue;
        }

        // Don't break until we have at least `page_size` transactions AND we've added everything from the last searched block.
        if transactions.len() >= page_size && txn_block_number != current_block {
            finished = false;
            break;
        }

        let timestamp = node
            .get_block(txn.block_hash.unwrap_or_default())?
            .unwrap()
            .timestamp();

        transactions.push(txn);

        let receipt = ots::TransactionReceiptWithTimestamp {
            receipt: get_transaction_receipt_inner_slow(node, txn_block_number, hash)
                .unwrap()
                .unwrap(),
            timestamp: timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        receipts.push(receipt);

        current_block = txn_block_number;
    }

    // The results should always be returned in descending order (latest to earliest). If we were searching forwards
    // in time, we should reverse the results to ensure they are in descending order.
    if !reverse {
        transactions.reverse();
        receipts.reverse();
    }

    // `first_page` should be set if this was the latest page in time and `last_page` should be set if this was the
    // earliest page in time.
    let (first_page, last_page) = if reverse {
        (block_number == u64::MAX, finished)
    } else {
        (finished, block_number == 0)
    };

    Ok(ots::Transactions {
        transactions,
        receipts,
        first_page,
        last_page,
    })
}

fn search_transactions_after(params: Params, node: &Arc<Node>) -> Result<ots::Transactions> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_number: u64 = params.next()?;
    let page_size: usize = params.next()?;

    search_transactions_inner(node, address, block_number, page_size, false)
}

fn search_transactions_before(params: Params, node: &Arc<Node>) -> Result<ots::Transactions> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let mut block_number: u64 = params.next()?;
    let page_size: usize = params.next()?;

    // A `block_number` of `0` tells us to search from the most recent block.
    if block_number == 0 {
        block_number = u64::MAX;
    }

    search_transactions_inner(node, address, block_number, page_size, true)
}

fn trace_transaction(params: Params, node: &Arc<Node>) -> Result<Vec<TraceEntry>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let mut inspector = OtterscanTraceInspector::default();
    Node::replay_transaction(node, txn_hash, &mut inspector)?;

    Ok(inspector.entries())
}
