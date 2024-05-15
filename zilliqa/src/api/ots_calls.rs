use std::{
    borrow::Cow,
    sync::{Arc, Mutex},
};

use alloy_primitives::{Address, B256};
use anyhow::{anyhow, Result};
use ethabi::Token;
use jsonrpsee::{types::Params, RpcModule};

use super::{
    eth::{get_transaction_inner, get_transaction_receipt_inner},
    types::ots::{self, Operation, TraceEntry},
};
use crate::{
    api::to_hex::ToHex,
    crypto::Hash,
    inspector::{self, OtterscanOperationInspector, OtterscanTraceInspector},
    node::Node,
    time::SystemTime,
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            (
                "ots_getApiLevel",
                crate::api::ots::ots_getapilevel::get_otterscan_api_level
            ),
            (
                "ots_getBlockDetails",
                crate::api::ots::ots_getblockdetails::get_block_details
            ),
            (
                "ots_getBlockDetailsByHash",
                crate::api::ots::ots_getblockdetailsbyhash::get_block_details_by_hash
            ),
            (
                "ots_getBlockTransactions",
                crate::api::ots::ots_getblocktransactions::get_block_transactions
            ),
            (
                "ots_getContractCreator",
                crate::api::ots::ots_getcontractcreator::get_contract_creator
            ),
            ("ots_getInternalOperations", get_internal_operations),
            (
                "ots_getTransactionBySenderAndNonce",
                get_transaction_by_sender_and_nonce
            ),
            ("ots_getTransactionError", get_transaction_error),
            ("ots_hasCode", crate::api::ots::ots_hascode::has_code),
            ("ots_searchTransactionsAfter", search_transactions_after),
            ("ots_searchTransactionsBefore", search_transactions_before),
            ("ots_traceTransaction", trace_transaction),
        ],
    )
}

fn get_internal_operations(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<Operation>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let mut inspector = OtterscanOperationInspector::default();
    node.lock()
        .unwrap()
        .replay_transaction(txn_hash, &mut inspector)?;

    Ok(inspector.entries())
}

fn get_transaction_by_sender_and_nonce(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<String>> {
    let mut params = params.sequence();
    let sender: Address = params.next()?;
    let nonce: u64 = params.next()?;

    let node = node.lock().unwrap();
    let touched = node.get_touched_transactions(sender)?;

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

fn get_transaction_error(params: Params, node: &Arc<Mutex<Node>>) -> Result<Cow<'static, str>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let result = node
        .lock()
        .unwrap()
        .replay_transaction(txn_hash, inspector::noop())?;

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

fn search_transactions_inner(
    node: &Arc<Mutex<Node>>,
    address: Address,
    block_number: u64,
    page_size: usize,
    reverse: bool,
) -> Result<ots::Transactions> {
    let mut touched = node.lock().unwrap().get_touched_transactions(address)?;

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

    for hash in touched {
        let txn = get_transaction_inner(hash, &node.lock().unwrap())
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
            .lock()
            .unwrap()
            .get_block_by_hash(Hash(txn.block_hash.unwrap_or_default().0))?
            .unwrap()
            .timestamp();

        transactions.push(txn);

        let node = node.lock().unwrap();
        let receipt = ots::TransactionReceiptWithTimestamp {
            receipt: get_transaction_receipt_inner(hash, &node).unwrap().unwrap(),
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

fn search_transactions_after(params: Params, node: &Arc<Mutex<Node>>) -> Result<ots::Transactions> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_number: u64 = params.next()?;
    let page_size: usize = params.next()?;

    search_transactions_inner(node, address, block_number, page_size, false)
}

fn search_transactions_before(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<ots::Transactions> {
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

fn trace_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<TraceEntry>> {
    let txn_hash: B256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let mut inspector = OtterscanTraceInspector::default();
    node.lock()
        .unwrap()
        .replay_transaction(txn_hash, &mut inspector)?;

    Ok(inspector.entries())
}
