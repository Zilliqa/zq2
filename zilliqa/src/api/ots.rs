use std::{
    borrow::Cow,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Result};
use ethabi::Token;
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::{H160, H256};
use serde_json::{json, Value};

use super::{
    eth::{get_transaction_inner, get_transaction_receipt_inner},
    types::ots::{self, TraceEntry},
};
use crate::{
    api::to_hex::ToHex,
    crypto::Hash,
    exec::TransactionOutput,
    inspector::{self, CreatorInspector, OtterscanTraceInspector},
    message::BlockNumber,
    node::Node,
    state::Contract,
    time::SystemTime,
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("ots_getApiLevel", get_otterscan_api_level),
            ("ots_getBlockDetails", get_block_details),
            ("ots_getBlockDetailsByHash", get_block_details_by_hash),
            ("ots_getBlockTransactions", get_block_transactions),
            ("ots_getContractCreator", get_contract_creator),
            ("ots_getTransactionError", get_transaction_error),
            ("ots_hasCode", has_code),
            ("ots_searchTransactionsAfter", search_transactions_after),
            ("ots_searchTransactionsBefore", search_transactions_before),
            ("ots_traceTransaction", trace_transaction),
        ],
    )
}

fn get_otterscan_api_level(_: Params, _: &Arc<Mutex<Node>>) -> Result<u64> {
    // https://github.com/otterscan/otterscan/blob/0a819f3557fe19c0f47327858261881ec5f56d6c/src/params.ts#L1
    Ok(8)
}

fn get_block_details(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<ots::BlockDetails>> {
    let block: u64 = params.one()?;

    let Some(ref block) = node.lock().unwrap().get_block_by_number(block)? else {
        return Ok(None);
    };
    let miner = node
        .lock()
        .unwrap()
        .get_proposer_reward_address(block.header)?;

    Ok(Some(ots::BlockDetails::from_block(
        block,
        miner.unwrap_or_default(),
    )))
}

fn get_block_details_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<ots::BlockDetails>> {
    let block_hash: H256 = params.one()?;

    let Some(ref block) = node.lock().unwrap().get_block_by_hash(Hash(block_hash.0))? else {
        return Ok(None);
    };
    let miner = node
        .lock()
        .unwrap()
        .get_proposer_reward_address(block.header)?;

    Ok(Some(ots::BlockDetails::from_block(
        block,
        miner.unwrap_or_default(),
    )))
}

fn get_block_transactions(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<ots::BlockTransactions>> {
    let mut params = params.sequence();
    let block_num: u64 = params.next()?;
    let page_number: usize = params.next()?;
    let page_size: usize = params.next()?;

    let node = node.lock().unwrap();

    let Some(block) = node.get_block_by_number(block_num)? else {
        return Ok(None);
    };
    let miner = node.get_proposer_reward_address(block.header)?;

    let start = usize::min(page_number * page_size, block.transactions.len());
    let end = usize::min((page_number + 1) * page_size, block.transactions.len());

    let txn_results = block.transactions[start..end].iter().map(|hash| {
        // There are some redundant calls between these two functions - We could optimise by combining them.
        let txn = get_transaction_inner(*hash, &node)?
            .ok_or_else(|| anyhow!("transaction not found: {hash}"))?;
        let receipt = get_transaction_receipt_inner(*hash, &node)?
            .ok_or_else(|| anyhow!("receipt not found: {hash}"))?;

        Ok::<_, anyhow::Error>((txn, receipt))
    });
    let (transactions, receipts): (Vec<_>, Vec<_>) =
        itertools::process_results(txn_results, |iter| iter.unzip())?;

    let full_block = ots::BlockWithTransactions {
        transactions,
        block: ots::Block::from_block(&block, miner.unwrap_or_default()),
    };

    Ok(Some(ots::BlockTransactions {
        full_block,
        receipts,
    }))
}

fn get_contract_creator(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<Value>> {
    let address: H160 = params.one()?;

    let touched = node.lock().unwrap().get_touched_transactions(address)?;

    // Perform a linear search over each transaction which touched this address. Replay each one to try and find the
    // transaction which created it.
    for txn_hash in touched {
        // Replay the creation transaction to work out the creator. This is important for contracts which are created
        // by other contracts, for which the creator is not the same as `txn.from_addr`.
        let mut inspector = CreatorInspector::new(address);
        node.lock()
            .unwrap()
            .replay_transaction(txn_hash, &mut inspector)?;

        if let Some(creator) = inspector.creator() {
            return Ok(Some(json!({
                "hash": H256(txn_hash.0).to_hex(),
                "creator": creator.to_hex(),
            })));
        }
    }

    Ok(None)
}

fn get_transaction_error(params: Params, node: &Arc<Mutex<Node>>) -> Result<Cow<'static, str>> {
    let txn_hash: H256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let result = node
        .lock()
        .unwrap()
        .replay_transaction(txn_hash, inspector::noop())?;

    if !result.exceptions.is_empty() {
        // If the transaction resulted in Scilla exceptions, concatenate them into a single string and ABI encode it.
        let error: String =
            itertools::intersperse_with(result.exceptions.into_iter().map(|e| e.message), || {
                ", ".to_owned()
            })
            .collect();
        let error = ethabi::encode(&[Token::String(error)]);
        // Prefix the error with the function selector for 'Error'. This is how raw reverts are encoded in Solidity.
        let mut encoded = vec![0x08, 0xc3, 0x79, 0xa0];
        encoded.extend_from_slice(&error);
        Ok(encoded.to_hex().into())
    } else {
        match result.output {
            TransactionOutput::Revert(output) => Ok(output.to_hex().into()),
            _ => Ok("0x".into()),
        }
    }
}

fn has_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<bool> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let block_number: BlockNumber = params.next()?;

    let contract = node
        .lock()
        .unwrap()
        .get_account(address, block_number)?
        .contract;
    let empty = match contract {
        Contract::Evm { code, .. } => code.is_empty(),
        Contract::Scilla { code, .. } => code.is_empty(),
    };

    Ok(!empty)
}

fn search_transactions_inner(
    node: &Arc<Mutex<Node>>,
    address: H160,
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
    let address: H160 = params.next()?;
    let block_number: u64 = params.next()?;
    let page_size: usize = params.next()?;

    search_transactions_inner(node, address, block_number, page_size, false)
}

fn search_transactions_before(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<ots::Transactions> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let mut block_number: u64 = params.next()?;
    let page_size: usize = params.next()?;

    // A `block_number` of `0` tells us to search from the most recent block.
    if block_number == 0 {
        block_number = u64::MAX;
    }

    search_transactions_inner(node, address, block_number, page_size, true)
}

fn trace_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<TraceEntry>> {
    let txn_hash: H256 = params.one()?;
    let txn_hash = Hash(txn_hash.0);

    let mut inspector = OtterscanTraceInspector::default();
    node.lock()
        .unwrap()
        .replay_transaction(txn_hash, &mut inspector)?;

    Ok(inspector.entries())
}
