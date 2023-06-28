use std::{
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{anyhow, Result};
use evm_ds::evm::{
    self,
    tracing::{Event, EventListener},
};
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::{H160, H256};
use serde::Deserialize;

use crate::{crypto::Hash, message::BlockNumber, node::Node, state::Address};

use super::{
    eth::{get_transaction_inner, get_transaction_receipt_inner},
    types::{
        EthTransaction, EthTransactionReceiptWithTimestamp, OtterscanBlockDetails,
        OtterscanBlockTransactions, OtterscanBlockWithTransactions, OtterscanContractCreator,
        OtterscanTransactions,
    },
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
            ("ots_hasCode", has_code),
            ("ots_searchTransactionsAfter", search_transactions_after),
            ("ots_searchTransactionsBefore", search_transactions_before),
        ],
    )
}

fn get_otterscan_api_level(_: Params, _: &Arc<Mutex<Node>>) -> Result<u64> {
    // https://github.com/otterscan/otterscan/blob/0a819f3557fe19c0f47327858261881ec5f56d6c/src/params.ts#L1
    Ok(8)
}

fn get_block_details(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<OtterscanBlockDetails>> {
    let block: u64 = params.one()?;

    let block = node
        .lock()
        .unwrap()
        .get_block_by_view(block)
        .map(OtterscanBlockDetails::from);

    Ok(block)
}

fn get_block_details_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<OtterscanBlockDetails>> {
    let block_hash: H256 = params.one()?;

    let block = node
        .lock()
        .unwrap()
        .get_block_by_hash(Hash(block_hash.0))
        .map(OtterscanBlockDetails::from);

    Ok(block)
}

fn get_block_transactions(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<OtterscanBlockTransactions>> {
    let mut params = params.sequence();
    let block_num: u64 = params.next()?;
    let page_number: usize = params.next()?;
    let page_size: usize = params.next()?;

    let node = node.lock().unwrap();

    let Some(block) = node.get_block_by_view(block_num) else { return Ok(None); };

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

    let full_block = OtterscanBlockWithTransactions {
        transactions,
        block: block.into(),
    };

    Ok(Some(OtterscanBlockTransactions {
        full_block,
        receipts,
    }))
}

/// An [EventListener] which records the creator of a contract.
#[derive(Default)]
pub struct ContractCreatorListener {
    pub contract: H160,
    pub creator: Option<H160>,
}

impl EventListener for ContractCreatorListener {
    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Create {
                caller, address, ..
            } if address == self.contract => {
                self.creator = Some(caller);
            }
            _ => {}
        }
    }
}

fn get_contract_creator(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<OtterscanContractCreator>> {
    let address: H160 = params.one()?;
    let address = Address(address);

    let touched = node.lock().unwrap().get_touched_transactions(address);

    // Perform a linear search over each transaction which touched this address. Replay each one to try and find the
    // transaction which created it. In the future if this is slow, we should consider a smarter search strategy or
    // another index.
    for txn_hash in touched {
        let receipt = node
            .lock()
            .unwrap()
            .get_transaction_receipt(txn_hash)
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;

        let txn = node
            .lock()
            .unwrap()
            .get_transaction_by_hash(txn_hash)
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;

        // Find the view in which this contract was executed. It is one less than the block in the receipt.
        let view = node
            .lock()
            .unwrap()
            .get_block_by_hash(receipt.block_hash)
            .ok_or_else(|| anyhow!("block not found"))?
            .view()
            - 1;

        let mut listener = ContractCreatorListener {
            contract: address.0,
            creator: None,
        };

        // Replay the creation transaction to work out the creator. This is important for contracts which are
        // created by other contracts, for which the creator is not the same as `txn.from_addr`.
        evm::tracing::using(&mut listener, || {
            node.lock().unwrap().call_contract(
                BlockNumber::Number(view),
                txn.from_addr,
                txn.transaction.to_addr,
                txn.transaction.payload,
            )
        })?;

        if let Some(creator) = listener.creator {
            return Ok(Some(OtterscanContractCreator {
                hash: H256(txn_hash.0),
                creator,
            }));
        }
    }

    Ok(None)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrInteger {
    String(String),
    Integer(u64),
}

fn has_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<bool> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let _tag: StringOrInteger = params.next()?;

    let empty = node
        .lock()
        .unwrap()
        .get_account(Address(address))?
        .code
        .is_empty();

    Ok(!empty)
}

fn search_transactions_inner(
    node: &Arc<Mutex<Node>>,
    address: Address,
    block_number: u64,
    page_size: usize,
    reverse: bool,
) -> Result<OtterscanTransactions> {
    let mut touched = node.lock().unwrap().get_touched_transactions(address);

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
        let txn: EthTransaction = get_transaction_inner(hash, &node.lock().unwrap())
            .unwrap()
            .unwrap();
        let txn_block_number = txn.block_number;

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
            .get_block_by_hash(Hash(txn.block_hash.0))
            .unwrap()
            .timestamp();

        transactions.push(txn);

        let node = node.lock().unwrap();
        let receipt = EthTransactionReceiptWithTimestamp {
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

    Ok(OtterscanTransactions {
        transactions,
        receipts,
        first_page,
        last_page,
    })
}

fn search_transactions_after(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<OtterscanTransactions> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let block_number: u64 = params.next()?;
    let page_size: usize = params.next()?;

    search_transactions_inner(node, Address(address), block_number, page_size, false)
}

fn search_transactions_before(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<OtterscanTransactions> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let mut block_number: u64 = params.next()?;
    let page_size: usize = params.next()?;

    // A `block_number` of `0` tells us to search from the most recent block.
    if block_number == 0 {
        block_number = u64::MAX;
    }

    search_transactions_inner(node, Address(address), block_number, page_size, true)
}
