use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::{H160, H256};

use super::{
    eth::{get_transaction_inner, get_transaction_receipt_inner},
    types::ots,
};
use crate::{crypto::Hash, message::BlockNumber, node::Node};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("ots_getApiLevel", get_otterscan_api_level),
            ("ots_getBlockDetails", get_block_details),
            ("ots_getBlockDetailsByHash", get_block_details_by_hash),
            ("ots_getBlockTransactions", get_block_transactions),
            ("ots_hasCode", has_code),
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
    let miner = node.lock().unwrap().get_proposer_reward_address(block)?;

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
    let miner = node.lock().unwrap().get_proposer_reward_address(block)?;

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

    let mut node = node.lock().unwrap();

    let Some(block) = node.get_block_by_number(block_num)? else {
        return Ok(None);
    };
    let miner = node.get_proposer_reward_address(&block)?;

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

fn has_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<bool> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let block_number: BlockNumber = params.next()?;

    let empty = node
        .lock()
        .unwrap()
        .get_account(address, block_number)?
        .code
        .is_empty();

    Ok(!empty)
}
