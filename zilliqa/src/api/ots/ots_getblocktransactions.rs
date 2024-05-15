use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use jsonrpsee::types::Params;

use crate::api::{
    eth::{get_transaction_inner, get_transaction_receipt_inner},
    types::ots::{self},
};
use crate::node::Node;

pub(crate) fn get_block_transactions(
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
