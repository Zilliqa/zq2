use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Result};
use cita_trie::DB;
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::H256;

use crate::{crypto::Hash, node::Node};

use super::{
    eth::EthRpc,
    types::{OtterscanBlockDetails, OtterscanBlockTransactions, OtterscanBlockWithTransactions},
};

pub fn rpc_module<D: DB>(node: Arc<Mutex<Node<D>>>) -> RpcModule<Arc<Mutex<Node<D>>>> {
    super::declare_module!(
        node,
        D,
        [
            ("ots_getApiLevel", OtsRpc::get_otterscan_api_level),
            ("ots_getBlockDetails", OtsRpc::get_block_details),
            (
                "ots_getBlockDetailsByHash",
                OtsRpc::get_block_details_by_hash
            ),
            ("ots_getBlockTransactions", OtsRpc::get_block_transactions),
        ],
    )
}

struct OtsRpc<'a, D: DB> {
    phantom_db: PhantomData<&'a D>,
}
impl<D: DB> OtsRpc<'_, D> {
    fn get_otterscan_api_level(_: Params, _: &Arc<Mutex<Node<D>>>) -> Result<u64> {
        // https://github.com/otterscan/otterscan/blob/0a819f3557fe19c0f47327858261881ec5f56d6c/src/params.ts#L1
        Ok(8)
    }

    fn get_block_details(
        params: Params,
        node: &Arc<Mutex<Node<D>>>,
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
        node: &Arc<Mutex<Node<D>>>,
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
        node: &Arc<Mutex<Node<D>>>,
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
            let txn = EthRpc::get_transaction_inner(*hash, &node)?
                .ok_or_else(|| anyhow!("transaction not found: {hash}"))?;
            let receipt = EthRpc::get_transaction_receipt_inner(*hash, &node)?
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
}
