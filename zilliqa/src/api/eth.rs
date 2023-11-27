//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{anyhow, Result};
use itertools::{Either, Itertools};
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::{H160, H256, U256};
use rlp::Rlp;
use serde::Deserialize;
use tracing::*;

use super::{
    to_hex::ToHex,
    types::eth::{self, CallParams, EstimateGasParams, HashOrTransaction, OneOrMany},
};
use crate::{
    crypto::Hash,
    message::{Block, BlockNumber},
    node::Node,
    state::Address,
    transaction::{EthSignature, SignedTransaction, Transaction, TxEip1559, TxEip2930, TxLegacy},
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    super::declare_module!(
        node,
        [
            ("eth_accounts", accounts),
            ("eth_blockNumber", block_number),
            ("eth_call", call),
            ("eth_chainId", chain_id),
            ("eth_estimateGas", estimate_gas),
            ("eth_getBalance", get_balance),
            ("eth_getCode", get_code),
            ("eth_getStorageAt", get_storage_at),
            ("eth_getTransactionCount", get_transaction_count),
            ("eth_gasPrice", get_gas_price),
            ("eth_getBlockByNumber", get_block_by_number),
            ("eth_getBlockByHash", get_block_by_hash),
            (
                "eth_getBlockTransactionCountByHash",
                get_block_transaction_count_by_hash
            ),
            (
                "eth_getBlockTransactionCountByNumber",
                get_block_transaction_count_by_number
            ),
            ("eth_getLogs", get_logs),
            ("eth_getTransactionByHash", get_transaction_by_hash),
            ("eth_getTransactionReceipt", get_transaction_receipt),
            ("eth_sendRawTransaction", send_raw_transaction),
            ("eth_getUncleCountByBlockHash", get_uncle_count),
            ("eth_getUncleCountByBlockNumber", get_uncle_count),
            ("eth_getUncleByBlockHashAndIndex", get_uncle),
            ("eth_getUncleByBlockNumberAndIndex", get_uncle),
            ("eth_mining", mining),
            ("eth_protocolVersion", protocol_version),
            ("eth_syncing", syncing),
            ("net_peerCount", net_peer_count),
            ("net_listening", net_listening),
        ],
    )
}

fn accounts(_: Params, _: &Arc<Mutex<Node>>) -> Result<[(); 0]> {
    Ok([])
}

fn block_number(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().number().to_hex())
}

fn call(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("call: params: {:?}", params);
    let mut params = params.sequence();
    let call_params: CallParams = params.next()?;
    let block_number: BlockNumber = params.next()?;

    let ret = node.lock().unwrap().call_contract(
        block_number,
        Address(call_params.from),
        call_params.to.map(Address),
        call_params.data.clone(),
        U256::from(call_params.value),
        false,
    )?;

    trace!(
        "Performed eth call. Args: {:?} ie: {:?} {:?} {:?}  ret: {:?}",
        serde_json::to_string(&call_params),
        call_params.from,
        call_params.to,
        call_params.data,
        ret.return_value.to_hex()
    );

    Ok(ret.return_value.to_hex())
}

fn chain_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().config.eth_chain_id.to_hex())
}

fn estimate_gas(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("estimate_gas: params: {:?}", params);
    let mut params = params.sequence();
    let call_params: EstimateGasParams = params.next()?;
    let block_number: BlockNumber = params.next().unwrap_or(BlockNumber::Latest);

    let return_value = node.lock().unwrap().estimate_gas(
        block_number,
        call_params.from,
        call_params.to,
        call_params.data.clone(),
        call_params.gas,
        call_params.gas_price,
        call_params.value,
    )?;

    Ok(return_value.to_hex())
}

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let block_number: BlockNumber = params.next()?;

    Ok(node
        .lock()
        .unwrap()
        .get_native_balance(Address(address), block_number)?
        .to_hex())
}

fn get_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_code: params: {:?}", params);
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let block_number: BlockNumber = params.next()?;

    Ok(node
        .lock()
        .unwrap()
        .get_account(Address(address), block_number)?
        .code
        .to_hex())
}

fn get_storage_at(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_storage_at: params: {:?}", params);
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let position: U256 = params.next()?;
    let block_number: BlockNumber = params.next()?;

    let mut position_bytes = [0; 32];
    position.to_big_endian(&mut position_bytes);
    let position = H256::from_slice(&position_bytes);

    let value =
        node.lock()
            .unwrap()
            .get_account_storage(Address(address), position, block_number)?;

    Ok(value.to_hex())
}

fn get_transaction_count(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_transaction_count: params: {:?}", params);
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let block_number: BlockNumber = params.next()?;

    trace!(
        "get_transaction_count resp: {:?}",
        node.lock()
            .unwrap()
            .get_account(Address(address), block_number)?
            .nonce
            .to_hex()
    );

    Ok(node
        .lock()
        .unwrap()
        .get_account(Address(address), block_number)?
        .nonce
        .to_hex())
}

fn get_gas_price(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().get_gas_price().to_hex())
}

fn get_block_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let block_number: BlockNumber = params.next()?;
    let full: bool = params.next()?;

    let node = node.lock().unwrap();
    let block = node.get_block_by_blocknum(block_number)?;

    let block = block.map(|b| convert_block(&node, &b, full)).transpose()?;

    Ok(block)
}

fn get_block_by_hash(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<eth::Block>> {
    let mut params = params.sequence();
    let hash: H256 = params.next()?;
    let full: bool = params.next()?;

    let node = node.lock().unwrap();
    let block = node
        .get_block_by_hash(Hash(hash.0))?
        .map(|b| convert_block(&node, &b, full))
        .transpose()?;

    Ok(block)
}

fn convert_block(node: &MutexGuard<Node>, block: &Block, full: bool) -> Result<eth::Block> {
    if !full {
        Ok(block.into())
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
        Ok(eth::Block {
            transactions,
            ..block.into()
        })
    }
}

fn get_block_transaction_count_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<String>> {
    let hash: H256 = params.one()?;

    let node = node.lock().unwrap();
    let block = node.get_block_by_hash(Hash(hash.0))?;

    Ok(block.map(|b| b.transactions.len().to_hex()))
}

fn get_block_transaction_count_by_number(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<String>> {
    let block_number: BlockNumber = params.one()?;

    let node = node.lock().unwrap();
    let block = node.get_block_by_blocknum(block_number)?;

    Ok(Some(
        block.map_or(0, |block| block.transactions.len()).to_hex(),
    ))
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct GetLogsParams {
    from_block: Option<BlockNumber>,
    to_block: Option<BlockNumber>,
    address: Option<OneOrMany<H160>>,
    /// Topics matches a prefix of the list of topics from each log. An empty element slice matches any topic. Non-empty
    /// elements represent an alternative that matches any of the contained topics.
    ///
    /// Examples (from Erigon):
    /// * `[]`                          matches any topic list
    /// * `[[A]]`                       matches topic A in first position
    /// * `[[], [B]]` or `[None, [B]]`  matches any topic in first position AND B in second position
    /// * `[[A], [B]]`                  matches topic A in first position AND B in second position
    /// * `[[A, B], [C, D]]`            matches topic (A OR B) in first position AND (C OR D) in second position
    topics: Vec<OneOrMany<H256>>,
    block_hash: Option<H256>,
}

fn get_logs(params: Params, node: &Arc<Mutex<Node>>) -> Result<Vec<eth::Log>> {
    let params: GetLogsParams = params.one()?;

    let node = node.lock().unwrap();

    // Find the range of blocks we care about. This is an iterator of blocks.
    let blocks = match (params.block_hash, params.from_block, params.to_block) {
        (Some(block_hash), None, None) => Either::Left(std::iter::once(Ok(node
            .get_block_by_hash(Hash(block_hash.0))?
            .ok_or_else(|| anyhow!("block not found"))?))),
        (None, from, to) => {
            let from = node.get_number(from.unwrap_or(BlockNumber::Latest));
            let to = node.get_number(to.unwrap_or(BlockNumber::Latest));

            if from > to {
                return Err(anyhow!("`from` is greater than `to` ({from} > {to})"));
            }

            Either::Right((from..=to).map(|number| {
                node.get_block_by_number(number)?
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

fn get_transaction_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::Transaction>> {
    trace!("get_transaction_by_hash: params: {:?}", params);
    let hash: H256 = params.one()?;
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
        node.get_block_by_hash(receipt.block_hash)?
    } else {
        // Even if it has not been mined, the tx may still be in the mempool and should return
        // a correct tx, with pending/null fields
        None
    };

    let from = tx.signer;
    let v = tx.tx.sig_v();
    let r = tx.tx.sig_r();
    let s = tx.tx.sig_s();
    let transaction = tx.tx.into_transaction();
    let (gas_price, max_fee_per_gas, max_priority_fee_per_gas) = match transaction {
        Transaction::Legacy(_) | Transaction::Eip2930(_) | Transaction::Zilliqa(_) => {
            (transaction.max_fee_per_gas(), None, None)
        }
        Transaction::Eip1559(TxEip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            ..
        }) => (
            // The `gasPrice` for EIP-1559 transactions should be set to the effective gas price of this transaction,
            // which depends on the block's base fee. We don't yet have a base fee so we just set it to the max fee
            // per gas.
            max_fee_per_gas,
            Some(max_fee_per_gas),
            Some(max_priority_fee_per_gas),
        ),
    };
    let transaction = eth::Transaction {
        block_hash: block.as_ref().map(|b| b.hash().0.into()),
        block_number: block.as_ref().map(|b| b.number()),
        from: from.0,
        gas: 0,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        hash: H256(hash.0),
        input: transaction.payload().to_vec(),
        nonce: transaction.nonce(),
        to: transaction.to_addr().map(|a| a.0),
        transaction_index: block
            .map(|b| b.transactions.iter().position(|t| *t == hash).unwrap() as u64),
        value: transaction.amount(),
        v,
        r,
        s,
        chain_id: transaction.chain_id(),
        access_list: transaction
            .access_list()
            .map(|a| a.iter().map(|(a, s)| (a.0, s.clone())).collect()),
        transaction_type: match transaction {
            Transaction::Legacy(_) => 0,
            Transaction::Eip2930(_) => 1,
            Transaction::Eip1559(_) => 2,
            // Set Zilliqa transaction types to a unique number. This is "ZIL" encoded in ASCII.
            Transaction::Zilliqa(_) => 90_73_76,
        },
    };

    Ok(Some(transaction))
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
        warn!("Failed to get TX receipt when getting TX receipt! {}", hash);
        return Ok(None);
    };

    info!(
        "get_transaction_receipt_inner: hash: {:?} result: {:?}",
        hash, receipt
    );

    let Some(block) = node.get_block_by_hash(receipt.block_hash)? else {
        warn!("Failed to get block when getting TX receipt! {}", hash);
        return Ok(None);
    };

    let transaction_index = block.transactions.iter().position(|t| *t == hash).unwrap();

    let mut logs_bloom = [0; 256];

    let logs = receipt
        .logs
        .into_iter()
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
    let transaction = signed_transaction.tx.into_transaction();
    let receipt = eth::TransactionReceipt {
        transaction_hash: H256(hash.0),
        transaction_index: transaction_index as u64,
        block_hash: H256(block.hash().0),
        block_number: block.number(),
        from: from.0,
        to: transaction.to_addr().map(|a| a.0),
        cumulative_gas_used: 0,
        effective_gas_price: 0,
        gas_used: 1,
        contract_address: receipt.contract_address.map(|a| a.0),
        logs,
        logs_bloom,
        ty: 0,
        status: receipt.success,
    };

    Ok(Some(receipt))
}

fn get_transaction_receipt(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<eth::TransactionReceipt>> {
    trace!("get_transaction_receipt: params: {:?}", params);
    let hash: H256 = params.one()?;
    let hash: Hash = Hash(hash.0);
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
    let chain_id = node.lock().unwrap().config.eth_chain_id;
    let transaction = parse_transaction(&transaction)?;

    if let Some(c) = transaction.chain_id() {
        if c != chain_id {
            return Err(anyhow!("invalid chain ID, expected: {chain_id}, got: {c}"));
        }
    }

    let transaction_hash = H256(node.lock().unwrap().create_transaction(transaction)?.0);

    Ok(transaction_hash.to_hex())
}

fn parse_transaction(bytes: &[u8]) -> Result<SignedTransaction> {
    // https://eips.ethereum.org/EIPS/eip-2718#backwards-compatibility
    // "Clients can differentiate between the legacy transactions and typed transactions by looking at the first byte.
    // If it starts with a value in the range [0, 0x7f] then it is a new transaction type, if it starts with a value in
    // the range [0xc0, 0xfe] then it is a legacy transaction type."
    match bytes[0] {
        0xc0..=0xfe => parse_legacy_transaction(Rlp::new(bytes)),
        0x01 => parse_eip2930_transaction(Rlp::new(&bytes[1..])),
        0x02 => parse_eip1559_transaction(Rlp::new(&bytes[1..])),
        _ => Err(anyhow!(
            "invalid transaction with starting byte {}",
            bytes[0]
        )),
    }
}

fn parse_legacy_transaction(rlp: Rlp<'_>) -> Result<SignedTransaction> {
    let nonce = rlp.val_at(0)?;
    let gas_price = rlp.val_at(1)?;
    let gas_limit = rlp.val_at(2)?;
    let to_addr = rlp.val_at::<Vec<u8>>(3)?;
    let amount = rlp.val_at(4)?;
    let payload = rlp.val_at(5)?;
    let v = rlp.val_at::<u64>(6)?;
    let r = left_pad_arr(&rlp.val_at::<Vec<_>>(7)?)?;
    let s = left_pad_arr(&rlp.val_at::<Vec<_>>(8)?)?;

    // If `v` is greater than `35`, then this is an EIP-155 value which includes the chain ID. If not, it must
    // be set to either `27` or `28`.
    let (y_is_odd, chain_id) = if v >= 35 {
        // The last bit of `v - 35` tells us whether Y is odd; the other bits tell us the chain ID.
        ((v - 35) % 2 != 0, Some((v - 35) / 2))
    } else if v == 27 {
        (false, None)
    } else if v == 28 {
        (true, None)
    } else {
        return Err(anyhow!("invalid signature with v={v}"));
    };

    let sig = EthSignature { r, s, y_is_odd };

    let tx = TxLegacy {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to_addr: (!to_addr.is_empty()).then_some(Address::from_slice(&to_addr)),
        amount,
        payload,
    };

    Ok(SignedTransaction::Legacy { tx, sig })
}

fn parse_eip2930_transaction(rlp: Rlp<'_>) -> Result<SignedTransaction> {
    let chain_id = rlp.val_at(0)?;
    let nonce = rlp.val_at(1)?;
    let gas_price = rlp.val_at(2)?;
    let gas_limit = rlp.val_at(3)?;
    let to_addr = rlp.val_at::<Vec<u8>>(4)?;
    let amount = rlp.val_at(5)?;
    let payload = rlp.val_at(6)?;
    let access_list = rlp
        .at(7)?
        .iter()
        .map(|rlp| Ok((rlp.val_at::<H160>(0)?, rlp.list_at::<H256>(1)?)))
        .collect::<Result<Vec<_>>>()?;
    let y_is_odd = rlp.val_at::<bool>(8)?;
    let r = left_pad_arr(&rlp.val_at::<Vec<_>>(9)?)?;
    let s = left_pad_arr(&rlp.val_at::<Vec<_>>(10)?)?;

    let sig = EthSignature { r, s, y_is_odd };

    let tx = TxEip2930 {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to_addr: (!to_addr.is_empty()).then_some(Address::from_slice(&to_addr)),
        amount,
        payload,
        access_list: access_list
            .into_iter()
            .map(|(a, s)| (Address(a), s))
            .collect(),
    };

    Ok(SignedTransaction::Eip2930 { tx, sig })
}

fn parse_eip1559_transaction(rlp: Rlp<'_>) -> Result<SignedTransaction> {
    let chain_id = rlp.val_at(0)?;
    let nonce = rlp.val_at(1)?;
    let max_priority_fee_per_gas = rlp.val_at(2)?;
    let max_fee_per_gas = rlp.val_at(3)?;
    let gas_limit = rlp.val_at(4)?;
    let to_addr = rlp.val_at::<Vec<u8>>(5)?;
    let amount = rlp.val_at(6)?;
    let payload = rlp.val_at(7)?;
    let access_list = rlp
        .at(8)?
        .iter()
        .map(|rlp| Ok((rlp.val_at::<H160>(0)?, rlp.list_at::<H256>(1)?)))
        .collect::<Result<Vec<_>>>()?;
    let y_is_odd = rlp.val_at::<bool>(9)?;
    let r = left_pad_arr(&rlp.val_at::<Vec<_>>(10)?)?;
    let s = left_pad_arr(&rlp.val_at::<Vec<_>>(11)?)?;

    let sig = EthSignature { r, s, y_is_odd };

    let tx = TxEip1559 {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to_addr: (!to_addr.is_empty()).then_some(Address::from_slice(&to_addr)),
        amount,
        payload,
        access_list: access_list
            .into_iter()
            .map(|(a, s)| (Address(a), s))
            .collect(),
    };

    Ok(SignedTransaction::Eip1559 { tx, sig })
}

fn left_pad_arr<const N: usize>(v: &[u8]) -> Result<[u8; N]> {
    let mut arr = [0; N];

    if v.len() > arr.len() {
        return Err(anyhow!(
            "invalid length: {}, expected: {}",
            v.len(),
            arr.len()
        ));
    }

    if !v.is_empty() && v[0] == 0 {
        return Err(anyhow!("unnecessary leading zero"));
    }

    let start = arr.len() - v.len();
    arr[start..].copy_from_slice(v);
    Ok(arr)
}

// These are no-ops basically
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

fn syncing(_: Params, _: &Arc<Mutex<Node>>) -> Result<bool> {
    Ok(false)
}

fn net_peer_count(_: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok("0x0".to_string())
}

fn net_listening(_: Params, _: &Arc<Mutex<Node>>) -> Result<bool> {
    Ok(true)
}

#[cfg(test)]
mod tests {
    use primitive_types::U256;

    use crate::{
        api::eth::{left_pad_arr, parse_transaction},
        crypto::Hash,
        state::Address,
        transaction::{EthSignature, SignedTransaction, TxLegacy, VerifiedTransaction},
    };

    #[test]
    fn test_transaction_from_rlp() {
        // From https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#example
        let transaction = hex::decode("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83").unwrap();
        let signed_tx = parse_transaction(&transaction).unwrap();
        let recovered_tx = signed_tx.verify().unwrap();
        let expected = VerifiedTransaction {
            tx: SignedTransaction::Legacy {
                tx: TxLegacy {
                    chain_id: Some(1),
                    nonce: 9,
                    gas_price: 20 * 10_u128.pow(9),
                    gas_limit: 21000u64,
                    to_addr: Some(Address("0x3535353535353535353535353535353535353535".parse().unwrap())),
                    amount: 10u128.pow(18),
                    payload: Vec::new(),
                },
                sig: EthSignature {
                    r: U256::from_dec_str("18515461264373351373200002665853028612451056578545711640558177340181847433846").unwrap().into(),
                    s: U256::from_dec_str("46948507304638947509940763649030358759909902576025900602547168820602576006531").unwrap().into(),
                    y_is_odd: false,
                },
            },
            signer: Address("0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F".parse().unwrap()),
            hash: Hash::from_bytes(hex::decode("33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788").unwrap()).unwrap(),
        };
        assert_eq!(recovered_tx, expected);
    }

    #[test]
    fn test_left_pad_arr() {
        let cases = [
            ("", Ok([0; 4])),
            ("01", Ok([0, 0, 0, 1])),
            ("ffffffff", Ok([255; 4])),
            ("ffffffffff", Err("invalid length: 5, expected: 4")),
            ("0001", Err("unnecessary leading zero")),
        ];

        for (val, expected) in cases {
            let vec = hex::decode(val).unwrap();
            let actual = left_pad_arr(&vec);

            match (expected, actual) {
                (Ok(e), Ok(a)) => assert_eq!(e, a),
                (Err(e), Err(a)) => assert_eq!(e, a.to_string()),
                _ => panic!("case failed: {val}"),
            }
        }
    }
}
