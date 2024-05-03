//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::sync::{Arc, Mutex, MutexGuard};

use alloy_consensus::{TxEip1559, TxEip2930, TxLegacy};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, Parity, Signature, TxKind, B256, U256, U64};
use alloy_rlp::{Decodable, Header};
use anyhow::{anyhow, Result};
use itertools::{Either, Itertools};
use jsonrpsee::{
    core::StringError, types::Params, PendingSubscriptionSink, RpcModule, SubscriptionMessage,
};
use serde::Deserialize;
use tracing::*;

use super::{
    to_hex::ToHex,
    types::eth::{self, CallParams, HashOrTransaction, OneOrMany},
};
use crate::{
    crypto::Hash,
    message::{Block, BlockNumber},
    node::Node,
    transaction::{EvmGas, SignedTransaction, Transaction},
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let mut module = super::declare_module!(
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
            (
                "eth_getTransactionByBlockHashAndIndex",
                get_transaction_by_block_hash_and_index
            ),
            (
                "eth_getTransactionByBlockNumberAndIndex",
                get_transaction_by_block_number_and_index
            ),
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
        call_params.from,
        call_params.to,
        call_params.data.clone(),
        call_params.value.to(),
    )?;

    trace!(
        "Performed eth call. Args: {:?} ie: {:?} {:?} {:?}  ret: {:?}",
        serde_json::to_string(&call_params),
        call_params.from,
        call_params.to,
        call_params.data,
        ret.to_hex()
    );

    Ok(ret.to_hex())
}

fn chain_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().config.eth_chain_id.to_hex())
}

fn estimate_gas(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("estimate_gas: params: {:?}", params);
    let mut params = params.sequence();
    let call_params: CallParams = params.next()?;
    let block_number: BlockNumber = params.next().unwrap_or(BlockNumber::Latest);

    let return_value = node.lock().unwrap().estimate_gas(
        block_number,
        call_params.from,
        call_params.to,
        call_params.data.clone(),
        call_params.gas.map(|g| EvmGas(g.to())),
        call_params.gas_price.map(|g| g.to()),
        call_params.value.to(),
    )?;

    Ok(return_value.to_hex())
}

fn get_balance(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_number: BlockNumber = params.next()?;

    Ok(node
        .lock()
        .unwrap()
        .get_native_balance(address, block_number)?
        .to_hex())
}

fn get_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_code: params: {:?}", params);
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_number: BlockNumber = params.next()?;

    Ok(node
        .lock()
        .unwrap()
        .get_account(address, block_number)?
        .contract
        .evm_code()
        .unwrap_or_default()
        .to_hex())
}

fn get_storage_at(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_storage_at: params: {:?}", params);
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let position: U256 = params.next()?;
    let position = B256::new(position.to_be_bytes());
    let block_number: BlockNumber = params.next()?;

    let value = node
        .lock()
        .unwrap()
        .get_account_storage(address, position, block_number)?;

    Ok(value.to_hex())
}

fn get_transaction_count(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    trace!("get_transaction_count: params: {:?}", params);
    let mut params = params.sequence();
    let address: Address = params.next()?;
    let block_number: BlockNumber = params.next()?;

    trace!(
        "get_transaction_count resp: {:?}",
        node.lock()
            .unwrap()
            .get_account(address, block_number)?
            .nonce
            .to_hex()
    );

    Ok(node
        .lock()
        .unwrap()
        .get_account(address, block_number)?
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
    let hash: B256 = params.next()?;
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
        let miner = node.get_proposer_reward_address(block.header)?;
        Ok(eth::Block::from_block(block, miner.unwrap_or_default()))
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
        let block = eth::Block::from_block(block, miner.unwrap_or_default());
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
    let hash: B256 = params.one()?;

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
    address: Option<OneOrMany<Address>>,
    /// Topics matches a prefix of the list of topics from each log. An empty element slice matches any topic. Non-empty
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
                .filter_map(|l| l.into_evm())
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

    let node = node.lock().unwrap();

    let Some(block) = node.get_block_by_hash(Hash(block_hash.0))? else {
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
    let block_number: BlockNumber = params.next()?;
    let index: U64 = params.next()?;

    let node = node.lock().unwrap();

    let Some(block) = node.get_block_by_blocknum(block_number)? else {
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
        Transaction::Legacy(_)
        | Transaction::Eip2930(_)
        | Transaction::Zilliqa(_)
        | Transaction::Intershard(_) => (transaction.max_fee_per_gas(), None, None),
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
        from,
        gas: transaction.gas_limit(),
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        hash: hash.into(),
        input: transaction.payload().to_vec(),
        nonce: transaction.nonce().unwrap_or(u64::MAX),
        to: transaction.to_addr(),
        transaction_index: block
            .map(|b| b.transactions.iter().position(|t| *t == hash).unwrap() as u64),
        value: transaction.amount(),
        v,
        r,
        s,
        chain_id: transaction.chain_id(),
        access_list: transaction.access_list().map(|a| a.to_vec()),
        transaction_type: match transaction {
            Transaction::Legacy(_) => 0,
            Transaction::Eip2930(_) => 1,
            Transaction::Eip1559(_) => 2,
            // Set Zilliqa transaction types to a unique number. This is "ZIL" encoded in ASCII.
            Transaction::Zilliqa(_) => 90_73_76,
            // Set intershard transactions as unique, too. This is ZIL + 1.
            Transaction::Intershard(_) => 90_73_77,
        },
    };

    Ok(Some(transaction))
}

pub(super) fn get_transaction_receipt_inner(
    hash: Hash,
    node: &MutexGuard<Node>,
) -> Result<Option<eth::TransactionReceipt>> {
    let Some(signed_transaction) = dbg!(node.get_transaction_by_hash(hash))? else {
        warn!("Failed to get TX by hash when getting TX receipt! {}", hash);
        return Ok(None);
    };
    // TODO: Return error if receipt or block does not exist.

    let Some(receipt) = dbg!(node.get_transaction_receipt(hash))? else {
        warn!("Failed to get TX receipt when getting TX receipt! {}", hash);
        return Ok(None);
    };

    info!(
        "get_transaction_receipt_inner: hash: {:?} result: {:?}",
        hash, receipt
    );

    let Some(block) = dbg!(node.get_block_by_hash(receipt.block_hash))? else {
        warn!("Failed to get block when getting TX receipt! {}", hash);
        return Ok(None);
    };

    let transaction_index = block.transactions.iter().position(|t| *t == hash).unwrap();

    let mut logs_bloom = [0; 256];

    let logs = receipt
        .logs
        .into_iter()
        // Filter non-EVM logs out. TODO: Encode Scilla logs and don't filter them.
        .filter_map(|log| log.into_evm())
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
        transaction_hash: hash.into(),
        transaction_index: transaction_index as u64,
        block_hash: block.hash().into(),
        block_number: block.number(),
        from,
        to: transaction.to_addr(),
        cumulative_gas_used: EvmGas(0),
        effective_gas_price: 0,
        gas_used: receipt.gas_used,
        contract_address: receipt.contract_address,
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
    let chain_id = node.lock().unwrap().config.eth_chain_id;
    let transaction = parse_transaction(&transaction)?;

    if let Some(c) = transaction.chain_id() {
        if c != chain_id {
            return Err(anyhow!("invalid chain ID, expected: {chain_id}, got: {c}"));
        }
    }

    let transaction_hash = B256::from(node.lock().unwrap().create_transaction(transaction)?);

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
    let mut bytes = Header::decode_bytes(&mut buf, true)?;

    let nonce = u64::decode(&mut bytes)?;
    let gas_price = u128::decode(&mut bytes)?;
    let gas_limit = u128::decode(&mut bytes)?;
    let to = TxKind::decode(&mut bytes)?;
    let value = U256::decode(&mut bytes)?;
    let input = Bytes::decode(&mut bytes)?;
    let v = u64::decode(&mut bytes)?;
    let r = U256::decode(&mut bytes)?;
    let s = U256::decode(&mut bytes)?;

    let sig = Signature::from_rs_and_parity(r, s, v)?;

    let tx = TxLegacy {
        chain_id: sig.v().chain_id(),
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        input,
    };

    Ok(SignedTransaction::Legacy { tx, sig })
}

fn parse_eip2930_transaction(mut buf: &[u8]) -> Result<SignedTransaction> {
    let mut bytes = Header::decode_bytes(&mut buf, true)?;

    let chain_id = u64::decode(&mut bytes)?;
    let nonce = u64::decode(&mut bytes)?;
    let gas_price = u128::decode(&mut bytes)?;
    let gas_limit = u128::decode(&mut bytes)?;
    let to = TxKind::decode(&mut bytes)?;
    let value = U256::decode(&mut bytes)?;
    let input = Bytes::decode(&mut bytes)?;
    let access_list = AccessList::decode(&mut bytes)?;
    let y_is_odd = bool::decode(&mut bytes)?;
    let r = U256::decode(&mut bytes)?;
    let s = U256::decode(&mut bytes)?;

    let sig = Signature::from_rs_and_parity(r, s, Parity::Parity(y_is_odd))?;

    let tx = TxEip2930 {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        input,
        access_list,
    };

    Ok(SignedTransaction::Eip2930 { tx, sig })
}

fn parse_eip1559_transaction(mut buf: &[u8]) -> Result<SignedTransaction> {
    let mut bytes = Header::decode_bytes(&mut buf, true)?;

    let chain_id = u64::decode(&mut bytes)?;
    let nonce = u64::decode(&mut bytes)?;
    let max_priority_fee_per_gas = u128::decode(&mut bytes)?;
    let max_fee_per_gas = u128::decode(&mut bytes)?;
    let gas_limit = u128::decode(&mut bytes)?;
    let to = TxKind::decode(&mut bytes)?;
    let value = U256::decode(&mut bytes)?;
    let input = Bytes::decode(&mut bytes)?;
    let access_list = AccessList::decode(&mut bytes)?;
    let y_is_odd = bool::decode(&mut bytes)?;
    let r = U256::decode(&mut bytes)?;
    let s = U256::decode(&mut bytes)?;

    let sig = Signature::from_rs_and_parity(r, s, Parity::Parity(y_is_odd))?;

    let tx = TxEip1559 {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        input,
        access_list,
    };

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

fn syncing(_: Params, _: &Arc<Mutex<Node>>) -> Result<bool> {
    Ok(false)
}

fn net_peer_count(_: Params, _: &Arc<Mutex<Node>>) -> Result<String> {
    Ok("0x0".to_string())
}

fn net_listening(_: Params, _: &Arc<Mutex<Node>>) -> Result<bool> {
    Ok(true)
}

#[allow(clippy::redundant_allocation)]
async fn subscribe(
    params: Params<'_>,
    pending: PendingSubscriptionSink,
    node: Arc<Arc<Mutex<Node>>>,
) -> Result<(), StringError> {
    let mut params = params.sequence();
    let kind: String = params.next()?;

    match kind.as_str() {
        "newHeads" => {
            let sink = pending.accept().await?;
            let mut new_blocks = node.lock().unwrap().subscribe_to_new_blocks();

            while let Ok(header) = new_blocks.recv().await {
                let miner = node.lock().unwrap().get_proposer_reward_address(header)?;
                let header = eth::Header::from_header(header, miner.unwrap_or_default());
                let _ = sink.send(SubscriptionMessage::from_json(&header)?).await;
            }
        }
        //"logs" => {},
        //"newPendingTransactions" => {},
        _ => {
            return Err("invalid subscription kind".into());
        }
    }

    Ok(())
}
