//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use primitive_types::{H160, H256, U256};
use rlp::Rlp;
use tracing::info;

use tracing::log::trace;

use crate::{
    crypto::Hash,
    message::{Block, BlockNumber},
    node::Node,
    state::{Address, SignedTransaction, SigningInfo, Transaction},
};

use super::{
    to_hex::ToHex,
    types::{
        CallParams, EstimateGasParams, EthBlock, EthTransaction, EthTransactionReceipt,
        HashOrTransaction, Log,
    },
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
    if let Some(block) = node.lock().unwrap().view().checked_sub(1) {
        Ok(block.to_hex())
    } else {
        Err(anyhow!("no blocks"))
    }
}

fn call(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let call_params: CallParams = params.next()?;
    let block_number: BlockNumber = params.next()?;

    let return_value = node.lock().unwrap().call_contract(
        block_number,
        Address(call_params.from),
        call_params.to.map(Address),
        call_params.data.clone(),
    )?;

    trace!(
        "Performed eth call. Args: {:?} ie: {:?} {:?} {:?}  ret: {:?}",
        serde_json::to_string(&call_params),
        call_params.from,
        call_params.to,
        call_params.data,
        return_value.to_hex()
    );

    Ok(return_value.to_hex())
}

fn chain_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().config.eth_chain_id.to_hex())
}

fn estimate_gas(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
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
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let block_number: BlockNumber = params.next()?;

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

fn get_block_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<EthBlock>> {
    let mut params = params.sequence();
    let block_number: BlockNumber = params.next()?;
    let full: bool = params.next()?;

    let node = node.lock().unwrap();
    let block = node.get_block_by_number(block_number)?;

    let block = block.map(|b| convert_block(&node, &b, full)).transpose()?;

    Ok(block)
}

fn get_block_by_hash(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<EthBlock>> {
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

fn convert_block(node: &MutexGuard<Node>, block: &Block, full: bool) -> Result<EthBlock> {
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
        Ok(EthBlock {
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
    let block = match block_number {
        BlockNumber::Number(number) => node.get_block_by_view(number),
        BlockNumber::Earliest => node.get_block_by_view(0),
        BlockNumber::Latest => node.get_latest_block(),
        _ => {
            return Err(anyhow!("unsupported block number: {block_number:?}"));
        }
    }?;

    Ok(block.map(|b| b.transactions.len().to_hex()))
}

fn get_transaction_by_hash(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<EthTransaction>> {
    let hash: H256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let node = node.lock().unwrap();

    get_transaction_inner(hash, &node)
}

pub(super) fn get_transaction_inner(
    hash: Hash,
    node: &MutexGuard<Node>,
) -> Result<Option<EthTransaction>> {
    let Some(signed_transaction) = node.get_transaction_by_hash(hash)? else { return Ok(None); };

    // The block can either be null or some based on whether the tx exists
    let block = if let Some(receipt) = node.get_transaction_receipt(hash)? {
        node.get_block_by_hash(receipt.block_hash)?
    } else {
        // Even if it has not been mined, the tx may still be in the mempool and should return
        // a correct tx, with pending/null fields
        None
    };

    let transaction = signed_transaction.transaction;
    let (v, r, s) = match signed_transaction.signing_info {
        SigningInfo::Eth {
            v,
            r,
            s,
            chain_id: _,
        } => (v, r, s),
    };
    let transaction = EthTransaction {
        block_hash: block.as_ref().map(|b| b.hash().0.into()),
        block_number: block.as_ref().map(|b| b.view()),
        from: signed_transaction.from_addr.0,
        gas: 0,
        gas_price: transaction.gas_price,
        hash: H256(hash.0),
        input: transaction.payload.clone(),
        nonce: transaction.nonce,
        to: transaction.to_addr.map(|a| a.0),
        transaction_index: block
            .map(|b| b.transactions.iter().position(|t| *t == hash).unwrap() as u64),
        value: transaction.amount,
        v,
        r,
        s,
    };

    Ok(Some(transaction))
}

pub(super) fn get_transaction_receipt_inner(
    hash: Hash,
    node: &MutexGuard<Node>,
) -> Result<Option<EthTransactionReceipt>> {
    let Some(signed_transaction) = node.get_transaction_by_hash(hash)? else { return Ok(None); };
    // TODO: Return error if receipt or block does not exist.

    let Some(receipt) = node.get_transaction_receipt(hash)? else { return Ok(None); };

    info!(
        "get_transaction_receipt_inner: hash: {:?} result: {:?}",
        hash, receipt
    );

    let Some(block) = node.get_block_by_hash(receipt.block_hash)? else { return Ok(None); };

    let transaction_hash = H256(hash.0);
    let transaction_index = block.transactions.iter().position(|t| *t == hash).unwrap() as u64;
    let block_hash = H256::from_slice(block.hash().as_bytes());
    let block_number = block.view();

    let mut logs_bloom = [0; 256];

    let logs = receipt
        .logs
        .into_iter()
        .enumerate()
        .map(|(log_index, log)| {
            let log = Log {
                removed: false,
                log_index: log_index as u64,
                transaction_index,
                transaction_hash,
                block_hash,
                block_number,
                address: log.address,
                data: log.data,
                topics: log.topics,
            };

            log.bloom(&mut logs_bloom);

            log
        })
        .collect();

    let transaction = signed_transaction.transaction;
    let receipt = EthTransactionReceipt {
        transaction_hash,
        transaction_index,
        block_hash,
        block_number,
        from: signed_transaction.from_addr.0,
        to: transaction.to_addr.map(|a| a.0),
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
) -> Result<Option<EthTransactionReceipt>> {
    let hash: H256 = params.one()?;
    let hash: Hash = Hash(hash.0);
    let node = node.lock().unwrap();
    get_transaction_receipt_inner(hash, &node)
}

fn send_raw_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let transaction: String = params.one()?;
    let transaction = transaction
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let transaction = hex::decode(transaction)?;
    let chain_id = node.lock().unwrap().config.eth_chain_id;
    let transaction = transaction_from_rlp(&transaction, chain_id)?;

    let transaction_hash = H256(node.lock().unwrap().create_transaction(transaction)?.0);

    Ok(transaction_hash.to_hex())
}

/// Decode a transaction from its RLP-encoded form.
fn transaction_from_rlp(bytes: &[u8], chain_id: u64) -> Result<SignedTransaction> {
    let rlp = Rlp::new(bytes);
    let nonce = rlp.val_at(0)?;
    let gas_price = rlp.val_at(1)?;
    let gas_limit = rlp.val_at(2)?;
    let to_addr = rlp.val_at::<Vec<u8>>(3)?;
    let amount = rlp.val_at(4)?;
    let payload = rlp.val_at(5)?;
    let v = rlp.val_at::<u64>(6)?;
    let r = left_pad_arr(&rlp.val_at::<Vec<_>>(7)?)?;
    let s = left_pad_arr(&rlp.val_at::<Vec<_>>(8)?)?;

    let signing_info = SigningInfo::Eth { v, r, s, chain_id };

    let transaction = Transaction {
        nonce,
        gas_price,
        gas_limit,
        to_addr: (!to_addr.is_empty()).then_some(Address::from_slice(&to_addr)),
        amount,
        payload,
    };

    SignedTransaction::new(transaction, signing_info)
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
    use primitive_types::H160;

    use crate::{
        api::eth::{left_pad_arr, transaction_from_rlp},
        state::Address,
    };

    #[test]
    fn test_transaction_from_rlp() {
        // From https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#example
        let transaction = hex::decode("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83").unwrap();
        let signed_tx = transaction_from_rlp(&transaction, 1).unwrap();
        let tx = &signed_tx.transaction;
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.gas_price, 20 * 10_u64.pow(9));
        assert_eq!(tx.gas_limit, 21000u64);
        assert_eq!(
            tx.to_addr.unwrap(),
            Address(
                "0x3535353535353535353535353535353535353535"
                    .parse::<H160>()
                    .unwrap()
            )
        );
        assert_eq!(tx.amount, 10u128.pow(18));
        assert_eq!(tx.payload, Vec::<u8>::new());
        assert_eq!(
            signed_tx.from_addr,
            Address(
                "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
                    .parse::<H160>()
                    .unwrap()
            )
        );
        assert!(signed_tx.verify().is_ok());
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
