//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{anyhow, Result};
use jsonrpsee::{types::Params, RpcModule};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use primitive_types::{H160, H256};
use rlp::Rlp;

use crate::{
    crypto::{Hash, TransactionPublicKey, TransactionSignature},
    message::Block,
    node::Node,
    state::{Address, Transaction},
};

use super::{
    to_hex::ToHex,
    types::{CallParams, EthBlock, EthTransaction, EthTransactionReceipt, HashOrTransaction, Log},
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
            ("eth_getTransactionCount", get_transaction_count),
            ("eth_gasPrice", gas_price),
            ("eth_getBlockByNumber", get_block_by_number),
            ("eth_getBlockByHash", get_block_by_hash),
            ("eth_getTransactionByHash", get_transaction_by_hash),
            ("eth_getTransactionReceipt", get_transaction_receipt),
            ("eth_sendRawTransaction", send_raw_transaction),
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
    let _tag: &str = params.next()?;

    let return_value = node.lock().unwrap().call_contract(
        Address(call_params.from),
        Address(call_params.to),
        call_params.data,
    )?;

    Ok(return_value.to_hex())
}

fn chain_id(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().config.eth_chain_id.to_hex())
}

fn estimate_gas(_: Params, _: &Arc<Mutex<Node>>) -> Result<&'static str> {
    // TODO: #69
    Ok("0x100")
}

fn get_balance(_: Params, _: &Arc<Mutex<Node>>) -> Result<&'static str> {
    // TODO: #70
    Ok("0xf000000000000000")
}

fn get_code(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let _tag: &str = params.next()?;

    Ok(node
        .lock()
        .unwrap()
        .get_account(Address(address))?
        .code
        .to_hex())
}

fn get_transaction_count(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let mut params = params.sequence();
    let address: H160 = params.next()?;
    let _tag: &str = params.next()?;

    Ok(node
        .lock()
        .unwrap()
        .get_account(Address(address))?
        .nonce
        .to_hex())
}

fn gas_price(_: Params, _: &Arc<Mutex<Node>>) -> Result<&'static str> {
    // TODO: #71
    Ok("0x454b7b38e70")
}

fn get_block_by_number(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<EthBlock>> {
    let mut params = params.sequence();
    let block: &str = params.next()?;
    let full: bool = params.next()?;

    if block == "latest" {
        let block = node.lock().unwrap().get_latest_block().map(EthBlock::from);

        Ok(block)
    } else {
        let block = block
            .strip_prefix("0x")
            .ok_or_else(|| anyhow!("no 0x prefix"))?;
        let block = u64::from_str_radix(block, 16)?;

        let node = node.lock().unwrap();
        let block = node
            .get_block_by_view(block)
            .map(|b| convert_block(&node, b, full))
            .transpose()?;

        Ok(block)
    }
}

fn get_block_by_hash(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<EthBlock>> {
    let mut params = params.sequence();
    let hash: H256 = params.next()?;
    let full: bool = params.next()?;

    let node = node.lock().unwrap();
    let block = node
        .get_block_by_hash(Hash(hash.0))
        .map(|b| convert_block(&node, b, full))
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
    let Some(transaction) = node.get_transaction_by_hash(hash) else { return Ok(None); };
    // TODO: Return error if receipt or block does not exist.
    let Some(receipt) = node.get_transaction_receipt(hash) else { return Ok(None); };
    let Some(block) = node.get_block_by_hash(receipt.block_hash) else { return Ok(None); };

    let transaction = EthTransaction {
        block_hash: H256(block.hash().0),
        block_number: block.view(),
        from: transaction.addr_from().0,
        gas: 0,
        gas_price: transaction.gas_price as u64,
        hash: H256(hash.0),
        input: transaction.payload.clone(),
        nonce: transaction.nonce,
        // `to` should be `None` if `transaction` is a contract creation.
        to: (transaction.to_addr != Address::DEPLOY_CONTRACT).then_some(transaction.to_addr.0),
        transaction_index: block.transactions.iter().position(|t| *t == hash).unwrap() as u64,
        value: transaction.amount as u64,
        v: 0,
        r: [0; 32],
        s: [0; 32],
    };

    Ok(Some(transaction))
}

pub(super) fn get_transaction_receipt_inner(
    hash: Hash,
    node: &MutexGuard<Node>,
) -> Result<Option<EthTransactionReceipt>> {
    let Some(transaction) = node.get_transaction_by_hash(hash) else { return Ok(None); };
    // TODO: Return error if receipt or block does not exist.
    let Some(receipt) = node.get_transaction_receipt(hash) else { return Ok(None); };
    let Some(block) = node.get_block_by_hash(receipt.block_hash) else { return Ok(None); };

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
                address: log.address.0,
                data: log.data,
                topics: log.topics,
            };

            log.bloom(&mut logs_bloom);

            log
        })
        .collect();

    let receipt = EthTransactionReceipt {
        transaction_hash,
        transaction_index,
        block_hash,
        block_number,
        from: transaction.addr_from().0,
        to: transaction.to_addr.0,
        cumulative_gas_used: 0,
        effective_gas_price: 0,
        gas_used: 0,
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

    transaction.verify()?;

    let transaction_hash = H256(node.lock().unwrap().create_transaction(transaction)?.0);

    Ok(transaction_hash.to_hex())
}

/// Decode a transaction from its RLP-encoded form.
fn transaction_from_rlp(bytes: &[u8], chain_id: u64) -> Result<Transaction> {
    let rlp = Rlp::new(bytes);
    let nonce = rlp.val_at(0)?;
    let gas_price = rlp.val_at(1)?;
    let gas_limit: u64 = rlp.val_at(2)?;
    let to_addr = rlp.val_at::<Vec<u8>>(3)?;
    let amount = rlp.val_at(4)?;
    let payload = rlp.val_at(5)?;
    let v = rlp.val_at::<u64>(6)?;
    let r = left_pad_arr(&rlp.val_at::<Vec<_>>(7)?)?;
    let s = left_pad_arr(&rlp.val_at::<Vec<_>>(8)?)?;

    let use_eip155 = v >= (chain_id * 2) + 35;

    let unsigned_transaction = Transaction {
        nonce,
        gas_price,
        gas_limit,
        signature: None,
        public_key: TransactionPublicKey::Ecdsa(
            // dummy temp signature to fill the object
            *SigningKey::from_slice(&[1_u8; 32]).unwrap().verifying_key(),
            use_eip155,
        ),
        to_addr: Address::from_slice(&to_addr),
        amount,
        payload,
        chain_id,
    };

    let recovery_id = if use_eip155 {
        v - ((chain_id * 2) + 35)
    } else {
        v - 27
    };
    let hash = unsigned_transaction.signing_hash();
    let recovery_id = RecoveryId::from_byte(recovery_id.try_into()?)
        .ok_or_else(|| anyhow!("invalid recovery id: {recovery_id}"))?;
    let signature = Signature::from_scalars(r, s)?;

    let verifying_key =
        VerifyingKey::recover_from_prehash(hash.as_bytes(), &signature, recovery_id)?;

    Ok(Transaction {
        signature: Some(TransactionSignature::Ecdsa(signature)),
        public_key: TransactionPublicKey::Ecdsa(verifying_key, use_eip155),
        ..unsigned_transaction
    })
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
        let transaction = transaction_from_rlp(&transaction, 1).unwrap();
        assert_eq!(transaction.nonce, 9);
        assert_eq!(transaction.gas_price, 20 * 10u128.pow(9));
        assert_eq!(transaction.gas_limit, 21000u64);
        assert_eq!(
            transaction.to_addr,
            Address(
                "0x3535353535353535353535353535353535353535"
                    .parse::<H160>()
                    .unwrap()
            )
        );
        assert_eq!(transaction.amount, 10u128.pow(18));
        assert_eq!(transaction.payload, Vec::<u8>::new());
        assert_eq!(
            transaction.addr_from(),
            Address(
                "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
                    .parse::<H160>()
                    .unwrap()
            )
        );
        assert!(transaction.verify().is_ok());
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
