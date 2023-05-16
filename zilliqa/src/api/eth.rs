//! The Ethereum API, as documented at <https://ethereum.org/en/developers/docs/apis/json-rpc>.

use std::{
    sync::{Arc, Mutex},
    time::SystemTime,
};

use anyhow::{anyhow, Result};
use generic_array::{
    sequence::Split,
    typenum::{U12, U20},
    GenericArray,
};
use jsonrpsee::{
    types::{error::ErrorCode, ErrorObject, Params},
    RpcModule,
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use opentelemetry::{metrics::Unit, Context, KeyValue};
use primitive_types::{H160, H256};
use rlp::{Rlp, RlpStream};
use sha2::Digest;
use sha3::Keccak256;

use crate::{
    crypto::Hash,
    message::Block,
    node::Node,
    state::{Address, NewTransaction},
};

use super::{
    to_hex::ToHex,
    types::{CallParams, EthBlock, EthTransaction, EthTransactionReceipt, HashOrTransaction},
};

pub fn rpc_module(node: Arc<Mutex<Node>>) -> RpcModule<Arc<Mutex<Node>>> {
    let mut module = RpcModule::new(node);
    let meter = opentelemetry::global::meter("");

    macro_rules! method {
        ($name:expr, $method:path) => {{
            let rpc_server_duration = meter
                .f64_histogram("rpc.server.duration")
                .with_unit(Unit::new("ms"))
                .init();
            let cx = Context::new();
            module
                .register_method($name, move |params, context| {
                    let mut attributes = vec![
                        KeyValue::new("rpc.system", "jsonrpc"),
                        KeyValue::new("rpc.service", "zilliqa.eth"),
                        KeyValue::new("rpc.method", $name),
                        KeyValue::new("network.transport", "tcp"),
                        KeyValue::new("rpc.jsonrpc.version", "2.0"),
                    ];

                    let start = SystemTime::now();
                    let result = $method(params, context).map_err(|e| {
                        tracing::error!(?e);
                        ErrorObject::owned(
                            ErrorCode::InternalError.code(),
                            e.to_string(),
                            None as Option<String>,
                        )
                    });
                    if let Err(err) = &result {
                        attributes.push(KeyValue::new("rpc.jsonrpc.error_code", err.code() as i64));
                    }
                    rpc_server_duration.record(
                        &cx,
                        start.elapsed().map_or(0.0, |d| d.as_secs_f64() * 1000.0),
                        &attributes,
                    );
                    result
                })
                .unwrap();
        }};
    }

    method!("eth_accounts", accounts);
    method!("eth_blockNumber", block_number);
    method!("eth_call", call);
    method!("eth_chainId", chain_id);
    method!("eth_estimateGas", estimate_gas);
    method!("eth_getBalance", get_balance);
    method!("eth_getCode", get_code);
    method!("eth_getTransactionCount", get_transaction_count);
    method!("eth_gasPrice", gas_price);
    method!("eth_getBlockByNumber", get_block_by_number);
    method!("eth_getBlockByHash", get_block_by_hash);
    method!("eth_getTransactionByHash", get_transaction_by_hash);
    method!("eth_getTransactionReceipt", get_transaction_receipt);
    method!("eth_sendRawTransaction", send_raw_transaction);
    method!("net_version", version);
    method!("web3_clientVersion", client_version);

    module
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

    let return_value = node
        .lock()
        .unwrap()
        .call_contract(Address(call_params.to), call_params.data)?;

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

        let block = node
            .lock()
            .unwrap()
            .get_block_by_view(block)
            .map(|b| convert_block(node, b, full))
            .transpose()?;

        Ok(block)
    }
}

fn get_block_by_hash(params: Params, node: &Arc<Mutex<Node>>) -> Result<Option<EthBlock>> {
    let mut params = params.sequence();
    let hash: H256 = params.next()?;
    let full: bool = params.next()?;

    let block = node
        .lock()
        .unwrap()
        .get_block_by_hash(Hash(hash.0))
        .map(|b| convert_block(node, b, full))
        .transpose()?;

    Ok(block)
}

fn convert_block(node: &Arc<Mutex<Node>>, block: &Block, full: bool) -> Result<EthBlock> {
    if !full {
        Ok(block.into())
    } else {
        let transactions = block
            .transactions
            .iter()
            .map(|h| {
                node.lock()
                    .unwrap()
                    .get_transaction_by_hash(*h)
                    .ok_or_else(|| anyhow!("missing transaction: {h}"))
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

    Ok(node.lock().unwrap().get_transaction_by_hash(Hash(hash.0)))
}

fn get_transaction_receipt(
    params: Params,
    node: &Arc<Mutex<Node>>,
) -> Result<Option<EthTransactionReceipt>> {
    let hash: H256 = params.one()?;

    Ok(node.lock().unwrap().get_transaction_receipt(Hash(hash.0)))
}

fn send_raw_transaction(params: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    let transaction: String = params.one()?;
    let transaction = transaction
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("no 0x prefix"))?;
    let transaction = hex::decode(transaction)?;
    let chain_id = node.lock().unwrap().config.eth_chain_id;
    let mut transaction = transaction_from_rlp(&transaction, chain_id).unwrap();
    transaction.gas_limit = 100000000000000;

    let transaction_hash = H256(node.lock().unwrap().create_transaction(transaction)?.0);

    Ok(transaction_hash.to_hex())
}

fn version(_: Params, node: &Arc<Mutex<Node>>) -> Result<String> {
    Ok(node.lock().unwrap().config.eth_chain_id.to_string())
}

fn client_version(_: Params, _: &Arc<Mutex<Node>>) -> Result<&'static str> {
    // Format: "<name>/<version>"
    Ok(concat!("zilliqa2/v", env!("CARGO_PKG_VERSION")))
}

/// Decode a transaction from its RLP-encoded form.
fn transaction_from_rlp(bytes: &[u8], chain_id: u64) -> Result<NewTransaction> {
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

    let (recovery_id, reencoded) = if v >= (chain_id * 2) + 35 {
        let mut rlp = RlpStream::new_list(9);
        rlp.append(&nonce)
            .append(&gas_price)
            .append(&gas_limit)
            .append(&to_addr)
            .append(&amount)
            .append(&payload)
            .append(&chain_id)
            .append(&0u8)
            .append(&0u8);
        (v - ((chain_id * 2) + 35), rlp.out())
    } else {
        let mut rlp = RlpStream::new_list(6);
        rlp.append(&nonce)
            .append(&gas_price)
            .append(&gas_limit)
            .append(&to_addr)
            .append(&amount)
            .append(&payload);
        (v - 27, rlp.out())
    };
    let hash = Keccak256::digest(reencoded);
    let recovery_id = RecoveryId::from_byte(recovery_id.try_into()?)
        .ok_or_else(|| anyhow!("invalid recovery id: {recovery_id}"))?;
    let signature = Signature::from_scalars(r, s)?;

    let verifying_key = VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id)?;
    // Remove the first byte before hashing - The first byte specifies the encoding tag.
    let hashed = Keccak256::digest(&verifying_key.to_encoded_point(false).as_bytes()[1..]);
    let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();
    let from_addr = Address::from_bytes(bytes.into());

    Ok(NewTransaction {
        nonce,
        gas_price,
        gas_limit,
        from_addr,
        to_addr: Address::from_slice(&to_addr),
        amount,
        payload,
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
            transaction.from_addr,
            Address(
                "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
                    .parse::<H160>()
                    .unwrap()
            )
        );
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
