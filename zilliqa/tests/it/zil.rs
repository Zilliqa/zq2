use std::{ops::DerefMut, str::FromStr};

use alloy::{
    hex::FromHex,
    primitives::{Address, B256, TxHash, U256, keccak256},
    providers::{Provider as _, WalletProvider},
    rpc::types::TransactionRequest,
    sol,
};
use anyhow::Result;
use bech32::{Bech32, Hrp};
use ethabi::ParamType;
use k256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use primitive_types::{H160, H256};
use prost::Message;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zilliqa::{
    api::types::{
        eth::{Log, TransactionReceipt},
        zil::GetTxResponse,
    },
    schnorr,
    transaction::{EvmGas, ScillaGas},
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};

use crate::{Network, Wallet, deploy_contract};

pub async fn zilliqa_account(
    network: &mut Network,
    wallet: &Wallet,
) -> (schnorr::SecretKey, Address) {
    zilliqa_account_with_funds(network, wallet, 1000 * 10u128.pow(18)).await
}

pub async fn zilliqa_account_with_funds(
    network: &mut Network,
    wallet: &Wallet,
    funds: u128,
) -> (schnorr::SecretKey, Address) {
    // Generate a Zilliqa account.
    let secret_key = schnorr::SecretKey::random(network.rng.lock().unwrap().deref_mut());
    let public_key = secret_key.public_key();
    let hashed = Sha256::digest(public_key.to_encoded_point(true).as_bytes());
    let address = Address::from_slice(&hashed[12..]);

    // Send the Zilliqa account some funds.
    let tx = TransactionRequest::default()
        .to(address)
        .value(U256::from(funds));
    let hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();
    network
        .run_until_async(
            || async {
                wallet
                    .client()
                    .request::<_, Option<Value>>("GetTransaction", [hash])
                    .await
                    .is_ok()
            },
            200,
        )
        .await
        .unwrap();

    // Verify the Zilliqa account has funds using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();

    let eth_balance = wallet.get_balance(address).await.unwrap().to::<u128>();

    // This is in decimal!
    let zil_balance = response["balance"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .unwrap();

    // assert_eq!(zil_balance * U128::from(10u128.pow(6)), funds.into());
    assert_eq!(zil_balance * 10u128.pow(6), eth_balance);
    assert_eq!(eth_balance, funds);
    assert_eq!(response["nonce"].as_u64().unwrap(), 0);

    (secret_key, address)
}

enum ToAddr {
    Address(H160),
    StringVal(String),
}

fn get_random_address(_network: &mut Network) -> Address {
    Address::random()
    // let mut rng_guard = network.rng.lock().unwrap();
    // let mut addr_bytes = [0u8; 20];
    // rand::RngCore::fill_bytes(&mut *rng_guard, &mut addr_bytes);
    // Address::from_slice(&addr_bytes)
}

#[allow(clippy::too_many_arguments)]
async fn issue_create_transaction(
    wallet: &Wallet,
    public_key: &PublicKey,
    gas_price: u128,
    _network: &mut Network,
    secret_key: &schnorr::SecretKey,
    nonce: u64,
    to_addr: ToAddr,
    amount: u128,
    gas_limit: u64,
    code: Option<&str>,
    data: Option<&str>,
) -> Result<Value> {
    let chain_id = wallet.get_chain_id().await.unwrap() as u32 - 0x8000;
    let version = (chain_id << 16) | 1u32;
    let (to_addr_val, to_addr_string) = match to_addr {
        ToAddr::Address(v) => {
            let vec = v.as_bytes().to_vec();
            (
                vec.clone(),
                Address::from_slice(vec.as_slice()).to_checksum(None),
            )
        }
        ToAddr::StringVal(v) => (
            H160::from_str(&v).unwrap().as_bytes().to_vec(),
            v.to_string(),
        ),
    };
    let proto = ProtoTransactionCoreInfo {
        version,
        toaddr: to_addr_val,
        senderpubkey: Some(public_key.to_sec1_bytes().into()),
        amount: Some(amount.to_be_bytes().to_vec().into()),
        gasprice: Some(gas_price.to_be_bytes().to_vec().into()),
        gaslimit: gas_limit,
        oneof2: Some(Nonce::Nonce(nonce)),
        oneof8: code.map(|c| Code::Code(c.as_bytes().to_vec())),
        oneof9: data.map(|d| Data::Data(d.as_bytes().to_vec())),
    };
    let txn_data = proto.encode_to_vec();
    let signature = schnorr::sign(&txn_data, secret_key);

    let mut request = json!({
        "version": version,
        "nonce": nonce,
        "toAddr": to_addr_string,
        "amount": amount.to_string(),
        "pubKey": hex::encode(public_key.to_sec1_bytes()),
        "gasPrice": gas_price.to_string(),
        "gasLimit": gas_limit.to_string(),
        "signature": hex::encode(signature.to_bytes()),
    });

    if let Some(code) = code {
        request["code"] = code.into();
    }
    if let Some(data) = data {
        request["data"] = data.into();
    }

    Ok(wallet
        .client()
        .request("CreateTransaction", [request])
        .await?)
}

async fn wait_eth_receipt(
    network: &mut Network,
    wallet: &Wallet,
    tx_hash: H256,
) -> TransactionReceipt {
    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> =
                    wallet.client().request("GetTransaction", [tx_hash]).await;
                response.is_ok()
            },
            400,
        )
        .await
        .unwrap();
    map_eth_receipt(wallet, TxHash::from_slice(tx_hash.as_bytes())).await
}
/// Needed to map ZIL receipts; due to type = 0xdd870 deserialization error.
async fn map_eth_receipt(wallet: &Wallet, tx_hash: TxHash) -> TransactionReceipt {
    /*
    {"jsonrpc":"2.0","id":212,"result":{"transactionHash":"0xa91f3c345cf0dda9d2cc3ac3809eae434e288c2b4bc9c381bab0844512c8dbfa","transactionIndex":"0x0","blockHash":"0x94fc8af233743c21fd424579bca502197abec6d9263a81e5130f4f285c47852a","blockNumber":"0xf","from":"0xf220a689dec0caca46bcd8e2f9af97ce9bd16676","to":"0x367800c2ef47f4550f2a8cba7b03a65155c6291e","cumulativeGasUsed":"0x5298c","effectiveGasPrice":"0x454b7a4e100","gasUsed":"0x5298c","contractAddress":null,"logs":[{"removed":false,"logIndex":"0x0","transactionIndex":"0x0","transactionHash":"0xa91f3c345cf0dda9d2cc3ac3809eae434e288c2b4bc9c381bab0844512c8dbfa","blockHash":"0x94fc8af233743c21fd424579bca502197abec6d9263a81e5130f4f285c47852a","blockNumber":"0xf","address":"0x9f4515ce985c2046732d9581950e6c30e6ae9b74","data":"0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000009a7b2261646472657373223a22307839663435313563653938356332303436373332643935383139353065366333306536616539623734222c225f6576656e746e616d65223a2242616c616e6365222c22706172616d73223a5b7b22766e616d65223a2262616c616e6365222c2276616c7565223a2231323334303030303030303030303030222c2274797065223a2255696e74313238227d5d7d000000000000","topics":["0xdb42f09d5a5cb193ea3eae569c8ce2e3a5c8d8b68aadbe1a637f44d07f67bc17"]},{"removed":false,"logIndex":"0x1","transactionIndex":"0x0","transactionHash":"0xa91f3c345cf0dda9d2cc3ac3809eae434e288c2b4bc9c381bab0844512c8dbfa","blockHash":"0x94fc8af233743c21fd424579bca502197abec6d9263a81e5130f4f285c47852a","blockNumber":"0xf","address":"0x9f4515ce985c2046732d9581950e6c30e6ae9b74","data":"0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000008d7b2261646472657373223a22307839663435313563653938356332303436373332643935383139353065366333306536616539623734222c225f6576656e746e616d65223a224d7942616c616e6365222c22706172616d73223a5b7b22766e616d65223a2262616c616e6365222c2276616c7565223a2230222c2274797065223a2255696e74313238227d5d7d00000000000000000000000000000000000000","topics":["0x71a97ba7830518ccc159d5a9da086633b982888de682fcc7328b79c3cdd27bbe"]}],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","type":"0x2","status":"0x1","v":"0x0","r":"0x95019c3d3d28f560953db16d810a678c4b1fb2f0381c9de33d0e5570d5ca73d1","s":"0x3367cb95861e49a8df6077e28f06e4b71da157bdc0864eb8ccd6702441fbd7c1"}}
    */
    let value = wallet
        .client()
        .request::<_, Value>("eth_getTransactionReceipt", [tx_hash])
        .await
        .unwrap();
    TransactionReceipt {
        transaction_hash: B256::from_hex(
            value["transactionHash"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap(),
        transaction_index: u64::from_str_radix(
            value["transactionIndex"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap(),
        block_hash: B256::from_hex(
            value["blockHash"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap(),
        block_number: u64::from_str_radix(
            value["blockNumber"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap(),
        from: Address::from_hex(value["from"].as_str().unwrap().strip_prefix("0x").unwrap())
            .unwrap(),
        to: value["to"]
            .as_str()
            .map(|s| Address::from_hex(s.strip_prefix("0x").unwrap()).unwrap()),
        cumulative_gas_used: EvmGas(
            u64::from_str_radix(
                value["cumulativeGasUsed"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
                16,
            )
            .unwrap(),
        ),
        effective_gas_price: u128::from_str_radix(
            value["effectiveGasPrice"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap(),
        gas_used: EvmGas(
            u64::from_str_radix(
                value["gasUsed"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
                16,
            )
            .unwrap(),
        ),
        contract_address: value["contractAddress"]
            .as_str()
            .map(|s| Address::from_hex(s.strip_prefix("0x").unwrap()).unwrap()),
        ty: u64::from_str_radix(
            value["gasUsed"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap(),
        status: value["status"].as_str().unwrap() != "0x0",
        logs: value["logs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|log| Log {
                removed: log["removed"].as_bool().unwrap(),
                log_index: u64::from_str_radix(
                    log["logIndex"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("0x")
                        .unwrap(),
                    16,
                )
                .unwrap(),
                transaction_index: u64::from_str_radix(
                    log["transactionIndex"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("0x")
                        .unwrap(),
                    16,
                )
                .unwrap(),
                transaction_hash: B256::from_hex(
                    log["transactionHash"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("0x")
                        .unwrap(),
                )
                .unwrap(),
                block_hash: B256::from_hex(
                    log["blockHash"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("0x")
                        .unwrap(),
                )
                .unwrap(),
                block_number: u64::from_str_radix(
                    log["blockNumber"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("0x")
                        .unwrap(),
                    16,
                )
                .unwrap(),
                address: Address::from_hex(
                    log["address"].as_str().unwrap().strip_prefix("0x").unwrap(),
                )
                .unwrap(),
                data: hex::decode(log["data"].as_str().unwrap().strip_prefix("0x").unwrap())
                    .unwrap(),
                topics: log["topics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|topic| {
                        B256::from_hex(topic.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
                    })
                    .collect(),
            })
            .collect(),
        // unused
        v: 0,
        r: U256::ZERO,
        s: U256::ZERO,
        logs_bloom: [0u8; 256],
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_transaction(
    network: &mut Network,
    wallet: &Wallet,
    secret_key: &schnorr::SecretKey,
    nonce: u64,
    to_addr: ToAddr,
    amount: u128,
    gas_limit: u64,
    code: Option<&str>,
    data: Option<&str>,
) -> (Option<Address>, Value) {
    let public_key = secret_key.public_key();

    // Get the gas price via the Zilliqa API.
    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();

    let response = issue_create_transaction(
        wallet,
        &public_key,
        gas_price,
        network,
        secret_key,
        nonce,
        to_addr,
        amount,
        gas_limit,
        code,
        data,
    )
    .await
    .unwrap();
    let txn_hash: H256 = response["TranID"].as_str().unwrap().parse().unwrap();

    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> =
                    wallet.client().request("GetTransaction", [txn_hash]).await;
                response.is_ok()
            },
            111,
        )
        .await
        .unwrap();

    let eth_receipt = map_eth_receipt(wallet, TxHash::from_slice(txn_hash.as_bytes())).await;
    assert!(eth_receipt.status, "{:?}", eth_receipt);

    (
        eth_receipt.contract_address,
        wallet
            .client()
            .request("GetTransaction", [txn_hash])
            .await
            .unwrap(),
    )
}

pub fn scilla_test_contract_code() -> String {
    String::from(
        r#"
        scilla_version 0

        library HelloWorld

        let one_msg =
          fun (msg : Message) =>
          let nil_msg = Nil {Message} in
            Cons {Message} msg nil_msg

        let one = Uint32 1
        let two = Uint32 2

        let amnt = Uint128 0

        contract HelloWorld
        (owner: ByStr20)

        field welcome_msg : String = "default"
        field welcome_map : Map Uint32 (Map Uint32 String) = Emp Uint32 (Map Uint32 String)

        (* Test variable which is a prefix of another variable *)
        field foo : Map Uint32 String = Emp Uint32 String
        field foobar : String = "goodbye"

        transition removeHello()
          delete welcome_map[one];
          e = {_eventname : "removeHello"};
          event e
        end

        transition setHello (msg : String)
        is_owner = builtin eq owner _sender;
        match is_owner with
        | False =>
            e = {_eventname : "setHello"; code : "1"};
            event e
        | True =>
            hello = "hello";
            foo[one] := hello;
            welcome_msg := msg;
            welcome_map[one][two] := msg;
            e = {_eventname : "setHello"; code : "2"};
            event e
        end
        end

        transition getHello ()
        r <- welcome_msg;
        e = {_eventname: "getHello"; msg: r};
        event e;
        maybe_s <- welcome_map[one][two];
        match maybe_s with
        | None =>
            e = {_eventname: "getHello"; msg: "failed"};
            event e
        | Some s =>
            e = {_eventname: "getHello"; msg: s};
            event e
        end
        end

        transition getFields ()
        a <- foo;
        a_one = builtin get a one;
        b <- foobar;
        e = {_eventname: "fields"; a_one: a_one; b: b};
        event e
        end

        transition callFailure(addr: ByStr20)
          accept;
          msg = { _tag : "failure"; _recipient : addr; _amount : amnt };
          msgs = one_msg msg;
          send msgs
        end

        transition failure()
            throw
        end
    "#,
    )
}

pub fn scilla_test_contract_data(address: Address) -> String {
    format!(
        r#"[
            {{
                "vname": "_scilla_version",
                "type": "Uint32",
                "value": "0"
            }},
            {{
                "vname": "owner",
                "type": "ByStr20",
                "value": "{address:#x}"
            }}
        ]"#
    )
}

pub async fn deploy_scilla_contract(
    network: &mut Network,
    wallet: &Wallet,
    sender_secret_key: &schnorr::SecretKey,
    code: &str,
    data: &str,
    amount: u128,
) -> Address {
    let (contract_address, txn) = send_transaction(
        network,
        wallet,
        sender_secret_key,
        1,
        ToAddr::Address(H160::zero()),
        amount,
        50_000,
        Some(code),
        Some(data),
    )
    .await;

    let api_contract_address = wallet
        .client()
        .request("GetContractAddressFromTransactionID", [&txn["ID"]])
        .await
        .unwrap();
    assert_eq!(contract_address, api_contract_address);

    contract_address.unwrap()
}

// Returns a pair (code, message) if there was one.
#[allow(clippy::too_many_arguments)]
async fn run_create_transaction_api_for_error(
    wallet: &Wallet,
    secret_key: &schnorr::SecretKey,
    nonce: u64,
    to_addr: ToAddr,
    amount: u128,
    gas_limit: u64,
    code: Option<&str>,
    data: Option<&str>,
    chain_id: Option<u32>,
    bad_signature: bool,
) -> Option<(i64, String)> {
    let public_key = secret_key.public_key();

    // Get the gas price via the Zilliqa API.
    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();

    let use_chain_id = chain_id.unwrap_or(wallet.get_chain_id().await.unwrap() as u32 - 0x8000);
    let version = (use_chain_id << 16) | 1u32;
    let (to_addr_val, to_addr_string) = match to_addr {
        ToAddr::Address(v) => {
            let vec = v.as_bytes().to_vec();
            (
                vec.clone(),
                Address::from_slice(vec.as_slice()).to_checksum(None),
            )
        }
        ToAddr::StringVal(v) => (
            H160::from_str(&v).unwrap().as_bytes().to_vec(),
            v.to_string(),
        ),
    };
    let proto = ProtoTransactionCoreInfo {
        version,
        toaddr: to_addr_val,
        senderpubkey: Some(public_key.to_sec1_bytes().into()),
        amount: Some(amount.to_be_bytes().to_vec().into()),
        gasprice: Some(gas_price.to_be_bytes().to_vec().into()),
        gaslimit: gas_limit,
        oneof2: Some(Nonce::Nonce(nonce)),
        oneof8: code.map(|c| Code::Code(c.as_bytes().to_vec())),
        oneof9: data.map(|d| Data::Data(d.as_bytes().to_vec())),
    };
    let txn_data = proto.encode_to_vec();
    let mut signature = schnorr::sign(&txn_data, secret_key).to_bytes();
    if bad_signature && let Some(x) = signature.first_mut() {
        *x = x.wrapping_add(1);
    }
    let mut request = json!({
        "version": version,
        "nonce": nonce,
        "toAddr": to_addr_string,
        "amount": amount.to_string(),
        "pubKey": hex::encode(public_key.to_sec1_bytes()),
        "gasPrice": gas_price.to_string(),
        "gasLimit": gas_limit.to_string(),
        "signature": hex::encode(signature)
    });

    if let Some(code) = code {
        request["code"] = code.into();
    }
    if let Some(data) = data {
        request["data"] = data.into();
    }

    let response: Result<Value, _> = wallet
        .client()
        .request("CreateTransaction", [request])
        .await;

    if let Some(rpc_error) = response.err()
        && let Some(json_error) = rpc_error.as_error_resp()
    {
        return Some((json_error.code, json_error.message.to_string()));
    }
    None
}

#[zilliqa_macros::test]
async fn create_transaction_bad_checksum(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;
    let public_key = secret_key.public_key();

    // Get the gas price via the Zilliqa API.
    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();

    let ans = issue_create_transaction(
        &wallet,
        &public_key,
        gas_price,
        &mut network,
        &secret_key,
        1,
        ToAddr::StringVal("0x00000000000000000000000000000000deaDbeef".to_string()),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;
    assert!(ans.is_err());
}

#[zilliqa_macros::test]
async fn create_transaction_zil_checksum(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::StringVal("0x00000000000000000000000000000000deADbeef".to_string()),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    // Verify the sender's nonce has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [to_addr])
        .await
        .unwrap();
    assert_eq!(response["balance"].as_str().unwrap(), "200000000000000");
}

#[zilliqa_macros::test]
async fn create_transaction(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let initial_balance = wallet.get_balance(address).await.unwrap().to::<u128>();

    let initial_balance_zil: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();
    let initial_balance_zil =
        u128::from_str(initial_balance_zil["balance"].as_str().unwrap()).unwrap();

    let amount = 111_111_111_111_111u128;

    let to_addr = H160::random();
    let (_, txn_response) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        amount,
        50,
        None,
        None,
    )
    .await;

    // Verify the sender's nonce has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [to_addr])
        .await
        .unwrap();
    assert_eq!(response["balance"].as_str().unwrap(), "111111111111111");

    let txn_hash: H256 = txn_response["ID"].as_str().unwrap().parse().unwrap();

    let eth_receipt = map_eth_receipt(&wallet, TxHash::from_slice(txn_hash.as_bytes())).await;

    // Check by eth receipt
    let transaction_fee: u128 =
        eth_receipt.cumulative_gas_used.0 as u128 * eth_receipt.effective_gas_price;

    let balance_after = wallet.get_balance(address).await.unwrap().to::<u128>();

    assert_eq!(
        balance_after,
        initial_balance - transaction_fee - amount * 10u128.pow(6)
    );

    // check by zil api
    let balance_after: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();
    let balance_after = u128::from_str(balance_after["balance"].as_str().unwrap()).unwrap();

    let gas_price: u128 = txn_response["gasPrice"].as_str().unwrap().parse().unwrap();
    let gas_limit: u128 = txn_response["gasLimit"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        balance_after,
        initial_balance_zil - gas_price * gas_limit - amount
    );
}

#[zilliqa_macros::test]
async fn get_balance_via_eth_api(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let to_addr = H160::random();

    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    let encoded_bech32 =
        bech32::encode::<Bech32>(Hrp::parse("zil").unwrap(), to_addr.as_bytes()).unwrap();

    let response: Value = wallet
        .client()
        .request("eth_getBalance", [encoded_bech32, "latest".to_string()])
        .await
        .unwrap();

    let stripped_str = response.as_str().unwrap().strip_prefix("0x").unwrap();
    let returned = u128::from_str_radix(stripped_str, 16).unwrap();
    assert_eq!(returned, 200u128 * 10u128.pow(18));
}

#[zilliqa_macros::test]
async fn create_transaction_errors(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;
    let to_addr = H160::random();

    {
        let (code, msg) = run_create_transaction_api_for_error(
            &wallet,
            &secret_key,
            0,
            ToAddr::Address(to_addr),
            200u128 * 10u128.pow(12),
            50_000,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();

        assert!(msg.to_lowercase().contains("invalid nonce"));
        assert_eq!(code, -8)
    }

    {
        let (code, msg) = run_create_transaction_api_for_error(
            &wallet,
            &secret_key,
            1,
            ToAddr::Address(to_addr),
            200u128 * 10u128.pow(12),
            50_000,
            None,
            None,
            Some(1),
            false,
        )
        .await
        .unwrap();

        assert!(msg.to_lowercase().contains("chain id"));
        assert_eq!(code, -26)
    }

    {
        let (code, msg) = run_create_transaction_api_for_error(
            &wallet,
            &secret_key,
            1,
            ToAddr::Address(to_addr),
            200u128 * 10u128.pow(12),
            50_000,
            None,
            None,
            None,
            true,
        )
        .await
        .unwrap();

        assert!(msg.to_lowercase().contains("signature"));
        assert_eq!(code, -26)
    }

    {
        // Too little for the deposit.
        let (no_funds_secret_key, _) =
            zilliqa_account_with_funds(&mut network, &wallet, 10u128.pow(6)).await;
        let (code, msg) = run_create_transaction_api_for_error(
            &wallet,
            &no_funds_secret_key,
            1,
            ToAddr::Address(to_addr),
            200u128 * 10u128.pow(12),
            50_000,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();
        assert!(msg.to_lowercase().contains("insufficient"));
        assert_eq!(code, -8)
    }
}

#[zilliqa_macros::test]
async fn get_transaction(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Create a Zilliqa account and get its secret key and address
    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    // Define the recipient address
    let address_string_w_prefix = "0x00000000000000000000000000000000deadbeef";
    let to_addr: H160 = address_string_w_prefix.parse().unwrap();

    // Send a transaction
    let (_contract_address, returned_transaction) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    // Get the transaction ID from the returned transaction
    let transaction_id = returned_transaction["ID"]
        .as_str()
        .expect("Failed to get ID from response");

    // Wait for the transaction to be mined
    network.run_until_block_finalized(1u64, 100).await.unwrap();

    // Use the GetTransaction API to retrieve the transaction details
    let response: Value = wallet
        .client()
        .request("GetTransaction", [transaction_id])
        .await
        .expect("Failed to call GetTransaction API");

    // Check for keys
    assert!(response["receipt"]["success"].is_boolean());
    assert!(response["receipt"]["event_logs"].is_array());
    assert!(response["receipt"]["transitions"].is_array());

    // Check the string formats
    assert!(!response["ID"].as_str().unwrap().starts_with("0x"));
    assert!(!response["toAddr"].as_str().unwrap().starts_with("0x"));
    assert!(response["senderPubKey"].as_str().unwrap().starts_with("0x"));
    assert!(response["signature"].as_str().unwrap().starts_with("0x"));

    // Verify the transaction details
    assert_eq!(response["ID"].as_str().unwrap(), transaction_id);
    assert_eq!(response["toAddr"].as_str().unwrap(), hex::encode(to_addr),);
    assert_eq!(response["amount"].as_str().unwrap(), "200000000000000");
    assert_eq!(response["gasLimit"].as_str().unwrap(), "50000");
    assert_eq!(
        response["senderPubKey"].as_str().unwrap(),
        format!("0x{}", hex::encode(secret_key.public_key().to_sec1_bytes()))
    );

    let parsed_response = zilliqa::api::types::zil::GetTxResponse::deserialize(&response)
        .expect("Failed to deserialize response");

    // Verify the transaction details
    assert_eq!(parsed_response.nonce, 1);
    // Logic should be case independent
    assert_eq!(
        parsed_response.to_addr.to_string().to_lowercase(),
        address_string_w_prefix
    );
    assert_eq!(parsed_response.amount.to_string(), "200000000000000");
    assert_eq!(parsed_response.gas_limit.0, 50000);

    let response_soft_confirmed: Value = wallet
        .client()
        .request("GetSoftConfirmedTransaction", [transaction_id])
        .await
        .expect("Failed to call GetTransaction API");

    assert_eq!(response, response_soft_confirmed);
}

#[zilliqa_macros::test]
async fn create_transaction_high_gas_limit(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, address) =
        zilliqa_account_with_funds(&mut network, &wallet, 60 * 10u128.pow(18)).await;

    let to_addr = H160::random();

    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();

    println!("gas_price {gas_price}");

    // how much we can actually pay for.
    // 50 = 60-10 (we're transferring 10)
    let max_gas_we_can_pay_for = (50u128 * 10u128.pow(12)) / gas_price;
    println!("max_gas {max_gas_we_can_pay_for}");
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        10 * 10u128.pow(12),
        u128::try_into(max_gas_we_can_pay_for * 2).unwrap(),
        None,
        None,
    )
    .await;

    // Verify the sender's nonce has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();
    println!("GetBalance() after transfer = {response:?}");
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [to_addr])
        .await
        .unwrap();
    assert_eq!(
        response["balance"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap(),
        (10u128 * 10u128.pow(12))
    );
}

// We need to restrict the concurrency level of this test, because each node in the network will spawn a TCP listener
// once it invokes Scilla. When many tests are run in parallel, this results in "Too many open files" errors.
#[zilliqa_macros::test(restrict_concurrency)]
async fn create_contract(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;
    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    let api_code: Value = wallet
        .client()
        .request("GetSmartContractCode", [contract_address])
        .await
        .unwrap();
    assert_eq!(code, api_code["code"]);

    let api_data: Vec<Value> = wallet
        .client()
        .request("GetSmartContractInit", [contract_address])
        .await
        .unwrap();
    // Assert the data returned from the API is a superset of the init data we passed.
    assert!(
        serde_json::from_str::<Vec<Value>>(&data)
            .unwrap()
            .iter()
            .all(|d| api_data.contains(d))
    );

    let old_balance: u128 = {
        let bal_resp: Value = wallet
            .client()
            .request("GetBalance", [address])
            .await
            .unwrap();
        bal_resp["balance"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
    };

    let call = r#"{
        "_tag": "setHello",
        "params": [
            {
                "vname": "msg",
                "value": "foobar",
                "type": "String"
            }
        ]
    }"#;
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await;
    let event = &txn["receipt"]["event_logs"][0];
    assert_eq!(event["_eventname"], "setHello");
    assert_eq!(event["params"][0]["value"], "2");
    let new_balance: u128 = {
        let bal_resp: Value = wallet
            .client()
            .request("GetBalance", [address])
            .await
            .unwrap();
        bal_resp["balance"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap()
    };
    // Let's check that we charged the right amount of gas.
    assert_eq!(old_balance - new_balance, 696000005568u128);

    let call = r#"{
        "_tag": "getHello",
        "params": []
    }"#;
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        3,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await;
    for event in txn["receipt"]["event_logs"].as_array().unwrap() {
        assert_eq!(event["_eventname"], "getHello");
        assert_eq!(event["params"][0]["value"], "foobar");
    }

    let state: serde_json::Value = wallet
        .client()
        .request("GetSmartContractState", [contract_address])
        .await
        .unwrap();
    assert_eq!(state["welcome_msg"], "foobar");

    let call = r#"{
        "_tag": "getFields",
        "params": []
    }"#;
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        4,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await;
    assert_eq!(
        txn["receipt"]["event_logs"][0]["params"][0]["value"]["arguments"][0],
        "hello"
    );
    assert_eq!(
        txn["receipt"]["event_logs"][0]["params"][1]["value"],
        "goodbye"
    );
}

sol!(
    #[sol(rpc)]
    "tests/it/contracts/ScillaInterop.sol",
);

#[zilliqa_macros::test(restrict_concurrency)]
async fn scilla_precompiles(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library HelloWorld

        let one = Uint128 1
        let two = Uint128 2
        let big_number = Uint128 1234
        let addr = 0x0123456789012345678901234567890123456789

        contract Hello
        ()

        field num : Uint128 = big_number
        field str : String = "foobar"
        field addr_to_int : Map ByStr20 Uint128 =
          let emp = Emp ByStr20 Uint128 in
          builtin put emp addr one
        field addr_to_addr_to_int : Map ByStr20 (Map ByStr20 Uint128) =
          let emp1 = Emp ByStr20 Uint128 in
          let inner = builtin put emp1 addr one in
          let emp2 = Emp ByStr20 (Map ByStr20 Uint128) in
          builtin put emp2 addr inner

        transition InsertIntoMap(a: ByStr20, b: Uint128)
          addr_to_int[a] := b;
          e = {_eventname : "Inserted"; a : a; b : b};
          event e
        end

        transition LogSender()
          e = {_eventname : "LogSender"; sender : _sender};
          event e
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    let (evm_contract_address, _abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = ScillaInterop::new(evm_contract_address, &wallet);

    let num = contract
        .readUint128(scilla_contract_address, "num".into())
        .call()
        .await
        .unwrap();
    assert_eq!(num, 1234);

    let str = contract
        .readString(scilla_contract_address, "str".into())
        .call()
        .await
        .unwrap();
    assert_eq!(str, "foobar");

    let key = "0x0123456789012345678901234567890123456789"
        .parse()
        .unwrap();

    let val = contract
        .readMapUint128(scilla_contract_address, "addr_to_int".into(), key)
        .call()
        .await
        .unwrap();
    assert_eq!(val, 1);

    let val = contract
        .readNestedMapUint128(
            scilla_contract_address,
            "addr_to_addr_to_int".into(),
            key,
            key,
        )
        .call()
        .await
        .unwrap();
    assert_eq!(val, 1);

    // Construct a transaction which uses the scilla_call precompile.
    //
    // First execute the transaction with `eth_call` and assert that updating a value in a Scilla contract, then
    // reading that value in the same transaction gives us the correct value.
    let response = contract
        .callScilla(
            scilla_contract_address,
            "InsertIntoMap".into(),
            "addr_to_int".into(),
            key,
            5,
        )
        .gas(84_000_000)
        .call()
        .await
        .unwrap();
    assert_eq!(response, 5);

    // Now actually run the transaction and assert that the EVM logs include the Scilla log from the internal Scilla
    // call.
    let hash = *contract
        .callScilla(
            scilla_contract_address,
            "InsertIntoMap".into(),
            "addr_to_int".into(),
            key,
            5,
        )
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();

    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;

    assert_eq!(receipt.logs().len(), 1);
    let log = &receipt.logs()[0];
    assert_eq!(log.address(), scilla_contract_address);
    assert_eq!(log.topics()[0], keccak256("Inserted(string)".as_bytes()));

    let data = ethabi::decode(&[ParamType::String], &log.data().data).unwrap()[0]
        .clone()
        .into_string()
        .unwrap();
    let scilla_log: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(
        scilla_log["address"],
        format!("{scilla_contract_address:?}")
    );
    assert_eq!(scilla_log["_eventname"], "Inserted");
    assert_eq!(scilla_log["params"][0]["type"], "ByStr20");
    assert_eq!(scilla_log["params"][0]["vname"], "a");
    assert_eq!(
        scilla_log["params"][0]["value"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap(),
        key
    );
    assert_eq!(scilla_log["params"][1]["type"], "Uint128");
    assert_eq!(scilla_log["params"][1]["vname"], "b");
    assert_eq!(scilla_log["params"][1]["value"], "5");

    // Assert that the value has been permanently updated for good measure.
    let val = contract
        .readMapUint128(scilla_contract_address, "addr_to_int".into(), key)
        .call()
        .await
        .unwrap();
    assert_eq!(val, 5);

    // Construct a transaction which logs the `_sender` from the Scilla call.
    let hash = *contract
        .callScillaNoArgs(scilla_contract_address, "LogSender".into())
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;

    assert_eq!(receipt.logs().len(), 1);
    let log = &receipt.logs()[0];
    let data = ethabi::decode(&[ParamType::String], &log.data().data).unwrap()[0]
        .clone()
        .into_string()
        .unwrap();
    let scilla_log: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(scilla_log["_eventname"], "LogSender");
    assert_eq!(scilla_log["params"][0]["vname"], "sender");
    assert_eq!(
        scilla_log["params"][0]["value"],
        format!("{:?}", wallet.default_signer_address())
    );
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn mutate_evm_then_read_from_scilla(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        contract Test
        ()

        transition LogBalance(addr: ByStr20 with contract end)
          myBal <- _balance;
          e1 = { _eventname : "MyBalance"; balance : myBal };
          event e1;
          bal <- & addr._balance;
          e2 = { _eventname : "Balance"; balance : bal };
          event e2
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    let (evm_contract_address, _) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = ScillaInterop::new(evm_contract_address, &wallet);

    // Generate a random Address
    let recipient = Address::random();

    let my_balance_before = wallet
        .get_balance(scilla_contract_address)
        .await
        .unwrap()
        .to::<u128>();

    let amount = 1_234_000_000_000_000_000_000;
    let hash = *contract
        .sendEtherThenCallScilla(
            recipient,
            scilla_contract_address,
            "LogBalance".into(),
            recipient,
        )
        .value(U256::from(amount))
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();

    // Run the transaction.
    let receipt = wait_eth_receipt(&mut network, &wallet, H256::from_slice(hash.as_slice())).await;

    assert!(!receipt.logs.is_empty(), "{receipt:?}");
    let log = &receipt.logs[0];
    let data = ethabi::decode(&[ParamType::String], &log.data).unwrap()[0]
        .clone()
        .into_string()
        .unwrap();
    let scilla_log: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(scilla_log["_eventname"], "Balance");
    assert_eq!(
        scilla_log["params"][0]["value"],
        (amount / 10u128.pow(6)).to_string()
    );

    let log = &receipt.logs[1];
    let data = ethabi::decode(&[ParamType::String], &log.data).unwrap()[0]
        .clone()
        .into_string()
        .unwrap();
    let scilla_log: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(scilla_log["_eventname"], "MyBalance");
    assert_eq!(
        scilla_log["params"][0]["value"],
        (my_balance_before / 10u128.pow(6)).to_string(),
    );
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn interop_send_funds_from_scilla(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library HelloWorld
        let one = Uint128 1

        let one_msg =
          fun (msg : Message) =>
          let nil_msg = Nil {Message} in
            Cons {Message} msg nil_msg

        contract Test
        ()

        transition SendTo(addr: ByStr20)
          msg = { _tag : ""; _recipient : addr; _amount : one };
          msgs = one_msg msg;
          send msgs
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        1,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    let (evm_contract_address, _) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let recipient = get_random_address(&mut network);
    let contract = ScillaInterop::new(evm_contract_address, &wallet);

    // transaction sender pays for gas, but the funds are withdrawn from contract that sends a message
    let balance_before = wallet
        .get_balance(wallet.default_signer_address())
        .await
        .unwrap()
        .to::<u128>();
    let tx_count_before = wallet
        .get_transaction_count(wallet.default_signer_address())
        .await
        .unwrap();

    let hash = *contract
        .callScillaOneArg(scilla_contract_address, "SendTo".into(), recipient)
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();

    // Run the transaction.
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;
    assert!(receipt.status());

    let tx_count_after = wallet
        .get_transaction_count(wallet.default_signer_address())
        .await
        .unwrap();
    let balance_after = wallet
        .get_balance(wallet.default_signer_address())
        .await
        .unwrap()
        .to::<u128>();

    // Sender of the txn pays for gas
    assert_eq!(tx_count_before + 1, tx_count_after);
    assert_eq!(
        balance_before - (receipt.gas_used as u128 * receipt.effective_gas_price),
        balance_after
    );

    // Contract doesn't hold any funds
    let contract_final_balance = wallet
        .get_balance(scilla_contract_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(contract_final_balance, 0u128);

    assert_eq!(
        wallet.get_balance(recipient).await.unwrap().to::<u128>(),
        1_000_000
    );
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn call_scilla_precompile_with_value(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library HelloWorld
        let one = Uint128 1

        let one_msg =
          fun (msg : Message) =>
          let nil_msg = Nil {Message} in
            Cons {Message} msg nil_msg

        contract Test
        ()

        transition justAccept()
            accept
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    let evm_contract_value = 10_000_000;
    let value_to_send = evm_contract_value / 2;

    let (evm_contract_address, _) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        evm_contract_value,
        &wallet,
        &mut network,
    )
    .await;

    let contract = ScillaInterop::new(evm_contract_address, &wallet);

    // Query evm contract balance
    let evm_contract_zero_balance = wallet
        .get_balance(evm_contract_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(evm_contract_zero_balance, evm_contract_value);

    // Scilla contract balance is zero
    let scilla_contract_zero_balance = wallet
        .get_balance(scilla_contract_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(scilla_contract_zero_balance, 0);

    // Call precompile that sends the value
    let hash = *contract
        .callScillaValue(scilla_contract_address, "justAccept".into(), value_to_send)
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;
    assert!(receipt.status());

    // Scilla contract balance received the value
    let scilla_contract_zero_balance = wallet
        .get_balance(scilla_contract_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(scilla_contract_zero_balance, value_to_send);

    // Evm contract balance modified by sent amount
    let evm_contract_zero_balance = wallet
        .get_balance(evm_contract_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(
        evm_contract_zero_balance,
        evm_contract_value - value_to_send
    );
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn scilla_call_with_bad_gas(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library HelloWorld

        let one = Uint128 1
        let two = Uint128 2
        let big_number = Uint128 1234
        let addr = 0x0123456789012345678901234567890123456789

        contract Hello
        ()

        field num : Uint128 = big_number
        field str : String = "foobar"
        field addr_to_int : Map ByStr20 Uint128 =
          let emp = Emp ByStr20 Uint128 in
          builtin put emp addr one
        field addr_to_addr_to_int : Map ByStr20 (Map ByStr20 Uint128) =
          let emp1 = Emp ByStr20 Uint128 in
          let inner = builtin put emp1 addr one in
          let emp2 = Emp ByStr20 (Map ByStr20 Uint128) in
          builtin put emp2 addr inner

        transition InsertIntoMap(a: ByStr20, b: Uint128)
          addr_to_int[a] := b;
          e = {_eventname : "Inserted"; a : a; b : b};
          event e
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    // Bump the genesis wallet's nonce up, so that the next contract we deploy will be exempt from gas charges when
    // calling the `scilla_call` precompile.
    let tx_hash = *wallet
        .send_transaction(TransactionRequest::default().to(Address::ZERO))
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, &tx_hash, 100).await;

    let (contract_address, _receipt) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        0u128,
        &wallet,
        &mut network,
    )
    .await;
    // let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();

    let contract = ScillaInterop::new(contract_address, &wallet);

    // Construct a transaction which uses the scilla_call precompile.
    let hash = *contract
        .callScillaWithBadGas(
            scilla_contract_address,
            "InsertIntoMap".into(),
            "addr_to_int".into(),
            wallet.default_signer_address(),
            5,
        )
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();

    // Make sure the transaction succeeds.
    let receipt = network.run_until_receipt(&wallet, &hash, 100).await;
    assert!(receipt.status());
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn interop_call_then_revert(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library HelloWorld

        let one = Uint128 1
        let two = Uint128 2
        let big_number = Uint128 1234
        let addr = 0x0123456789012345678901234567890123456789

        contract Hello
        ()

        field num : Uint128 = big_number
        field str : String = "foobar"
        field addr_to_int : Map ByStr20 Uint128 =
          let emp = Emp ByStr20 Uint128 in
          builtin put emp addr one
        field addr_to_addr_to_int : Map ByStr20 (Map ByStr20 Uint128) =
          let emp1 = Emp ByStr20 Uint128 in
          let inner = builtin put emp1 addr one in
          let emp2 = Emp ByStr20 (Map ByStr20 Uint128) in
          builtin put emp2 addr inner

        transition InsertIntoMap(a: ByStr20, b: Uint128)
          addr_to_int[a] := b;
          e = {_eventname : "Inserted"; a : a; b : b};
          event e
        end

        transition GetFromMap(a: ByStr20)
            addr_to_int_o <- addr_to_int[a];

            match addr_to_int_o with
            | Some value =>
                e = {
                    _eventname: "Value";
                    element: value
                };
                event e
            | None =>
            end
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    // Bump the genesis wallet's nonce up, so that the next contract we deploy will be exempt from gas charges when
    // calling the `scilla_call` precompile.
    let tx_hash = *wallet
        .send_transaction(TransactionRequest::default().to(Address::ZERO))
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, &tx_hash, 100).await;

    let (evm_contract_address, _abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = ScillaInterop::new(evm_contract_address, &wallet);

    // Construct a transaction which uses the scilla_call precompile.
    let tx_hash = *contract
        .callScillaRevert(
            scilla_contract_address,
            "InsertIntoMap".into(),
            scilla_contract_address,
            5,
        )
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();

    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;

    assert!(!receipt.status());

    let call = format!(
        r#"
            {{
            "_tag": "GetFromMap",
            "params": [
                {{
                    "vname": "a",
                    "type": "ByStr20",
                    "value": "{scilla_contract_address:#x}"
                }}
            ]
           }}
        "#
    );

    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(scilla_contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(&call),
    )
    .await;

    assert!(txn["receipt"]["event_logs"].as_array().unwrap().is_empty());
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn interop_read_after_write(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library HelloWorld

        let one = Uint128 1
        let two = Uint128 2
        let big_number = Uint128 1234
        let addr = 0x0123456789012345678901234567890123456789

        contract Hello
        ()

        field num : Uint128 = big_number
        field str : String = "foobar"
        field addr_to_int : Map ByStr20 Uint128 =
          let emp = Emp ByStr20 Uint128 in
          builtin put emp addr one

        transition InsertIntoMap(a: ByStr20, b: Uint128)
          addr_to_int[a] := b;
          e = {_eventname : "Inserted"; a : a; b : b};
          event e
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    // Bump the genesis wallet's nonce up, so that the next contract we deploy will be exempt from gas charges when
    // calling the `scilla_call` precompile.
    let tx_hash = *wallet
        .send_transaction(TransactionRequest::default().to(Address::ZERO))
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, &tx_hash, 100).await;

    let (evm_contract_address, _abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        0u128,
        &wallet,
        &mut network,
    )
    .await;

    let contract = ScillaInterop::new(evm_contract_address, &wallet);

    // Construct a transaction which uses the scilla_call precompile.
    let tx_hash = *contract
        .readAfterWrite(
            scilla_contract_address,
            "InsertIntoMap".into(),
            scilla_contract_address,
            5,
            "addr_to_int".into(),
        )
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, &tx_hash, 100).await;
    assert!(receipt.status());
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn interop_nested_call_to_precompile_then_revert(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library HelloWorld

        let one = Uint128 1
        let two = Uint128 2
        let big_number = Uint128 1234
        let addr = 0x0123456789012345678901234567890123456789

        contract Hello
        ()

        field num : Uint128 = big_number
        field str : String = "foobar"
        field addr_to_int : Map ByStr20 Uint128 =
          let emp = Emp ByStr20 Uint128 in
          builtin put emp addr one

        transition InsertIntoMap(a: ByStr20, b: Uint128)
          addr_to_int[a] := b;
          e = {_eventname : "Inserted"; a : a; b : b};
          event e
        end

        transition GetFromMap(a: ByStr20)
            addr_to_int_o <- addr_to_int[a];

            match addr_to_int_o with
            | Some value =>
                e = {
                    _eventname: "Value";
                    element: value
                };
                event e
            | None =>
            end
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    // Bump the genesis wallet's nonce up, so that the next contract we deploy will be exempt from gas charges when
    // calling the `scilla_call` precompile.
    let tx_hash = *wallet
        .send_transaction(TransactionRequest::default().to(Address::ZERO))
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, &tx_hash, 100).await;

    let (evm_contract_address, _abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        0u128,
        &wallet,
        &mut network,
    )
    .await;
    let contract = ScillaInterop::new(evm_contract_address, &wallet);

    // Construct a transaction which uses the scilla_call precompile.
    let tx_hash = *contract
        .makeNestedPrecompileCallWhichReverts(
            scilla_contract_address,
            "InsertIntoMap".into(),
            scilla_contract_address,
            5,
            "addr_to_int".into(),
        )
        .gas(84_000_000)
        .send()
        .await
        .unwrap()
        .tx_hash();

    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> =
                    wallet.client().request("GetTransaction", [tx_hash]).await;
                response.is_ok()
            },
            400,
        )
        .await
        .unwrap();

    let eth_receipt = map_eth_receipt(&wallet, tx_hash).await;

    assert!(!eth_receipt.status);

    let call = format!(
        r#"
            {{
            "_tag": "GetFromMap",
            "params": [
                {{
                    "vname": "a",
                    "type": "ByStr20",
                    "value": "{scilla_contract_address:#x}"
                }}
            ]
           }}
        "#
    );

    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(scilla_contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(&call),
    )
    .await;

    assert!(txn["receipt"]["event_logs"].as_array().unwrap().is_empty());
}

#[zilliqa_macros::test]
async fn get_tx_block(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Ensure there is at least one block in the chain
    network.run_until_block_finalized(3u64, 100).await.unwrap();

    // Request the first block
    let block_number = "1";

    let response: Value = wallet
        .client()
        .request("GetTxBlock", [block_number])
        .await
        .expect("Failed to call GetTxBlock API");

    dbg!(&response);

    // Ensure the response is an object
    assert!(response.is_object(), "Expected response to be an object");

    // Verify header fields
    let header = &response["header"];
    assert_eq!(header["BlockNum"].as_str().unwrap(), block_number);
    assert!(
        header["DSBlockNum"].as_str().is_some(),
        "Missing DSBlockNum"
    );
    assert!(header["GasLimit"].as_str().is_some(), "Missing GasLimit");
    assert!(header["GasUsed"].as_str().is_some(), "Missing GasUsed");
    assert!(
        header["MbInfoHash"].as_str().is_some(),
        "Missing MbInfoHash"
    );
    assert!(
        header["NumMicroBlocks"].as_u64().is_some(),
        "Missing NumMicroBlocks"
    );
    assert!(header["NumPages"].as_u64().is_some(), "Missing NumPages");
    assert!(header["NumTxns"].as_u64().is_some(), "Missing NumTxns");
    assert!(
        header["PrevBlockHash"].as_str().is_some(),
        "Missing PrevBlockHash"
    );
    assert!(header["Rewards"].as_str().is_some(), "Missing Rewards");
    assert!(
        header["StateDeltaHash"].as_str().is_some(),
        "Missing StateDeltaHash"
    );
    assert!(
        header["StateRootHash"].as_str().is_some(),
        "Missing StateRootHash"
    );
    assert!(header["Timestamp"].as_str().is_some(), "Missing Timestamp");
    assert!(header["TxnFees"].as_str().is_some(), "Missing TxnFees");
    assert!(header["Version"].as_u64().is_some(), "Missing Version");

    // Verify body fields
    let body = &response["body"];
    let block_hash = body["BlockHash"].as_str().expect("Missing BlockHash");
    assert!(!block_hash.is_empty(), "BlockHash should not be empty");

    assert!(body["HeaderSign"].as_str().is_some(), "Missing HeaderSign");

    // Verify MicroBlockInfos
    let micro_blocks = body["MicroBlockInfos"]
        .as_array()
        .expect("Expected MicroBlockInfos to be an array");
    for micro_block in micro_blocks {
        assert!(
            micro_block["MicroBlockHash"].as_str().is_some(),
            "Missing MicroBlockHash"
        );
        assert!(
            micro_block["MicroBlockShardId"].as_u64().is_some(),
            "Missing MicroBlockShardId"
        );
        assert!(
            micro_block["MicroBlockTxnRootHash"].as_str().is_some(),
            "Missing MicroBlockTxnRootHash"
        );
    }

    // Additional validation of relationships between fields
    let num_micro_blocks = header["NumMicroBlocks"].as_u64().unwrap();
    assert_eq!(
        micro_blocks.len() as u64,
        num_micro_blocks,
        "NumMicroBlocks should match length of MicroBlockInfos array"
    );
}

#[zilliqa_macros::test]
async fn get_tx_block_verbose(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Ensure there is at least one block in the chain
    network.run_until_block_finalized(3u64, 100).await.unwrap();

    // Request the first block
    let block_number = "1";

    let response: Value = wallet
        .client()
        .request("GetTxBlockVerbose", [block_number])
        .await
        .expect("Failed to call GetTxBlockVerbose API");

    dbg!(&response);

    // Ensure the response is an object
    assert!(response.is_object(), "Expected response to be an object");

    // Verify header fields
    let header = &response["header"];
    assert_eq!(header["BlockNum"].as_str().unwrap(), block_number);
    assert!(
        header["CommitteeHash"].as_str().is_some(),
        "Missing CommitteeHash"
    );
    assert!(
        header["DSBlockNum"].as_str().is_some(),
        "Missing DSBlockNum"
    );
    assert!(header["GasLimit"].as_str().is_some(), "Missing GasLimit");
    assert!(header["GasUsed"].as_str().is_some(), "Missing GasUsed");
    assert!(
        header["MbInfoHash"].as_str().is_some(),
        "Missing MbInfoHash"
    );
    assert!(
        header["MinerPubKey"].as_str().is_some(),
        "Missing MinerPubKey"
    );
    assert!(
        header["NumMicroBlocks"].as_u64().is_some(),
        "Missing NumMicroBlocks"
    );
    assert!(header["NumPages"].as_u64().is_some(), "Missing NumPages");
    assert!(header["NumTxns"].as_u64().is_some(), "Missing NumTxns");
    assert!(
        header["PrevBlockHash"].as_str().is_some(),
        "Missing PrevBlockHash"
    );
    assert!(header["Rewards"].as_str().is_some(), "Missing Rewards");
    assert!(
        header["StateDeltaHash"].as_str().is_some(),
        "Missing StateDeltaHash"
    );
    assert!(
        header["StateRootHash"].as_str().is_some(),
        "Missing StateRootHash"
    );
    assert!(header["Timestamp"].as_str().is_some(), "Missing Timestamp");
    assert!(header["TxnFees"].as_str().is_some(), "Missing TxnFees");
    assert!(header["Version"].as_u64().is_some(), "Missing Version");

    // Verify body fields
    let body = &response["body"];

    // Verify B1 and B2 arrays
    assert!(body["B1"].as_array().is_some(), "Missing B1 array");
    assert!(body["B2"].as_array().is_some(), "Missing B2 array");

    // Verify all B1 and B2 elements are booleans
    for value in body["B1"].as_array().unwrap() {
        assert!(value.is_boolean(), "B1 array element is not a boolean");
    }
    for value in body["B2"].as_array().unwrap() {
        assert!(value.is_boolean(), "B2 array element is not a boolean");
    }

    let block_hash = body["BlockHash"].as_str().expect("Missing BlockHash");
    assert!(!block_hash.is_empty(), "BlockHash should not be empty");

    assert!(body["CS1"].as_str().is_some(), "Missing CS1");
    assert!(body["HeaderSign"].as_str().is_some(), "Missing HeaderSign");

    // Verify MicroBlockInfos
    let micro_blocks = body["MicroBlockInfos"]
        .as_array()
        .expect("Expected MicroBlockInfos to be an array");
    for micro_block in micro_blocks {
        assert!(
            micro_block["MicroBlockHash"].as_str().is_some(),
            "Missing MicroBlockHash"
        );
        assert!(
            micro_block["MicroBlockShardId"].as_u64().is_some(),
            "Missing MicroBlockShardId"
        );
        assert!(
            micro_block["MicroBlockTxnRootHash"].as_str().is_some(),
            "Missing MicroBlockTxnRootHash"
        );
    }

    // Additional validation of relationships between fields
    let num_micro_blocks = header["NumMicroBlocks"].as_u64().unwrap();
    assert_eq!(
        micro_blocks.len() as u64,
        num_micro_blocks,
        "NumMicroBlocks should match length of MicroBlockInfos array"
    );

    // Verify hash formats
    let is_valid_hash = |hash: &str| hash.len() == 64 || hash.starts_with("0x");
    assert!(
        is_valid_hash(header["CommitteeHash"].as_str().unwrap()),
        "Invalid CommitteeHash format"
    );
    assert!(
        is_valid_hash(header["MbInfoHash"].as_str().unwrap()),
        "Invalid MbInfoHash format"
    );
    assert!(
        is_valid_hash(header["PrevBlockHash"].as_str().unwrap()),
        "Invalid PrevBlockHash format"
    );
    assert!(
        is_valid_hash(header["StateDeltaHash"].as_str().unwrap()),
        "Invalid StateDeltaHash format"
    );
    assert!(
        is_valid_hash(header["StateRootHash"].as_str().unwrap()),
        "Invalid StateRootHash format"
    );

    // Verify timestamp is a valid number
    let timestamp = header["Timestamp"].as_str().unwrap();
    assert!(timestamp.parse::<u64>().is_ok(), "Invalid Timestamp format");
}

#[zilliqa_macros::test]
async fn get_smart_contract_init(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Deploy a Scilla contract
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;
    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    // Test the success case
    let response: Value = wallet
        .client()
        .request("GetSmartContractInit", [contract_address])
        .await
        .expect("Failed to call GetSmartContractInit API");

    let init_data: Vec<zilliqa::scilla::ParamValue> =
        serde_json::from_value(response).expect("Failed to deserialize response");

    // Assert the data returned from the API is a superset of the init data we passed.
    let expected_data: Vec<Value> = serde_json::from_str(&data).unwrap();
    for expected in expected_data {
        assert!(
            init_data
                .iter()
                .any(|d| serde_json::to_value(d).unwrap() == expected)
        );
    }

    // Test the error case with an invalid contract address
    let invalid_contract_address: H160 = "0x0000000000000000000000000000000000000000"
        .parse()
        .unwrap();
    let response = wallet
        .client()
        .request::<_, Value>("GetSmartContractInit", [invalid_contract_address])
        .await;

    assert!(response.is_err());
    if let Some(rpc_error) = response.err()
        && let Some(json_error) = rpc_error.as_error_resp()
    {
        assert_eq!(json_error.code, -32603); // Invalid params error code
        assert!(json_error.message.contains("Address does not exist"));
    } else {
        panic!("Expected JSON-RPC error response");
    }
}

#[zilliqa_macros::test]
async fn get_ds_block(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetDSBlock", ["9000"])
        .await
        .expect("Failed to call GetDSBlock API");

    zilliqa::api::types::zil::DSBlock::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_ds_block_verbose(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetDSBlockVerbose", ["9000"])
        .await
        .expect("Failed to call GetDSBlockVerbose API");

    zilliqa::api::types::zil::DSBlockVerbose::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_latest_ds_block(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetLatestDSBlock", [""])
        .await
        .expect("Failed to call GetLatestDSBlock API");

    zilliqa::api::types::zil::DSBlock::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_current_ds_comm(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetCurrentDSComm", [""])
        .await
        .expect("Failed to call GetCurrentDSComm API");

    zilliqa::api::types::zil::GetCurrentDSCommResult::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_current_ds_epoch(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetCurrentDSEpoch", [""])
        .await
        .expect("Failed to call GetCurrentDSEpoch API");

    assert!(response.is_string());
}

#[zilliqa_macros::test]
async fn ds_block_listing(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(8u64, 300).await.unwrap();

    let response: Value = wallet
        .client()
        .request("DSBlockListing", [1])
        .await
        .expect("Failed to call DSBlockListing API");

    zilliqa::api::types::zil::DSBlockListingResult::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_ds_block_rate(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetDSBlockRate", [""])
        .await
        .expect("Failed to call GetDSBlockRate API");

    let returned = zilliqa::api::types::zil::DSBlockRateResult::deserialize(&response).unwrap();

    assert!(returned.rate >= 0.0, "Block rate should be non-negative");
}

#[zilliqa_macros::test]
async fn get_tx_block_rate_0(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetTxBlockRate", [""])
        .await
        .expect("Failed to call GetTxBlockRate API");

    let returned = zilliqa::api::types::zil::TXBlockRateResult::deserialize(&response).unwrap();

    assert!(returned.rate >= 0.0, "Block rate should be non-negative");
}

#[zilliqa_macros::test]
async fn get_tx_block_rate_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(3u64, 100).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetTxBlockRate", [""])
        .await
        .expect("Failed to call GetTxBlockRate API");

    let returned = zilliqa::api::types::zil::TXBlockRateResult::deserialize(&response).unwrap();

    assert!(returned.rate > 0.0, "Block rate should be positive");
}

#[zilliqa_macros::test]
async fn get_num_peers(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .client()
        .request("GetNumPeers", [""])
        .await
        .expect("Failed to call GetNumPeers API");

    assert!(
        response.is_number(),
        "Expected response to be a number, got: {response:?}"
    );
}

#[zilliqa_macros::test]
async fn get_tx_rate_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    network.run_until_block_finalized(1u64, 100).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetTransactionRate", [""])
        .await
        .expect("Failed to call GetTxRate API");

    let tx_rate: f64 = serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(tx_rate >= 0.0, "Transaction rate should be non-negative");

    network.run_until_block_finalized(8u64, 300).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetTransactionRate", [""])
        .await
        .expect("Failed to call GetTxRate API");

    let tx_rate: f64 = serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(tx_rate >= 0.0, "Transaction rate should be non-negative");
}

#[zilliqa_macros::test]
async fn get_tx_rate_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 300).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetTransactionRate", [""])
        .await
        .expect("Failed to call GetTxRate API");

    let tx_rate: f64 = serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(tx_rate > 0.0, "Transaction block rate should be positive");
}

#[zilliqa_macros::test]
async fn get_txns_for_tx_block_ex_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    network.run_until_block_finalized(2, 100).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetTransactionsForTxBlockEx", ["1", "1"])
        .await
        .expect("Failed to call GetTransactionsForTxBlockEx API");

    let txns: zilliqa::api::types::zil::TxnsForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txns.curr_page, 1);
    assert!(
        txns.transactions.len() <= 2500,
        "Expected Transactions length to be less than or equal to 2500"
    );
}

#[zilliqa_macros::test]
async fn test_simulate_transactions(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    // Verify the sender's nonce has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [to_addr])
        .await
        .unwrap();
    assert_eq!(response["balance"].as_str().unwrap(), "200000000000000");

    let node = network.get_node(0);

    let mut num_transactions = 0;
    let mut i = 0;
    while let Some(b) = node.get_block(i).unwrap() {
        for tx in b.transactions.iter() {
            num_transactions += 1;
            println!("Block {:?}, transaction {:?}", &b, &tx);
        }
        i += 1;
    }

    assert!(num_transactions >= 1);
}

#[zilliqa_macros::test]
async fn get_txns_for_tx_block_ex_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 300).await.unwrap();

    let result: zilliqa::api::types::zil::GetTxResponse =
        serde_json::from_value(txn).expect("serdes error");

    let block_number = result.receipt.epoch_num;
    let page_number = 0;

    let response: Value = wallet
        .client()
        .request(
            "GetTransactionsForTxBlockEx",
            [
                block_number.to_string().as_str(),
                page_number.to_string().as_str(),
            ],
        )
        .await
        .expect("Failed to call GetTransactionsForTxBlockEx API");

    let txns: zilliqa::api::types::zil::TxnsForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txns.curr_page, page_number);
    assert!(
        txns.transactions.len() <= 2500,
        "Expected Transactions length to be less than or equal to 2500"
    );
    assert!(
        !txns.transactions.is_empty(),
        "Expected Transactions length to be greater than or equal to 1"
    );
}

#[zilliqa_macros::test]
async fn get_txns_for_tx_block_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2, 300).await.unwrap();

    let result: zilliqa::api::types::zil::GetTxResponse =
        serde_json::from_value(txn).expect("serdes error");

    let block_number = result.receipt.epoch_num;

    let response: Value = wallet
        .client()
        .request(
            "GetTransactionsForTxBlock",
            [block_number.to_string().as_str()],
        )
        .await
        .expect("Failed to call GetTransactionsForTxBlock API");

    let txns: Vec<Vec<String>> =
        serde_json::from_value(response.clone()).expect("Failed to deserialize response");

    assert!(
        !txns[0].is_empty(),
        "Expected Transactions length to be greater than or equal to 1"
    );

    // Check it's an array of arrays of transaction hashes
    assert!(response.is_array());
    if let Some(shards) = response.as_array()
        && !shards.is_empty()
    {
        assert!(shards[0].is_array());
        if let Some(txns) = shards[0].as_array()
            && !txns.is_empty()
        {
            // Each hash should be a 32 byte hex string
            assert!(txns[0].is_string());
            assert_eq!(txns[0].as_str().unwrap().len(), 64);
        }
    }
}

#[zilliqa_macros::test]
async fn get_txn_bodies_for_tx_block_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 300).await.unwrap();

    let result: zilliqa::api::types::zil::GetTxResponse =
        serde_json::from_value(txn).expect("serdes error");

    let block_number = result.receipt.epoch_num;

    let response: Value = wallet
        .client()
        .request(
            "GetTxnBodiesForTxBlock",
            [block_number.to_string().as_str()],
        )
        .await
        .expect("Failed to call GetTxnBodiesForTxBlock API");

    let txn_bodies: Vec<zilliqa::api::types::zil::TransactionBody> =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(
        !txn_bodies.is_empty(),
        "Expected Transactions length to be greater than or equal to 1"
    );
}

#[zilliqa_macros::test]
async fn get_txn_bodies_for_tx_block_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 300).await.unwrap();

    let result: zilliqa::api::types::zil::GetTxResponse =
        serde_json::from_value(txn).expect("serdes error");

    let block_number = result.receipt.epoch_num;

    let response: Value = wallet
        .client()
        .request(
            "GetTxnBodiesForTxBlock",
            [block_number.to_string().as_str()],
        )
        .await
        .expect("Failed to call GetTxnBodiesForTxBlock API");

    let txn_bodies: Vec<zilliqa::api::types::zil::TransactionBody> =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(
        !txn_bodies.is_empty(),
        "Expected Transactions length to be greater than or equal to 1"
    );
    assert!(
        txn_bodies.len() <= 2500,
        "Expected Transactions length to be less than or equal to 2500"
    );
}

#[zilliqa_macros::test]
async fn get_txn_bodies_for_tx_block_ex_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 300).await.unwrap();

    let result: zilliqa::api::types::zil::GetTxResponse =
        serde_json::from_value(txn).expect("serdes error");

    let block_number = result.receipt.epoch_num;
    let page_number = 2;

    let response: Value = wallet
        .client()
        .request(
            "GetTxnBodiesForTxBlockEx",
            [
                block_number.to_string().as_str(),
                page_number.to_string().as_str(),
            ],
        )
        .await
        .expect("Failed to call GetTxnBodiesForTxBlockEx API");

    let txn_bodies: zilliqa::api::types::zil::TxnBodiesForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txn_bodies.curr_page, page_number);
    assert!(
        txn_bodies.num_pages > 0,
        "Expected NumPages to be greater than 0"
    );
    assert!(
        txn_bodies.transactions.len() <= 2500,
        "Expected Transactions length to be less than or equal to 2500"
    );
}

#[zilliqa_macros::test]
async fn get_txn_bodies_for_tx_block_ex_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 300).await.unwrap();

    let result: zilliqa::api::types::zil::GetTxResponse =
        serde_json::from_value(txn).expect("serdes error");

    let block_number = result.receipt.epoch_num;
    let page_number = 0;

    let response: Value = wallet
        .client()
        .request(
            "GetTxnBodiesForTxBlockEx",
            [
                block_number.to_string().as_str(),
                page_number.to_string().as_str(),
            ],
        )
        .await
        .expect("Failed to call GetTxnBodiesForTxBlockEx API");

    let result = response["result"].clone();

    let txn_bodies: zilliqa::api::types::zil::TxnBodiesForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txn_bodies.curr_page, page_number);
    assert!(
        txn_bodies.num_pages > 0,
        "Expected NumPages to be greater than 0"
    );
    assert!(
        txn_bodies.transactions.len() <= 2500,
        "Expected Transactions length to be less than or equal to 2500"
    );
    assert!(
        !txn_bodies.transactions.is_empty(),
        "Expected Transactions length to be greater than or equal to 1"
    );

    // Check transaction array structure
    if let Some(shards) = result["Transactions"].as_array()
        && !shards.is_empty()
        && !shards[0].is_null()
    {
        assert!(shards[0].is_array());
        if let Some(txns) = shards[0].as_array()
            && !txns.is_empty()
        {
            assert!(txns[0].is_string());
            assert_eq!(txns[0].as_str().unwrap().len(), 64);
        }
    }
}

#[zilliqa_macros::test]
async fn get_num_ds_blocks(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .client()
        .request("GetNumDSBlocks", [""])
        .await
        .expect("Failed to call GetNumDSBlocks API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {response:?}"
    );
}

#[zilliqa_macros::test]
async fn get_recent_transactions_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .client()
        .request("GetRecentTransactions", [""])
        .await
        .expect("Failed to call GetRecentTransactions API");

    let recent_transactions =
        zilliqa::api::types::zil::RecentTransactionsResponse::deserialize(&response)
            .expect("Failed to deserialize response");

    assert_eq!(
        recent_transactions.number as usize,
        recent_transactions.txn_hashes.len()
    );
    assert!(recent_transactions.number < 100);
}

#[zilliqa_macros::test]
async fn get_recent_transactions_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(1u64, 300).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetRecentTransactions", [""])
        .await
        .expect("Failed to call GetRecentTransactions API");

    let recent_transactions =
        zilliqa::api::types::zil::RecentTransactionsResponse::deserialize(&response)
            .expect("Failed to deserialize response");

    assert_eq!(
        recent_transactions.number as usize,
        recent_transactions.txn_hashes.len()
    );
    assert_eq!(recent_transactions.number, 4);
}

// #[zilliqa_macros::test] // Disabled since API is currently not working
// async fn get_num_transactions_0(mut network: Network) {
//     let wallet = network.genesis_wallet().await;

//     let response: Value = wallet
//         .client()
//         .request("GetNumTransactions", [""])
//         .await
//         .expect("Failed to call GetNumTransactions API");

//     assert!(
//         response.is_string(),
//         "Expected response to be a string, got: {:?}",
//         response
//     );
//     response
//         .as_str()
//         .expect("Expected response to be a string")
//         .parse::<u64>()
//         .expect("Failed to parse response as u64");
// }

// Disabled since API is currently not working
// #[zilliqa_macros::test] // Disabled since API is currently not working
// async fn get_num_transactions_1(mut network: Network) {
//     let wallet = network.random_wallet().await;

//     let (secret_key, _address) = zilliqa_account(&mut network).await;

//     let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
//         .parse()
//         .unwrap();
//     send_transaction(
//         &mut network,
//         &secret_key,
//         1,
//         ToAddr::Address(to_addr),
//         200u128 * 10u128.pow(12),
//         50_000,
//         None,
//         None,
//     )
//     .await;

//     network.run_until_block_finalized(1u64, 100).await.unwrap();

//     let (secret_key, _address) = zilliqa_account(&mut network).await;

//     let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
//         .parse()
//         .unwrap();
//     send_transaction(
//         &mut network,
//         &secret_key,
//         1,
//         ToAddr::Address(to_addr),
//         200u128 * 10u128.pow(12),
//         50_000,
//         None,
//         None,
//     )
//     .await;

//     network.run_until_block_finalized(8u64, 300).await.unwrap();

//     let response: Value = wallet
//         .client()
//         .request("GetNumTransactions", [""])
//         .await
//         .expect("Failed to call GetNumTransactions API");

//     assert!(
//         response.is_string(),
//         "Expected response to be a string, got: {:?}",
//         response
//     );

//     let response_num = response
//         .as_str()
//         .expect("Expected response to be a string")
//         .parse::<u64>()
//         .expect("Failed to parse response as u64");

//     assert_eq!(response_num, 4);
// }

#[zilliqa_macros::test]
async fn get_num_txns_ds_epoch_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .client()
        .request("GetNumTxnsDSEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsDSEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {response:?}"
    );
}

#[zilliqa_macros::test]
async fn get_num_txns_ds_epoch_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 100).await.unwrap();

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(3u64, 300).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetNumTxnsDSEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsDSEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {response:?}"
    );

    let response_num = response
        .as_str()
        .expect("Expected response to be a string")
        .parse::<u64>()
        .expect("Failed to parse response as u64");

    assert_eq!(response_num, 3);
}

#[zilliqa_macros::test]
async fn get_num_txns_tx_epoch_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .client()
        .request("GetNumTxnsTXEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsTxEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {response:?}"
    );
}

#[zilliqa_macros::test]
async fn get_num_txns_tx_epoch_1(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(2u64, 100).await.unwrap();

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await;

    network.run_until_block_finalized(3u64, 300).await.unwrap();

    let response: Value = wallet
        .client()
        .request("GetNumTxnsTXEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsTXEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {response:?}"
    );

    let response_num = response
        .as_str()
        .expect("Expected response to be a string")
        .parse::<u64>()
        .expect("Failed to parse response as u64");

    assert_eq!(response_num, 1);
}

#[zilliqa_macros::test]
async fn combined_total_coin_supply_test(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response_str: Value = wallet
        .client()
        .request("GetTotalCoinSupply", [""])
        .await
        .expect("Failed to call GetTotalCoinSupply API");

    assert!(
        response_str.is_string(),
        "Expected response to be a string, got: {response_str:?}"
    );

    let total_coin_supply_str = response_str.as_str().expect("Expected string conversion");
    let total_coin_supply_as_f64_from_str: f64 = total_coin_supply_str
        .parse()
        .expect("Expected string to be parsed as an integer");

    let response_int: Value = wallet
        .client()
        .request("GetTotalCoinSupplyAsInt", [""])
        .await
        .expect("Failed to call GetTotalCoinSupplyAsInt API");

    assert!(
        response_int.is_number(),
        "Expected response to be a number, got: {response_int:?}"
    );

    let total_coin_supply_as_int: u128 = response_int
        .as_number()
        .expect("Expected number conversion")
        .as_u128()
        .expect("Expected u128 conversion");

    assert!(
        (total_coin_supply_as_f64_from_str - total_coin_supply_as_int as f64).abs() < 1.0,
        "Total coin supply from string and int APIs should be the same"
    );

    assert_eq!(
        total_coin_supply_as_int, 1000000256,
        "Total coin supply should be 1000000256"
    )
}

#[zilliqa_macros::test]
async fn get_miner_info(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .client()
        .request("GetMinerInfo", ["5500"])
        .await
        .expect("Failed to call GetMinerInfo API");

    zilliqa::api::types::zil::MinerInfo::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_node_type(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    let response: Value = wallet
        .client()
        .request("GetNodeType", [""])
        .await
        .expect("Failed to call GetNodeType API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {response:?}"
    );

    let allowed_node_types = ["Seed"];
    let response_str = response.as_str().expect("Expected response to be a string");

    assert!(
        allowed_node_types.contains(&response_str),
        "Unexpected node type: {response_str}"
    );
}

// #[allow(dead_code)]
// async fn get_prev_difficulty(mut network: Network) {
//     let wallet = network.genesis_wallet().await;

//     let response: Value = wallet
//         .client()
//         .request("GetPrevDifficulty", [""])
//         .await
//         .expect("Failed to call GetPrevDifficulty API");

//     assert!(
//         response.is_u64(),
//         "Expected response to be a u64, got: {response:?}"
//     );

//     let response_u64 = response.as_u64().expect("Expected response to be a u64");

//     assert_eq!(response_u64, 0);
// }

// #[allow(dead_code)]
// async fn get_prev_ds_difficulty(mut network: Network) {
//     let wallet = network.genesis_wallet().await;

//     let response: Value = wallet
//         .client()
//         .request("GetPrevDSDifficulty", [""])
//         .await
//         .expect("Failed to call GetPrevDSDifficulty API");

//     assert!(
//         response.is_u64(),
//         "Expected response to be a u64, got: {response:?}"
//     );

//     let response_u64 = response.as_u64().expect("Expected response to be a u64");

//     assert_eq!(response_u64, 0);
// }

#[zilliqa_macros::test]
async fn get_sharding_structure(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Get the sharding structure
    let response: Value = wallet
        .client()
        .request("GetShardingStructure", [""])
        .await
        .expect("Failed to call GetShardingStructure API");

    // Deserialize the response into our expected type
    let sharding_structure: zilliqa::api::types::zil::ShardingStructure =
        serde_json::from_value(response).expect("Failed to deserialize response");

    // Since Zilliqa 2.0 uses XShard instead of traditional sharding,
    // we expect exactly one shard with the number of connected peers
    assert_eq!(
        sharding_structure.num_peers.len(),
        1,
        "Expected exactly one shard in sharding structure"
    );

    // Get the number of peers to verify
    let num_peers_response: Value = wallet
        .client()
        .request("GetNumPeers", [""])
        .await
        .expect("Failed to call GetNumPeers API");

    let num_peers = num_peers_response
        .as_u64()
        .expect("Expected GetNumPeers to return a number");

    // Verify that the number of peers matches
    assert_eq!(
        sharding_structure.num_peers[0], num_peers,
        "Number of peers in sharding structure doesn't match GetNumPeers"
    );
}

// We need to restrict the concurrency level of this test, because each node in the network will spawn a TCP listener
// once it invokes Scilla. When many tests are run in parallel, this results in "Too many open files" errors.
#[zilliqa_macros::test(restrict_concurrency)]
async fn get_smart_contract_sub_state(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;
    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    let api_code: Value = wallet
        .client()
        .request("GetSmartContractCode", [contract_address])
        .await
        .unwrap();
    assert_eq!(code, api_code["code"]);

    let api_data: Vec<Value> = wallet
        .client()
        .request("GetSmartContractInit", [contract_address])
        .await
        .unwrap();
    // Assert the data returned from the API is a superset of the init data we passed.
    assert!(
        serde_json::from_str::<Vec<Value>>(&data)
            .unwrap()
            .iter()
            .all(|d| api_data.contains(d))
    );

    let call = r#"{
        "_tag": "setHello",
        "params": [
            {
                "vname": "msg",
                "value": "foobar",
                "type": "String"
            }
        ]
    }"#;
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await;
    let event = &txn["receipt"]["event_logs"][0];
    assert_eq!(event["_eventname"], "setHello");
    assert_eq!(event["params"][0]["value"], "2");

    let call = r#"{
        "_tag": "getHello",
        "params": []
    }"#;
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        3,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await;
    for event in txn["receipt"]["event_logs"].as_array().unwrap() {
        assert_eq!(event["_eventname"], "getHello");
        assert_eq!(event["params"][0]["value"], "foobar");
    }

    network.run_until_block_finalized(8u64, 300).await.unwrap();

    let state: serde_json::Value = wallet
        .client()
        .request("GetSmartContractState", [contract_address])
        .await
        .unwrap();
    assert_eq!(state["welcome_msg"], "foobar");

    let empty_string_vec: Vec<String> = vec![]; // Needed for type annotation
    let substate0: serde_json::Value = wallet
        .client()
        .request(
            "GetSmartContractSubState",
            (contract_address, "", empty_string_vec.clone()),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");
    assert_eq!(substate0, state);

    let substate1: serde_json::Value = wallet
        .client()
        .request(
            "GetSmartContractSubState",
            (contract_address, "welcome_msg", empty_string_vec),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");
    assert_eq!(substate1["welcome_msg"], "foobar");
    assert!(substate1.get("welcome_map").is_none());

    let substate2: serde_json::Value = wallet
        .client()
        .request(
            "GetSmartContractSubState",
            (contract_address, "welcome_map", ["1", "2"]),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");
    assert_eq!(
        substate2["welcome_map"]["1"]["2"].as_str().unwrap(),
        "foobar"
    );
    assert!(substate2.get("welcome_msg").is_none());
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn get_smart_contract_sub_state_empty_should_return_null(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;
    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    network.run_until_block_finalized(5u64, 300).await.unwrap();

    // Test querying for a non-existent variable name
    let empty_string_vec: Vec<String> = vec![];
    let substate_nonexistent: serde_json::Value = wallet
        .client()
        .request(
            "GetSmartContractSubState",
            (
                contract_address,
                "nonexistent_variable",
                empty_string_vec.clone(),
            ),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");

    // ZQ1 returns null for non-existent variables, ZQ2 should match this behavior
    // This test will fail initially, demonstrating the bug where {} is returned instead of null
    assert_eq!(substate_nonexistent, serde_json::Value::Null);

    // Test querying for non-existent indices in an existing map
    let substate_nonexistent_indices: serde_json::Value = wallet
        .client()
        .request(
            "GetSmartContractSubState",
            (contract_address, "welcome_map", ["nonexistent_key"]),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");

    // ZQ1 returns null for non-existent map indices, ZQ2 should match this behavior
    // This test will also fail initially, demonstrating the bug where {} is returned instead of null
    assert_eq!(substate_nonexistent_indices, serde_json::Value::Null);
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn nested_maps_insert_removal(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    // Set nested map to some value
    {
        let call = r#"{
        "_tag": "setHello",
        "params": [
            {
                "vname": "msg",
                "value": "foobar",
                "type": "String"
            }
        ]
    }"#;

        let (_, txn) = send_transaction(
            &mut network,
            &wallet,
            &secret_key,
            2,
            ToAddr::Address(H160::from_slice(contract_address.as_slice())),
            0,
            50_000,
            None,
            Some(call),
        )
        .await;
        let event = &txn["receipt"]["event_logs"][0];
        assert_eq!(event["_eventname"], "setHello");
    }

    // Confirm the value exists in the nested map
    {
        let call = r#"{
        "_tag": "getHello",
        "params": []
    }"#;
        let (_, txn) = send_transaction(
            &mut network,
            &wallet,
            &secret_key,
            3,
            ToAddr::Address(H160::from_slice(contract_address.as_slice())),
            0,
            50_000,
            None,
            Some(call),
        )
        .await;
        for event in txn["receipt"]["event_logs"].as_array().unwrap() {
            assert_eq!(event["_eventname"], "getHello");
            assert_eq!(event["params"][0]["value"], "foobar");
        }
    }

    // Remove entry from map
    {
        let call = r#"{
        "_tag": "removeHello",
        "params": []
    }"#;

        let (_, txn) = send_transaction(
            &mut network,
            &wallet,
            &secret_key,
            4,
            ToAddr::Address(H160::from_slice(contract_address.as_slice())),
            0,
            50_000,
            None,
            Some(call),
        )
        .await;
        let event = &txn["receipt"]["event_logs"][0];
        assert_eq!(event["_eventname"], "removeHello");
    }

    // Check and confirm the entry does not exist anymore
    {
        let call = r#"{
        "_tag": "getHello",
        "params": []
    }"#;
        let (_, txn) = send_transaction(
            &mut network,
            &wallet,
            &secret_key,
            5,
            ToAddr::Address(H160::from_slice(contract_address.as_slice())),
            0,
            50_000,
            None,
            Some(call),
        )
        .await;
        let event = &txn["receipt"]["event_logs"][0];
        assert_eq!(event["params"][0]["value"], "failed");
    }
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn failed_scilla_contract_proper_fee(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    let initial_balance = wallet.get_balance(address).await.unwrap().to::<u128>();

    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();

    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();
    let gas_limit = 50_000;

    let amount_to_transfer = 10 * 10u128.pow(12);

    let call = format!(
        r#"{{
        "_tag": "callFailure",
        "_amount": "0x{amount_to_transfer:x}",
        "params": [
            {{
                "vname": "addr",
                "type": "ByStr20",
                "value": "0x{contract_address:x}"
            }}
        ]
         }}"#
    );

    let response = issue_create_transaction(
        &wallet,
        &secret_key.public_key(),
        gas_price,
        &mut network,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        amount_to_transfer,
        gas_limit as u64,
        None,
        Some(&call),
    )
    .await
    .unwrap();

    let txn_hash: H256 = response["TranID"].as_str().unwrap().parse().unwrap();

    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> =
                    wallet.client().request("GetTransaction", [txn_hash]).await;
                response.is_ok()
            },
            400,
        )
        .await
        .unwrap();

    let eth_receipt = map_eth_receipt(&wallet, TxHash::from_slice(txn_hash.as_bytes())).await;
    assert!(!eth_receipt.status);

    // Verify the sender's nonce has increased using the `GetBalance` API.
    let response: Value = wallet
        .client()
        .request("GetBalance", [address])
        .await
        .unwrap();
    println!("GetBalance() after transfer = {response:?}");
    assert_eq!(response["nonce"].as_u64().unwrap(), 2);

    let transaction_fee =
        eth_receipt.cumulative_gas_used.0 as u128 * eth_receipt.effective_gas_price;

    let balance_after_failed_call = wallet.get_balance(address).await.unwrap().to::<u128>();

    assert_eq!(balance_after_failed_call, initial_balance - transaction_fee);
}

#[zilliqa_macros::test]
async fn get_state_proof(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let contract_address = "6d84363526a2d764835f8cf52dfeefe80a360fac";
    let variable_hash = "A0BD91DE66D97E6930118179BA4F1836C366C4CB3309A6B354D26F52ABB2AAC6";
    let tx_block = "39";

    let response: Value = wallet
        .client()
        .request("GetStateProof", [contract_address, variable_hash, tx_block])
        .await
        .expect("Failed to call GetStateProof API");

    let _state_proof: zilliqa::api::types::zil::StateProofResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");
}

// LLM generated, may be buggy
#[zilliqa_macros::test]
async fn get_transaction_status(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Test 1: Create a transaction and check it while pending/dispatched
    let (secret_key_1, _address_1) = zilliqa_account(&mut network, &wallet).await;
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    // Get the gas price via the Zilliqa API.
    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();

    // Send first transaction (nonce 1) - should be dispatched initially
    let response = issue_create_transaction(
        &wallet,
        &secret_key_1.public_key(),
        gas_price,
        &mut network,
        &secret_key_1,
        1,
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await
    .unwrap();
    let txn_hash_1: H256 = response["TranID"].as_str().unwrap().parse().unwrap();

    // Check status immediately - should be dispatched (pending)
    let response_dispatched: Value = wallet
        .client()
        .request("GetTransactionStatus", [txn_hash_1])
        .await
        .expect("Failed to call GetTransactionStatus API");

    let tx_status_dispatched: zilliqa::api::types::zil::TransactionStatusResponse =
        serde_json::from_value(response_dispatched).expect("Failed to deserialize response");

    assert!(matches!(
        tx_status_dispatched.status,
        zilliqa::api::types::zil::TxnStatusCode::Dispatched
    ));
    assert_eq!(tx_status_dispatched.modification_state, 1);

    // Test 2: Send transaction with future nonce - should be queued
    let response = issue_create_transaction(
        &wallet,
        &secret_key_1.public_key(),
        gas_price,
        &mut network,
        &secret_key_1,
        3, // Skip nonce 2, so this will be queued
        ToAddr::Address(to_addr),
        200u128 * 10u128.pow(12),
        50_000,
        None,
        None,
    )
    .await
    .unwrap();
    let txn_hash_queued: H256 = response["TranID"].as_str().unwrap().parse().unwrap();

    // Check status - should be queued due to high nonce
    let response_queued: Value = wallet
        .client()
        .request("GetTransactionStatus", [txn_hash_queued])
        .await
        .expect("Failed to call GetTransactionStatus API");

    let tx_status_queued: zilliqa::api::types::zil::TransactionStatusResponse =
        serde_json::from_value(response_queued).expect("Failed to deserialize response");

    assert!(matches!(
        tx_status_queued.status,
        zilliqa::api::types::zil::TxnStatusCode::PresentNonceHigh
    ));
    assert_eq!(tx_status_queued.modification_state, 1);

    // Test 3: Wait for first transaction to be mined and finalized
    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> = wallet
                    .client()
                    .request("GetTransaction", [txn_hash_1])
                    .await;
                response.is_ok()
            },
            400,
        )
        .await
        .unwrap();

    // Wait for the block to be finalized
    network.run_until_block_finalized(3u64, 300).await.unwrap();

    // Check status after finalization - should be confirmed
    let response_confirmed: Value = wallet
        .client()
        .request("GetTransactionStatus", [txn_hash_1])
        .await
        .expect("Failed to call GetTransactionStatus API");

    let tx_status_confirmed: zilliqa::api::types::zil::TransactionStatusResponse =
        serde_json::from_value(response_confirmed).expect("Failed to deserialize response");

    assert!(matches!(
        tx_status_confirmed.status,
        zilliqa::api::types::zil::TxnStatusCode::Confirmed
    ));
    assert_eq!(tx_status_confirmed.modification_state, 2);
    assert!(tx_status_confirmed.success);
    assert!(!tx_status_confirmed.epoch_inserted.is_empty());
    assert!(!tx_status_confirmed.epoch_updated.is_empty());

    // Test 4: Create a transaction that will fail/error
    let (secret_key_error, _) = zilliqa_account(&mut network, &wallet).await;

    // Deploy a contract that will revert
    let revert_code = r#"
        scilla_version 0

        contract RevertContract
        ()

        transition AlwaysRevert()
            throw
        end
    "#;

    let revert_data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let (revert_contract_address, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key_error,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(revert_code),
        Some(revert_data),
    )
    .await;
    let revert_contract_address = revert_contract_address.unwrap();

    // Call the reverting function
    let call = r#"{
        "_tag": "AlwaysRevert",
        "params": []
    }"#;

    let response_error = issue_create_transaction(
        &wallet,
        &secret_key_error.public_key(),
        gas_price,
        &mut network,
        &secret_key_error,
        2,
        ToAddr::Address(H160::from_slice(revert_contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await
    .unwrap();
    let txn_hash_error: H256 = response_error["TranID"].as_str().unwrap().parse().unwrap();

    // Wait for the error transaction to be mined
    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> = wallet
                    .client()
                    .request("GetTransaction", [txn_hash_error])
                    .await;
                response.is_ok()
            },
            400,
        )
        .await
        .unwrap();

    // Wait for finalization
    network.run_until_block_finalized(5u64, 300).await.unwrap();

    // Check status of error transaction - should be confirmed but with success=false
    let response_error_status: Value = wallet
        .client()
        .request("GetTransactionStatus", [txn_hash_error])
        .await
        .expect("Failed to call GetTransactionStatus API");

    let tx_status_error: zilliqa::api::types::zil::TransactionStatusResponse =
        serde_json::from_value(response_error_status).expect("Failed to deserialize response");

    // Even failed transactions show as "Confirmed" once they're in a finalized block
    assert!(matches!(
        tx_status_error.status,
        zilliqa::api::types::zil::TxnStatusCode::Error
    ));
    assert_eq!(tx_status_error.modification_state, 2);
    assert!(!tx_status_error.success); // This should be false for failed transactions

    // Verify all basic fields are properly formatted
    assert!(tx_status_confirmed.amount.parse::<u128>().is_ok());
    assert!(tx_status_confirmed.gas_limit.parse::<u64>().is_ok());
    assert!(tx_status_confirmed.gas_price.parse::<u64>().is_ok());
    assert!(tx_status_confirmed.nonce.parse::<u64>().is_ok());
    assert!(!tx_status_confirmed.to_addr.is_empty());
    assert!(!tx_status_confirmed.version.is_empty());
}

#[zilliqa_macros::test]
async fn get_blockchain_info_structure(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let result: Value = wallet
        .client()
        .request("GetBlockchainInfo", [""])
        .await
        .expect("Failed to call GetBlockchainInfo API");

    // Verify all required fields exist and have correct types
    assert!(result["CurrentDSEpoch"].is_string());
    assert!(result["CurrentMiniEpoch"].is_string());
    assert!(result["DSBlockRate"].is_number());
    assert!(result["NumDSBlocks"].is_string());
    assert!(result["NumPeers"].is_number());
    assert!(result["NumTransactions"].is_string());
    assert!(result["NumTxBlocks"].is_string());
    assert!(result["NumTxnsDSEpoch"].is_string());
    assert!(result["NumTxnsTxEpoch"].is_string());
    assert!(result["TransactionRate"].is_number());
    assert!(result["TxBlockRate"].is_number());

    // Verify ShardingStructure
    assert!(result["ShardingStructure"]["NumPeers"].is_array());
}

#[zilliqa_macros::test]
async fn get_num_tx_blocks_structure(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .client()
        .request("GetNumTxBlocks", [""])
        .await
        .expect("Failed to call GetNumTxBlocks API");

    // Should be a string containing a number
    assert!(response.is_string());
    assert!(response.as_str().unwrap().parse::<u64>().is_ok());
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn return_map_and_parse(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        contract ReturnMap
        ()

        field complex_map : Map ByStr20 (Map BNum Uint128) = Emp ByStr20 (Map BNum Uint128)

        transition AddToMap(a: ByStr20, b: BNum, c: Uint128)
            complex_map[a][b] := c
        end

        transition GetFromMap(a: ByStr20)
            complex_map_o <- complex_map[a];

            match complex_map_o with
            | Some complex_map =>
                values_list = builtin to_list complex_map;

                e = {
                    _eventname: "MapValues";
                    a: a;
                    values_list: values_list
                };
                event e
            | None =>
            end
        end
    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, code, data, 0_u128).await;

    // Set nested map to some value
    let call = r#"{
        "_tag": "AddToMap",
        "params": [
            {
                "vname": "a",
                "type": "ByStr20",
                "value": "0x964d9004b1ba9f362766cd681e9f97837a5cbb85"
            },
            {
                "vname": "b",
                "value": "1",
                "type": "BNum"
            },
            {
                "vname": "c",
                "value": "100",
                "type": "Uint128"
            }
        ]
    }"#;

    let (_, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await;

    // Parse returned nested map
    let call = r#"{
        "_tag": "GetFromMap",
        "params": [
            {
                "vname": "a",
                "type": "ByStr20",
                "value": "0x964d9004b1ba9f362766cd681e9f97837a5cbb85"
            }
        ]
    }"#;

    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        3,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(call),
    )
    .await;
    let event = &txn["receipt"]["event_logs"][0];
    assert_eq!(event["_eventname"], "MapValues");
    assert_eq!(
        event["params"][1]["value"][0]["arguments"]
            .as_array()
            .unwrap()
            .clone(),
        vec![Value::from("1"), Value::from("100")]
    );
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn withdraw_from_contract(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

    let code = r#"
        scilla_version 0

        library WithdrawLib

        let one_msg =
            fun (msg : Message) =>
            let nil_msg = Nil {Message} in
            Cons {Message} msg nil_msg

        contract Withdraw
        ()

        transition Withdraw(recipient: ByStr20, amount: Uint128)
            msg = {_tag : "SomeMessage"; _recipient: recipient; _amount: amount};
            msgs = one_msg msg;
            send msgs
        end

    "#;

    let data = r#"[
        {
            "vname": "_scilla_version",
            "type": "Uint32",
            "value": "0"
        }
    ]"#;

    let deploy_contract_balance = 1_000_000_u128;
    let contract_address = deploy_scilla_contract(
        &mut network,
        &wallet,
        &secret_key,
        code,
        data,
        deploy_contract_balance,
    )
    .await;

    let queried_balance = wallet
        .get_balance(contract_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(deploy_contract_balance, queried_balance / 10u128.pow(6));

    let random_wallet_address = network.random_wallet().await.default_signer_address();

    assert_eq!(
        0_u128,
        wallet
            .get_balance(random_wallet_address)
            .await
            .unwrap()
            .to::<u128>()
    );

    // Simulate withdrawal from contract
    let call = format!(
        r#"{{
        "_tag": "Withdraw",
        "params": [
            {{
                "vname": "recipient",
                "type": "ByStr20",
                "value": "0x{random_wallet_address:x}"
            }},
            {{
                "vname": "amount",
                "value": "{deploy_contract_balance}",
                "type": "Uint128"
            }}
        ]
    }}"#
    );

    let (_, _) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        0,
        50_000,
        None,
        Some(&call),
    )
    .await;

    let random_wallet_balance = wallet
        .get_balance(random_wallet_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(
        random_wallet_balance / 10u128.pow(6),
        deploy_contract_balance
    );

    let contract_zero_balance = wallet
        .get_balance(contract_address)
        .await
        .unwrap()
        .to::<u128>();
    assert_eq!(0_u128, contract_zero_balance);
}

/// This test is for hardfork scilla_fix_contract_code_removal_on_evm_tx's behaviour
#[zilliqa_macros::test(restrict_concurrency)]
async fn create_scilla_contract_send_evm_tx(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;
    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    let account_code_before = network
        .get_node(0)
        .consensus
        .read()
        .state()
        .get_account(contract_address)
        .unwrap()
        .code;

    // Send type 0 tx
    let hash = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(contract_address)
                .value(U256::from(0))
                .gas_limit(1_000_000),
        )
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, &hash, 200).await;

    let account_code_after = network
        .get_node(0)
        .consensus
        .read()
        .state()
        .get_account(contract_address)
        .unwrap()
        .code;
    assert_eq!(
        serde_json::to_string(&account_code_before).unwrap(),
        serde_json::to_string(&account_code_after).unwrap()
    );
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn evm_tx_to_scilla_contract_should_fail(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;
    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    // Send type 0 tx
    let hash = *wallet
        .send_transaction(
            TransactionRequest::default()
                .to(contract_address)
                .value(U256::from(10))
                .gas_limit(21000),
        )
        .await
        .unwrap()
        .tx_hash();

    // Process pending transaction
    let receipt = network.run_until_receipt(&wallet, &hash, 200).await;

    assert!(!receipt.status());
    assert_eq!(receipt.inner.cumulative_gas_used(), 21000);
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn failed_scilla_to_scilla_transfers_proper_fee(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data, 0_u128).await;

    let initial_balance = wallet.get_balance(address).await.unwrap().to::<u128>();

    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();

    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();
    let gas_limit: ScillaGas = EvmGas(21000).into();

    let amount_to_transfer = 10 * 10u128.pow(12);

    let response = issue_create_transaction(
        &wallet,
        &secret_key.public_key(),
        gas_price,
        &mut network,
        &secret_key,
        2,
        ToAddr::Address(H160::from_slice(contract_address.as_slice())),
        amount_to_transfer,
        gas_limit.0,
        None,
        None,
    )
    .await
    .unwrap();

    let txn_hash: H256 = response["TranID"].as_str().unwrap().parse().unwrap();

    let eth_receipt = wait_eth_receipt(&mut network, &wallet, txn_hash).await;
    assert!(!eth_receipt.status);
    assert_eq!(eth_receipt.cumulative_gas_used.0, 21000);

    let transaction_fee =
        eth_receipt.cumulative_gas_used.0 as u128 * eth_receipt.effective_gas_price;

    let balance_after_failed_call = wallet.get_balance(address).await.unwrap().to::<u128>();

    assert_eq!(balance_after_failed_call, initial_balance - transaction_fee);
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn failed_zil_transfers_proper_fee(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let initial_balance = wallet.get_balance(address).await.unwrap().to::<u128>();

    let gas_price_str: String = wallet
        .client()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();

    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();
    let gas_limit: ScillaGas = EvmGas(21000).into();

    let destination = get_random_address(&mut network);

    let amount_to_transfer = initial_balance;

    let response = issue_create_transaction(
        &wallet,
        &secret_key.public_key(),
        gas_price,
        &mut network,
        &secret_key,
        1,
        ToAddr::Address(H160::from_slice(destination.as_slice())),
        amount_to_transfer,
        gas_limit.0,
        None,
        None,
    )
    .await
    .unwrap();

    let txn_hash: H256 = response["TranID"].as_str().unwrap().parse().unwrap();
    let eth_receipt = wait_eth_receipt(&mut network, &wallet, txn_hash).await;

    assert!(!eth_receipt.status);
    assert_eq!(eth_receipt.cumulative_gas_used.0, 21000);

    let transaction_fee: u128 =
        eth_receipt.cumulative_gas_used.0 as u128 * eth_receipt.effective_gas_price;

    let balance_after_failed_call = wallet.get_balance(address).await.unwrap().to::<u128>();

    assert_eq!(balance_after_failed_call, initial_balance - transaction_fee);
}
