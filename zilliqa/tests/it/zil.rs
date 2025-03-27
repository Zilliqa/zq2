use std::{ops::DerefMut, str::FromStr};

use alloy::primitives::Address;
use anyhow::Result;
use bech32::{Bech32, Hrp};
use ethabi::{ParamType, Token};
use ethers::{
    providers::{Middleware, ProviderError},
    types::TransactionRequest,
    utils::keccak256,
};
use k256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use primitive_types::{H160, H256, U128};
use prost::Message;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::debug;
use zilliqa::{
    api::types::zil::GetTxResponse,
    schnorr,
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};

use crate::{Network, Wallet, deploy_contract};

pub async fn zilliqa_account(network: &mut Network, wallet: &Wallet) -> (schnorr::SecretKey, H160) {
    zilliqa_account_with_funds(network, wallet, 1000 * 10u128.pow(18)).await
}

pub async fn zilliqa_account_with_funds(
    network: &mut Network,
    wallet: &Wallet,
    funds: u128,
) -> (schnorr::SecretKey, H160) {
    // Generate a Zilliqa account.
    let secret_key = schnorr::SecretKey::random(network.rng.lock().unwrap().deref_mut());
    let public_key = secret_key.public_key();
    let hashed = Sha256::digest(public_key.to_encoded_point(true).as_bytes());
    let address = H160::from_slice(&hashed[12..]);

    // Send the Zilliqa account some funds.
    let tx = TransactionRequest::pay(address, funds);
    let hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    network
        .run_until_async(
            || async {
                wallet
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // Verify the Zilliqa account has funds using the `GetBalance` API.
    let response: Value = wallet
        .provider()
        .request("GetBalance", [address])
        .await
        .unwrap();

    let resp_eth = wallet
        .provider()
        .request::<[&str; 2], String>(
            "eth_getBalance",
            [
                &Address::new(*address.as_fixed_bytes()).to_checksum(None),
                "latest",
            ],
        )
        .await
        .unwrap();
    let eth_balance: U128 =
        U128::from_str_radix(resp_eth.strip_prefix("0x").unwrap_or(&resp_eth), 16).unwrap();

    // This is in decimal!
    let zil_balance = U128::from_str_radix(response["balance"].as_str().unwrap(), 10).unwrap();

    assert_eq!(zil_balance * U128::from(10u128.pow(6)), funds.into());
    assert_eq!(eth_balance, funds.into());
    assert_eq!(response["nonce"].as_u64().unwrap(), 0);

    (secret_key, address)
}

enum ToAddr {
    Address(H160),
    StringVal(String),
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
    let chain_id = wallet.get_chainid().await.unwrap().as_u32() - 0x8000;
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
        .provider()
        .request("CreateTransaction", [request])
        .await?)
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
) -> (Option<H160>, Value) {
    let public_key = secret_key.public_key();

    // Get the gas price via the Zilliqa API.
    let gas_price_str: String = wallet
        .provider()
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
                let response: Result<GetTxResponse, _> = wallet
                    .provider()
                    .request("GetTransaction", [txn_hash])
                    .await;
                response.is_ok()
            },
            400,
        )
        .await
        .unwrap();

    let eth_receipt = wallet
        .get_transaction_receipt(txn_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(eth_receipt.status.unwrap().as_u32(), 1);

    (
        eth_receipt.contract_address,
        wallet
            .provider()
            .request("GetTransaction", [txn_hash])
            .await
            .unwrap(),
    )
}

// Returns Err() if the txn fails.
#[allow(clippy::too_many_arguments)]
async fn send_transaction_for_status(
    network: &mut Network,
    wallet: &Wallet,
    secret_key: &schnorr::SecretKey,
    nonce: u64,
    to_addr: H160,
    amount: u128,
    gas_limit: u64,
    code: Option<&str>,
    data: Option<&str>,
) -> (u32, Option<H160>, Value) {
    let public_key = secret_key.public_key();

    // Get the gas price via the Zilliqa API.
    let gas_price_str: String = wallet
        .provider()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();

    let chain_id = wallet.get_chainid().await.unwrap().as_u32() - 0x8000;
    let version = (chain_id << 16) | 1u32;
    let proto = ProtoTransactionCoreInfo {
        version,
        toaddr: to_addr.as_bytes().to_vec(),
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
        "toAddr": Address::from_slice(to_addr.as_bytes()).to_checksum(None),
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

    let response: Value = wallet
        .provider()
        .request("CreateTransaction", [request])
        .await
        .unwrap();
    let txn_hash: H256 = response["TranID"].as_str().unwrap().parse().unwrap();

    network
        .run_until_async(
            || async {
                let response: Result<GetTxResponse, _> = wallet
                    .provider()
                    .request("GetTransaction", [txn_hash])
                    .await;
                response.is_ok()
            },
            100,
        )
        .await
        .unwrap();

    let eth_receipt = wallet
        .get_transaction_receipt(txn_hash)
        .await
        .unwrap()
        .unwrap();
    // assert_eq!(eth_receipt.status.unwrap().as_u32(), 0);

    (
        eth_receipt.status.unwrap().as_u32(),
        eth_receipt.contract_address,
        wallet
            .provider()
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

        let one = Uint32 1
        let two = Uint32 2

        contract HelloWorld
        (owner: ByStr20)

        field welcome_msg : String = "default"
        field welcome_map : Map Uint32 (Map Uint32 String) = Emp Uint32 (Map Uint32 String)

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
    "#,
    )
}

pub fn scilla_test_contract_data(address: H160) -> String {
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
) -> H160 {
    let (contract_address, txn) = send_transaction(
        network,
        wallet,
        sender_secret_key,
        1,
        ToAddr::Address(H160::zero()),
        0,
        50_000,
        Some(code),
        Some(data),
    )
    .await;

    let api_contract_address = wallet
        .provider()
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
        .provider()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();

    let use_chain_id = chain_id.unwrap_or(wallet.get_chainid().await.unwrap().as_u32() - 0x8000);
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
    if bad_signature {
        if let Some(x) = signature.first_mut() {
            *x = x.wrapping_add(1);
        }
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

    let response: Result<Value, ProviderError> = wallet
        .provider()
        .request("CreateTransaction", [request])
        .await;

    if let Err(ProviderError::JsonRpcClientError(rpc_error)) = response {
        if let Some(json_error) = rpc_error.as_error_response() {
            return Some((json_error.code, json_error.message.to_string()));
        }
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
        .provider()
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
        .provider()
        .request("GetBalance", [address])
        .await
        .unwrap();
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .provider()
        .request("GetBalance", [to_addr])
        .await
        .unwrap();
    assert_eq!(response["balance"].as_str().unwrap(), "200000000000000");
}

#[zilliqa_macros::test]
async fn create_transaction(mut network: Network) {
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
        .provider()
        .request("GetBalance", [address])
        .await
        .unwrap();
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .provider()
        .request("GetBalance", [to_addr])
        .await
        .unwrap();
    assert_eq!(response["balance"].as_str().unwrap(), "200000000000000");
}

#[zilliqa_macros::test]
async fn get_balance_via_eth_api(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _) = zilliqa_account(&mut network, &wallet).await;

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

    let encoded_bech32 =
        bech32::encode::<Bech32>(Hrp::parse("zil").unwrap(), to_addr.as_bytes()).unwrap();

    let response: Value = wallet
        .provider()
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
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
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
        .provider()
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
        .provider()
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

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    let gas_price_str: String = wallet
        .provider()
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
        .provider()
        .request("GetBalance", [address])
        .await
        .unwrap();
    println!("GetBalance() after transfer = {response:?}");
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .provider()
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

#[zilliqa_macros::test]
async fn zil_with_insufficient_gas_should_fail(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    // Create a contract and check for lack of deposit rejection.
    let (deployer_key, _) =
        zilliqa_account_with_funds(&mut network, &wallet, 60 * 10u128.pow(18)).await;

    let code = scilla_test_contract_code();
    let gas_price_str: String = wallet
        .provider()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();
    // Just over the 300 gas we need to invoke the runner.
    // Enough to pay the deposit, but not the transaction fee.
    let gas_price: u128 = u128::from_str(&gas_price_str).unwrap();
    let zil_value: u128 = (301u128 * gas_price) / 10u128.pow(6);
    let amount_to_request: u128 = zil_value * 10u128.pow(6);
    let (caller_key, caller_address) =
        zilliqa_account_with_funds(&mut network, &wallet, amount_to_request).await;
    let data = scilla_test_contract_data(caller_address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &deployer_key, &code, &data).await;
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

    let max_gas_we_can_pay_for = (50u128 * 10u128.pow(12)) / gas_price;
    let (status, addr, _) = send_transaction_for_status(
        &mut network,
        &wallet,
        &caller_key,
        1,
        contract_address,
        0,
        // Doesn't actually need to be > the max gas we can pay for, but
        // it might as well be.
        u128::try_into(max_gas_we_can_pay_for * 2).unwrap(),
        None,
        Some(call),
    )
    .await;
    assert_eq!(addr, None);
    // The txn should fail.
    assert_eq!(status, 0);
    let response: Value = wallet
        .provider()
        .request("GetBalance", [caller_address])
        .await
        .unwrap();
    // Weirdly, Zilliqa native doesn't increment the nonce when a txn fails.
    assert_eq!(response["nonce"].as_u64().unwrap(), 0);
    // Or charge you the deposit - node that this is 10^6 smaller than the amt
    // we requested because we requested in eth and are reading in zil.
    assert_eq!(
        response["balance"]
            .as_str()
            .unwrap()
            .parse::<u128>()
            .unwrap(),
        zil_value
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
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data).await;

    let api_code: Value = wallet
        .provider()
        .request("GetSmartContractCode", [contract_address])
        .await
        .unwrap();
    assert_eq!(code, api_code["code"]);

    let api_data: Vec<Value> = wallet
        .provider()
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
            .provider()
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
        ToAddr::Address(contract_address),
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
            .provider()
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
    assert_eq!(old_balance - new_balance, 690000005520u128);

    let call = r#"{
        "_tag": "getHello",
        "params": []
    }"#;
    let (_, txn) = send_transaction(
        &mut network,
        &wallet,
        &secret_key,
        3,
        ToAddr::Address(contract_address),
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
        .provider()
        .request("GetSmartContractState", [contract_address])
        .await
        .unwrap();
    assert_eq!(state["welcome_msg"], "foobar");
}

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

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let evm_contract_address = receipt.contract_address.unwrap();

    let read = |fn_name, var_name: &'_ str, keys: &[H160], ty| {
        let abi = &abi;
        let wallet = &wallet;
        let var_name = var_name.to_owned();
        let keys = keys.to_vec();
        async move {
            let function = abi.function(fn_name).unwrap();
            let mut input = vec![
                Token::Address(scilla_contract_address),
                Token::String(var_name),
            ];
            for key in keys {
                input.push(Token::Address(key));
            }
            let call_tx = TransactionRequest::new()
                .to(receipt.contract_address.unwrap())
                .data(function.encode_input(&input).unwrap());

            let response = wallet.call(&call_tx.clone().into(), None).await.unwrap();
            ethabi::decode(&[ty], &response).unwrap().remove(0)
        }
    };

    let num = read("readUint128", "num", &[], ParamType::Uint(128))
        .await
        .into_uint()
        .unwrap();
    assert_eq!(num, 1234.into());

    let str = read("readString", "str", &[], ParamType::String)
        .await
        .into_string()
        .unwrap();
    assert_eq!(str, "foobar");

    let key = "0x0123456789012345678901234567890123456789"
        .parse()
        .unwrap();

    let val = read(
        "readMapUint128",
        "addr_to_int",
        &[key],
        ParamType::Uint(128),
    )
    .await
    .into_uint()
    .unwrap();
    assert_eq!(val, 1.into());

    let val = read(
        "readNestedMapUint128",
        "addr_to_addr_to_int",
        &[key, key],
        ParamType::Uint(128),
    )
    .await
    .into_uint()
    .unwrap();
    assert_eq!(val, 1.into());

    // Construct a transaction which uses the scilla_call precompile.
    let function = abi.function("callScilla").unwrap();
    let input = &[
        Token::Address(scilla_contract_address),
        Token::String("InsertIntoMap".to_owned()),
        Token::String("addr_to_int".to_owned()),
        Token::Address(key),
        Token::Uint(5.into()),
    ];
    let tx = TransactionRequest::new()
        .to(evm_contract_address)
        .data(function.encode_input(input).unwrap())
        .gas(84_000_000);

    // First execute the transaction with `eth_call` and assert that updating a value in a Scilla contract, then
    // reading that value in the same transaction gives us the correct value.
    let response = wallet.call(&tx.clone().into(), None).await.unwrap();
    let response = ethabi::decode(&[ParamType::Uint(128)], &response)
        .unwrap()
        .remove(0)
        .into_uint()
        .unwrap()
        .as_u32();
    assert_eq!(response, 5);

    // Now actually run the transaction and assert that the EVM logs include the Scilla log from the internal Scilla
    // call.
    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, tx_hash, 100).await;
    assert_eq!(receipt.logs.len(), 1);
    let log = &receipt.logs[0];
    assert_eq!(log.address, scilla_contract_address);
    assert_eq!(
        log.topics[0],
        H256(keccak256("Inserted(string)".as_bytes()))
    );
    let data = ethabi::decode(&[ParamType::String], &log.data).unwrap()[0]
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
            .parse::<H160>()
            .unwrap(),
        key
    );
    assert_eq!(scilla_log["params"][1]["type"], "Uint128");
    assert_eq!(scilla_log["params"][1]["vname"], "b");
    assert_eq!(scilla_log["params"][1]["value"], "5");

    // Assert that the value has been permanently updated for good measure.
    let val = read(
        "readMapUint128",
        "addr_to_int",
        &[key],
        ParamType::Uint(128),
    )
    .await
    .into_uint()
    .unwrap();
    assert_eq!(val, 5.into());

    // Construct a transaction which logs the `_sender` from the Scilla call.
    let function = abi.function("callScillaNoArgs").unwrap();
    let input = &[
        Token::Address(scilla_contract_address),
        Token::String("LogSender".to_owned()),
    ];
    let tx = TransactionRequest::new()
        .to(evm_contract_address)
        .data(function.encode_input(input).unwrap())
        .gas(84_000_000);

    // Run the transaction.
    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, tx_hash, 100).await;
    assert_eq!(receipt.logs.len(), 1);
    let log = &receipt.logs[0];
    let data = ethabi::decode(&[ParamType::String], &log.data).unwrap()[0]
        .clone()
        .into_string()
        .unwrap();
    let scilla_log: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(scilla_log["_eventname"], "LogSender");
    assert_eq!(scilla_log["params"][0]["vname"], "sender");
    assert_eq!(
        scilla_log["params"][0]["value"],
        format!("{:?}", wallet.address())
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

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let evm_contract_address = receipt.contract_address.unwrap();

    let recipient = Address::random_with(network.rng.lock().unwrap().deref_mut());
    debug!(%recipient);

    let function = abi.function("sendEtherThenCallScilla").unwrap();
    let input = &[
        Token::Address(H160(recipient.0.0)),
        Token::Address(scilla_contract_address),
        Token::String("LogBalance".to_owned()),
        Token::Address(H160(recipient.0.0)),
    ];
    let amount = 1_234_000_000_000_000_000_000;
    let tx = TransactionRequest::new()
        .to(evm_contract_address)
        .data(function.encode_input(input).unwrap())
        .gas(84_000_000)
        .value(amount);

    let my_balance_before = wallet
        .get_balance(scilla_contract_address, None)
        .await
        .unwrap()
        .as_u128();

    // Run the transaction.
    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, tx_hash, 100).await;

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
        1_000_000,
        50_000,
        Some(code),
        Some(data),
    )
    .await;
    let scilla_contract_address = contract_address.unwrap();

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let evm_contract_address = receipt.contract_address.unwrap();

    let recipient = Address::random_with(network.rng.lock().unwrap().deref_mut());
    debug!(%recipient);

    let function = abi.function("callScillaOneArg").unwrap();
    let input = &[
        Token::Address(scilla_contract_address),
        Token::String("SendTo".to_owned()),
        Token::Address(H160(recipient.0.0)),
    ];
    let tx = TransactionRequest::new()
        .to(evm_contract_address)
        .data(function.encode_input(input).unwrap())
        .gas(84_000_000);

    let tx_count_before = wallet
        .get_transaction_count(wallet.address(), None)
        .await
        .unwrap();
    let balance_before = wallet.get_balance(wallet.address(), None).await.unwrap();

    // Run the transaction.
    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, tx_hash, 100).await;
    assert_eq!(receipt.status.unwrap().as_u64(), 1);

    let tx_count_after = wallet
        .get_transaction_count(wallet.address(), None)
        .await
        .unwrap();
    let balance_after = wallet.get_balance(wallet.address(), None).await.unwrap();

    assert_eq!(tx_count_before + 1, tx_count_after);
    assert_eq!(
        balance_before
            - 1_000_000
            - (receipt.gas_used.unwrap() * receipt.effective_gas_price.unwrap()),
        balance_after
    );
    assert_eq!(
        wallet
            .get_balance(H160(recipient.0.0), None)
            .await
            .unwrap()
            .as_u128(),
        1_000_000
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
    let tx_hash = wallet
        .send_transaction(TransactionRequest::new().to(H160::zero()), None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, tx_hash, 100).await;

    let (hash, abi) = deploy_contract(
        "tests/it/contracts/ScillaInterop.sol",
        "ScillaInterop",
        &wallet,
        &mut network,
    )
    .await;
    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();

    // Construct a transaction which uses the scilla_call precompile.
    let function = abi.function("callScillaWithBadGas").unwrap();
    let input = &[
        Token::Address(scilla_contract_address),
        Token::String("InsertIntoMap".to_owned()),
        Token::String("addr_to_int".to_owned()),
        Token::Address(wallet.address()),
        Token::Uint(5.into()),
    ];
    let tx = TransactionRequest::new()
        .to(receipt.contract_address.unwrap())
        .data(function.encode_input(input).unwrap())
        .gas(84_000_000);

    // Make sure the transaction succeeds.
    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();
    let receipt = network.run_until_receipt(&wallet, tx_hash, 100).await;
    assert_eq!(receipt.status.unwrap().as_u64(), 1);
}

#[zilliqa_macros::test]
async fn get_tx_block(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Ensure there is at least one block in the chain
    network.run_until_block_finalized(3u64, 100).await.unwrap();

    // Request the first block
    let block_number = "1";

    let response: Value = wallet
        .provider()
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
        .provider()
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
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data).await;

    // Test the success case
    let response: Value = wallet
        .provider()
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
    let response: Result<Value, ProviderError> = wallet
        .provider()
        .request("GetSmartContractInit", [invalid_contract_address])
        .await;

    assert!(response.is_err());
    if let Err(ProviderError::JsonRpcClientError(rpc_error)) = response {
        if let Some(json_error) = rpc_error.as_error_response() {
            assert_eq!(json_error.code, -32603); // Invalid params error code
            assert!(json_error.message.contains("Address does not exist"));
        } else {
            panic!("Expected JSON-RPC error response");
        }
    } else {
        panic!("Expected ProviderError::JsonRpcClientError");
    }
}

#[zilliqa_macros::test]
async fn get_ds_block(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetDSBlock", ["9000"])
        .await
        .expect("Failed to call GetDSBlock API");

    zilliqa::api::types::zil::DSBlock::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_ds_block_verbose(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetDSBlockVerbose", ["9000"])
        .await
        .expect("Failed to call GetDSBlockVerbose API");

    zilliqa::api::types::zil::DSBlockVerbose::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_latest_ds_block(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetLatestDSBlock", [""])
        .await
        .expect("Failed to call GetLatestDSBlock API");

    zilliqa::api::types::zil::DSBlock::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_current_ds_comm(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetCurrentDSComm", [""])
        .await
        .expect("Failed to call GetCurrentDSComm API");

    zilliqa::api::types::zil::GetCurrentDSCommResult::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_current_ds_epoch(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
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
        .provider()
        .request("DSBlockListing", [1])
        .await
        .expect("Failed to call DSBlockListing API");

    zilliqa::api::types::zil::DSBlockListingResult::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_ds_block_rate(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetDSBlockRate", [""])
        .await
        .expect("Failed to call GetDSBlockRate API");

    let returned = zilliqa::api::types::zil::DSBlockRateResult::deserialize(&response).unwrap();

    assert!(returned.rate >= 0.0, "Block rate should be non-negative");
}

#[zilliqa_macros::test]
async fn get_tx_block_rate_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
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
        .provider()
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
        .provider()
        .request("GetNumPeers", [""])
        .await
        .expect("Failed to call GetNumPeers API");

    assert!(
        response.is_number(),
        "Expected response to be a number, got: {:?}",
        response
    );
}

#[zilliqa_macros::test]
async fn get_tx_rate_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    network.run_until_block_finalized(1u64, 100).await.unwrap();

    let response: Value = wallet
        .provider()
        .request("GetTransactionRate", [""])
        .await
        .expect("Failed to call GetTxRate API");

    let tx_rate: f64 = serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(tx_rate >= 0.0, "Transaction rate should be non-negative");

    network.run_until_block_finalized(8u64, 300).await.unwrap();

    let response: Value = wallet
        .provider()
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
        .provider()
        .request("GetTransactionRate", [""])
        .await
        .expect("Failed to call GetTxRate API");

    let tx_rate: f64 = serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(tx_rate > 0.0, "Transaction block rate should be positive");
}

#[zilliqa_macros::test]
async fn get_txns_for_tx_block_ex_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    network.run_until_block_finalized(1u64, 100).await.unwrap();

    let block_number = "1";
    let page_number = "1";

    let response: Value = wallet
        .provider()
        .request("GetTransactionsForTxBlockEx", [block_number, page_number])
        .await
        .expect("Failed to call GetTransactionsForTxBlockEx API");

    let txns: zilliqa::api::types::zil::TxnsForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txns.curr_page, page_number.parse::<u64>().unwrap());
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
        .provider()
        .request("GetBalance", [address])
        .await
        .unwrap();
    assert_eq!(response["nonce"].as_u64().unwrap(), 1);

    // Verify the receiver's balance has increased using the `GetBalance` API.
    let response: Value = wallet
        .provider()
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
        .provider()
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

    network.run_until_block_finalized(2u64, 300).await.unwrap();

    let result: zilliqa::api::types::zil::GetTxResponse =
        serde_json::from_value(txn).expect("serdes error");

    let block_number = result.receipt.epoch_num;

    let response: Value = wallet
        .provider()
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
    if let Some(shards) = response.as_array() {
        if !shards.is_empty() {
            assert!(shards[0].is_array());
            if let Some(txns) = shards[0].as_array() {
                if !txns.is_empty() {
                    // Each hash should be a 32 byte hex string
                    assert!(txns[0].is_string());
                    assert_eq!(txns[0].as_str().unwrap().len(), 64);
                }
            }
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
        .provider()
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
        .provider()
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
        .provider()
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
        .provider()
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
    if let Some(shards) = result["Transactions"].as_array() {
        if !shards.is_empty() && !shards[0].is_null() {
            assert!(shards[0].is_array());
            if let Some(txns) = shards[0].as_array() {
                if !txns.is_empty() {
                    assert!(txns[0].is_string());
                    assert_eq!(txns[0].as_str().unwrap().len(), 64);
                }
            }
        }
    }
}

#[zilliqa_macros::test]
async fn get_num_ds_blocks(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetNumDSBlocks", [""])
        .await
        .expect("Failed to call GetNumDSBlocks API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
    );
}

#[zilliqa_macros::test]
async fn get_recent_transactions_0(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
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

    network.run_until_block_finalized(1u64, 100).await.unwrap();

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
        .provider()
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
//         .provider()
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
//         .provider()
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
        .provider()
        .request("GetNumTxnsDSEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsDSEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
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

    network.run_until_block_finalized(7u64, 100).await.unwrap();

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
        .provider()
        .request("GetNumTxnsDSEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsDSEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
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
        .provider()
        .request("GetNumTxnsTXEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsTxEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
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

    network.run_until_block_finalized(7u64, 100).await.unwrap();

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
        .provider()
        .request("GetNumTxnsTXEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsTXEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
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
    let wallet = network.genesis_wallet().await;

    let response_str: Value = wallet
        .provider()
        .request("GetTotalCoinSupply", [""])
        .await
        .expect("Failed to call GetTotalCoinSupply API");

    assert!(
        response_str.is_string(),
        "Expected response to be a string, got: {:?}",
        response_str
    );

    let total_coin_supply_str = response_str.as_str().expect("Expected string conversion");
    let total_coin_supply_as_int_from_str: u128 = total_coin_supply_str
        .parse()
        .expect("Expected string to be parsed as an integer");

    assert!(
        total_coin_supply_as_int_from_str > 0,
        "Total coin supply should be greater than 0"
    );

    let response_int: Value = wallet
        .provider()
        .request("GetTotalCoinSupplyAsInt", [""])
        .await
        .expect("Failed to call GetTotalCoinSupplyAsInt API");

    assert!(
        response_int.is_number(),
        "Expected response to be a number, got: {:?}",
        response_int
    );

    let total_coin_supply_as_int: u128 = response_int
        .as_number()
        .expect("Expected number conversion")
        .as_u128()
        .expect("Expected u128 conversion");

    assert!(
        total_coin_supply_as_int > 0,
        "Total coin supply should be greater than 0"
    );

    assert_eq!(
        total_coin_supply_as_int_from_str, total_coin_supply_as_int,
        "Total coin supply from string and int APIs should be the same"
    );
}

#[zilliqa_macros::test]
async fn get_miner_info(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetMinerInfo", ["5500"])
        .await
        .expect("Failed to call GetMinerInfo API");

    zilliqa::api::types::zil::MinerInfo::deserialize(&response).unwrap();
}

#[zilliqa_macros::test]
async fn get_node_type(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetNodeType", [""])
        .await
        .expect("Failed to call GetNodeType API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
    );

    let allowed_node_types = ["Seed"];
    let response_str = response.as_str().expect("Expected response to be a string");

    assert!(
        allowed_node_types.contains(&response_str),
        "Unexpected node type: {}",
        response_str
    );
}

#[allow(dead_code)]
async fn get_prev_difficulty(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetPrevDifficulty", [""])
        .await
        .expect("Failed to call GetPrevDifficulty API");

    assert!(
        response.is_u64(),
        "Expected response to be a u64, got: {:?}",
        response
    );

    let response_u64 = response.as_u64().expect("Expected response to be a u64");

    assert_eq!(response_u64, 0);
}

#[allow(dead_code)]
async fn get_prev_ds_difficulty(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetPrevDSDifficulty", [""])
        .await
        .expect("Failed to call GetPrevDSDifficulty API");

    assert!(
        response.is_u64(),
        "Expected response to be a u64, got: {:?}",
        response
    );

    let response_u64 = response.as_u64().expect("Expected response to be a u64");

    assert_eq!(response_u64, 0);
}

#[zilliqa_macros::test]
async fn get_sharding_structure(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Get the sharding structure
    let response: Value = wallet
        .provider()
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
        .provider()
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
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data).await;

    let api_code: Value = wallet
        .provider()
        .request("GetSmartContractCode", [contract_address])
        .await
        .unwrap();
    assert_eq!(code, api_code["code"]);

    let api_data: Vec<Value> = wallet
        .provider()
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
        ToAddr::Address(contract_address),
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
        ToAddr::Address(contract_address),
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
        .provider()
        .request("GetSmartContractState", [contract_address])
        .await
        .unwrap();
    assert_eq!(state["welcome_msg"], "foobar");

    let empty_string_vec: Vec<String> = vec![]; // Needed for type annotation
    let substate0: serde_json::Value = wallet
        .provider()
        .request(
            "GetSmartContractSubState",
            (contract_address, "", empty_string_vec.clone()),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");
    assert_eq!(substate0, state);

    let substate1: serde_json::Value = wallet
        .provider()
        .request(
            "GetSmartContractSubState",
            (contract_address, "welcome_msg", empty_string_vec),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");
    assert_eq!(substate1["welcome_msg"], "foobar");
    assert!(substate1.get("welcome_map").is_none());

    let substate2: serde_json::Value = wallet
        .provider()
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
async fn nested_maps_insert_removal(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, address) = zilliqa_account(&mut network, &wallet).await;

    let code = scilla_test_contract_code();
    let data = scilla_test_contract_data(address);
    let contract_address =
        deploy_scilla_contract(&mut network, &wallet, &secret_key, &code, &data).await;

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
            ToAddr::Address(contract_address),
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
            ToAddr::Address(contract_address),
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
            ToAddr::Address(contract_address),
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
            ToAddr::Address(contract_address),
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

#[zilliqa_macros::test]
async fn get_state_proof(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let contract_address = "6d84363526a2d764835f8cf52dfeefe80a360fac";
    let variable_hash = "A0BD91DE66D97E6930118179BA4F1836C366C4CB3309A6B354D26F52ABB2AAC6";
    let tx_block = "39";

    let response: Value = wallet
        .provider()
        .request("GetStateProof", [contract_address, variable_hash, tx_block])
        .await
        .expect("Failed to call GetStateProof API");

    let _state_proof: zilliqa::api::types::zil::StateProofResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");
}

#[zilliqa_macros::test]
async fn get_transaction_status(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_contract_address_1, returned_transaction_1) = send_transaction(
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

    let returned_transaction_1_id = returned_transaction_1["ID"]
        .as_str()
        .expect("Failed to get ID from response");

    network.run_until_block_finalized(1u64, 100).await.unwrap();

    let (secret_key, _address) = zilliqa_account(&mut network, &wallet).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let (_contract_address_2, returned_transaction_2) = send_transaction(
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

    let returned_transaction_2_id = returned_transaction_2["ID"]
        .as_str()
        .expect("Failed to get ID from response");

    //    network.run_until_block_finalized(8u64, 300).await.unwrap();

    let response_1: Value = wallet
        .provider()
        .request("GetTransactionStatus", [returned_transaction_1_id])
        .await
        .expect("Failed to call GetTransactionStatus API");

    let tx_status_1: zilliqa::api::types::zil::TransactionStatusResponse =
        serde_json::from_value(response_1).expect("Failed to deserialize response");

    assert_eq!(tx_status_1.id.to_string(), returned_transaction_1_id);
    assert!(
        tx_status_1.amount.parse::<f64>().is_ok(),
        "Invalid amount format"
    );
    assert!(
        tx_status_1.gas_limit.parse::<u64>().is_ok(),
        "Invalid gasLimit format"
    );
    assert!(
        tx_status_1.gas_price.parse::<u64>().is_ok(),
        "Invalid gasPrice format"
    );
    assert!(
        tx_status_1.nonce.parse::<u64>().is_ok(),
        "Invalid nonce format"
    );

    let response_2: Value = wallet
        .provider()
        .request("GetTransactionStatus", [returned_transaction_2_id])
        .await
        .expect("Failed to call GetTransactionStatus API");

    let tx_status_2: zilliqa::api::types::zil::TransactionStatusResponse =
        serde_json::from_value(response_2).expect("Failed to deserialize response");

    assert_eq!(tx_status_2.id.to_string(), returned_transaction_2_id);
    assert!(
        tx_status_2.amount.parse::<f64>().is_ok(),
        "Invalid amount format"
    );
    assert!(
        tx_status_2.gas_limit.parse::<u64>().is_ok(),
        "Invalid gasLimit format"
    );
    assert!(
        tx_status_2.gas_price.parse::<u64>().is_ok(),
        "Invalid gasPrice format"
    );
    assert!(
        tx_status_2.nonce.parse::<u64>().is_ok(),
        "Invalid nonce format"
    );
}

#[zilliqa_macros::test]
async fn get_blockchain_info_structure(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let result: Value = wallet
        .provider()
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
        .provider()
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
        deploy_scilla_contract(&mut network, &wallet, &secret_key, code, data).await;

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
        ToAddr::Address(contract_address),
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
        ToAddr::Address(contract_address),
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
