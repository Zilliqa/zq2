use std::ops::DerefMut;

use ethabi::{ParamType, Token};
use ethers::{providers::Middleware, types::TransactionRequest, utils::keccak256};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use primitive_types::{H160, H256};
use prost::Message;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zilliqa::{
    schnorr,
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};

use crate::{deploy_contract, Network};

async fn zilliqa_account(network: &mut Network) -> (schnorr::SecretKey, H160) {
    let wallet = network.genesis_wallet().await;

    // Generate a Zilliqa account.
    let secret_key = schnorr::SecretKey::random(network.rng.lock().unwrap().deref_mut());
    let public_key = secret_key.public_key();
    let hashed = Sha256::digest(public_key.to_encoded_point(true).as_bytes());
    let address = H160::from_slice(&hashed[12..]);

    // Send the Zilliqa account some funds.
    let tx = TransactionRequest::pay(address, 1000 * 10u128.pow(18));
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
    assert_eq!(response["balance"].as_str().unwrap(), "1000000000000000");
    assert_eq!(response["nonce"].as_u64().unwrap(), 0);

    (secret_key, address)
}

#[allow(clippy::too_many_arguments)]
async fn send_transaction(
    network: &mut Network,
    secret_key: &schnorr::SecretKey,
    nonce: u64,
    to_addr: H160,
    amount: u128,
    gas_limit: u64,
    code: Option<&str>,
    data: Option<&str>,
) -> (Option<H160>, Value) {
    let wallet = network.random_wallet().await;
    let public_key = secret_key.public_key();

    // Get the gas price via the Zilliqa API.
    let gas_price: u128 = wallet
        .provider()
        .request("GetMinimumGasPrice", ())
        .await
        .unwrap();

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
        "toAddr": to_addr,
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
                wallet
                    .get_transaction_receipt(txn_hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
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

#[zilliqa_macros::test]
async fn create_transaction(mut network: Network) {
    let wallet = network.random_wallet().await;

    let (secret_key, address) = zilliqa_account(&mut network).await;

    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    send_transaction(
        &mut network,
        &secret_key,
        1,
        to_addr,
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

// We need to restrict the concurrency level of this test, because each node in the network will spawn a TCP listener
// once it invokes Scilla. When many tests are run in parallel, this results in "Too many open files" errors.
#[zilliqa_macros::test(restrict_concurrency)]
async fn create_contract(mut network: Network) {
    let (secret_key, address) = zilliqa_account(&mut network).await;

    let code = r#"
        scilla_version 0

        library HelloWorld

        let one = Uint32 1
        let two = Uint32 2

        contract HelloWorld
        (owner: ByStr20)

        field welcome_msg : String = ""
        field welcome_map : Map Uint32 (Map Uint32 String) = Emp Uint32 (Map Uint32 String)

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
    "#;

    let data = format!(
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
    );

    let (contract_address, txn) = send_transaction(
        &mut network,
        &secret_key,
        1,
        H160::zero(),
        0,
        50_000,
        Some(code),
        Some(&data),
    )
    .await;
    let contract_address = contract_address.unwrap();

    let api_contract_address = network
        .random_wallet()
        .await
        .provider()
        .request("GetContractAddressFromTransactionID", [&txn["ID"]])
        .await
        .unwrap();
    assert_eq!(contract_address, api_contract_address);

    let api_code: Value = network
        .random_wallet()
        .await
        .provider()
        .request("GetSmartContractCode", [contract_address])
        .await
        .unwrap();
    assert_eq!(code, api_code["code"]);

    let api_data: Vec<Value> = network
        .random_wallet()
        .await
        .provider()
        .request("GetSmartContractInit", [contract_address])
        .await
        .unwrap();
    // Assert the data returned from the API is a superset of the init data we passed.
    assert!(serde_json::from_str::<Vec<Value>>(&data)
        .unwrap()
        .iter()
        .all(|d| api_data.contains(d)));

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
        &secret_key,
        2,
        contract_address,
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
        &secret_key,
        3,
        contract_address,
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

    let state: serde_json::Value = network
        .random_wallet()
        .await
        .provider()
        .request("GetSmartContractState", [contract_address])
        .await
        .unwrap();
    assert_eq!(state["welcome_msg"], "foobar");
}

#[zilliqa_macros::test(restrict_concurrency)]
async fn scilla_precompiles(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let (secret_key, _) = zilliqa_account(&mut network).await;

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
        &secret_key,
        1,
        H160::zero(),
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
        .to(receipt.contract_address.unwrap())
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
        H256(keccak256("event Inserted(string)".as_bytes()))
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
    assert_eq!(scilla_log["params"][0]["value"], format!("{key:?}"));
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

    let response: Value = wallet
        .provider()
        .request("DSBlockListing", ["1"])
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
async fn get_tx_block_rate(mut network: Network) {
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
async fn tx_block_listing(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    network.run_until_block(&wallet, 2.into(), 50).await;

    let response: Value = wallet
        .provider()
        .request("TxBlockListing", [0])
        .await
        .expect("Failed to call TxBlockListing API");

    let tx_block_listing: zilliqa::api::types::zil::TxBlockListingResult =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(wallet.get_block_number().await.unwrap(), 2.into());
    assert_eq!(
        tx_block_listing.data.len(),
        2,
        "Expected 2 TxBlock listings"
    );
    assert!(
        tx_block_listing.max_pages >= 1,
        "Expected at least 1 page of TxBlock listings"
    );

    assert!(
        tx_block_listing.data[0].block_num == 0,
        "Expected BlockNum to be 0, got: {:?}",
        tx_block_listing.data[0].block_num
    );
    assert!(
        tx_block_listing.data[1].block_num > 0,
        "Expected BlockNum to be greater than 0, got: {:?}",
        tx_block_listing.data[1].block_num
    );
    assert!(
        !tx_block_listing.data[1].hash.is_empty(),
        "Expected Hash to be non-empty, got: {:?}",
        tx_block_listing.data[1].hash
    );
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
