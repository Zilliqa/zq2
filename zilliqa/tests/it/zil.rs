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

    zilliqa::api::types::zil::DSBlockRateResult::deserialize(&response).unwrap();
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

    let node_types = vec![
        "Seed",
        "Lookup",
        "Not in network, synced till epoch", // assuming node.get_synced_epoch() returns some epoch.
    ];
    let response_str = response.as_str().expect("Expected response to be a string");

    assert!(
        node_types.iter().any(|&n| response_str.starts_with(n)),
        "Unexpected node type: {}",
        response_str
    );
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
async fn get_num_transactions(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetNumTransactions", [""])
        .await
        .expect("Failed to call GetNumTransactions API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
    );
    response
        .parse::<u64>()
        .expect("Failed to parse response as u64");
}

#[zilliqa_macros::test]
async fn get_num_txns_ds_epoch(mut network: Network) {
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
async fn get_num_txns_tx_epoch(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetNumTxnsTxEpoch", [""])
        .await
        .expect("Failed to call GetNumTxnsTxEpoch API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
    );
}

#[zilliqa_macros::test]
async fn get_recent_transactions(mut network: Network) {
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
        recent_transactions.TxnHashes.len()
    );
    assert_eq!(recent_transactions.number, 100); // Adjust based on the expected number of recent transactions
}

#[zilliqa_macros::test]
async fn get_smart_contract_sub_state(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let contract_address = "fe001824823b12b58708bf24edd94d8b5e1cfcf7";
    let variable_name = "admins";
    let indices: Vec<Value> = vec![];

    let response: Value = wallet
        .provider()
        .request(
            "GetSmartContractSubState",
            (contract_address, variable_name, indices),
        )
        .await
        .expect("Failed to call GetSmartContractSubState API");

    let sub_state: zilliqa::api::types::zil::SmartContractSubState =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(
        sub_state._balance.parse::<u64>().is_ok(),
        "Invalid balance format"
    );
    if let Some(admins) = sub_state.admins {
        assert!(
            admins.is_object(),
            "Expected admins to be an object, got: {:?}",
            admins
        );
    }
}

#[zilliqa_macros::test]
async fn get_soft_confirmed_transaction(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let txn_hash = "cd8727674bc05e0ede405597a218164e1c13c7103b9d0ba43586785f3d8cede5";

    let response: Value = wallet
        .provider()
        .request("GetSoftConfirmedTransaction", [txn_hash])
        .await
        .expect("Failed to call GetSoftConfirmedTransaction API");

    zilliqa::api::types::zil::GetTxResponse::deserialize(&response)
        .expect("Failed to deserialize response");
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

    let state_proof: zilliqa::api::types::zil::StateProofResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(
        state_proof.accountProof.len() > 0,
        "Expected accountProof to be non-empty, got: {:?}",
        state_proof.accountProof
    );
    assert!(
        state_proof.stateProof.len() > 0,
        "Expected stateProof to be non-empty, got: {:?}",
        state_proof.stateProof
    );
}

#[zilliqa_macros::test]
async fn get_total_coin_supply(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetTotalCoinSupply", [""])
        .await
        .expect("Failed to call GetTotalCoinSupply API");

    assert!(
        response.is_string(),
        "Expected response to be a string, got: {:?}",
        response
    );
}

#[zilliqa_macros::test]
async fn get_total_coin_supply_as_int(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetTotalCoinSupplyAsInt", [""])
        .await
        .expect("Failed to call GetTotalCoinSupplyAsInt API");

    assert!(
        response.is_number(),
        "Expected response to be a number, got: {:?}",
        response
    );

    let total_coin_supply_as_int: u64 = response.as_u64().expect("Expected number conversion");
    assert!(
        total_coin_supply_as_int > 0,
        "Total coin supply should be greater than 0"
    );
}

#[zilliqa_macros::test]
async fn get_transaction_status(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let txn_hash = "1bb178b023f816e950d862f6505cd79a32bb97e71fd78441cbc3486940a2e1b7";

    let response: Value = wallet
        .provider()
        .request("GetTransactionStatus", [txn_hash])
        .await
        .expect("Failed to call GetTransactionStatus API");

    let tx_status: zilliqa::api::types::zil::TransactionStatusResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(tx_status.ID, txn_hash);
    assert!(
        tx_status.amount.parse::<f64>().is_ok(),
        "Invalid amount format"
    );
    assert!(
        tx_status.gasLimit.parse::<u64>().is_ok(),
        "Invalid gasLimit format"
    );
    assert!(
        tx_status.gasPrice.parse::<u64>().is_ok(),
        "Invalid gasPrice format"
    );
    assert!(
        tx_status.nonce.parse::<u64>().is_ok(),
        "Invalid nonce format"
    );
}

#[zilliqa_macros::test]
async fn get_txn_bodies_for_tx_block_ex(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let block_number = "1002353";
    let page_number = "2";

    let response: Value = wallet
        .provider()
        .request("GetTxnBodiesForTxBlockEx", [block_number, page_number])
        .await
        .expect("Failed to call GetTxnBodiesForTxBlockEx API");

    let txn_bodies: zilliqa::api::types::zil::TxnBodiesForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txn_bodies.CurrPage, page_number.parse::<u64>().unwrap());
    assert!(
        txn_bodies.NumPages > 0,
        "Expected NumPages to be greater than 0"
    );
    assert!(
        txn_bodies.Transactions.len() <= 2500,
        "Expected Transcations length to be less than or equal to 2500"
    );
}

#[zilliqa_macros::test]
async fn get_tx_block_rate(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetTxBlockRate", [""])
        .await
        .expect("Failed to call GetTxBlockRate API");

    assert!(
        response.is_number(),
        "Expected response to be a number, got: {:?}",
        response
    );

    let tx_block_rate: f64 = response.as_f64().expect("Expected number conversion");
    assert!(
        tx_block_rate >= 0.0,
        "Transaction block rate should be non-negative"
    );
}

#[zilliqa_macros::test]
async fn get_tx_rate(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let response: Value = wallet
        .provider()
        .request("GetTxRate", [""])
        .await
        .expect("Failed to call GetTxRate API");

    let tx_rate: zilliqa::api::types::zil::TxRate =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert!(
        tx_rate.tx_block_rate >= 0.0,
        "Transaction block rate should be non-negative"
    );
    assert!(
        tx_rate.transaction_rate >= 0.0,
        "Transaction rate should be non-negative"
    );
}

#[zilliqa_macros::test]
async fn get_txn_bodies_for_tx_block_ex(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let block_number = "1002353";
    let page_number = "2";

    let response: Value = wallet
        .provider()
        .request("GetTxnBodiesForTxBlockEx", [block_number, page_number])
        .await
        .expect("Failed to call GetTxnBodiesForTxBlockEx API");

    let txn_bodies: zilliqa::api::types::zil::TxnBodiesForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txn_bodies.CurrPage, page_number.parse::<u64>().unwrap());
    assert!(
        txn_bodies.NumPages > 0,
        "Expected NumPages to be greater than 0"
    );
    assert!(
        txn_bodies.Transactions.len() <= 2500,
        "Expected Transactions length to be less than or equal to 2500"
    );

    if !txn_bodies.Transactions.is_empty() {
        assert!(
            txn_bodies.Transactions[0].receipt.success,
            "Expected the first transaction to be successful, got: {:?}",
            txn_bodies.Transactions[0].receipt.success
        );
    }
}

#[zilliqa_macros::test]
async fn tx_block_listing(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let page_number = 1;

    let response: Value = wallet
        .provider()
        .request("TxBlockListing", [page_number])
        .await
        .expect("Failed to call TxBlockListing API");

    let tx_block_listing: zilliqa::api::types::zil::TxBlockListingResult =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(
        tx_block_listing.data.len(),
        10,
        "Expected 10 TxBlock listings"
    );
    assert!(
        tx_block_listing.maxPages >= 1,
        "Expected at least 1 page of TxBlock listings"
    );

    if !tx_block_listing.data.is_empty() {
        assert!(
            tx_block_listing.data[0].BlockNum > 0,
            "Expected BlockNum to be greater than 0, got: {:?}",
            tx_block_listing.data[0].BlockNum
        );
        assert!(
            !tx_block_listing.data[0].Hash.is_empty(),
            "Expected Hash to be non-empty, got: {:?}",
            tx_block_listing.data[0].Hash
        );
    }
}

#[zilliqa_macros::test]
async fn get_txns_for_tx_block_ex(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let block_number = "1002353";
    let page_number = "2";

    let response: Value = wallet
        .provider()
        .request("GetTransactionsForTxBlockEx", [block_number, page_number])
        .await
        .expect("Failed to call GetTransactionsForTxBlockEx API");

    let txns: zilliqa::api::types::zil::TxnsForTxBlockExResponse =
        serde_json::from_value(response).expect("Failed to deserialize response");

    assert_eq!(txns.CurrPage, page_number.parse::<u64>().unwrap());
    assert!(txns.NumPages > 0, "Expected NumPages to be greater than 0");
    assert!(
        txns.Transactions.len() <= 2500,
        "Expected Transactions length to be less than or equal to 2500"
    );
}
