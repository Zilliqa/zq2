use std::ops::DerefMut;

use ethers::{providers::Middleware, types::TransactionRequest};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use primitive_types::{H160, H256};
use prost::Message;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zilliqa::{
    schnorr,
    zq1_proto::{Nonce, ProtoTransactionCoreInfo},
};

use crate::Network;

#[zilliqa_macros::test]
async fn create_transaction(mut network: Network) {
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
            60,
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

    // Send a transaction from the Zilliqa account using the `CreateTransaction` API.
    let chain_id = wallet.get_chainid().await.unwrap().as_u32() - 0x8000;
    let version = (chain_id << 16) | 1u32;
    // Note the nonce is one-indexed.
    let nonce = 1;
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let amount = 200u128 * 10u128.pow(12);
    // TODO: Consider impact of scaling on gas parameters.
    let gas_price = wallet.get_gas_price().await.unwrap().as_u128();
    let gas_limit = 50_000u64;
    let proto = ProtoTransactionCoreInfo {
        version,
        toaddr: to_addr.as_bytes().to_vec(),
        senderpubkey: Some(public_key.to_sec1_bytes().into()),
        amount: Some(amount.to_be_bytes().to_vec().into()),
        gasprice: Some(gas_price.to_be_bytes().to_vec().into()),
        gaslimit: gas_limit,
        oneof2: Some(Nonce::Nonce(nonce)),
        oneof8: None,
        oneof9: None,
    };
    let txn_data = proto.encode_to_vec();
    let signature = schnorr::sign(&txn_data, &secret_key);

    let request = json!({
        "version": version,
        "nonce": nonce,
        "toAddr": to_addr,
        "amount": amount.to_string(),
        "pubKey": hex::encode(public_key.to_sec1_bytes()),
        "gasPrice": gas_price.to_string(),
        "gasLimit": gas_limit.to_string(),
        "signature": hex::encode(signature.to_bytes()),
    });

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
            60,
        )
        .await
        .unwrap();

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
