use ethers::{core::types::TransactionRequest, providers::Middleware};
use primitive_types::H160;
use serde_json::Value;

use crate::Network;

// txpool_content tests

#[zilliqa_macros::test]
async fn txpool_content(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // First check that the txpool is empty
    let empty_response: Value = provider
        .request("txpool_content", ())
        .await
        .expect("Failed to call txpool_content API");

    let empty_pending = empty_response["pending"].as_object().unwrap();
    let empty_queued = empty_response["queued"].as_object().unwrap();
    assert!(
        empty_pending.is_empty(),
        "Expected empty pending transactions"
    );
    assert!(
        empty_queued.is_empty(),
        "Expected empty queued transactions"
    );

    // Send a transaction but don't mine it yet
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let tx = TransactionRequest::pay(to_addr, 100).gas(21000);
    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    // Now check the txpool to see if our transaction is there
    let response: Value = provider
        .request("txpool_content", ())
        .await
        .expect("Failed to call txpool_content API");

    let pending = response["pending"].as_object().unwrap();
    assert!(
        !pending.is_empty(),
        "Expected non-empty pending transactions"
    );

    // Convert wallet address to lowercase string for comparison
    let wallet_addr = format!("{:?}", wallet.address()).to_lowercase();

    // Check if our transaction is in the pending pool
    let found = pending.iter().any(|(addr, txs)| {
        addr.to_lowercase() == wallet_addr
            && txs.as_object().is_some()
            && !txs.as_object().unwrap().is_empty()
    });
    assert!(found, "Couldn't find our transaction in the pending pool");

    // Mine the block with our transaction
    network
        .run_until_async(
            || async {
                provider
                    .get_transaction_receipt(tx_hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // Check that the txpool is empty again
    let final_response: Value = provider
        .request("txpool_content", ())
        .await
        .expect("Failed to call txpool_content API");

    let final_pending = final_response["pending"].as_object().unwrap();
    let final_queued = final_response["queued"].as_object().unwrap();
    assert!(
        final_pending.is_empty(),
        "Expected empty pending transactions after mining"
    );
    assert!(
        final_queued.is_empty(),
        "Expected empty queued transactions after mining"
    );
}

// txpool_content_from tests

// txpool_inspect tests

// txpool_status tests

#[zilliqa_macros::test]
async fn txpool_status(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // First check that the txpool is empty
    let empty_response: Value = provider
        .request("txpool_status", ())
        .await
        .expect("Failed to call txpool_status API");

    assert_eq!(
        empty_response["pending"].as_u64().unwrap(),
        0,
        "Expected 0 pending transactions"
    );
    assert_eq!(
        empty_response["queued"].as_u64().unwrap(),
        0,
        "Expected 0 queued transactions"
    );

    // Send multiple transactions but don't mine them yet
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    // Send 3 transactions with different nonces
    let tx1 = TransactionRequest::pay(to_addr, 100).gas(21000).nonce(0);
    let tx_hash1 = wallet.send_transaction(tx1, None).await.unwrap().tx_hash();

    let tx2 = TransactionRequest::pay(to_addr, 200).gas(21000).nonce(1);
    let tx_hash2 = wallet.send_transaction(tx2, None).await.unwrap().tx_hash();

    let tx3 = TransactionRequest::pay(to_addr, 300).gas(21000).nonce(2);
    let tx_hash3 = wallet.send_transaction(tx3, None).await.unwrap().tx_hash();

    // Now check the txpool status to see if our transactions are counted
    let response: Value = provider
        .request("txpool_status", ())
        .await
        .expect("Failed to call txpool_status API");

    assert_eq!(
        response["pending"].as_u64().unwrap(),
        3,
        "Expected 3 pending transactions"
    );
    assert_eq!(
        response["queued"].as_u64().unwrap(),
        0,
        "Expected 0 queued transactions"
    );

    // Mine the block with our transactions
    network
        .run_until_async(
            || async {
                provider
                    .get_transaction_receipt(tx_hash1)
                    .await
                    .unwrap()
                    .is_some()
                    && provider
                        .get_transaction_receipt(tx_hash2)
                        .await
                        .unwrap()
                        .is_some()
                    && provider
                        .get_transaction_receipt(tx_hash3)
                        .await
                        .unwrap()
                        .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // Check that the txpool is empty again
    let final_response: Value = provider
        .request("txpool_status", ())
        .await
        .expect("Failed to call txpool_status API");

    assert_eq!(
        final_response["pending"].as_u64().unwrap(),
        0,
        "Expected 0 pending transactions after mining"
    );
    assert_eq!(
        final_response["queued"].as_u64().unwrap(),
        0,
        "Expected 0 queued transactions after mining"
    );
}

#[zilliqa_macros::test]
async fn txpool_status_with_queued(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // Send transactions with nonces out of order to create queued transactions
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();

    // First send a transaction with nonce 2 (should be queued)
    let tx_queued = TransactionRequest::pay(to_addr, 300).gas(21000).nonce(2);
    let tx_hash_queued = wallet
        .send_transaction(tx_queued, None)
        .await
        .unwrap()
        .tx_hash();

    // Check txpool status - should show 0 pending, 1 queued
    let response1: Value = provider
        .request("txpool_status", ())
        .await
        .expect("Failed to call txpool_status API");

    assert_eq!(
        response1["pending"].as_u64().unwrap(),
        0,
        "Expected 0 pending transactions"
    );
    assert_eq!(
        response1["queued"].as_u64().unwrap(),
        1,
        "Expected 1 queued transaction"
    );

    // Send transaction with nonce 0 (should be pending)
    let tx_pending = TransactionRequest::pay(to_addr, 100).gas(21000).nonce(0);
    let tx_hash_pending = wallet
        .send_transaction(tx_pending, None)
        .await
        .unwrap()
        .tx_hash();

    // Check txpool status - should show 1 pending, 1 queued
    let response2: Value = provider
        .request("txpool_status", ())
        .await
        .expect("Failed to call txpool_status API");

    assert_eq!(
        response2["pending"].as_u64().unwrap(),
        1,
        "Expected 1 pending transaction"
    );
    assert_eq!(
        response2["queued"].as_u64().unwrap(),
        1,
        "Expected 1 queued transaction"
    );

    // Mine the transactions
    network
        .run_until_async(
            || async {
                provider
                    .get_transaction_receipt(tx_hash_pending)
                    .await
                    .unwrap()
                    .is_some()
                    && provider
                        .get_transaction_receipt(tx_hash_queued)
                        .await
                        .unwrap()
                        .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // Verify txpool is empty
    let final_response: Value = provider
        .request("txpool_status", ())
        .await
        .expect("Failed to call txpool_status API");

    assert_eq!(
        final_response["pending"].as_u64().unwrap(),
        0,
        "Expected 0 pending transactions after mining"
    );
    assert_eq!(
        final_response["queued"].as_u64().unwrap(),
        0,
        "Expected 0 queued transactions after mining"
    );
}
