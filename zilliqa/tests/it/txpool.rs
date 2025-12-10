use alloy::{
    primitives::{Address, U256},
    providers::{Provider as _, WalletProvider},
    rpc::types::TransactionRequest,
};
use serde_json::Value;

use crate::Network;

// txpool_content tests

#[zilliqa_macros::test]
async fn txpool_content(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

    // First check that the txpool is empty
    let empty_response: Value = provider
        .request("txpool_content", ())
        .await
        .expect("Failed to call txpool_content API");

    assert!(
        empty_response
            .get("pending")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty pending transactions"
    );
    assert!(
        empty_response
            .get("queued")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty queued transactions"
    );

    // Send a transaction but don't mine it yet
    let to_addr = Address::random();
    let tx = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(100))
        .gas_limit(21_000);
    let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();

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
    let wallet_addr = format!("{:?}", wallet.default_signer_address()).to_lowercase();

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
                wallet
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

    assert!(
        final_response
            .get("pending")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty pending transactions after mining"
    );
    assert!(
        final_response
            .get("queued")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty queued transactions after mining"
    );
}

// txpool_content_from tests

#[zilliqa_macros::test]
async fn txpool_content_from(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

    // Send a transaction but don't mine it yet
    let to_addr = Address::random();
    let tx = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(100))
        .gas_limit(21_000);
    let _tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();

    // Check the txpool for transactions from our wallet address
    let response: Value = provider
        .request("txpool_contentFrom", [wallet.default_signer_address()])
        .await
        .expect("Failed to call txpool_contentFrom API");

    let pending = response["pending"].as_object().unwrap();
    assert!(
        !pending.is_empty(),
        "Expected non-empty pending transactions for our address"
    );

    // Convert wallet address to lowercase string for comparison
    let wallet_addr = format!("{:?}", wallet.default_signer_address()).to_lowercase();

    // Check if our transaction is in the pending pool
    let found = pending
        .iter()
        .any(|(addr, _)| addr.to_lowercase() == wallet_addr);
    assert!(found, "Couldn't find our address in the pending pool");

    // Try with a different address that should have no transactions
    let random_addr = Address::random();
    let empty_response: Value = provider
        .request("txpool_contentFrom", [random_addr])
        .await
        .expect("Failed to call txpool_contentFrom API with random address");

    assert!(
        empty_response
            .get("pending")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty pending transactions for random address"
    );
    assert!(
        empty_response
            .get("queued")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty queued transactions for random address"
    );
}

#[zilliqa_macros::test]
async fn txpool_content_from_with_queued(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

    // Send transactions with nonces out of order to create queued transactions
    let to_addr = Address::random();

    // First send a transaction with nonce 2 (should be queued)
    let tx_queued = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(300))
        .gas_limit(21_000)
        .nonce(2);
    let _ = *wallet.send_transaction(tx_queued).await.unwrap().tx_hash();

    // Then send a transaction with nonce 0 (should be pending)
    let tx_pending = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(100))
        .gas_limit(21_000)
        .nonce(0);
    let _ = *wallet.send_transaction(tx_pending).await.unwrap().tx_hash();

    // Check txpool_contentFrom for our wallet
    let content: Value = provider
        .request("txpool_contentFrom", [wallet.default_signer_address()])
        .await
        .expect("Failed to call txpool_contentFrom API");

    // Verify there's a transaction in the pending section
    let pending = content["pending"].as_object().unwrap();
    assert!(!pending.is_empty(), "Expected transactions in pending");

    // Verify there's a transaction in the queued section
    let queued = content["queued"].as_object().unwrap();
    assert!(!queued.is_empty(), "Expected transactions in queued");

    // Check for a random address - should be empty
    let random_addr = Address::random();
    let empty_content: Value = provider
        .request("txpool_contentFrom", [random_addr])
        .await
        .expect("Failed to call txpool_contentFrom API with random address");

    assert!(
        empty_content
            .get("pending")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty pending for random address"
    );
    assert!(
        empty_content
            .get("queued")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty queued for random address"
    );
}

// txpool_inspect tests

#[zilliqa_macros::test]
async fn txpool_inspect(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

    // First check that the txpool is empty
    let empty_response: Value = provider
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

    assert!(
        empty_response
            .get("pending")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty pending transactions"
    );
    assert!(
        empty_response
            .get("queued")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty queued transactions"
    );

    // Send a transaction but don't mine it yet
    let to_addr = Address::random();
    let value = 1234;
    let gas = 21000;
    let tx = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(value))
        .gas_limit(gas);

    let tx_hash = *wallet.send_transaction(tx).await.unwrap().tx_hash();

    // Now check the txpool inspect to see if our transaction is there
    let response: Value = provider
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

    // Check structure and content
    let pending = response["pending"].as_object().unwrap();
    assert!(
        !pending.is_empty(),
        "Expected non-empty pending transactions"
    );

    // Convert wallet address to lowercase string for comparison
    let wallet_addr = format!("{:?}", wallet.default_signer_address()).to_lowercase();

    // Check if our transaction is in the pending pool
    // The summary should contain the to address, value, and gas information
    let found = pending.iter().any(|(addr, txs)| {
        if addr.to_lowercase() == wallet_addr && txs.as_object().is_some() {
            let txs_obj = txs.as_object().unwrap();
            if !txs_obj.is_empty() {
                // Check if any of the transaction summaries contain our transaction details
                for (_, summary) in txs_obj {
                    let summary_str = summary.as_str().unwrap().to_lowercase();
                    let to_addr_string = format!("{to_addr:?}");
                    let value_string = value.to_string();
                    if summary_str.contains(&to_addr_string) && summary_str.contains(&value_string)
                    {
                        return true;
                    }
                }
            }
        }
        false
    });
    assert!(found, "Couldn't find our transaction in the pending pool");

    // Mine the block with our transaction
    network
        .run_until_async(
            || async {
                wallet
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
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

    assert!(
        final_response
            .get("pending")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty pending transactions after mining"
    );
    assert!(
        final_response
            .get("queued")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty queued transactions after mining"
    );
}

#[zilliqa_macros::test]
async fn txpool_inspect_with_queued(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

    // Send transactions with nonces out of order to create queued transactions
    let to_addr = Address::random();

    // First send a transaction with nonce 2 (should be queued)
    let tx_queued = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(300))
        .gas_limit(21_000)
        .nonce(2);
    let tx_hash_queued = *wallet.send_transaction(tx_queued).await.unwrap().tx_hash();

    // Then send a transaction with nonce 0 (should be pending)
    let tx_pending = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(100))
        .gas_limit(21_000)
        .nonce(0);
    let tx_hash_pending = *wallet.send_transaction(tx_pending).await.unwrap().tx_hash();

    // Check txpool_inspect to verify transaction locations
    let inspect: Value = provider
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

    let wallet_addr = format!("{:?}", wallet.default_signer_address()).to_lowercase();

    // Verify the pending section has our transaction
    let pending = inspect["pending"].as_object().unwrap();
    let pending_entry = pending
        .iter()
        .find(|(addr, _)| addr.to_lowercase() == wallet_addr);
    assert!(
        pending_entry.is_some(),
        "Wallet address not found in pending"
    );

    // Verify the queued section has our transaction
    let queued = inspect["queued"].as_object().unwrap();
    let queued_entry = queued
        .iter()
        .find(|(addr, _)| addr.to_lowercase() == wallet_addr);
    assert!(queued_entry.is_some(), "Wallet address not found in queued");

    // Send another transaction so we can mine
    let tx_nonce_1 = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(200))
        .gas_limit(21_000)
        .nonce(1);
    wallet.send_transaction(tx_nonce_1).await.unwrap().tx_hash();

    // Mine the transactions
    network
        .run_until_async(
            || async {
                wallet
                    .get_transaction_receipt(tx_hash_pending)
                    .await
                    .unwrap()
                    .is_some()
                    && wallet
                        .get_transaction_receipt(tx_hash_queued)
                        .await
                        .unwrap()
                        .is_some()
            },
            50,
        )
        .await
        .unwrap();

    // Check that the txpool is empty again
    let final_inspect: Value = provider
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

    assert!(
        final_inspect
            .get("pending")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty pending transactions after mining"
    );
    assert!(
        final_inspect
            .get("queued")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty(),
        "Expected empty queued transactions after mining"
    );
}

// txpool_status tests

#[zilliqa_macros::test]
async fn txpool_status(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.client();

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
    let to_addr = Address::random();

    // Send 3 transactions with different nonces
    let tx1 = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(100))
        .gas_limit(21_000)
        .nonce(0);
    let tx_hash1 = *wallet.send_transaction(tx1).await.unwrap().tx_hash();

    let tx2 = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(200))
        .gas_limit(21_000)
        .nonce(1);
    let tx_hash2 = *wallet.send_transaction(tx2).await.unwrap().tx_hash();

    let tx3 = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(300))
        .gas_limit(21_000)
        .nonce(2);

    let tx_hash3 = *wallet.send_transaction(tx3).await.unwrap().tx_hash();

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
                wallet
                    .get_transaction_receipt(tx_hash1)
                    .await
                    .unwrap()
                    .is_some()
                    && wallet
                        .get_transaction_receipt(tx_hash2)
                        .await
                        .unwrap()
                        .is_some()
                    && wallet
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
    let provider = wallet.client();

    // Send transactions with nonces out of order to create queued transactions
    let to_addr = Address::random();

    // First send a transaction with nonce 2 (should be queued)
    let tx_queued = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(300))
        .gas_limit(21_000)
        .nonce(2);
    let _ = *wallet.send_transaction(tx_queued).await.unwrap().tx_hash();

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
    let tx_pending = TransactionRequest::default()
        .to(to_addr)
        .value(U256::from(100))
        .gas_limit(21_000)
        .nonce(0);
    let _ = *wallet.send_transaction(tx_pending).await.unwrap().tx_hash();

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
}
