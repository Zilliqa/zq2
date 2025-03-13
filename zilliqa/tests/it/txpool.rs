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

#[zilliqa_macros::test]
async fn txpool_content_from(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // Send a transaction but don't mine it yet
    let to_addr: H160 = "0x00000000000000000000000000000000deadbeef"
        .parse()
        .unwrap();
    let tx = TransactionRequest::pay(to_addr, 100).gas(21000);
    let _tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

    // Check the txpool for transactions from our wallet address
    let response: Value = provider
        .request("txpool_contentFrom", [wallet.address()])
        .await
        .expect("Failed to call txpool_contentFrom API");

    let pending = response["pending"].as_object().unwrap();
    assert!(
        !pending.is_empty(),
        "Expected non-empty pending transactions for our address"
    );

    // Convert wallet address to lowercase string for comparison
    let wallet_addr = format!("{:?}", wallet.address()).to_lowercase();

    // Check if our transaction is in the pending pool
    let found = pending
        .iter()
        .any(|(addr, _)| addr.to_lowercase() == wallet_addr);
    assert!(found, "Couldn't find our address in the pending pool");

    // Try with a different address that should have no transactions
    let random_addr = H160::random();
    let empty_response: Value = provider
        .request("txpool_contentFrom", [random_addr])
        .await
        .expect("Failed to call txpool_contentFrom API with random address");

    let empty_pending = empty_response["pending"].as_object().unwrap();
    let empty_queued = empty_response["queued"].as_object().unwrap();
    assert!(
        empty_pending.is_empty(),
        "Expected empty pending transactions for random address"
    );
    assert!(
        empty_queued.is_empty(),
        "Expected empty queued transactions for random address"
    );
}

#[zilliqa_macros::test]
async fn txpool_content_from_with_queued(mut network: Network) {
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

    // Then send a transaction with nonce 0 (should be pending)
    let tx_pending = TransactionRequest::pay(to_addr, 100).gas(21000).nonce(0);
    let tx_hash_pending = wallet
        .send_transaction(tx_pending, None)
        .await
        .unwrap()
        .tx_hash();

    // Check txpool_contentFrom for our wallet
    let content: Value = provider
        .request("txpool_contentFrom", [wallet.address()])
        .await
        .expect("Failed to call txpool_contentFrom API");

    // Verify there's a transaction in the pending section
    let pending = content["pending"].as_object().unwrap();
    assert!(!pending.is_empty(), "Expected transactions in pending");

    // Verify there's a transaction in the queued section
    let queued = content["queued"].as_object().unwrap();
    assert!(!queued.is_empty(), "Expected transactions in queued");

    // Check for a random address - should be empty
    let random_addr = H160::random();
    let empty_content: Value = provider
        .request("txpool_contentFrom", [random_addr])
        .await
        .expect("Failed to call txpool_contentFrom API with random address");

    assert!(
        empty_content["pending"].as_object().unwrap().is_empty(),
        "Expected empty pending for random address"
    );
    assert!(
        empty_content["queued"].as_object().unwrap().is_empty(),
        "Expected empty queued for random address"
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

    // Check our address again - should be empty now
    let final_content: Value = provider
        .request("txpool_contentFrom", [wallet.address()])
        .await
        .expect("Failed to call txpool_contentFrom API after mining");

    assert!(
        final_content["pending"].as_object().unwrap().is_empty(),
        "Expected empty pending after mining"
    );
    assert!(
        final_content["queued"].as_object().unwrap().is_empty(),
        "Expected empty queued after mining"
    );
}

// txpool_inspect tests

// txpool_status tests
