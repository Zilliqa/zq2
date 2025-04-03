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

#[zilliqa_macros::test]
async fn txpool_inspect(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // First check that the txpool is empty
    let empty_response: Value = provider
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

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
    let value = 1234;
    let gas = 21000;
    let tx = TransactionRequest::pay(to_addr, value).gas(gas);
    let tx_hash = wallet.send_transaction(tx, None).await.unwrap().tx_hash();

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
    let wallet_addr = format!("{:?}", wallet.address()).to_lowercase();

    // Check if our transaction is in the pending pool
    // The summary should contain the to address, value, and gas information
    let found = pending.iter().any(|(addr, txs)| {
        if addr.to_lowercase() == wallet_addr && txs.as_object().is_some() {
            let txs_obj = txs.as_object().unwrap();
            if !txs_obj.is_empty() {
                // Check if any of the transaction summaries contain our transaction details
                for (_, summary) in txs_obj {
                    let summary_str = summary.as_str().unwrap().to_lowercase();
                    let to_addr_string = format!("{:?}", to_addr);
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
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

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

#[zilliqa_macros::test]
async fn txpool_inspect_with_queued(mut network: Network) {
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

    // Check txpool_inspect to verify transaction locations
    let inspect: Value = provider
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

    let wallet_addr = format!("{:?}", wallet.address()).to_lowercase();

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

    // Check that the txpool is empty again
    let final_inspect: Value = provider
        .request("txpool_inspect", ())
        .await
        .expect("Failed to call txpool_inspect API");

    let final_pending = final_inspect["pending"].as_object().unwrap();
    let final_queued = final_inspect["queued"].as_object().unwrap();
    assert!(
        final_pending.is_empty(),
        "Expected empty pending transactions after mining"
    );
    assert!(
        final_queued.is_empty(),
        "Expected empty queued transactions after mining"
    );
}

// txpool_status tests
