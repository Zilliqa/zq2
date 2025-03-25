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

// txpool_* tests
