use alloy::providers::Provider;
use serde_json::Value;

use crate::Network;

#[zilliqa_macros::test]
async fn generate_checkpoint(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    // admin_generateCheckpoint snaps the requested block down to the nearest
    // epoch boundary. With blocks_per_epoch=10, requesting block 24 (0x18)
    // snaps to block 20 (0x14); hist_start=11 so epoch_parent=block 10 and
    // epoch_grandparent=block 9 — no genesis involved.
    network.run_until_block_finalized(25, 800).await.unwrap();
    let response: Value = wallet
        .client()
        .request("admin_generateCheckpoint", ["0x18"])
        .await
        .unwrap();
    assert!(response["file_name"].is_string());
    assert!(
        !response["file_name"]
            .as_str()
            .unwrap()
            .to_string()
            .is_empty()
    );
    assert!(!response["hash"].as_str().unwrap().to_string().is_empty());
    assert_eq!(response["block"], "0x14");
}

#[zilliqa_macros::test]
async fn admin_votes_received_empty(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    // Query votes when no consensus activity has happened yet
    let response: Value = wallet
        .client()
        .request("admin_votesReceived", ())
        .await
        .unwrap();

    // Verify all fields are empty
    assert!(response["votes"].as_array().unwrap().is_empty());
    assert!(response["buffered_votes"].as_array().unwrap().is_empty());
    assert!(response["new_views"].as_array().unwrap().is_empty());
}

#[zilliqa_macros::test]
async fn admin_votes_received_with_data(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Generate some blocks to trigger consensus activity
    // This should generate votes, possibly new views
    network.run_until_block_finalized(8, 800).await.unwrap();

    // Query votes after consensus activity
    let response: Value = wallet
        .client()
        .request("admin_votesReceived", ())
        .await
        .unwrap();
    // FIXME: missing asserts
    tracing::debug!("{:?}", response);
}
