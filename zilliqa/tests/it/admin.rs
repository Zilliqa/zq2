use ethers::providers::Middleware;
use serde_json::Value;

use crate::Network;

#[zilliqa_macros::test]
async fn generate_checkpoint(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    network.run_until_block(&wallet, 8.into(), 800).await;
    let response: Value = wallet
        .provider()
        .request("admin_generateCheckpoint", ["0x4"])
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
    assert_eq!(response["block"], "0x4");
}

#[zilliqa_macros::test]
async fn admin_votes_received_empty(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Query votes when no consensus activity has happened yet
    let response: Value = wallet
        .provider()
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
    network.run_until_block(&wallet, 10.into(), 800).await;

    // Query votes after consensus activity
    let _response: Value = wallet
        .provider()
        .request("admin_votesReceived", ())
        .await
        .unwrap();
}
