use ethers::providers::Middleware;
use serde_json::Value;

use crate::Network;

#[zilliqa_macros::test]
async fn generate_checkpoint(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    network.run_until_block(&wallet, 8.into(), 400).await;
    let response: Value = wallet
        .provider()
        .request("admin_generateCheckpoint", ["0x4"])
        .await
        .unwrap();
    assert!(response["file_name"].is_string());
    assert!(!response["file_name"]
        .as_str()
        .unwrap()
        .to_string()
        .is_empty());
    assert!(!response["hash"].as_str().unwrap().to_string().is_empty());
    assert_eq!(response["block"], "0x4");
}
