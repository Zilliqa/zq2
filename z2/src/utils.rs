use anyhow::Result;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub async fn file_exists(file_name: &str) -> Result<bool> {
    Ok(tokio::fs::metadata(file_name).await.is_ok())
}

#[derive(Serialize, Deserialize, Debug)]
struct ChainIdResult {
    jsonrpc: String,
    id: u64,
    result: String,
}

pub async fn get_chain_id(url: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let res = client
        .post(url)
        .json(&json!(
        { "jsonrpc": "2.0",
           "method": "eth_chainId",
           "params": {},
           "id": 1
        }))
        .send()
        .await?;
    println!("Got chain id!");
    let json: ChainIdResult = res.json().await?;
    println!("Parsed {json:?}");
    let without_prefix = json.result.trim_start_matches("0x");
    Ok(u64::from_str_radix(without_prefix, 16)?)
}
