use core::convert::AsRef;
use std::path::Path;

use anyhow::{anyhow, Result};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub async fn file_exists(file_name: impl AsRef<Path>) -> Result<bool> {
    Ok(tokio::fs::metadata(file_name).await.is_ok())
}

#[derive(Serialize, Deserialize, Debug)]
struct ChainIdResult {
    jsonrpc: String,
    id: u64,
    result: String,
}

pub fn split_repo_spec(repo_spec: &str) -> Result<(String, String)> {
    let split = repo_spec.split(':').collect::<Vec<&str>>();
    let branch = if let Some(val) = split.get(1) {
        val.to_string()
    } else {
        "main".to_string()
    };
    Ok((split[0].to_string(), branch))
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

/// Get string from path
pub fn string_from_path(in_path: &Path) -> Result<String> {
    Ok(in_path
        .as_os_str()
        .to_str()
        .ok_or(anyhow!("Cannot convert path to string"))?
        .to_string())
}

/// Get local public IP
pub async fn get_public_ip() -> Result<String> {
    let output: zqutils::commands::CommandOutput = zqutils::commands::CommandBuilder::new()
        .silent()
        .cmd("curl", &["-4", "ipconfig.io"])
        .run_for_output()
        .await?;

    let stdout = output.stdout;
    Ok(std::str::from_utf8(&stdout)?.trim().to_owned())
}
