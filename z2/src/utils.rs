use core::convert::AsRef;
use std::{env, fs, os::unix::fs::PermissionsExt, path::Path};

use anyhow::{anyhow, Result};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zilliqa::{cfg::Checkpoint, crypto::Hash};

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
        .cmd("curl", &["-s", "https://ipinfo.io/ip"])
        .run_for_output()
        .await?;

    let stdout = output.stdout;
    Ok(std::str::from_utf8(&stdout)?.trim().to_owned())
}

pub fn compute_log_string(
    log_level: &str,
    debug_modules: &Vec<String>,
    trace_modules: &Vec<String>,
) -> Result<String> {
    // Now build the log string. If there already was one, use that ..
    let log_var = env::var("RUST_LOG");
    let log_spec = match log_var {
        Ok(val) => {
            println!("Using RUST_LOG from environment");
            val
        }
        _ => {
            let mut val = log_level.to_string();
            for i in debug_modules {
                val.push_str(&format!(",{i}=debug"));
            }
            for i in trace_modules {
                val.push_str(&format!(",{i}=trace"));
            }
            val.push_str(",opentelemetry=trace,opentelemetry_otlp=trace");
            val
        }
    };
    Ok(log_spec)
}

pub fn make_executable<P: AsRef<Path>>(file_path: &P) -> Result<()> {
    let mut perms = fs::metadata(file_path)?.permissions();
    perms.set_mode(perms.mode() | 0o111);
    fs::set_permissions(file_path, perms)?;
    Ok(())
}

pub fn hash_from_hex(in_str: &str) -> Result<Hash> {
    let bytes = hex::decode(in_str)?;
    let result = Hash::try_from(bytes.as_slice())?;
    Ok(result)
}

pub fn parse_checkpoint_spec(spec: &str) -> Result<Checkpoint> {
    let components = spec.split(':').collect::<Vec<&str>>();
    if components.len() != 2 {
        Err(anyhow!(
            "Checkpoint spec is not in form <file>:<hash> - {spec}"
        ))
    } else {
        Ok(zilliqa::cfg::Checkpoint {
            file: components[0].to_string(),
            hash: hash_from_hex(components[1])?,
        })
    }
}

pub fn parse_range(in_val: &str) -> Result<(u64, u64)> {
    let mut fields = in_val.split('-');
    let mut min: u64 = 0;
    let mut max: u64 = 0;
    if let Some(mv) = fields.next() {
        min = mv.parse::<u64>()?;
    }
    if let Some(mv) = fields.next() {
        max = mv.parse::<u64>()?;
    }
    Ok((min, max))
}
