use core::convert::AsRef;
use std::{env, fs, os::unix::fs::PermissionsExt, path::Path};

use alloy::hex;
use anyhow::{Result, anyhow};
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
    let response = reqwest::get("https://ipinfo.io/ip")
        .await?
        .error_for_status()?;
    Ok(response.text().await?)
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

pub fn string_decimal_to_hex(input: &str) -> Result<String> {
    if let Ok(decimal_value) = input.trim().parse::<u64>() {
        return Ok(format!("0x{decimal_value:X}"));
    }

    Err(anyhow!("Invalid decimal number provided."))
}

pub fn format_amount(number: f64) -> String {
    // Separate the integer and fractional parts
    let integer_part = number.trunc() as u64; // Get the integer part
    let fractional_part = number.fract(); // Get the fractional part

    // Format the integer part with commas
    let mut integer_str = integer_part.to_string();
    let mut formatted_integer = String::new();
    while integer_str.len() > 3 {
        let len = integer_str.len();
        formatted_integer = format!(",{}{}", &integer_str[len - 3..], formatted_integer);
        integer_str.truncate(len - 3);
    }
    formatted_integer = format!("{integer_str}{formatted_integer}");

    // Format the fractional part with six decimal places
    let formatted_fractional = format!("{fractional_part:.18}");
    let formatted_fractional = formatted_fractional.trim_start_matches('0');

    // Combine the integer and fractional parts
    format!("{formatted_integer}{formatted_fractional}")
}
