#![allow(unused_imports)]

use std::{
    path::PathBuf,
    process::{self, Stdio},
};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;

use tokio::fs;

#[derive(Deserialize, Serialize)]
struct NetworkConfig {
    name: String,
    version: String,
    gcp_project: String,
    binary_bucket: String,
}

impl NetworkConfig {
    fn new(name: String, gcp_project: String, binary_bucket: String) -> Self {
        Self {
            name,
            version: "main".to_owned(),
            gcp_project,
            binary_bucket,
        }
    }
}

async fn get_local_block_number(project: &str, instance: &str, zone: &str) -> Result<u64> {
    let inner_command = r#"curl -s http://localhost:4201 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}'"#;
    let output = zqutils::commands::CommandBuilder::new()
        .cmd(
            "gcloud",
            &[
                "--project",
                &project,
                "compute",
                "ssh",
                "--ssh-flag=-o StrictHostKeyChecking=no",
                &instance,
                "--tunnel-through-iap",
                "--zone",
                &zone,
                "--command",
                &inner_command,
            ],
        )
        .run()
        .await?;

    if !output.success {
        return Err(anyhow!(
            "getting local block number failed: {:?}",
            output.stderr
        ));
    }

    let response: Value = serde_json::from_slice(&output.stdout)?;
    let block_number = response
        .get("result")
        .ok_or_else(|| anyhow!("response has no result"))?
        .as_str()
        .ok_or_else(|| anyhow!("result is not a string"))?
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("result does not start with 0x"))?;
    let block_number = u64::from_str_radix(block_number, 16)?;

    Ok(block_number)
}

pub async fn new(network_name: &str, gcp_project: &str, binary_bucket: &str) -> Result<()> {
    let config = NetworkConfig::new(network_name.to_string(), gcp_project.to_string(), binary_bucket.to_string());
    let config = toml::to_string_pretty(&config)?;
    fs::write(format!("{network_name}.toml"), config).await?;
    Ok(())
}

pub async fn upgrade(_config_file: String) -> Result<()> {
    Ok(())
}
