#![allow(unused_imports)]

use std::{
    path::PathBuf,
    process::{self, Stdio},
};

use anyhow::{anyhow, Result};
use git2::Repository;
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
    let config = NetworkConfig::new(
        network_name.to_string(),
        gcp_project.to_string(),
        binary_bucket.to_string(),
    );
    let config = toml::to_string_pretty(&config)?;
    fs::write(format!("{network_name}.toml"), config).await?;
    Ok(())
}

pub async fn upgrade(config_file: &str) -> Result<()> {
    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = toml::from_str(&config)?;

    // Checkout Zilliqa 2 source
    let repo_dir: TempDir = TempDir::new()?;
    let repo = Repository::clone("https://github.com/Zilliqa/zq2", repo_dir.path())?;
    let (object, _) = repo
        .revparse_ext(&format!("origin/{}", config.version))
        .or_else(|_| repo.revparse_ext(&config.version))?;
    repo.checkout_tree(&object, None)?;

    let binary_name = format!("zilliqa_{}", object.id());
    let binary_location = format!("gs://{}/{binary_name}", config.binary_bucket);

    // Check if binary already exists
    let status = process::Command::new("gsutil")
        .args(["-q", "stat"])
        .arg(&binary_location)
        .status()?;
    if !status.success() {
        println!("Building binary");

        // Build binary
        let status = process::Command::new("cross")
            .args([
                "build",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--profile",
                "release",
                "--bin",
                "zilliqa",
            ])
            .current_dir(repo_dir.path())
            .status()?;
        if !status.success() {
            return Err(anyhow!("build failed"));
        }

        println!("Binary built, uploading to GCS");

        // Upload binary to GCS
        let binary = repo_dir
            .path()
            .join("target")
            .join("x86_64-unknown-linux-gnu")
            .join("release")
            .join("zilliqa");
        let status = process::Command::new("gcloud")
            .arg("--project")
            .arg(&config.gcp_project)
            .args(["storage", "cp"])
            .arg(binary)
            .arg(&binary_location)
            .status()?;
        if !status.success() {
            return Err(anyhow!("upload failed"));
        }

        println!("Binary uploaded to GCS");
    } else {
        println!("Binary already exists in GCS");
    }

    // Get the list of instances we need to update.
    let output = process::Command::new("gcloud")
        .arg("--project")
        .arg(&config.gcp_project)
        .args(["compute", "instances", "list"])
        .args(["--format", "json"])
        .args(["--filter", &format!("labels.zq2-network={}", config.name)])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!("listing instances failed"));
    }
    let output: Value = serde_json::from_slice(&output.stdout)?;
    let instances: Vec<_> = output
        .as_array()
        .ok_or_else(|| anyhow!("instances is not an array"))?
        .iter()
        .map(|i| {
            let name = i
                .get("name")
                .ok_or_else(|| anyhow!("name is missing"))?
                .as_str()
                .ok_or_else(|| anyhow!("name is not a string"))?;
            let zone = i
                .get("zone")
                .ok_or_else(|| anyhow!("zone is missing"))?
                .as_str()
                .ok_or_else(|| anyhow!("zone is not a string"))?;
            Ok((name, zone))
        })
        .collect::<Result<_>>()?;

    if instances.is_empty() {
        println!("No instances found");
    }

    for (instance, zone) in instances {
        println!("Upgrading instance {instance}");

        let inner_command = format!(
            r#"
            sudo gcloud storage cp {binary_location} /{binary_name} &&
            sudo chmod +x /{binary_name} &&
            sudo rm /zilliqa &&
            sudo ln -s /{binary_name} /zilliqa &&
            sudo systemctl restart zilliqa.service
        "#
        );
        let output = zqutils::commands::CommandBuilder::new()
            .cmd(
                "gcloud",
                &[
                    "--project",
                    &config.gcp_project,
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
            println!("{:?}", output.stderr);
            return Err(anyhow!("upgrade failed"));
        }

        // Check the node is making progress
        let first_block_number =
            get_local_block_number(&config.gcp_project, instance, zone).await?;
        loop {
            let next_block_number =
                get_local_block_number(&config.gcp_project, instance, zone).await?;
            println!(
                "Polled block number at {next_block_number}, waiting for {} more blocks",
                (first_block_number + 10).saturating_sub(next_block_number)
            );
            if next_block_number >= first_block_number + 10 {
                break;
            }
        }
    }
    Ok(())
}
