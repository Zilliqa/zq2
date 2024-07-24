#![allow(unused_imports)]

use std::{
    collections::{BTreeMap, HashMap},
    fmt::{self, Display},
    io::Write,
    path::PathBuf,
    process::{self, Stdio},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use bitvec::order::verify_for_type;
use clap::ValueEnum;
use git2::Repository;
use regex::Regex;
use revm::handler::validation;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};
use tera::{Context, Tera};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use zilliqa::node::Node;

use crate::{
    github::{self, get_release_or_commit},
    node::get_nodes,
    validators,
};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Components {
    #[serde(rename = "zq2")]
    ZQ2,
    #[serde(rename = "otterscan")]
    Otterscan,
    #[serde(rename = "spout")]
    Spout,
}

impl FromStr for Components {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "zq2" => Ok(Components::ZQ2),
            "otterscan" => Ok(Components::Otterscan),
            "spout" => Ok(Components::Spout),
            _ => Err(anyhow!("Component not supported")),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct NetworkConfig {
    name: String,
    project_id: String,
    regions: Vec<String>,
    roles: Vec<NodeRole>,
    versions: HashMap<String, String>,
}

pub fn docker_image(component: &str, version: &str) -> Result<String> {
    // Define regular expressions for semantic version and 8-character commit ID
    let semver_re = Regex::new(r"^v\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$").unwrap();
    let commit_id_re = Regex::new(r"^[a-f0-9]{8}$").unwrap();
    match component.to_string().parse::<Components>()? {
        Components::ZQ2 => {
            if semver_re.is_match(version) {
                Ok(format!(
                    "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zq2:{}",
                    version
                ))
            } else if commit_id_re.is_match(version) {
                Ok(format!(
                    "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-private/zq2:{}",
                    version
                ))
            } else {
                Err(anyhow!("Invalid version for ZQ2"))
            }
        }
        Components::Spout => Ok(format!(
            "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/eth-spout:{}",
            version
        )),
        Components::Otterscan => Ok(format!("docker.io/zilliqa/otterscan:{}", version)),
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Virtual machine validator
    Validator,
    /// Virtual machine apps
    Apps,
    /// Virtual machine bootstrap
    Bootstrap,
    /// Virtual machine sentry
    Sentry,
    /// Virtual machine checkpoint
    Checkpoint,
}

impl FromStr for NodeRole {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "validator" => Ok(NodeRole::Validator),
            "apps" => Ok(NodeRole::Apps),
            "bootstrap" => Ok(NodeRole::Bootstrap),
            "sentry" => Ok(NodeRole::Sentry),
            "checkpoint" => Ok(NodeRole::Checkpoint),
            _ => Err(anyhow!("Node role not supported")),
        }
    }
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NodeRole::Apps => write!(f, "apps"),
            NodeRole::Validator => write!(f, "validator"),
            NodeRole::Bootstrap => write!(f, "bootstrap"),
            NodeRole::Sentry => write!(f, "sentry"),
            NodeRole::Checkpoint => write!(f, "checkpoint"),
        }
    }
}

impl NetworkConfig {
    async fn new(name: String, project_id: String, roles: Vec<NodeRole>) -> Result<Self> {
        let mut versions = HashMap::new();

        for r in roles.clone() {
            if r.to_string().to_lowercase() == "validator" {
                versions.insert(
                    "zq2".to_string(),
                    github::get_release_or_commit("zq2").await?,
                );
            } else if r.to_string().to_lowercase() == "apps" {
                versions.insert(
                    "spout".to_string(),
                    github::get_release_or_commit("zilliqa-developer").await?,
                );
                versions.insert("otterscan".to_string(), "latest".to_string());
            }
        }

        Ok(Self {
            name,
            project_id,
            roles,
            versions,
            regions: vec!["asia-southeast1".to_owned()],
        })
    }
}

pub struct Machine {
    pub project_id: String,
    pub zone: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub external_address: String,
}

impl Machine {
    pub async fn copy_to(&self, file_from: &[&str], file_to: &str) -> Result<()> {
        let tgt_spec = format!("{0}:{file_to}", &self.name);
        let args = [
            &[
                "compute",
                "scp",
                "--project",
                &self.project_id,
                "--zone",
                &self.zone,
                "--tunnel-through-iap",
                "--strict-host-key-checking=no",
                "--scp-flag=-r",
            ],
            file_from,
            &[&tgt_spec],
        ]
        .concat();

        zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd("gcloud", &args)
            .run()
            .await?;
        Ok(())
    }

    pub async fn run(&self, cmd: &str) -> Result<zqutils::commands::CommandOutput> {
        println!("Running command '{}' in {}", cmd, self.name);
        let output: zqutils::commands::CommandOutput = zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd(
                "gcloud",
                &[
                    "compute",
                    "ssh",
                    "--project",
                    &self.project_id,
                    "--zone",
                    &self.zone,
                    &self.name,
                    "--tunnel-through-iap",
                    "--strict-host-key-checking=no",
                    "--ssh-flag=",
                    "--command",
                    cmd,
                ],
            )
            .run_for_output()
            .await?;
        Ok(output)
    }
}

async fn get_local_block_number(instance: &Machine) -> Result<u64> {
    let inner_command = r#"curl -s http://localhost:4201 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}'"#;
    let output = instance.run(inner_command).await?;
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

pub async fn new(network_name: &str, project_id: &str, roles: Vec<NodeRole>) -> Result<()> {
    let config =
        NetworkConfig::new(network_name.to_string(), project_id.to_string(), roles).await?;
    let content = serde_yaml::to_string(&config)?;
    let mut file_path = std::env::current_dir()?;
    file_path.push(format!("{network_name}.yaml"));
    fs::write(file_path, content).await?;
    Ok(())
}

pub async fn install_or_upgrade(config_file: &str, is_upgrade: bool) -> Result<()> {
    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;
    let versions = config.versions;

    for node_role in config.roles.clone() {
        // Create a list of instances we need to update
        let nodes = get_nodes(
            &config.name,
            &config.project_id,
            node_role.clone(),
            versions.clone(),
        )
        .await?;

        for node in nodes.iter() {
            println!(
                "{} {} instance {} with address {}",
                if is_upgrade {
                    "Upgrading"
                } else {
                    "Installing"
                },
                node_role,
                node.machine.name,
                node.machine.external_address,
            );

            node.import_config_files().await?;
            node.run_provisioning_script().await?;

            // Check the node is making progress
            if is_upgrade && (node_role == NodeRole::Bootstrap || node_role == NodeRole::Validator)
            {
                let first_block_number = get_local_block_number(&node.machine).await?;
                loop {
                    let next_block_number = get_local_block_number(&node.machine).await?;
                    println!(
                        "Polled block number at {next_block_number}, waiting for {} more blocks",
                        (first_block_number + 10).saturating_sub(next_block_number)
                    );
                    if next_block_number >= first_block_number + 10 {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
