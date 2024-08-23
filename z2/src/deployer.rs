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
    task,
};
use zilliqa::node::Node;

use crate::{
    address::EthereumAddress,
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
    eth_chain_id: u64,
    project_id: String,
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

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Virtual machine bootstrap
    Bootstrap,
    /// Virtual machine api
    Api,
    /// Virtual machine apps
    Apps,
    /// Virtual machine validator
    Validator,
    /// Virtual machine checkpoint
    Checkpoint,
    /// Virtual machine sentry
    Sentry,
}

impl FromStr for NodeRole {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "bootstrap" => Ok(NodeRole::Bootstrap),
            "api" => Ok(NodeRole::Api),
            "apps" => Ok(NodeRole::Apps),
            "validator" => Ok(NodeRole::Validator),
            "checkpoint" => Ok(NodeRole::Checkpoint),
            "sentry" => Ok(NodeRole::Sentry),
            _ => Err(anyhow!("Node role not supported")),
        }
    }
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NodeRole::Bootstrap => write!(f, "bootstrap"),
            NodeRole::Api => write!(f, "api"),
            NodeRole::Apps => write!(f, "apps"),
            NodeRole::Validator => write!(f, "validator"),
            NodeRole::Checkpoint => write!(f, "checkpoint"),
            NodeRole::Sentry => write!(f, "sentry"),
        }
    }
}

impl NetworkConfig {
    async fn new(
        name: String,
        eth_chain_id: u64,
        project_id: String,
        roles: Vec<NodeRole>,
    ) -> Result<Self> {
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
            eth_chain_id,
            project_id,
            roles,
            versions,
        })
    }
}

#[derive(Clone)]
pub struct Machine {
    pub project_id: String,
    pub zone: String,
    pub name: String,
    pub external_address: String,
    pub labels: BTreeMap<String, String>,
}

impl Machine {
    pub async fn add_labels(&self, labels: BTreeMap<String, String>) -> Result<()> {
        let labels = &labels
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        let args = [
            "--project",
            &self.project_id,
            "compute",
            "instances",
            "add-labels",
            &self.name,
            &format!("--labels={}", labels.to_lowercase()),
            "--zone",
            &self.zone,
        ];

        println!("gcloud {}", args.join(" "));

        zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd("gcloud", &args)
            .run()
            .await?;
        Ok(())
    }

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

    pub async fn get_local_block_number(&self) -> Result<u64> {
        let inner_command = r#"curl -s http://localhost:4201 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}'"#;
        let output = self.run(inner_command).await?;
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
}

pub async fn new(
    network_name: &str,
    eth_chain_id: u64,
    project_id: &str,
    roles: Vec<NodeRole>,
) -> Result<()> {
    let config = NetworkConfig::new(
        network_name.to_string(),
        eth_chain_id,
        project_id.to_string(),
        roles,
    )
    .await?;
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

    let mut node_roles = config.roles.clone();
    node_roles.sort();

    for node_role in node_roles {
        // Create a list of instances we need to update
        let nodes = get_nodes(
            &config.name,
            config.eth_chain_id,
            &config.project_id,
            node_role.clone(),
            versions.clone(),
        )
        .await?;

        let futures = nodes
            .into_iter()
            .map(|node| {
                task::spawn(async move {
                    let result = if is_upgrade {
                        node.upgrade().await
                    } else {
                        node.install().await
                    };
                    (node, result)
                })
            })
            .collect::<Vec<_>>();

        let results = futures::future::join_all(futures).await;

        let mut successes = vec![];
        let mut failures = vec![];

        for result in results {
            match result? {
                (node, Ok(())) => successes.push(node.name()),
                (node, Err(err)) => {
                    println!("Node {} failed with error: {}", node.name(), err);
                    failures.push(node.name());
                }
            }
        }

        if !successes.is_empty() {
            println!("Successes: {}", successes.join(" "));
        }

        if !failures.is_empty() {
            println!("Failures: {}", failures.join(" "));
        }
    }

    Ok(())
}

pub async fn get_deposit_commands(config_file: &str) -> Result<()> {
    let config = fs::read_to_string(config_file).await?;
    let config: NetworkConfig = serde_yaml::from_str(&config.clone())?;
    let versions = config.versions;
    let chain_name = &config.name;

    // Create a list of validators instances
    let nodes = get_nodes(
        chain_name,
        config.eth_chain_id,
        &config.project_id,
        NodeRole::Validator,
        versions.clone(),
    )
    .await?;

    println!(
        "Deposit commands for the validators in the chain {}",
        chain_name
    );

    for node in nodes {
        let genesis_private_key = node.get_genesis_key();
        let private_keys = node.get_private_key().await?;
        let node_ethereum_address = EthereumAddress::from_private_key(&private_keys)?;
        let reward_private_keys = node.get_wallet_private_key().await?;
        let node_reward_ethereum_address = EthereumAddress::from_private_key(&reward_private_keys)?;

        println!("Validator {}:", node.get_node_name());
        println!("z2 deposit --chain {} \\", chain_name);
        println!("\t--peer-id {} \\", node_ethereum_address.peer_id);
        println!("\t--public-key {} \\", node_ethereum_address.bls_public_key);
        println!(
            "\t--pop-signature {} \\",
            node_ethereum_address.bls_pop_signature
        );
        println!("\t--private-key {} \\", genesis_private_key);
        println!(
            "\t--reward-address {} \\",
            node_reward_ethereum_address.address
        );
        println!("\t--amount 100\n");
    }

    Ok(())
}
