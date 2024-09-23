use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    str::FromStr,
};

use anyhow::{anyhow, Ok, Result};
use clap::ValueEnum;
use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::NamedTempFile;
use tera::{Context, Tera};
use tokio::{fs::File, io::AsyncWriteExt};

use crate::{address::EthereumAddress, chain::Chain};

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
    /// Virtual machine validator
    Validator,
    /// Virtual machine api
    Api,
    /// Virtual machine apps
    Apps,
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct ChainNode {
    chain_name: String,
    eth_chain_id: u64,
    pub role: NodeRole,
    machine: Machine,
    versions: HashMap<String, String>,
    bootstrap_public_ip: String,
    bootstrap_private_key: String,
    genesis_wallet_private_key: String,
}

#[allow(clippy::too_many_arguments)]
impl ChainNode {
    pub fn new(
        chain_name: String,
        eth_chain_id: u64,
        role: NodeRole,
        machine: Machine,
        versions: HashMap<String, String>,
        bootstrap_public_ip: String,
        bootstrap_private_key: String,
        genesis_wallet_private_key: String,
    ) -> Self {
        Self {
            chain_name,
            eth_chain_id,
            role,
            machine,
            versions,
            bootstrap_public_ip,
            bootstrap_private_key,
            genesis_wallet_private_key,
        }
    }

    pub fn chain(&self) -> Result<Chain> {
        let chain_name = &self.chain_name;
        chain_name.parse()
    }

    pub fn name(&self) -> String {
        self.machine.name.clone()
    }

    pub async fn install(&self) -> Result<()> {
        let message = format!("Installing {} instance {}", self.role, self.machine.name);
        println!("{}", message.bold().yellow());

        self.tag_machine().await?;
        self.clean_previous_install().await?;
        self.import_config_files().await?;
        self.run_provisioning_script().await?;

        Ok(())
    }

    pub async fn upgrade(&self) -> Result<()> {
        let message = format!("Upgrading {} instance {}", self.role, self.machine.name);
        println!("{}", message.bold().yellow());

        self.tag_machine().await?;
        self.clean_previous_install().await?;
        self.import_config_files().await?;
        self.run_provisioning_script().await?;

        // Check the node is making progress
        if self.role != NodeRole::Apps {
            let first_block_number = self.machine.get_local_block_number().await?;
            loop {
                let next_block_number = self.machine.get_local_block_number().await?;
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

    pub fn get_genesis_key(&self) -> String {
        self.genesis_wallet_private_key.clone()
    }

    pub fn get_node_name(&self) -> String {
        self.machine.name.clone()
    }

    pub async fn get_private_key(&self) -> Result<String> {
        if self.role == NodeRole::Apps {
            return Err(anyhow!(
                "Node {} has role 'apps' and does not own a private key",
                &self.machine.name
            ));
        }

        let private_keys = retrieve_secret_by_node_name(
            &self.chain_name,
            &self.machine.project_id,
            &self.machine.name,
        )
        .await?;
        let private_key = if let Some(private_key) = private_keys.first() {
            private_key
        } else {
            return Err(anyhow!(
                "Found multiple private keys for the instance {}",
                &self.machine.name
            ));
        };

        Ok(private_key.to_owned())
    }

    pub async fn get_wallet_private_key(&self) -> Result<String> {
        if self.role == NodeRole::Apps {
            return Err(anyhow!(
                "Node {} has role 'apps' and does not own a private key",
                &self.machine.name
            ));
        }

        let private_keys = retrieve_wallet_secret_by_node_name(
            &self.chain_name,
            &self.machine.project_id,
            &self.machine.name,
        )
        .await?;
        let private_key = if let Some(private_key) = private_keys.first() {
            private_key
        } else {
            return Err(anyhow!(
                "Found multiple private keys for the instance {}",
                &self.machine.name
            ));
        };

        Ok(private_key.to_owned())
    }

    async fn tag_machine(&self) -> Result<()> {
        if self.role == NodeRole::Apps {
            return Ok(());
        }

        let private_keys = retrieve_secret_by_node_name(
            &self.chain_name,
            &self.machine.project_id,
            &self.machine.name,
        )
        .await?;
        let private_key = if let Some(private_key) = private_keys.first() {
            private_key
        } else {
            return Err(anyhow!(
                "Found multiple private keys for the instance {}",
                &self.machine.name
            ));
        };

        let ethereum_address = EthereumAddress::from_private_key(private_key)?;

        let mut labels = BTreeMap::<String, String>::new();
        labels.insert("peer-id".to_string(), ethereum_address.peer_id.clone());

        self.machine.add_labels(labels).await?;

        println!(
            "Tagged the machine {} with the peer-id {}",
            self.machine.name, ethereum_address.peer_id
        );

        Ok(())
    }

    async fn import_config_files(&self) -> Result<()> {
        let temp_config_toml = NamedTempFile::new()?;
        let config_toml = &self
            .create_config_toml(temp_config_toml.path().to_str().unwrap())
            .await?;
        let temp_provisioning_script = NamedTempFile::new()?;
        let provisioning_script = &self
            .create_provisioning_script(temp_provisioning_script.path().to_str().unwrap())
            .await?;

        self.machine
            .copy_to(&[config_toml], "/tmp/config.toml")
            .await?;

        self.machine
            .copy_to(&[provisioning_script], "/tmp/provision_node.py")
            .await?;

        if self.role == NodeRole::Checkpoint {
            let temp_checkpoint_cron_job = NamedTempFile::new()?;
            let checkpoint_cron_job = &self
                .create_checkpoint_cron_job(temp_checkpoint_cron_job.path().to_str().unwrap())
                .await?;

            self.machine
                .copy_to(&[checkpoint_cron_job], "/tmp/checkpoint_cron_job.sh")
                .await?;
        }

        println!("Configuration files imported in the node");

        Ok(())
    }

    async fn clean_previous_install(&self) -> Result<()> {
        let cmd = "sudo rm -f /tmp/config.toml /tmp/provision_node.py";
        let output = self.machine.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("Error removing previous installation files"));
        }

        println!("Removed previous installation files");

        Ok(())
    }

    async fn run_provisioning_script(&self) -> Result<()> {
        let cmd = "sudo chmod 666 /tmp/config.toml /tmp/provision_node.py && sudo mv /tmp/config.toml /config.toml && sudo python3 /tmp/provision_node.py";
        let output = self.machine.run(cmd).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("Error running the provisioning script"));
        }

        if self.role == NodeRole::Checkpoint {
            let cmd = "sudo chmod 777 /tmp/checkpoint_cron_job.sh && sudo mv /tmp/checkpoint_cron_job.sh /checkpoint_cron_job.sh && echo '*/5 * * * * /checkpoint_cron_job.sh' | sudo crontab -";
            let output = self.machine.run(cmd).await?;
            if !output.success {
                println!("{:?}", output.stderr);
                return Err(anyhow!("Error creating the checkpoint cronjob"));
            }
        }

        println!("Provisioning script run successfully");

        Ok(())
    }

    async fn create_checkpoint_cron_job(&self, filename: &str) -> Result<String> {
        let spec_config = include_str!("../../resources/checkpoints.tera.sh");

        let eth_chain_id = self.eth_chain_id.to_string();

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("network_name", &self.chain_name);
        var_map.insert("eth_chain_id", &eth_chain_id);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(spec_config, &ctx, false)?;
        let config_file = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(config_file.as_bytes()).await?;
        println!("Cron job file created: {filename}");

        Ok(filename.to_owned())
    }

    async fn create_config_toml(&self, filename: &str) -> Result<String> {
        let spec_config = include_str!("../../resources/config.tera.toml");

        let genesis_wallet = EthereumAddress::from_private_key(&self.genesis_wallet_private_key)?;
        let bootstrap_node = EthereumAddress::from_private_key(&self.bootstrap_private_key)?;
        let role_name = self.role.to_string();
        let eth_chain_id = self.eth_chain_id.to_string();

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("role", &role_name);
        var_map.insert("eth_chain_id", &eth_chain_id);
        var_map.insert("bootstrap_public_ip", &self.bootstrap_public_ip);
        var_map.insert("bootstrap_peer_id", &bootstrap_node.peer_id);
        var_map.insert("bootstrap_bls_public_key", &bootstrap_node.bls_public_key);
        var_map.insert("genesis_address", &genesis_wallet.address);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(spec_config, &ctx, false)?;
        let config_file = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(config_file.as_bytes()).await?;
        println!("Configuration file created: {filename}");

        Ok(filename.to_owned())
    }

    async fn create_provisioning_script(&self, filename: &str) -> Result<String> {
        // horrific implementation of a rendering engine for the provisioning script used
        // for both first install and upgrade of the ZQ2 network instances.
        // After the proto-testnet launch we can split the provisioning of the infra from the
        // deployment and the configuration of the apps and validator so, we can move it to a proper
        // tera template and remove this.

        let provisioning_script = include_str!("../../resources/node_provision.tera.py");
        let role_name = &self.role.to_string();

        let z2_image = &docker_image(
            "zq2",
            self.versions.get("zq2").unwrap_or(&"latest".to_string()),
        )?;

        let otterscan_image = &docker_image(
            "otterscan",
            self.versions
                .get("otterscan")
                .unwrap_or(&"latest".to_string()),
        )?;

        let spout_image = &docker_image(
            "spout",
            self.versions.get("spout").unwrap_or(&"latest".to_string()),
        )?;

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("role", role_name);
        var_map.insert("docker_image", z2_image);
        var_map.insert("otterscan_image", otterscan_image);
        var_map.insert("spout_image", spout_image);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(provisioning_script, &ctx, false)?;
        let provisioning_script = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(provisioning_script.as_bytes()).await?;
        println!("Provisioning file created: {filename}");

        Ok(filename.to_owned())
    }
}

pub async fn retrieve_secret_by_role(
    chain_name: &str,
    project_id: &str,
    role_name: &str,
) -> Result<Vec<String>> {
    retrieve_secret(
        chain_name,
        project_id,
        format!(
            "labels.zq2-network={} AND labels.role={}",
            chain_name, role_name
        )
        .as_str(),
    )
    .await
}

async fn retrieve_secret_by_node_name(
    chain_name: &str,
    project_id: &str,
    node_name: &str,
) -> Result<Vec<String>> {
    retrieve_secret(
        chain_name,
        project_id,
        format!(
            "labels.zq2-network={} AND labels.node-name={}",
            chain_name, node_name
        )
        .as_str(),
    )
    .await
}

async fn retrieve_wallet_secret_by_node_name(
    chain_name: &str,
    project_id: &str,
    node_name: &str,
) -> Result<Vec<String>> {
    retrieve_secret(
        chain_name,
        project_id,
        format!(
            "labels.zq2-network={} AND labels.node-name={} AND labels.is_reward_wallet=true",
            chain_name, node_name
        )
        .as_str(),
    )
    .await
}

async fn retrieve_secret(chain_name: &str, project_id: &str, filter: &str) -> Result<Vec<String>> {
    let mut secrets_found = Vec::<String>::new();

    // List secrets with gcloud command
    let output = zqutils::commands::CommandBuilder::new()
        .silent()
        .cmd(
            "gcloud",
            &[
                "secrets",
                "list",
                "--project",
                project_id,
                "--format=json",
                "--filter",
                filter,
            ],
        )
        .run()
        .await?;

    if !output.success {
        return Err(anyhow!("listing secrets failed"));
    }

    // Parse the JSON output
    let secrets: Vec<BTreeMap<String, serde_json::Value>> = serde_json::from_slice(&output.stdout)?;

    // Iterate over the secrets and get their latest versions
    for secret in secrets {
        if let Some(secret_name) = secret.get("name").and_then(|v| v.as_str()) {
            // Find the last '/' in the string
            if let Some(last_slash_pos) = secret_name.rfind('/') {
                let last_part = &secret_name[last_slash_pos + 1..];

                let output = zqutils::commands::CommandBuilder::new()
                    .silent()
                    .cmd(
                        "gcloud",
                        &[
                            "--project",
                            project_id,
                            "secrets",
                            "versions",
                            "access",
                            "latest",
                            "--secret",
                            last_part,
                        ],
                    )
                    .run()
                    .await?;

                if !output.success {
                    return Err(anyhow!("Error executing the command to retrieve secrets with filter '{}' in the network {}", filter, chain_name));
                }

                secrets_found.push(std::str::from_utf8(&output.stdout)?.to_string());
            } else {
                return Err(anyhow!("Error: secret name {} malformed", secret_name));
            }
        }
    }

    Ok(secrets_found)
}
