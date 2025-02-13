use std::{collections::BTreeMap, fmt, str::FromStr};

use anyhow::{anyhow, Ok, Result};
use clap::ValueEnum;
use cliclack::MultiProgress;
use colored::Colorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempfile::NamedTempFile;
use tera::{Context, Tera};
use tokio::{fs::File, io::AsyncWriteExt};

use super::instance::ChainInstance;
use crate::{address::EthereumAddress, chain::Chain, secret::Secret};

#[derive(Clone, Debug, Default, ValueEnum, PartialEq)]
pub enum NodePort {
    #[default]
    Default,
    Admin,
}

impl NodePort {
    pub fn value(&self) -> u64 {
        match self {
            NodePort::Default => 4201,
            NodePort::Admin => 4202,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Components {
    #[serde(rename = "zq2")]
    ZQ2,
    #[serde(rename = "otterscan")]
    Otterscan,
    #[serde(rename = "spout")]
    Spout,
    #[serde(rename = "stats_dashboard")]
    StatsDashboard,
    #[serde(rename = "stats_agent")]
    StatsAgent,
    #[serde(rename = "zq2_metrics")]
    ZQ2Metrics,
}

impl FromStr for Components {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "zq2" => Ok(Components::ZQ2),
            "otterscan" => Ok(Components::Otterscan),
            "spout" => Ok(Components::Spout),
            "stats_dashboard" => Ok(Components::StatsDashboard),
            "stats_agent" => Ok(Components::StatsAgent),
            "zq2_metrics" => Ok(Components::ZQ2Metrics),
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
        Components::Otterscan => Ok(format!("docker.io/zilliqa/otterscan:{}", version)),
        Components::Spout => Ok(format!(
            "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/eth-spout:{}",
            version
        )),
        Components::StatsDashboard => Ok(format!(
            "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zilstats-server:{}",
            version
        )),
        Components::StatsAgent => Ok(format!(
            "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zilstats-agent:{}",
            version
        )),
        Components::ZQ2Metrics => Ok(format!(
            "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-private/zq2-metrics:{}",
            version
        )),
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    /// Virtual machine bootstrap
    Bootstrap,
    /// Virtual machine validator
    Validator,
    /// Virtual machine api
    Api,
    /// Virtual machine private api
    PrivateApi,
    /// Virtual machine apps
    Apps,
    /// Virtual machine checkpoint
    Checkpoint,
    /// Virtual machine persistence
    Persistence,
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
            "private-api" => Ok(NodeRole::PrivateApi),
            "persistence" => Ok(NodeRole::Persistence),
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
            NodeRole::PrivateApi => write!(f, "private-api"),
            NodeRole::Persistence => write!(f, "persistence"),
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

    async fn copy(&self, file_from: &[&str], file_to: &str) -> Result<()> {
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

    pub async fn run(&self, cmd: &str, print: bool) -> Result<zqutils::commands::CommandOutput> {
        if print {
            println!("Running command '{}' in {}", cmd, self.name);
        }
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
        let output = self.run(inner_command, true).await?;
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

    pub async fn get_rpc_response(
        &self,
        method: &str,
        params: &Option<String>,
        timeout: usize,
        port: NodePort,
    ) -> Result<String> {
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"{}\",\"params\":{}}}",
            method,
            params.clone().unwrap_or("[]".to_string()),
        );

        let args = &[
            "--max-time",
            &timeout.to_string(),
            "-X",
            "POST",
            "-H",
            "Content-Type:application/json",
            "-H",
            "accept:application/json,*/*;q=0.5",
            "--data",
            &body,
            &format!("http://{}:{}", self.external_address, port.value()),
        ];

        let output = if port == NodePort::Admin {
            let inner_command = format!(
                r#"curl --max-time {} -X POST -H 'content-type: application/json' -H 'accept:application/json,*/*;q=0.5' -d '{}' http://localhost:{}"#,
                &timeout.to_string(),
                &body,
                port.value()
            );
            self.run(&inner_command, false).await?
        } else {
            zqutils::commands::CommandBuilder::new()
                .silent()
                .cmd("curl", args)
                .run_for_output()
                .await?
        };

        if !output.success {
            return Err(anyhow!(
                "getting rpc response for {} with params {:?} failed: {:?}",
                method,
                params,
                output.stderr
            ));
        }

        Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
    }

    pub async fn get_block_number(&self, timeout: usize) -> Result<u64> {
        let response: Value = serde_json::from_str(
            &self
                .get_rpc_response("eth_blockNumber", &None, timeout, NodePort::Default)
                .await?,
        )?;
        let block_number = response
            .get("result")
            .ok_or_else(|| anyhow!("response has no result"))?
            .as_str()
            .ok_or_else(|| anyhow!("result is not a string"))?
            .strip_prefix("0x")
            .ok_or_else(|| anyhow!("result does not start with 0x"))?;

        Ok(u64::from_str_radix(block_number, 16)?)
    }

    pub async fn get_consensus_info(&self, timeout: usize) -> Result<Value> {
        let response: Value = serde_json::from_str(
            &self
                .get_rpc_response("admin_consensusInfo", &None, timeout, NodePort::Admin)
                .await?,
        )?;

        let response = response
            .get("result")
            .ok_or_else(|| anyhow!("response has no result"))?;

        Ok(response.to_owned())
    }
}

#[derive(Debug, Deserialize)]
struct ConsensusInfo {
    view: String,
    high_qc: HighQc,
    milliseconds_since_last_view_change: u64,
    milliseconds_until_next_view_change: u64,
}

impl Default for ConsensusInfo {
    fn default() -> Self {
        Self {
            view: "---".to_string(),
            high_qc: HighQc::default(),
            milliseconds_since_last_view_change: u64::MIN,
            milliseconds_until_next_view_change: u64::MIN,
        }
    }
}

impl fmt::Display for ConsensusInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "view: {}\ttime_since_last_view_change: {}ms\ttime_until_next_view_change: {}ms\n{} {}",
            self.view,
            self.milliseconds_since_last_view_change,
            self.milliseconds_until_next_view_change,
            "high_qc:".bold(),
            self.high_qc
        )
    }
}

#[derive(Debug, Deserialize)]
struct HighQc {
    signature: String,
    cosigned: String,
    view: String,
    block_hash: String,
}

impl Default for HighQc {
    fn default() -> Self {
        Self {
            signature: "---".to_string(),
            cosigned: "---".to_string(),
            view: "---".to_string(),
            block_hash: "---".to_string(),
        }
    }
}

impl fmt::Display for HighQc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "view: {}\tblock_hash: {}\tcosigned: {}\nsign: {}",
            self.view, self.block_hash, self.cosigned, self.signature
        )
    }
}

#[derive(Clone, Debug)]
pub struct ChainNode {
    chain: ChainInstance,
    pub role: NodeRole,
    machine: Machine,
    eth_chain_id: u64,
}

#[allow(clippy::too_many_arguments)]
impl ChainNode {
    pub fn new(chain: ChainInstance, eth_chain_id: u64, role: NodeRole, machine: Machine) -> Self {
        Self {
            chain,
            eth_chain_id,
            role,
            machine,
        }
    }

    pub fn chain(&self) -> Result<Chain> {
        self.chain.chain()
    }

    pub fn chain_id(&self) -> u64 {
        self.eth_chain_id
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
            self.wait_for_block_number().await?;
        }

        Ok(())
    }

    pub async fn wait_for_block_number(&self) -> Result<u64> {
        let max_wait_in_mins = 15; // 15 minutes
        let retry_interval = std::time::Duration::from_secs(10); // Retry every 10 seconds
        let max_wait_duration = std::time::Duration::from_secs(max_wait_in_mins * 60);

        let start_time = tokio::time::Instant::now();
        let mut last_block_number = None;
        let mut last_check_time = tokio::time::Instant::now();
        let mut block_progress_count = 0;
        const EXPECTED_AVERAGE_RATE: f64 = 0.8;

        loop {
            // Check if we've exceeded the maximum wait time
            if tokio::time::Instant::now().duration_since(start_time) > max_wait_duration {
                return Err(anyhow!(
                    "Timeout: Block number did not progress within {} minutes.",
                    max_wait_in_mins
                ));
            }

            match self.machine.get_local_block_number().await {
                // endpoint responding with the block number
                std::result::Result::Ok(block_number) => {
                    if let Some(last) = last_block_number {
                        if block_number > last {
                            // Calculate time difference since the last successful check
                            let elapsed_time = tokio::time::Instant::now()
                                .duration_since(last_check_time)
                                .as_secs_f64();

                            // Update the progress tracking
                            block_progress_count += block_number - last;
                            last_check_time = tokio::time::Instant::now();

                            // Check if the average progress rate meets the threshold
                            let average_rate = block_progress_count as f64 / elapsed_time;
                            if average_rate >= EXPECTED_AVERAGE_RATE {
                                log::info!(
                                    "{}: Block number is progressing at an average rate of {:.2} blocks/sec.",
                                    self.name(),
                                    average_rate
                                );
                                return Ok(block_number);
                            } else {
                                log::warn!(
                                    "{}: Block progression rate is too slow ({:.2} blocks/sec). Retrying...",
                                    self.name(),
                                    average_rate
                                );
                            }
                        } else {
                            log::warn!(
                                "{}: Block number stagnated at {}. Retrying...",
                                self.name(),
                                block_number
                            );
                        }
                    } else {
                        // First successful retrieval; store the block number and time
                        last_block_number = Some(block_number);
                        last_check_time = tokio::time::Instant::now();
                        log::warn!(
                            "{}: Block number is {}. Checking if progressing...",
                            self.name(),
                            block_number
                        );
                    }
                }
                // endpoint not responding (yet)
                Err(err) => {
                    // Log the error
                    log::warn!(
                        "{}: Error retrieving block number: {err:?}. Retrying...",
                        self.name()
                    );
                }
            }

            // Wait for the retry interval before trying again
            tokio::time::sleep(retry_interval).await;
        }
    }

    pub async fn get_private_key(&self) -> Result<String> {
        if self.role == NodeRole::Apps {
            return Err(anyhow!(
                "Node {} has role 'apps' and does not own a private key",
                &self.machine.name
            ));
        }

        let private_keys = retrieve_secret_by_node_name(
            &self.chain.name(),
            &self.machine.project_id,
            &self.machine.name,
        )
        .await?;
        let private_key = if let Some(private_key) = private_keys.first() {
            private_key
        } else {
            return Err(anyhow!(
                "No private key for the instance {}",
                &self.machine.name
            ));
        };

        Ok(private_key.value().await?)
    }

    pub async fn get_validator_identities(&self) -> Result<String> {
        let validator_identities_items = retrieve_validator_identities_by_chain_name(
            &self.chain.name(),
            &self.machine.project_id,
        )
        .await?;
        let validator_identities =
            if let Some(validator_identities) = validator_identities_items.first() {
                validator_identities
            } else {
                return Err(anyhow!(
                    "No validator_identities for the chain {}",
                    &self.chain.name()
                ));
            };

        Ok(validator_identities.value().await?)
    }

    async fn tag_machine(&self) -> Result<()> {
        if self.role == NodeRole::Apps {
            return Ok(());
        }

        let private_keys = retrieve_secret_by_node_name(
            &self.chain.name(),
            &self.machine.project_id,
            &self.machine.name,
        )
        .await?;
        let private_key = if let Some(private_key) = private_keys.first() {
            private_key.value().await?
        } else {
            return Err(anyhow!(
                "No private key for the instance {}",
                &self.machine.name
            ));
        };

        let ethereum_address = EthereumAddress::from_private_key(&private_key)?;

        let mut labels = BTreeMap::<String, String>::new();
        labels.insert("peer-id".to_string(), ethereum_address.peer_id.to_string());

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
            .copy(&[config_toml], "/tmp/config.toml")
            .await?;

        self.machine
            .copy(&[provisioning_script], "/tmp/provision_node.py")
            .await?;

        if self.role == NodeRole::Checkpoint {
            let temp_checkpoint_cron_job = NamedTempFile::new()?;
            let checkpoint_cron_job = &self
                .create_checkpoint_cron_job(temp_checkpoint_cron_job.path().to_str().unwrap())
                .await?;

            self.machine
                .copy(&[checkpoint_cron_job], "/tmp/checkpoint_cron_job.sh")
                .await?;
        }

        if self.role == NodeRole::Persistence {
            let temp_persistence_export_cron_job = NamedTempFile::new()?;
            let persistence_export_cron_job = &self
                .create_persistence_export_cron_job(
                    temp_persistence_export_cron_job.path().to_str().unwrap(),
                )
                .await?;

            self.machine
                .copy(
                    &[persistence_export_cron_job],
                    "/tmp/persistence_export_cron_job.sh",
                )
                .await?;
        }

        println!("Configuration files imported in the node");

        Ok(())
    }

    async fn clean_previous_install(&self) -> Result<()> {
        let cmd = "sudo rm -f /tmp/config.toml /tmp/provision_node.py";
        let output = self.machine.run(cmd, true).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("Error removing previous installation files"));
        }

        if self.role == NodeRole::Checkpoint {
            let cmd = "sudo rm -f /tmp/checkpoint_cron_job.sh";
            let output = self.machine.run(cmd, true).await?;
            if !output.success {
                println!("{:?}", output.stderr);
                return Err(anyhow!("Error removing previous checkpoint cron job"));
            }
        }

        if self.role == NodeRole::Persistence {
            let cmd = "sudo rm -f /tmp/persistence_export_cron_job.sh";
            let output = self.machine.run(cmd, true).await?;
            if !output.success {
                println!("{:?}", output.stderr);
                return Err(anyhow!(
                    "Error removing previous persistence export cron job"
                ));
            }
        }

        println!("Removed previous installation files");

        Ok(())
    }

    async fn run_provisioning_script(&self) -> Result<()> {
        let cmd = "sudo chmod 666 /tmp/config.toml /tmp/provision_node.py && sudo mv /tmp/config.toml /config.toml && sudo python3 /tmp/provision_node.py";
        let output = self.machine.run(cmd, true).await?;
        if !output.success {
            println!("{:?}", output.stderr);
            return Err(anyhow!("Error running the provisioning script"));
        }

        if self.role == NodeRole::Checkpoint {
            let cmd = r#"
                sudo chmod 777 /tmp/checkpoint_cron_job.sh && \
                sudo mv /tmp/checkpoint_cron_job.sh /checkpoint_cron_job.sh && \
                echo '*/30 * * * * /checkpoint_cron_job.sh' | sudo crontab -"#;

            let output = self.machine.run(cmd, true).await?;
            if !output.success {
                println!("{:?}", output.stderr);
                return Err(anyhow!("Error creating the checkpoint cronjob"));
            }
        }

        if self.role == NodeRole::Persistence {
            let cmd = r#"
                sudo chmod 777 /tmp/persistence_export_cron_job.sh && \
                sudo mv /tmp/persistence_export_cron_job.sh /persistence_export_cron_job.sh && \
                echo '0 */2 * * * /persistence_export_cron_job.sh' | sudo crontab -"#;

            let output = self.machine.run(cmd, true).await?;
            if !output.success {
                println!("{:?}", output.stderr);
                return Err(anyhow!("Error creating the persistence export cronjob"));
            }
        }

        println!(
            "Provisioning script run successfully on {}",
            self.name().bold()
        );

        Ok(())
    }

    async fn create_checkpoint_cron_job(&self, filename: &str) -> Result<String> {
        let spec_config = include_str!("../../resources/checkpoints.tera.sh");

        let chain_name = self.chain.name();
        let eth_chain_id = self.eth_chain_id.to_string();

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("network_name", &chain_name);
        var_map.insert("eth_chain_id", &eth_chain_id);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(spec_config, &ctx, false)?;
        let config_file = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(config_file.as_bytes()).await?;
        println!("Checkpoint cron job file created: {filename}");

        Ok(filename.to_owned())
    }

    async fn create_persistence_export_cron_job(&self, filename: &str) -> Result<String> {
        let spec_config = include_str!("../../resources/persistence_export.tera.sh");

        let chain_name = self.chain.name();
        let eth_chain_id = self.eth_chain_id.to_string();

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("network_name", &chain_name);
        var_map.insert("eth_chain_id", &eth_chain_id);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(spec_config, &ctx, false)?;
        let config_file = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(config_file.as_bytes()).await?;
        println!("Persistence export cron job file created: {filename}");

        Ok(filename.to_owned())
    }

    pub async fn get_config_toml(&self) -> Result<String> {
        let spec_config = include_str!("../../resources/config.tera.toml");
        let bootstrap_nodes = self.chain.nodes_by_role(NodeRole::Bootstrap).await?;
        let subdomain = self.chain()?.get_subdomain()?;

        if bootstrap_nodes.is_empty() {
            return Err(anyhow!(
                "No bootstrap instances found in the network {}",
                &self.chain.name()
            ));
        };

        let mut bootstrap_addresses = Vec::new();
        for (idx, n) in bootstrap_nodes.into_iter().enumerate() {
            let private_key = n.get_private_key().await?;
            let eth_address = EthereumAddress::from_private_key(&private_key)?;
            let endpoint = format!("/dns/bootstrap-{idx}.{subdomain}/tcp/3333");
            bootstrap_addresses.push((endpoint, eth_address));
        }

        let genesis_account =
            EthereumAddress::from_private_key(&self.chain.genesis_private_key().await?)?;
        let role_name = self.role.to_string();
        let eth_chain_id = self.eth_chain_id.to_string();
        let whitelisted_evm_contract_addresses = self.chain()?.get_whitelisted_evm_contracts();
        let contract_upgrade_block_heights = self.chain()?.get_contract_upgrades_block_heights();
        // 4201 is the publically exposed port - We don't expose everything there.
        let public_api = if self.role == NodeRole::Api || self.role == NodeRole::PrivateApi {
            // Enable all APIs, except `admin_` for API nodes.
            json!({ "port": 4201, "enabled_apis": ["erigon", "eth", "net", "ots", "trace", "txpool", "web3", "zilliqa"] })
        } else {
            // Only enable `eth_blockNumber` for other nodes.
            json!({"port": 4201, "enabled_apis": [ { "namespace": "eth", "apis": ["blockNumber"] } ] })
        };
        // 4202 is not exposed, so enable everything for local debugging.
        let private_api = json!({ "port": 4202, "enabled_apis": ["admin", "debug", "erigon", "eth", "net", "ots", "trace", "txpool", "web3", "zilliqa"] });
        let api_servers = json!([public_api, private_api]);

        // Enable Otterscan indices on API nodes.
        let enable_ots_indices = self.role == NodeRole::Api || self.role == NodeRole::PrivateApi;

        let mut ctx = Context::new();
        ctx.insert("role", &role_name);
        ctx.insert("eth_chain_id", &eth_chain_id);

        let bootstrap_address = if bootstrap_addresses.len() > 1 {
            serde_json::to_value(
                bootstrap_addresses
                    .iter()
                    .map(|(e, a)| (a.peer_id, e))
                    .collect::<Vec<_>>(),
            )?
        } else {
            serde_json::to_value((
                bootstrap_addresses[0].1.peer_id,
                format!("/dns/bootstrap.{subdomain}/tcp/3333"),
            ))?
        };

        ctx.insert(
            "bootstrap_address",
            &serde_json::to_string_pretty(&bootstrap_address)?,
        );
        ctx.insert("bootstrap_peer_id", &bootstrap_addresses[0].1.peer_id);
        ctx.insert(
            "bootstrap_bls_public_key",
            &bootstrap_addresses[0].1.bls_public_key,
        );
        ctx.insert("genesis_address", &genesis_account.address);
        ctx.insert(
            "whitelisted_evm_contract_addresses",
            &serde_json::from_value::<toml::Value>(json!(whitelisted_evm_contract_addresses))?
                .to_string(),
        );
        ctx.insert(
            "contract_upgrade_block_heights",
            &contract_upgrade_block_heights.to_toml().to_string(),
        );
        // convert json to toml formatting
        let toml_servers: toml::Value = serde_json::from_value(api_servers)?;
        ctx.insert("api_servers", &toml_servers.to_string());
        ctx.insert("enable_ots_indices", &enable_ots_indices);
        if let Some(genesis_fork) = self.chain()?.genesis_fork() {
            ctx.insert(
                "genesis_fork",
                &serde_json::from_value::<toml::Value>(genesis_fork)?.to_string(),
            );
        }
        if let Some(forks) = self.chain()?.get_forks() {
            ctx.insert(
                "forks",
                &forks
                    .into_iter()
                    .map(|f| Ok(serde_json::from_value::<toml::Value>(f)?.to_string()))
                    .collect::<Result<Vec<_>>>()?,
            );
        }

        if let Some(checkpoint_url) = self.chain.checkpoint_url() {
            if self.role == NodeRole::Validator {
                let checkpoint_file = checkpoint_url.rsplit('/').next().unwrap_or("");
                ctx.insert("checkpoint_file", &format!("/{}", checkpoint_file));

                let checkpoint_hex_block =
                    crate::utils::string_decimal_to_hex(&checkpoint_file.replace(".dat", ""))?;

                let json_response = self
                    .chain
                    .run_rpc_call(
                        "eth_getBlockByNumber",
                        &Some(format!("[\"{}\", false]", checkpoint_hex_block)),
                        30,
                    )
                    .await?;

                let parsed_json: Value = serde_json::from_str(&json_response)?;

                let checkpoint_hash = parsed_json["result"]["hash"]
                    .as_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "{}: Error retrieving the hash of the block {}",
                            self.name(),
                            checkpoint_hex_block
                        )
                    })?
                    .strip_prefix("0x")
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "{}: Error stripping 0x from the hash of the block {}",
                            self.name(),
                            checkpoint_hex_block
                        )
                    })?;

                ctx.insert("checkpoint_hash", checkpoint_hash);

                log::info!(
                    "Importing the checkpoint from the block {} ({} hex) whose hash is {}",
                    checkpoint_file,
                    checkpoint_hex_block,
                    checkpoint_hash,
                );
            }
        }

        Ok(Tera::one_off(spec_config, &ctx, false)?)
    }

    async fn create_config_toml(&self, filename: &str) -> Result<String> {
        let rendered_template = self.get_config_toml().await?;
        let config_file = rendered_template.as_str();

        // Adding the OpenTelemetry collector endpoint to all nodes configurations
        let otlp_collector_endpoint = "http://localhost:4317";
        let config_file_with_otlp = format!(
            "otlp_collector_endpoint = \"{otlp_collector_endpoint}\"\n{}",
            config_file
        );

        let mut fh = File::create(filename).await?;
        fh.write_all(config_file_with_otlp.as_bytes()).await?;
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

        let z2_image = &docker_image("zq2", &self.chain.get_version("zq2"))?;
        let otterscan_image = &docker_image("otterscan", &self.chain.get_version("otterscan"))?;
        let spout_image = &docker_image("spout", &self.chain.get_version("spout"))?;
        let stats_dashboard_image = &docker_image(
            "stats_dashboard",
            &self.chain.get_version("stats_dashboard"),
        )?;
        let stats_agent_image =
            &docker_image("stats_agent", &self.chain.get_version("stats_agent"))?;

        let private_key = if *role_name == NodeRole::Apps.to_string() {
            ""
        } else {
            &self.get_private_key().await?
        };

        let genesis_key = if *role_name == NodeRole::Apps.to_string() {
            &self.chain.genesis_private_key().await?
        } else {
            ""
        };

        let enable_z2_metrics = self.chain()?.is_z2_metrics_enabled().to_string();
        let zq2_metrics_image =
            &docker_image("zq2_metrics", &self.chain.get_version("zq2_metrics"))?;
        let validator_identities = if *role_name == NodeRole::Apps.to_string() {
            &self.get_validator_identities().await?
        } else {
            ""
        };

        let stats_dashboard_key = &self.chain.stats_dashboard_key().await?;

        let persistence_url = self.chain.persistence_url().unwrap_or_default();
        let checkpoint_url = self.chain.checkpoint_url().unwrap_or_default();

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("role", role_name);
        var_map.insert("docker_image", z2_image);
        var_map.insert("otterscan_image", otterscan_image);
        var_map.insert("spout_image", spout_image);
        var_map.insert("stats_dashboard_image", stats_dashboard_image);
        var_map.insert("stats_dashboard_key", stats_dashboard_key);
        var_map.insert("stats_agent_image", stats_agent_image);
        var_map.insert("secret_key", private_key);
        var_map.insert("genesis_key", genesis_key);
        var_map.insert("persistence_url", &persistence_url);
        var_map.insert("checkpoint_url", &checkpoint_url);
        var_map.insert("enable_z2_metrics", &enable_z2_metrics);
        var_map.insert("zq2_metrics_image", zq2_metrics_image);
        var_map.insert("validator_identities", validator_identities);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(provisioning_script, &ctx, false)?;
        let provisioning_script = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(provisioning_script.as_bytes()).await?;
        println!("Provisioning file created: {filename}");

        Ok(filename.to_owned())
    }

    pub async fn backup_to(&self, name: Option<String>, zip: bool) -> Result<()> {
        let machine = &self.machine;

        let mut backup_name = name.unwrap_or(self.name());

        if zip {
            backup_name = format!("{}.zip", backup_name);
        }

        let multi_progress =
            cliclack::multi_progress(format!("Backing up {} ...", self.name()).yellow());
        let bar_length = if zip { 6 } else { 4 };
        let progress_bar = multi_progress.add(cliclack::progress_bar(bar_length));

        // clean previous backup files
        progress_bar.start("Clean the previous backup files");
        let command = format!(
            "sudo gsutil ls gs://{}-persistence/{}",
            self.chain()?,
            backup_name
        );
        let result = machine.run(&command, false).await;
        if result.is_ok() {
            let command = format!(
                "sudo gsutil -m rm -rf gs://{}-persistence/{}",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false).await?;
        }
        progress_bar.inc(1);

        // stop the service
        progress_bar.start("Stopping the service");
        machine
            .run("sudo systemctl stop zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        if zip {
            // create the zip file
            progress_bar.start("Packaging the data dir");
            machine
                .run(
                    "sudo apt install -y zip && sudo zip -r /tmp/data.zip /data",
                    false,
                )
                .await?;
            progress_bar.inc(1);

            // upload the zip file to the bucket
            progress_bar.start("Exporting the backup file");
            let command = format!(
                "sudo gsutil -m cp /tmp/data.zip gs://{}-persistence/{}",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false).await?;
            progress_bar.inc(1);

            // clean the temp backup file
            progress_bar.start("Cleaning the temp backup files");
            machine.run("sudo rm -rf /tmp/data.zip", false).await?;
            progress_bar.inc(1);
        } else {
            // export the backup files
            progress_bar.start("Exporting the backup files");
            let command = format!(
                "sudo gsutil -m cp -r /data gs://{}-persistence/{}/",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false).await?;
            progress_bar.inc(1);
        }

        // start the service
        progress_bar.start("Starting the service");
        machine
            .run("sudo systemctl start zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.stop(format!("{} Backup completed", "✔".green()));
        multi_progress.stop();

        Ok(())
    }

    pub async fn restore_from(
        &self,
        name: Option<String>,
        zip: bool,
        multi_progress: &MultiProgress,
    ) -> Result<()> {
        let machine = &self.machine;

        let mut backup_name = name.unwrap_or(self.name());

        if zip {
            backup_name = format!("{}.zip", backup_name);
        }

        let bar_length = if zip { 6 } else { 4 };
        let progress_bar = multi_progress.add(cliclack::progress_bar(bar_length));

        // stop the service
        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine
            .run("sudo systemctl stop zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        if zip {
            progress_bar.start(format!("{}: Importing the backup file", self.name()));
            let command = format!(
                "sudo gsutil -m cp gs://{}-persistence/{}.zip /tmp/data.zip",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false).await?;
            progress_bar.inc(1);

            progress_bar.start(format!("{}: Deleting the data folder", self.name()));
            machine.run("sudo rm -rf /data", false).await?;
            progress_bar.inc(1);

            progress_bar.start(format!("{}: Restoring the data folder", self.name()));
            machine
                .run(
                    "sudo apt install -y unzip && sudo unzip /tmp/data.zip -d /",
                    false,
                )
                .await?;
            progress_bar.inc(1);

            progress_bar.start(format!("{}: Cleaning the backup files", self.name()));
            machine.run("sudo rm -f /tmp/data.zip", false).await?;
            progress_bar.inc(1);
        } else {
            // delete the data folder
            progress_bar.start(format!("{}: Deleting the data folder", self.name()));
            machine.run("sudo rm -rf /data", false).await?;
            progress_bar.inc(1);

            // import the backup files
            progress_bar.start(format!("{}: Importing the backup files", self.name()));
            let command = format!(
                "sudo gsutil -m cp -r gs://{}-persistence/{}/* /",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false).await?;
            progress_bar.inc(1);
        }

        // start the service
        progress_bar.start(format!("{}: Starting the service", self.name()));
        machine
            .run("sudo systemctl start zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.stop(format!(
            "{} {}: Restore completed",
            "✔".green(),
            self.name()
        ));

        Ok(())
    }

    pub async fn reset(&self, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(2));

        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine
            .run("sudo systemctl stop zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.start(format!("{}: Deleting the data folder", self.name()));
        machine.run("sudo rm -rf /data", false).await?;
        progress_bar.inc(1);

        progress_bar.stop(format!("{} {}: Reset completed", "✔".green(), self.name()));

        Ok(())
    }

    pub async fn restart(&self, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(2));

        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine
            .run("sudo systemctl stop zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.start(format!("{}: Starting the service", self.name()));
        machine
            .run("sudo systemctl start zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.stop(format!(
            "{} {}: Restart completed",
            "✔".green(),
            self.name()
        ));

        Ok(())
    }

    pub async fn get_block_number(
        &self,
        multi_progress: &indicatif::MultiProgress,
        follow: bool,
    ) -> Result<()> {
        const BAR_SIZE: u64 = 40;
        const INTERVAL_IN_SEC: u64 = 5;
        const BAR_BLOCK_PER_TIME: u64 = 8;
        const BAR_REFRESH_IN_MILLIS: u64 = INTERVAL_IN_SEC * 1000 / BAR_SIZE * BAR_BLOCK_PER_TIME;

        let progress_bar = multi_progress.add(indicatif::ProgressBar::new(BAR_SIZE));
        progress_bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(&format!(
                    "{{spinner:.green}} {{bar:{}.cyan/blue}} {{msg}}",
                    BAR_SIZE
                ))
                .unwrap()
                .progress_chars("#>-"),
        );

        let block_number = self
            .machine
            .get_block_number(INTERVAL_IN_SEC as usize)
            .await
            .ok();

        let block_number_as_string = block_number.map_or("---".to_string(), |v| v.to_string());
        let message = format!("{:>12} => {}", block_number_as_string, self.name());
        progress_bar.set_message(message.clone());

        if follow {
            let mut previous_block_number = block_number.unwrap_or_default();
            loop {
                let start_time = tokio::time::Instant::now();

                for i in 1..=(BAR_SIZE / BAR_BLOCK_PER_TIME) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(BAR_REFRESH_IN_MILLIS))
                        .await;
                    progress_bar.set_position(i * BAR_BLOCK_PER_TIME);
                }

                let response = self
                    .machine
                    .get_block_number(INTERVAL_IN_SEC as usize)
                    .await
                    .ok();

                let (blocks_per_sec, current_block) = if let Some(current_block_number) = response {
                    let blocks_per_sec = format!(
                        "{:.0}",
                        (current_block_number - previous_block_number) as f64
                            / start_time.elapsed().as_secs_f64()
                    );

                    let blocks_per_sec = if blocks_per_sec == "0" {
                        "---".to_string()
                    } else {
                        blocks_per_sec
                    };

                    previous_block_number = current_block_number;
                    (blocks_per_sec, current_block_number.to_string())
                } else {
                    ("---".to_string(), "---".to_string())
                };

                let message = format!(
                    "{:>5} block/s {:>12} => {}",
                    blocks_per_sec,
                    current_block,
                    self.name()
                );
                progress_bar.set_message(message);
                progress_bar.set_position(0);
            }
        }

        progress_bar.finish_with_message(message);

        Ok(())
    }

    pub async fn get_consensus_info(
        &self,
        multi_progress: &indicatif::MultiProgress,
        follow: bool,
    ) -> Result<()> {
        const BAR_SIZE: u64 = 40;
        const INTERVAL_IN_SEC: u64 = 5;
        const BAR_BLOCK_PER_TIME: u64 = 8;
        const BAR_REFRESH_IN_MILLIS: u64 = INTERVAL_IN_SEC * 1000 / BAR_SIZE * BAR_BLOCK_PER_TIME;

        let progress_bar = multi_progress.add(indicatif::ProgressBar::new(BAR_SIZE));
        progress_bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(&format!(
                    "--------------------------------------------------------\n{{spinner:.green}} {} {{bar:{}.cyan/blue}} {{msg}}",
                    self.name().yellow(),
                    BAR_SIZE
                ))
                .unwrap()
                .progress_chars("#>-"),
        );

        let response = self
            .machine
            .get_consensus_info(INTERVAL_IN_SEC as usize)
            .await
            .ok();

        let consensus_info = response.map_or(ConsensusInfo::default(), |ci| {
            serde_json::from_value(ci).expect("Failed to parse JSON")
        });

        let mut message = format!("{}", consensus_info);
        progress_bar.set_message(message.clone());

        if follow {
            loop {
                for i in 1..=(BAR_SIZE / BAR_BLOCK_PER_TIME) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(BAR_REFRESH_IN_MILLIS))
                        .await;
                    progress_bar.set_position(i * BAR_BLOCK_PER_TIME);
                }

                let response = self
                    .machine
                    .get_consensus_info(INTERVAL_IN_SEC as usize)
                    .await
                    .ok();

                let consensus_info = response.map_or(ConsensusInfo::default(), |ci| {
                    serde_json::from_value(ci).expect("Failed to parse JSON")
                });

                message = format!("{}", consensus_info);
                progress_bar.set_message(message);
                progress_bar.set_position(0);
            }
        }

        progress_bar.finish_with_message(message);

        Ok(())
    }

    pub async fn api_attach(&self, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(1));

        progress_bar.start(format!("{}: Starting the service", self.name()));
        machine
            .run("sudo systemctl start healthcheck.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.stop(format!("{} {}: Attach completed", "✔".green(), self.name()));

        Ok(())
    }

    pub async fn api_detach(&self, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(1));

        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine
            .run("sudo systemctl stop healthcheck.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.stop(format!("{} {}: Detach completed", "✔".green(), self.name()));

        Ok(())
    }
}

pub async fn retrieve_secret_by_role(
    chain_name: &str,
    project_id: &str,
    role_name: &str,
) -> Result<Vec<Secret>> {
    Secret::get_secrets(
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
) -> Result<Vec<Secret>> {
    Secret::get_secrets(
        project_id,
        format!(
            "labels.zq2-network={} AND labels.node-name={} AND labels.is-private-key=true",
            chain_name, node_name
        )
        .as_str(),
    )
    .await
}

async fn retrieve_validator_identities_by_chain_name(
    chain_name: &str,
    project_id: &str,
) -> Result<Vec<Secret>> {
    Secret::get_secrets(
        project_id,
        format!(
            "labels.zq2-network={} AND labels.is-validator-identities-list=true",
            chain_name
        )
        .as_str(),
    )
    .await
}
