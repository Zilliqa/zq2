use std::{collections::BTreeMap, fmt, str::FromStr};

use anyhow::{anyhow, Ok, Result};
use clap::ValueEnum;
use cliclack::MultiProgress;
use colored::Colorize;
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tempfile::NamedTempFile;
use tera::{Context, Tera};
use tokio::{fs::File, io::AsyncWriteExt};

use super::instance::ChainInstance;
use crate::{address::EthereumAddress, chain::Chain, secret::Secret};

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

    async fn copy_from(&self, file_from: &str, file_to: &str) -> Result<()> {
        let file_from = &format!("{0}:{file_from}", &self.name);
        let args = &[
            "compute",
            "scp",
            "--project",
            &self.project_id,
            "--zone",
            &self.zone,
            "--tunnel-through-iap",
            "--strict-host-key-checking=no",
            "--scp-flag=-r",
            file_from,
            file_to,
        ];

        zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd("gcloud", args)
            .run()
            .await?;
        Ok(())
    }

    async fn copy_to(&self, file_from: &[&str], file_to: &str) -> Result<()> {
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
            &format!("http://{}:4201", self.external_address),
        ];

        let output = zqutils::commands::CommandBuilder::new()
            .silent()
            .cmd("curl", args)
            .run_for_output()
            .await?;
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
                .get_rpc_response("eth_blockNumber", &None, timeout)
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

        // TODO implement a more effective check
        // Check the node is making progress
        // if self.role != NodeRole::Apps {
        //     let first_block_number = self.machine.get_local_block_number().await?;
        //     loop {
        //         let next_block_number = self.machine.get_local_block_number().await?;
        //         println!(
        //             "Polled block number at {next_block_number}, waiting for {} more blocks",
        //             (first_block_number + 10).saturating_sub(next_block_number)
        //         );
        //         if next_block_number >= first_block_number + 10 {
        //             break;
        //         }
        //     }
        // }

        Ok(())
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
                return Err(anyhow!("Error removing previous checkpoint cronjob"));
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
            let cmd = "sudo chmod 777 /tmp/checkpoint_cron_job.sh && sudo mv /tmp/checkpoint_cron_job.sh /checkpoint_cron_job.sh && echo '*/5 * * * * /checkpoint_cron_job.sh' | sudo crontab -";
            let output = self.machine.run(cmd, true).await?;
            if !output.success {
                println!("{:?}", output.stderr);
                return Err(anyhow!("Error creating the checkpoint cronjob"));
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
        println!("Cron job file created: {filename}");

        Ok(filename.to_owned())
    }

    pub async fn get_config_toml(&self) -> Result<String> {
        let spec_config = include_str!("../../resources/config.tera.toml");
        let mut bootstrap_nodes = self.chain.nodes_by_role(NodeRole::Bootstrap).await?;

        let set_bootstrap_address = if self.role != NodeRole::Bootstrap || bootstrap_nodes.len() > 1
        {
            "true"
        } else {
            "false"
        };

        if bootstrap_nodes.len() > 1 {
            bootstrap_nodes.retain(|node| node.name() != self.name());
        }

        // Pick a random element among the bootstrap nodes
        let selected_bootstrap =
            if let Some(random_item) = bootstrap_nodes.choose(&mut rand::thread_rng()) {
                println!("Bootstrap picked: {}", random_item.name().bold());
                random_item.to_owned()
            } else {
                return Err(anyhow!(
                    "No bootstrap instances found in the network {}",
                    &self.chain.name()
                ));
            };

        let genesis_account =
            EthereumAddress::from_private_key(&self.chain.genesis_private_key().await?)?;
        let bootstrap_node =
            EthereumAddress::from_private_key(&selected_bootstrap.get_private_key().await?)?;
        let role_name = self.role.to_string();
        let eth_chain_id = self.eth_chain_id.to_string();
        let bootstrap_public_ip = selected_bootstrap.machine.external_address;
        let whitelisted_evm_contract_addresses = self.chain()?.get_whitelisted_evm_contracts();
        let contract_upgrade_block_heights = self.chain()?.get_contract_upgrades_block_heights();
        // 4201 is the publically exposed port - We don't expose everything there.
        let public_api = if self.role == NodeRole::Api {
            // Enable all APIs, except `admin_` for API nodes.
            json!({ "port": 4201, "enabled_apis": ["erigon", "eth", "net", "ots", "trace", "txpool", "web3", "zilliqa"] })
        } else {
            // Only enable `eth_blockNumber` for other nodes.
            json!({"port": 4201, "enabled_apis": [ { "namespace": "eth", "apis": ["blockNumber"] } ] })
        };
        // 4202 is not exposed, so enable everything for local debugging.
        let private_api = json!({ "port": 4202, "enabled_apis": ["admin", "erigon", "eth", "net", "ots", "trace", "txpool", "web3", "zilliqa"] });
        let api_servers = json!([public_api, private_api]);

        // Enable Otterscan indices on API nodes.
        let enable_ots_indices = self.role == NodeRole::Api;

        let mut ctx = Context::new();
        ctx.insert("role", &role_name);
        ctx.insert("eth_chain_id", &eth_chain_id);
        ctx.insert("bootstrap_public_ip", &bootstrap_public_ip);
        ctx.insert("bootstrap_peer_id", &bootstrap_node.peer_id);
        ctx.insert("bootstrap_bls_public_key", &bootstrap_node.bls_public_key);
        ctx.insert("set_bootstrap_address", set_bootstrap_address);
        ctx.insert("genesis_address", &genesis_account.address);
        ctx.insert(
            "whitelisted_evm_contract_addresses",
            &serde_json::from_value::<toml::Value>(json!(whitelisted_evm_contract_addresses))?
                .to_string(),
        );
        ctx.insert(
            "contract_upgrade_block_heights",
            &serde_json::from_value::<toml::Value>(json!(contract_upgrade_block_heights))?
                .to_string(),
        );
        // convert json to toml formatting
        let toml_servers: toml::Value = serde_json::from_value(api_servers)?;
        ctx.insert("api_servers", &toml_servers.to_string());
        ctx.insert("enable_ots_indices", &enable_ots_indices);
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

        let z2_image = &docker_image("zq2", &self.chain.get_version("zq2"))?;
        let otterscan_image = &docker_image("otterscan", &self.chain.get_version("otterscan"))?;
        let spout_image = &docker_image("spout", &self.chain.get_version("spout"))?;

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

        let persistence_url = self.chain.persistence_url().unwrap_or_default();
        let checkpoint_url = self.chain.checkpoint_url().unwrap_or_default();

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("role", role_name);
        var_map.insert("docker_image", z2_image);
        var_map.insert("otterscan_image", otterscan_image);
        var_map.insert("spout_image", spout_image);
        var_map.insert("secret_key", private_key);
        var_map.insert("genesis_key", genesis_key);
        var_map.insert("persistence_url", &persistence_url);
        var_map.insert("checkpoint_url", &checkpoint_url);

        let ctx = Context::from_serialize(var_map)?;
        let rendered_template = Tera::one_off(provisioning_script, &ctx, false)?;
        let provisioning_script = rendered_template.as_str();

        let mut fh = File::create(filename).await?;
        fh.write_all(provisioning_script.as_bytes()).await?;
        println!("Provisioning file created: {filename}");

        Ok(filename.to_owned())
    }

    pub async fn backup_to(&self, filename: &str) -> Result<()> {
        let machine = &self.machine;

        let multi_progress =
            cliclack::multi_progress(format!("Backing up {} ...", self.name()).yellow());
        let progress_bar = multi_progress.add(cliclack::progress_bar(5));

        progress_bar.start("Stopping the service");
        machine
            .run("sudo systemctl stop zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.start("Packaging the data dir");
        machine
            .run(
                "sudo apt install -y zip && sudo zip -r /tmp/data.zip /data",
                false,
            )
            .await?;
        progress_bar.inc(1);

        progress_bar.start("Exporting the backup file");
        if filename.starts_with("gs://") {
            let command = format!("sudo gsutil -m cp /tmp/data.zip {}", filename);
            machine.run(&command, false).await?;
        } else {
            machine.copy_from("/tmp/data.zip", filename).await?;
        }
        progress_bar.inc(1);

        progress_bar.start("Cleaning the backup files");
        machine.run("sudo rm -rf /tmp/data.zip", false).await?;
        progress_bar.inc(1);

        progress_bar.start("Starting the service");
        machine
            .run("sudo systemctl start zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.stop(format!("{} Backup completed", "✔".green()));
        multi_progress.stop();

        Ok(())
    }

    pub async fn restore_from(&self, filename: &str, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(6));

        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine
            .run("sudo systemctl stop zilliqa.service", false)
            .await?;
        progress_bar.inc(1);

        progress_bar.start(format!("{}: Importing the backup file", self.name()));
        if filename.starts_with("gs://") {
            let command = format!("sudo gsutil -m cp {} /tmp/data.zip", filename);
            machine.run(&command, false).await?;
        } else {
            machine.copy_to(&[filename], "/tmp/data.zip").await?;
        }
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

    pub async fn get_block(
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

    pub async fn api_attach(&self, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(1));

        progress_bar.start(format!("{}: Starting the service", self.name()));
        machine
            .run("sudo systemctl start api_healthcheck.service", false)
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
            .run("sudo systemctl stop api_healthcheck.service", false)
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
