use std::{
    collections::BTreeMap,
    fmt,
    process::{Child, Command, Output, Stdio},
    str::FromStr,
    thread::sleep,
    time::Duration,
};

use anyhow::{Ok, Result, anyhow};
use clap::ValueEnum;
use cliclack::MultiProgress;
use colored::Colorize;
use itertools::Itertools;
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tera::{Context, Tera};
use tokio::{fs::File, io::AsyncWriteExt};

use super::instance::ChainInstance;
use crate::{chain::Chain, kms::KmsService};

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
}

impl FromStr for Components {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "zq2" => Ok(Components::ZQ2),
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
                    "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/zq2:{version}"
                ))
            } else if commit_id_re.is_match(version) {
                Ok(format!(
                    "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-private/zq2:{version}"
                ))
            } else {
                Err(anyhow!("Invalid version for ZQ2"))
            }
        }
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
    /// Virtual machine opsnode (checkpoint + persistence)
    Opsnode,
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
            "opsnode" => Ok(NodeRole::Opsnode),
            "private-api" => Ok(NodeRole::PrivateApi),
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
            NodeRole::Opsnode => write!(f, "opsnode"),
            NodeRole::PrivateApi => write!(f, "private-api"),
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

        Command::new("gcloud").args(args).output()?;

        Ok(())
    }

    pub fn run(&self, cmd: &str, print: bool) -> Result<Output> {
        if print {
            println!("Running command '{}' in {}", cmd, self.name);
        }
        Ok(Command::new("gcloud")
            .args([
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
            ])
            .output()?)
    }

    pub fn get_private_key(&self, chain_name: &str, enable_kms: bool) -> Result<String> {
        // Get the base64 encoded secret from Secret Manager
        let secret_suffix = if enable_kms { "-enckey" } else { "-pk" };
        let cmd = format!(
            "gcloud secrets versions access latest --project=\"{}\" --secret=\"{}{}\"",
            self.project_id, self.name, secret_suffix
        );

        let output = self.run(&cmd, false)?;
        if !output.status.success() {
            return Err(anyhow!(
                "Error retrieving {} private key: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let value = std::str::from_utf8(&output.stdout)?.trim();

        // Decrypt the key if KMS is enabled
        if enable_kms {
            let plaintext = KmsService::decrypt(
                &self.project_id,
                value,
                &format!("kms-{chain_name}"),
                &self.name,
                Some(self.clone()),
            )?;
            Ok(plaintext)
        } else {
            Ok(value.to_string())
        }
    }

    pub async fn get_local_block_number(&self) -> Result<u64> {
        let inner_command = r#"curl -s http://localhost:4201 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}'"#;
        let output = self.run(inner_command, true)?;
        if !output.status.success() {
            return Err(anyhow!(
                "getting local block number failed: {}",
                String::from_utf8_lossy(&output.stderr)
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

    pub fn get_rpc_response(
        &self,
        method: &str,
        params: &Option<String>,
        timeout: usize,
        port: u64,
    ) -> Result<String> {
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"{}\",\"params\":{}}}",
            method,
            params.clone().unwrap_or("[]".to_string()),
        );

        let url = format!("http://localhost:{port}");
        let output = std::process::Command::new("curl")
            .args([
                "--max-time",
                &timeout.to_string(),
                "-X",
                "POST",
                "-H",
                "content-type: application/json",
                "-H",
                "accept:application/json,*/*;q=0.5",
                "-d",
                &body,
                &url,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "getting rpc response for {} with params {:?} failed: {}",
                method,
                params,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(std::str::from_utf8(&output.stdout)?.trim().to_owned())
    }

    pub async fn get_block_number(&self, timeout: usize, port: u64) -> Result<u64> {
        let response: Value = serde_json::from_str(&self.get_rpc_response(
            "eth_blockNumber",
            &None,
            timeout,
            port,
        )?)?;
        let block_number = response
            .get("result")
            .ok_or_else(|| anyhow!("response has no result"))?
            .as_str()
            .ok_or_else(|| anyhow!("result is not a string"))?
            .strip_prefix("0x")
            .ok_or_else(|| anyhow!("result does not start with 0x"))?;

        Ok(u64::from_str_radix(block_number, 16)?)
    }

    pub async fn get_consensus_info(&self, timeout: usize, port: u64) -> Result<Value> {
        let response: Value = serde_json::from_str(&self.get_rpc_response(
            "admin_consensusInfo",
            &None,
            timeout,
            port,
        )?)?;

        let response = response
            .get("result")
            .ok_or_else(|| anyhow!("response has no result"))?;

        Ok(response.to_owned())
    }

    pub fn find_available_port(&self) -> Option<u16> {
        let mut rng = rand::thread_rng();
        let min_port = 5000u16;
        let max_port = 8000u16;
        for _ in 0..20 {
            let port = rng.gen_range(min_port..=max_port);
            if self.port_is_available(port) {
                return Some(port);
            }
        }
        // Fallback: sequential search
        (min_port..=max_port).find(|&port| self.port_is_available(port))
    }

    fn port_is_available(&self, port: u16) -> bool {
        std::net::TcpStream::connect(("127.0.0.1", port)).is_err()
    }

    pub fn open_tunnel(&self, port: u16, remote_port: u64) -> Option<Child> {
        Command::new("gcloud")
            .args([
                "compute",
                "start-iap-tunnel",
                &self.name,
                &remote_port.to_string(),
                "--project",
                &self.project_id,
                "--zone",
                &self.zone,
                "--local-host-port",
                &format!("localhost:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()
    }

    pub fn wait_for_port(&self, port: u16, max_retries: u32) -> bool {
        for _ in 0..max_retries {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return true;
            }
            sleep(Duration::from_millis(500));
        }
        false
    }

    pub fn close_tunnel(&self, child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
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
    cosigned: String,
    view: String,
    block_hash: String,
}

impl Default for HighQc {
    fn default() -> Self {
        Self {
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
            "view: {}\tblock_hash: {}\tcosigned: {}",
            self.view, self.block_hash, self.cosigned
        )
    }
}

#[derive(Clone, Debug)]
pub struct ChainNode {
    chain: ChainInstance,
    pub role: NodeRole,
    pub machine: Machine,
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

        self.clean_previous_install().await?;
        self.import_config_files().await?;
        self.run_provisioning_script().await?;

        Ok(())
    }

    pub async fn upgrade(&self) -> Result<()> {
        let message = format!("Upgrading {} instance {}", self.role, self.machine.name);
        println!("{}", message.bold().yellow());

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
                    "Timeout: Block number did not progress within {max_wait_in_mins} minutes.",
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

    pub fn get_private_key(&self) -> Result<String> {
        if self.role == NodeRole::Apps {
            return Err(anyhow!(
                "Node {} has role 'apps' and does not own a private key",
                &self.machine.name
            ));
        }

        self.machine
            .get_private_key(&self.chain.name(), self.chain()?.get_enable_kms()?)
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

        println!("Configuration files imported in the node");

        Ok(())
    }

    async fn clean_previous_install(&self) -> Result<()> {
        let cmd = "sudo rm -f /tmp/config.toml /tmp/provision_node.py";
        let output = self.machine.run(cmd, true)?;
        if !output.status.success() {
            println!("{}", String::from_utf8_lossy(&output.stderr));
            return Err(anyhow!("Error removing previous installation files"));
        }

        println!("Removed previous installation files");

        Ok(())
    }

    async fn run_provisioning_script(&self) -> Result<()> {
        let cmd = "sudo chmod 666 /tmp/config.toml /tmp/provision_node.py && sudo mv /tmp/config.toml /config.toml && sudo python3 /tmp/provision_node.py";
        let output = self.machine.run(cmd, true)?;
        if !output.status.success() {
            println!("{}", String::from_utf8_lossy(&output.stderr));
            return Err(anyhow!("Error running the provisioning script"));
        }

        println!(
            "Provisioning script run successfully on {}",
            self.name().bold()
        );

        Ok(())
    }

    pub fn get_keys_config(
        &self,
    ) -> Result<serde_json::Map<std::string::String, serde_json::Value>> {
        let keys_config_file = format!("/opt/zilliqa/{}-keys-config.toml", self.chain.name());
        let output = self
            .machine
            .run(format!("sudo cat {keys_config_file}").as_str(), false)?;

        if !output.status.success() {
            eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
            return Err(anyhow!("Error getting the keys config file"));
        }

        let content = String::from_utf8_lossy(&output.stdout);
        let nodes_info: serde_json::Value = serde_json::from_str(&content)?;

        Ok(nodes_info.as_object().unwrap().to_owned())
    }

    pub async fn get_config_toml(&self) -> Result<String> {
        let spec_config = include_str!("../../resources/config.tera.toml");
        let bootstrap_nodes = self.chain.nodes_by_role(NodeRole::Bootstrap).await?;
        let subdomain = self.chain()?.get_subdomain()?;
        let keys_config = self.get_keys_config()?;

        if bootstrap_nodes.is_empty() {
            return Err(anyhow!(
                "No bootstrap instances found in the network {}",
                &self.chain.name()
            ));
        };

        let mut bootstrap_addresses = Vec::new();
        for (idx, n) in bootstrap_nodes.into_iter().enumerate() {
            let (public_key, peer_id) = if let Some(node_keys) = keys_config.get(&n.name()) {
                let bls_public_key = node_keys["bls_public_key"].as_str().unwrap().to_string();
                let peer_id = node_keys["peer_id"].as_str().unwrap().to_string();
                (bls_public_key, peer_id)
            } else {
                return Err(anyhow!("{} not found in keys config", n.name()));
            };

            let endpoint = format!("/dns/bootstrap-{idx}.{subdomain}/udp/3333/quic-v1");
            bootstrap_addresses.push((endpoint, (public_key, peer_id)));
        }

        let mut validator_addresses = Vec::new();

        let validator_nodes = self.chain.nodes_by_role(NodeRole::Validator).await?;
        for n in validator_nodes.into_iter() {
            let (public_key, peer_id) = if let Some(node_keys) = keys_config.get(&n.name()) {
                let bls_public_key = node_keys["bls_public_key"].as_str().unwrap().to_string();
                let peer_id = node_keys["peer_id"].as_str().unwrap().to_string();
                (bls_public_key, peer_id)
            } else {
                return Err(anyhow!("{} not found in keys config", n.name()));
            };

            validator_addresses.push((public_key, peer_id));
        }

        let role_name = self.role.to_string();
        let eth_chain_id = self.eth_chain_id.to_string();
        let contract_upgrades = self.chain()?.get_contract_upgrades_block_heights();
        // 4201 is the publically exposed port - We don't expose everything there.
        let public_api = if self.role == NodeRole::Api {
            // Enable all APIs, except `admin_` for API nodes; with default quota
            json!({
                // arbitrarily chosen
                "default_quota": {
                    "balance": 40_000,
                    "period": 1,
                },
                "port": 4201,
                "enabled_apis": [
                    "erigon",
                    "eth",
                    "net",
                    "txpool",
                    "web3",
                    "zilliqa",
                    {
                        "namespace": "ots",
                        // Enable all APIs except `ots_getContractCreator` until #2381 is resolved.
                        "apis": [
                            "getApiLevel",
                            "getBlockDetails",
                            "getBlockDetailsByHash",
                            "getBlockTransactions",
                            "getInternalOperations",
                            "getTransactionBySenderAndNonce",
                            "getTransactionError",
                            "hasCode",
                            "searchTransactionsAfter",
                            "searchTransactionsBefore",
                            "traceTransaction",
                        ],
                    },
                ]
            })
        } else if self.role == NodeRole::PrivateApi {
            // Enable all APIs, except `admin_` for API nodes; with no quota
            json!({
                "port": 4201,
                "enabled_apis": [
                    "erigon",
                    "eth",
                    "net",
                    "ots",
                    "txpool",
                    "web3",
                    "zilliqa",
                ]
            })
        } else {
            // Only enable `eth_blockNumber` for other nodes; with default quota
            json!({
                "default_quota": {
                    "balance": 500,
                    "period": 1,
                },
                "port": 4201,
                "enabled_apis": [ { "namespace": "eth", "apis": ["blockNumber"] } ] })
        };
        // 4202 is not exposed, so enable everything for local debugging; with no quota
        let private_api = json!({ "port": 4202, "enabled_apis": ["admin", "debug", "erigon", "eth", "net", "ots", "trace", "txpool", "web3", "zilliqa"] });
        let api_servers = json!([public_api, private_api]);

        // Enable Otterscan indices on API and opsnode nodes.
        let enable_ots_indices = self.role == NodeRole::Api
            || self.role == NodeRole::PrivateApi
            || self.role == NodeRole::Opsnode;

        let mut ctx = Context::new();
        ctx.insert("role", &role_name);
        ctx.insert("network", &self.chain.name());
        ctx.insert("eth_chain_id", &eth_chain_id);

        // Only add API limits if this is an API node
        if matches!(self.role, NodeRole::Api) {
            let api_limits = if matches!(self.chain.chain()?, Chain::Zq2Mainnet) {
                serde_json::json!({
                    "max_blocks_to_fetch": 50,
                    "max_txns_in_block_to_fetch": 50,
                    "disable_get_full_state_for_contracts": [
                        "0x54d10Ee86cd2C3258b23FDb78782F70e84966683",
                        "0xa7c67d49c82c7dc1b73d231640b2e4d0661d37c1"
                    ],
                    "max_rpc_response_size": 10_485_760
                })
            } else {
                serde_json::json!({
                    "disable_get_full_state_for_contracts": []
                })
            };

            let toml_api_limits: toml::Value = serde_json::from_value(api_limits)?;
            let toml_string = toml::to_string_pretty(&toml_api_limits)?;
            ctx.insert("api_limits", &toml_string);

            let credit_rates_str = include_str!("../../resources/rpc_rates.toml");
            let credit_rates: Value = toml::from_str(credit_rates_str)
                .map_err(|_| anyhow!("Unable to parse rpc_rates.toml".to_string()))?;
            let credit_rates_toml = credit_rates
                .get("credit_rates")
                .unwrap()
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect_vec()
                .join("\n");
            ctx.insert("credit_rates", &credit_rates_toml);
        }

        let bootstrap_address = if bootstrap_addresses.len() > 1 {
            serde_json::to_value(
                bootstrap_addresses
                    .iter()
                    .map(|(e, a)| (a.1.clone(), e))
                    .collect::<Vec<_>>(),
            )?
        } else {
            serde_json::to_value((
                bootstrap_addresses[0].1.1.clone(),
                format!("/dns/bootstrap.{subdomain}/udp/3333/quic-v1"),
            ))?
        };

        let genesis_account_address = if let Some(genesis_key) = keys_config.get("genesis-key") {
            genesis_key["control_address"].as_str().unwrap().to_string()
        } else {
            return Err(anyhow!("Genesis account address not found in keys config"));
        };

        let validator_control_address = self
            .chain()?
            .get_validator_control_address()
            .unwrap_or(&genesis_account_address);

        let genesis_deposits_amount = &self.chain()?.get_genesis_deposits_amount()?;
        let genesis_deposits = serde_json::to_value(
            validator_addresses
                .iter()
                .map(|v| {
                    (
                        v.0.clone(),
                        v.1.clone(),
                        &genesis_deposits_amount,
                        "0x0000000000000000000000000000000000000000",
                        &validator_control_address,
                    )
                })
                .collect::<Vec<_>>(),
        )?;

        ctx.insert(
            "bootstrap_address",
            &serde_json::to_string_pretty(&bootstrap_address)?,
        );
        ctx.insert(
            "genesis_deposits",
            &serde_json::to_string_pretty(&genesis_deposits)?,
        );
        ctx.insert("genesis_address", &genesis_account_address);
        ctx.insert("genesis_amount", &self.chain()?.get_genesis_amount()?);
        ctx.insert(
            "contract_upgrades",
            &contract_upgrades.to_toml().to_string(),
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
            let checkpoint_file = checkpoint_url.rsplit('/').next().unwrap_or("");
            ctx.insert("checkpoint_file", &format!("/{checkpoint_file}"));

            let checkpoint_hex_block = crate::utils::string_decimal_to_hex(
                &checkpoint_file.replace(".dat", "").replace(".ckpt", ""),
            )?;

            let json_response = self.chain.run_rpc_call(
                "eth_getBlockByNumber",
                &Some(format!("[\"{checkpoint_hex_block}\", false]")),
                30,
            )?;

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
                "Importing the checkpoint from the block {checkpoint_file} ({checkpoint_hex_block} hex) whose hash is {checkpoint_hash}"
            );
        }

        if let Some(new_view_interval) = self.chain()?.get_new_view_broadcast_interval() {
            ctx.insert("new_view_broadcast_interval", &new_view_interval.as_secs());
        }

        Ok(Tera::one_off(spec_config, &ctx, false)?)
    }

    async fn create_config_toml(&self, filename: &str) -> Result<String> {
        let rendered_template = self.get_config_toml().await?;
        let config_file = rendered_template.as_str();

        // Adding the OpenTelemetry collector endpoint to all nodes configurations
        let otlp_collector_endpoint = "http://localhost:4317";
        let config_file_with_otlp =
            format!("otlp_collector_endpoint = \"{otlp_collector_endpoint}\"\n{config_file}");

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
        let persistence_url = self.chain.persistence_url().unwrap_or_default();
        let checkpoint_url = self.chain.checkpoint_url().unwrap_or_default();
        let log_level = self.chain()?.get_log_level()?;
        let project_id = &self.machine.project_id;
        let chain_name = &self.chain.name();
        let node_name = &self.machine.name;
        let enable_kms = if self.chain()?.get_enable_kms()? {
            "true"
        } else {
            "false"
        };

        let mut var_map = BTreeMap::<&str, &str>::new();
        var_map.insert("role", role_name);
        var_map.insert("docker_image", z2_image);
        var_map.insert("enable_kms", enable_kms);
        var_map.insert("persistence_url", &persistence_url);
        var_map.insert("checkpoint_url", &checkpoint_url);
        var_map.insert("log_level", log_level);
        var_map.insert("project_id", project_id);
        var_map.insert("chain_name", chain_name);
        var_map.insert("node_name", node_name);

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
            backup_name = format!("{backup_name}.zip");
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
        let result = machine.run(&command, false);
        if result.is_ok() {
            let command = format!(
                "sudo gsutil -m rm -rf gs://{}-persistence/{}",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false)?;
        }
        progress_bar.inc(1);

        // stop the service
        progress_bar.start("Stopping the service");
        machine.run("sudo systemctl stop zilliqa.service", false)?;
        progress_bar.inc(1);

        if zip {
            // create the zip file
            progress_bar.start("Packaging the data dir");
            machine.run(
                "sudo apt install -y zip && sudo zip -r /tmp/data.zip /data",
                false,
            )?;
            progress_bar.inc(1);

            // upload the zip file to the bucket
            progress_bar.start("Exporting the backup file");
            let command = format!(
                "sudo gsutil -m cp /tmp/data.zip gs://{}-persistence/{}",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false)?;
            progress_bar.inc(1);

            // clean the temp backup file
            progress_bar.start("Cleaning the temp backup files");
            machine.run("sudo rm -rf /tmp/data.zip", false)?;
            progress_bar.inc(1);
        } else {
            // export the backup files
            progress_bar.start("Exporting the backup files");
            let command = format!(
                "sudo gsutil -o \"GSUtil:parallel_process_count=64\" -o \"GSUtil:parallel_thread_count=8\" -m cp -r /data gs://{}-persistence/{}/",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false)?;
            progress_bar.inc(1);
        }

        // start the service
        progress_bar.start("Starting the service");
        machine.run("sudo systemctl start zilliqa.service", false)?;
        progress_bar.inc(1);

        progress_bar.stop(format!("{} Backup completed", "✔".green()));
        multi_progress.stop();

        Ok(())
    }

    pub async fn restore_from(
        &self,
        name: Option<String>,
        zip: bool,
        no_restart: bool,
        multi_progress: &MultiProgress,
    ) -> Result<()> {
        let machine = &self.machine;

        let backup_name = name.unwrap_or(self.name());

        let bar_length = if zip {
            if no_restart { 5 } else { 6 }
        } else if no_restart {
            3
        } else {
            4
        };
        let progress_bar = multi_progress.add(cliclack::progress_bar(bar_length));

        // stop the service
        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine.run("sudo systemctl stop zilliqa.service", false)?;
        progress_bar.inc(1);

        if zip {
            progress_bar.start(format!("{}: Importing the backup file", self.name()));
            let command = format!(
                "sudo gsutil -m cp gs://{}-persistence/{}.zip /tmp/data.zip",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false)?;
            progress_bar.inc(1);

            progress_bar.start(format!("{}: Deleting the data folder", self.name()));
            machine.run("sudo rm -rf /data", false)?;
            progress_bar.inc(1);

            progress_bar.start(format!("{}: Restoring the data folder", self.name()));
            machine.run(
                "sudo apt install -y unzip && sudo unzip /tmp/data.zip -d /",
                false,
            )?;
            progress_bar.inc(1);

            progress_bar.start(format!("{}: Cleaning the backup files", self.name()));
            machine.run("sudo rm -f /tmp/data.zip", false)?;
            progress_bar.inc(1);
        } else {
            // delete the data folder
            progress_bar.start(format!("{}: Deleting the data folder", self.name()));
            machine.run("sudo rm -rf /data", false)?;
            progress_bar.inc(1);

            // import the backup files
            progress_bar.start(format!("{}: Importing the backup files", self.name()));
            let command = format!(
                "sudo gsutil -o \"GSUtil:parallel_process_count=64\" -o \"GSUtil:parallel_thread_count=8\" -m cp -r gs://{}-persistence/{}/* /",
                self.chain()?,
                backup_name
            );
            machine.run(&command, false)?;
            progress_bar.inc(1);
        }

        // start the service
        if !no_restart {
            progress_bar.start(format!("{}: Starting the service", self.name()));
            machine.run("sudo systemctl start zilliqa.service", false)?;
            progress_bar.inc(1);
        }

        let completion_message = if no_restart {
            format!(
                "{} {}: Restore completed (service not restarted)",
                "✔".green(),
                self.name()
            )
        } else {
            format!("{} {}: Restore completed", "✔".green(), self.name())
        };

        progress_bar.stop(completion_message);

        Ok(())
    }

    pub async fn reset(&self, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(2));

        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine.run("sudo systemctl stop zilliqa.service", false)?;
        progress_bar.inc(1);

        progress_bar.start(format!("{}: Deleting the data folder", self.name()));
        machine.run("sudo rm -rf /data", false)?;
        progress_bar.inc(1);

        progress_bar.stop(format!("{} {}: Reset completed", "✔".green(), self.name()));

        Ok(())
    }

    pub async fn restart(&self, multi_progress: &MultiProgress) -> Result<()> {
        let machine = &self.machine;
        let progress_bar = multi_progress.add(cliclack::progress_bar(2));

        progress_bar.start(format!("{}: Stopping the service", self.name()));
        machine.run("sudo systemctl stop zilliqa.service", false)?;
        progress_bar.inc(1);

        progress_bar.start(format!("{}: Starting the service", self.name()));
        machine.run("sudo systemctl start zilliqa.service", false)?;
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
        port: u64,
    ) -> Result<()> {
        const BAR_SIZE: u64 = 40;
        const INTERVAL_IN_SEC: u64 = 5;
        const BAR_BLOCK_PER_TIME: u64 = 8;
        const BAR_REFRESH_IN_MILLIS: u64 = INTERVAL_IN_SEC * 1000 / BAR_SIZE * BAR_BLOCK_PER_TIME;

        let progress_bar = multi_progress.add(indicatif::ProgressBar::new(BAR_SIZE));
        progress_bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template(&format!(
                    "{{spinner:.green}} {{bar:{BAR_SIZE}.cyan/blue}} {{msg}}"
                ))
                .unwrap()
                .progress_chars("#>-"),
        );

        let block_number = self
            .machine
            .get_block_number(INTERVAL_IN_SEC as usize, port)
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
                    .get_block_number(INTERVAL_IN_SEC as usize, port)
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
        port: u64,
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
            .get_consensus_info(INTERVAL_IN_SEC as usize, port)
            .await
            .ok();

        let consensus_info = response.map_or(ConsensusInfo::default(), |ci| {
            serde_json::from_value(ci).expect("Failed to parse JSON")
        });

        let mut message = format!("{consensus_info}");
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
                    .get_consensus_info(INTERVAL_IN_SEC as usize, port)
                    .await
                    .ok();

                let consensus_info = response.map_or(ConsensusInfo::default(), |ci| {
                    serde_json::from_value(ci).expect("Failed to parse JSON")
                });

                message = format!("{consensus_info}");
                progress_bar.set_message(message);
                progress_bar.set_position(0);
            }
        }

        progress_bar.finish_with_message(message);

        Ok(())
    }
}
