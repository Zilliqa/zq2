use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use alloy::primitives::{address, Address};
use anyhow::{anyhow, Context, Result};
use k256::ecdsa::SigningKey;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_yaml;
use tokio::fs;
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto::{SecretKey, TransactionPublicKey};
use zilliqa::{
    cfg,
    cfg::{
        allowed_timestamp_skew_default, block_request_batch_size_default,
        block_request_limit_default, consensus_timeout_default, disable_rpc_default,
        empty_block_timeout_default, eth_chain_id_default, failed_request_sleep_duration_default,
        local_address_default, max_blocks_in_flight_default,
        minimum_time_left_for_empty_block_default, scilla_address_default,
        scilla_ext_libs_path_default, scilla_stdlib_dir_default, state_rpc_limit_default,
        total_native_token_supply_default, Amount, ConsensusConfig,
    },
    crypto::NodePublicKey,
    transaction::EvmGas,
};

use crate::{
    collector::{self, Collector},
    components::{Component, Requirements},
    node_spec::Composition,
    scilla, utils,
};

const GENESIS_DEPOSIT: u128 = 10000000000000000000000000;
const DATADIR_PREFIX: &str = "z2_node_";
const NETWORK_CONFIG_FILE_NAME: &str = "network.yaml";
const ZQ2_CONFIG_FILE_NAME: &str = "config.toml";

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeData {
    // Secret key as hex.
    secret_key: String,
    address: Address,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// Network shape
    pub shape: Composition,
    /// Node data.
    pub node_data: HashMap<u64, NodeData>,
    /// Base port
    pub base_port: u16,
}

pub struct Setup {
    /// Configuration
    pub config: Config,
    /// The collector, if one is running
    pub collector: Option<collector::Collector>,
    /// Where we store config files.
    pub config_dir: String,
    /// Log spec
    pub log_spec: String,
    /// Base dir - the one zq2 is in.
    pub base_dir: String,
    /// Restart an old network
    pub keep_old_network: bool,
    /// Watch source
    pub watch: bool,
}

impl Config {
    pub fn get_config_file_name(config_dir: &str) -> Result<String> {
        let file_name = format!("{}/{}", config_dir, NETWORK_CONFIG_FILE_NAME);
        Ok(file_name.to_string())
    }

    pub async fn from_config_dir(config_dir: &str) -> Result<Option<Self>> {
        let file_name = Config::get_config_file_name(config_dir)?;
        if Path::new(&file_name).exists() {
            let data = fs::read_to_string(&file_name).await?;
            Ok(Some(serde_yaml::from_str(&data)?))
        } else {
            Ok(None)
        }
    }

    pub async fn save_to_config_dir(&self, config_dir: &str) -> Result<()> {
        let file_name = Config::get_config_file_name(config_dir)?;
        let str = serde_yaml::to_string(self)?;
        fs::write(file_name, str).await?;
        Ok(())
    }

    pub fn composition(&self) -> Composition {
        self.shape.clone()
    }

    pub fn from_spec(network: &Composition, base_port: u16) -> Result<Self> {
        // Generate secret keys and node addresses for the nodes in the network and stash it all in config.
        let mut node_data: HashMap<u64, NodeData> = HashMap::new();
        for node_id in network.nodes.keys() {
            let (secret_key, signing_key) = generate_keys_from_index(*node_id + 1)?;
            let address =
                TransactionPublicKey::Ecdsa(*signing_key.verifying_key(), true).into_addr();
            println!("[#{node_id}] = {}", secret_key.to_hex());
            node_data.insert(
                *node_id,
                NodeData {
                    secret_key: secret_key.to_hex(),
                    address,
                },
            );
        }

        let result = Config {
            shape: network.clone(),
            node_data,
            base_port,
        };
        Ok(result)
    }
}

impl Setup {
    pub fn ephemeral(base_port: u16, base_dir: &str, config_dir: &str) -> Result<Self> {
        let config = Config::from_spec(&Composition::small_network(), base_port)?;
        Ok(Self {
            config,
            collector: None,
            config_dir: config_dir.to_string(),
            log_spec: "".to_string(),
            base_dir: base_dir.to_string(),
            keep_old_network: true,
            watch: false,
        })
    }

    pub async fn load(
        config_dir: &str,
        log_spec: &str,
        base_dir: &str,
        watch: bool,
    ) -> Result<Self> {
        let config = Config::from_config_dir(config_dir)
            .await?
            .ok_or(anyhow!("Couldn't load configuration from {config_dir}"))?;
        Ok(Self {
            config,
            collector: None,
            config_dir: config_dir.to_string(),
            log_spec: log_spec.to_string(),
            base_dir: base_dir.to_string(),
            keep_old_network: true,
            watch,
        })
    }

    pub async fn create(
        network: &Option<Composition>,
        config_dir: &str,
        base_port: u16,
        log_spec: &str,
        base_dir: &str,
        keep_old_network: bool,
        watch: bool,
    ) -> Result<Self> {
        // If we had a config file, load it. Otherwise create a new one and save it so that
        // we can find it later.
        let loaded_config = Config::from_config_dir(config_dir).await?;
        let config = if let Some(val) = &network {
            // One was specified.
            if let Some(val2) = loaded_config {
                println!("WARNING: You've specified a network configuration; we'll ignore this and take the config from the existing loaded configuration file");
                val2
            } else {
                Config::from_spec(val, base_port)?
            }
        } else if let Some(val2) = loaded_config {
            println!("Starting previously saved config in {config_dir}");
            val2
        } else {
            // Set up a default network
            println!(">> No network specified or loaded; using default 4-node network for legacy reasons.");
            Config::from_spec(&Composition::small_network(), base_port)?
        };
        // Whatever we did, save it!
        config.save_to_config_dir(config_dir).await?;
        Ok(Self {
            config,
            collector: None,
            config_dir: config_dir.to_string(),
            log_spec: log_spec.to_string(),
            base_dir: base_dir.to_string(),
            keep_old_network,
            watch,
        })
    }

    /// For historical reasons, this is 201.
    pub fn get_json_rpc_port(&self, index: u16, proxied: bool) -> u16 {
        index + 201 + self.config.base_port + if proxied { 1000 } else { 0 }
    }

    pub fn get_scilla_port(&self, index: u16) -> u16 {
        index + self.config.base_port + 500
    }

    pub fn get_docs_port(&self) -> u16 {
        self.config.base_port + 2004
    }

    /// this used to be + 2000, but the default (base_port=4000) causes chrome to fail to browse, because it considers
    /// 6000 unsafe. Sigh.
    pub fn get_otterscan_port(&self) -> u16 {
        self.config.base_port + 2003
    }

    pub fn get_spout_port(&self) -> u16 {
        self.config.base_port + 2001
    }

    pub fn get_mitmproxy_port(&self) -> u16 {
        self.config.base_port + 2002
    }

    pub fn get_explorer_url(&self) -> String {
        format!("http://localhost:{0}", self.get_otterscan_port())
    }

    pub fn get_json_rpc_url(&self, proxied: bool) -> String {
        format!("http://localhost:{0}", self.get_json_rpc_port(0, proxied))
    }

    pub fn get_docs_listening_hostport(&self) -> String {
        format!("0.0.0.0:{0}", self.get_docs_port())
    }

    pub fn get_port_map(&self) -> String {
        let mut result = String::new();
        result.push_str(&format!(
            "🦏  JSON-RPC ports are at {0}+<node_index>\n",
            self.get_json_rpc_port(0, false)
        ));
        result.push_str(&format!(
            "🦏  Scilla ports are at {0}+<node_index>\n",
            self.get_scilla_port(0)
        ));
        result.push_str(&format!(
            "🦏  Otterscan: http://localhost:{0}/\n",
            self.get_otterscan_port()
        ));
        result.push_str(&format!(
            "🦏  Spout is at http://localhost:{0}/\n",
            self.get_spout_port()
        ));
        result.push_str(&format!(
            "🦏  mitmproxy API at http://localhost:{0}/\n",
            self.get_json_rpc_port(0, true)
        ));
        result.push_str(&format!(
            "🦏  mitmproxy port at http://localhost:{0}/\n",
            self.get_mitmproxy_port()
        ));
        result.push_str(&format!(
            "🦏  docs port at http://localhost:{0}/\n",
            self.get_docs_port()
        ));
        result
    }

    pub async fn generate_config(&self) -> Result<()> {
        // The genesis deposits.
        let mut genesis_deposits: Vec<(NodePublicKey, PeerId, Amount, Address)> = Vec::new();
        for (node, desc) in self.config.shape.nodes.iter() {
            if desc.is_validator {
                let data = self
                    .config
                    .node_data
                    .get(node)
                    .ok_or(anyhow!("no node data for {node}"))?;
                // Better have a genesis deposit.
                let secret_key = SecretKey::from_hex(&data.secret_key)?;
                genesis_deposits.push((
                    secret_key.node_public_key(),
                    secret_key.to_libp2p_keypair().public().to_peer_id(),
                    GENESIS_DEPOSIT.into(),
                    data.address,
                ))
            }
        }

        let genesis_accounts: Vec<(Address, Amount)> = vec![
            (
                address!("7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
                5000000000000000000000u128.into(),
            ),
            // privkey db11cfa086b92497c8ed5a4cc6edb3a5bfe3a640c43ffb9fc6aa0873c56f2ee3
            (
                address!("cb57ec3f064a16cadb36c7c712f4c9fa62b77415"),
                5000000000000000000000u128.into(),
            ),
        ];

        // Node vector
        println!(
            "Writing {0} config files to {1}",
            self.config.shape.nodes.len(),
            &self.config_dir
        );
        for (node_index, _node_desc) in self.config.shape.nodes.iter() {
            println!("🎱 Generating configuration for node {node_index}...");
            let mut cfg = zilliqa::cfg::Config {
                otlp_collector_endpoint: Some("http://localhost:4317".to_string()),
                bootstrap_address: None,
                nodes: Vec::new(),
                p2p_port: 0,
                external_address: None,
            };
            // @todo should pass this in!
            let mut node_config = cfg::NodeConfig {
                json_rpc_port: self.get_json_rpc_port(u64::try_into(*node_index)?, false),
                allowed_timestamp_skew: allowed_timestamp_skew_default(),
                data_dir: None,
                load_checkpoint: None,
                do_checkpoints: false,
                disable_rpc: disable_rpc_default(),
                eth_chain_id: eth_chain_id_default(),
                consensus: ConsensusConfig {
                    scilla_address: scilla_address_default(),
                    scilla_stdlib_dir: scilla_stdlib_dir_default(),
                    scilla_ext_libs_path: scilla_ext_libs_path_default(),
                    minimum_time_left_for_empty_block: minimum_time_left_for_empty_block_default(),
                    main_shard_id: None,
                    local_address: local_address_default(),
                    consensus_timeout: consensus_timeout_default(),
                    genesis_deposits: Vec::new(),
                    eth_block_gas_limit: EvmGas(84000000),
                    gas_price: 4_761_904_800_000u128.into(),
                    minimum_stake: 10_000_000_000_000_000_000_000_000u128.into(),
                    empty_block_timeout: empty_block_timeout_default(),
                    genesis_accounts: Vec::new(),
                    is_main: true,
                    blocks_per_hour: 3600,
                    blocks_per_epoch: 3600,
                    epochs_per_checkpoint: 24,
                    rewards_per_hour: 51_000_000_000_000_000_000_000u128.into(),
                    total_native_token_supply: total_native_token_supply_default(),
                },
                block_request_limit: block_request_limit_default(),
                max_blocks_in_flight: max_blocks_in_flight_default(),
                block_request_batch_size: block_request_batch_size_default(),
                state_rpc_limit: state_rpc_limit_default(),
                failed_request_sleep_duration: failed_request_sleep_duration_default(),
            };
            println!(
                "🧩  Node {node_index} has RPC port {0}",
                node_config.json_rpc_port
            );

            let data_dir_name = format!("{0}{1}", DATADIR_PREFIX, node_index);
            let mut path = PathBuf::from(&self.config_dir);
            path.push(&data_dir_name);
            if utils::file_exists(&path).await? {
                if self.keep_old_network {
                    continue;
                } else {
                    // Kill it.
                    tokio::fs::remove_dir_all(&path).await?;
                }
            }
            let _ = fs::create_dir(&path).await;
            let mut full_node_data_path = PathBuf::from(&self.config_dir);
            full_node_data_path.push(&data_dir_name);
            full_node_data_path.push("data");
            // Create if doesn't exist
            tokio::fs::create_dir(&full_node_data_path).await?;
            node_config.disable_rpc = false;
            node_config.eth_chain_id = 700 | 0x8000;
            node_config.data_dir = Some(utils::string_from_path(&full_node_data_path)?);
            node_config
                .consensus
                .genesis_deposits
                .clone_from(&genesis_deposits);
            node_config
                .consensus
                .genesis_accounts
                .clone_from(&genesis_accounts);
            node_config.consensus.scilla_address = format!(
                "http://localhost:{0}",
                self.get_scilla_port(u64::try_into(*node_index)?)
            );
            node_config.state_rpc_limit = usize::try_from(i64::MAX)?;
            node_config.consensus.scilla_stdlib_dir =
                scilla::Runner::get_scilla_stdlib_dir(&self.base_dir);

            cfg.nodes = Vec::new();
            cfg.nodes.push(node_config);
            cfg.p2p_port = 0;
            // Now write the config.
            let mut path = PathBuf::from(&self.config_dir);
            path.push(&data_dir_name);
            path.push(ZQ2_CONFIG_FILE_NAME);
            println!("🪅 Writing configuration file for node {0} .. ", node_index);
            let config_str = toml::to_string(&cfg)?;
            fs::write(path, config_str).await?;
        }
        Ok(())
    }

    pub async fn describe_component(component: &Component) -> Result<Requirements> {
        match component {
            Component::ZQ2 => crate::zq2::Runner::requirements().await,
            Component::Otel => crate::otel::Runner::requirements().await,
            Component::Otterscan => crate::otterscan::Runner::requirements().await,
            Component::Spout => crate::spout::Runner::requirements().await,
            Component::Docs => crate::docs::Runner::requirements().await,
            Component::Mitmweb => crate::mitmweb::Runner::requirements().await,
            Component::Scilla => crate::scilla::Runner::requirements().await,
        }
    }

    pub async fn preprocess_config_file(
        config_file: &str,
        checkpoint: Option<&zilliqa::cfg::Checkpoint>,
    ) -> Result<()> {
        // Load the config file, modify it and save it back.
        let loaded_config_str = fs::read_to_string(&config_file)
            .await
            .context(format!("Cannot read from {config_file} - are you sure you are trying to start a node that actually exists?"))?;
        let mut loaded_config: zilliqa::cfg::Config = toml::from_str(&loaded_config_str)?;
        for node in loaded_config.nodes.iter_mut() {
            if let Some(cp) = checkpoint {
                println!(
                    " 😇 Configuring Zilliqa to load a checkpoint from {}:{} .. ",
                    cp.file,
                    hex::encode(cp.hash.0)
                );
                node.load_checkpoint = Some(cp.clone());
            } else {
                node.load_checkpoint = None
            }
        }
        let config_str = toml::to_string(&loaded_config)?;
        fs::write(config_file, config_str).await?;
        Ok(())
    }

    /// for_nodes restricts which nodes start.
    pub async fn run_component(
        &mut self,
        component: &Component,
        collector: &mut Collector,
        for_nodes: &Composition,
        checkpoints: &Option<HashMap<u64, zilliqa::cfg::Checkpoint>>,
    ) -> Result<()> {
        match component {
            Component::Scilla => {
                // Generate a collector
                self.generate_config().await?;
                for idx in for_nodes.nodes.keys() {
                    collector
                        .start_scilla(
                            &self.base_dir,
                            u64::try_into(*idx)?,
                            self.get_scilla_port(u64::try_into(*idx)?),
                        )
                        .await?;
                }
                Ok(())
            }
            Component::ZQ2 => {
                for idx in for_nodes.nodes.keys() {
                    let config_file = format!(
                        "{0}/{1}{2}/{ZQ2_CONFIG_FILE_NAME}",
                        self.config_dir, DATADIR_PREFIX, idx
                    );
                    // Now, we need to rewrite the config file to take account of checkpoints...
                    Self::preprocess_config_file(
                        &config_file,
                        checkpoints.as_ref().and_then(|x| x.get(idx)),
                    )
                    .await?;
                    let node_data = self
                        .config
                        .node_data
                        .get(idx)
                        .ok_or(anyhow!("No node data for node {idx}"))?;
                    let secret_key = SecretKey::from_hex(&node_data.secret_key)?;
                    collector
                        .start_zq2_node(
                            &self.base_dir,
                            u64::try_into(*idx)?,
                            &secret_key,
                            &config_file,
                            self.watch,
                        )
                        .await?;
                }
                Ok(())
            }
            Component::Otel => {
                println!("Setting up otel .. ");
                collector
                    .start_otel(&self.base_dir, &self.config_dir)
                    .await?;
                Ok(())
            }
            Component::Otterscan => {
                collector
                    .start_otterscan(
                        &self.base_dir,
                        &self.get_json_rpc_url(false),
                        self.get_otterscan_port(),
                    )
                    .await?;
                Ok(())
            }
            Component::Spout => {
                self.wait_for_chain().await?;
                collector
                    .start_spout(
                        &self.base_dir,
                        &self.get_json_rpc_url(true),
                        &self.get_explorer_url(),
                        // 0xcb...
                        "db11cfa086b92497c8ed5a4cc6edb3a5bfe3a640c43ffb9fc6aa0873c56f2ee3",
                        self.get_spout_port(),
                    )
                    .await?;
                Ok(())
            }
            Component::Docs => {
                collector
                    .start_docs(&self.base_dir, &self.get_docs_listening_hostport())
                    .await?;
                Ok(())
            }
            Component::Mitmweb => {
                collector
                    .start_mitmweb(
                        &self.base_dir,
                        0,
                        self.get_json_rpc_port(0, true),
                        self.get_json_rpc_port(0, false),
                        self.get_mitmproxy_port(),
                    )
                    .await?;
                Ok(())
            }
        }
    }

    pub async fn wait_for_chain(&mut self) -> Result<()> {
        let rpc_url = self.get_json_rpc_url(true);
        loop {
            println!("Check chain liveness on {rpc_url} .. ");
            match utils::get_chain_id(&rpc_url).await {
                Ok(val) => {
                    println!("Chain id is {val}");
                    return Ok(());
                }
                _ => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                }
            }
        }
    }
}

pub fn generate_secret_key() -> Result<SecretKey> {
    SecretKey::new().map_err(|err| anyhow!(Box::new(err)))
}

pub fn generate_keys_from_index(index: u64) -> Result<(SecretKey, SigningKey)> {
    assert_ne!(
        index, 0,
        "index must be non-zero when generating secret key"
    );
    let padded_key = format!("{:0>64}", index);
    let secret_key = SecretKey::from_hex(&padded_key).map_err(|err| anyhow!(Box::new(err)))?;
    let signing_key = SigningKey::from_slice(&hex::decode(padded_key)?)?;
    Ok((secret_key, signing_key))
}
