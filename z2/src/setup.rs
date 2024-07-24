//use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use alloy_primitives::{address, Address};
use anyhow::{anyhow, Result};
use libp2p::PeerId;
use tokio::fs;
use toml;
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto::SecretKey;
use zilliqa::{
    cfg,
    cfg::{
        allowed_timestamp_skew_default, block_request_batch_size_default,
        block_request_limit_default, consensus_timeout_default, disable_rpc_default,
        empty_block_timeout_default, eth_chain_id_default, failed_request_sleep_duration_default,
        filter_expiry_default, local_address_default, max_blocks_in_flight_default,
        max_filters_default, minimum_time_left_for_empty_block_default, scilla_address_default,
        scilla_lib_dir_default, Amount, ConsensusConfig,
    },
    crypto::NodePublicKey,
    transaction::EvmGas,
};

use crate::{
    collector::{self, Collector},
    components::{Component, Requirements},
    scilla, utils,
};

const GENESIS_DEPOSIT: u128 = 10000000000000000000000000;
const DATADIR_PREFIX: &str = "z2_node_";

pub struct Setup {
    /// How many nodes should we start?
    pub how_many: usize,
    /// Secret keys for the nodes
    pub secret_keys: Vec<SecretKey>,
    /// Node addresses
    pub node_addresses: Vec<Address>,
    /// The collector, if one is running
    pub collector: Option<collector::Collector>,
    /// Where we store config files.
    pub config_dir: String,
    /// Log spec
    pub log_spec: String,
    /// Base dir - the one zq2 is in.
    pub base_dir: String,
    /// Base port
    pub base_port: u16,
    /// Restart an old network
    pub keep_old_network: bool,
    /// Watch source
    pub watch: bool,
}

impl Setup {
    pub fn new(
        how_many: usize,
        config_dir: &str,
        log_spec: &str,
        base_dir: &str,
        base_port: u16,
        keep_old_network: bool,
        watch: bool,
    ) -> Result<Self> {
        let mut secret_keys = Vec::new();
        let mut node_addresses = Vec::new();
        for i in 0..how_many {
            let key = generate_secret_key_from_index(i + 1)?;
            println!("[#{i}] = {}", key.to_hex());
            secret_keys.push(key);
            node_addresses.push(key.tx_ecdsa_public_key().into_addr());
        }

        Ok(Self {
            how_many,
            secret_keys,
            node_addresses,
            collector: None,
            config_dir: config_dir.to_string(),
            log_spec: log_spec.to_string(),
            base_dir: base_dir.to_string(),
            base_port,
            keep_old_network,
            watch,
        })
    }

    /// For historical reasons, this is 201.
    pub fn get_json_rpc_port(&self, index: u16, proxied: bool) -> u16 {
        index + 201 + self.base_port + if proxied { 1000 } else { 0 }
    }

    pub fn get_scilla_port(&self, index: u16) -> u16 {
        index + self.base_port + 500
    }

    pub fn get_docs_port(&self) -> u16 {
        self.base_port + 2004
    }

    /// this used to be + 2000, but the default (base_port=4000) causes chrome to fail to browse, because it considers
    /// 6000 unsafe. Sigh.
    pub fn get_otterscan_port(&self) -> u16 {
        self.base_port + 2003
    }

    pub fn get_spout_port(&self) -> u16 {
        self.base_port + 2001
    }

    pub fn get_mitmproxy_port(&self) -> u16 {
        self.base_port + 2002
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
        for i in 0..self.how_many {
            genesis_deposits.push((
                self.secret_keys[i].node_public_key(),
                self.secret_keys[i]
                    .to_libp2p_keypair()
                    .public()
                    .to_peer_id(),
                GENESIS_DEPOSIT.into(),
                self.node_addresses[i],
            ))
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
        println!("Writing config files to {0}", &self.config_dir);
        for i in 0..self.how_many {
            let mut cfg = zilliqa::cfg::Config {
                otlp_collector_endpoint: Some("http://localhost:4317".to_string()),
                bootstrap_address: None,
                nodes: Vec::new(),
                p2p_port: 0,
                external_address: None,
            };
            // @todo should pass this in!
            let mut node_config = cfg::NodeConfig {
                json_rpc_port: self.get_json_rpc_port(usize::try_into(i)?, false),
                allowed_timestamp_skew: allowed_timestamp_skew_default(),
                data_dir: None,
                load_checkpoint: None,
                do_checkpoints: false,
                disable_rpc: disable_rpc_default(),
                eth_chain_id: eth_chain_id_default(),
                consensus: ConsensusConfig {
                    scilla_address: scilla_address_default(),
                    scilla_lib_dir: scilla_lib_dir_default(),
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
                },
                block_request_limit: block_request_limit_default(),
                max_blocks_in_flight: max_blocks_in_flight_default(),
                block_request_batch_size: block_request_batch_size_default(),
                filter_expiry: filter_expiry_default(),
                max_filters: max_filters_default(),
                failed_request_sleep_duration: failed_request_sleep_duration_default(),
            };
            println!("Node {i} has RPC port {0}", node_config.json_rpc_port);
            let data_dir_name = format!("{0}{1}", DATADIR_PREFIX, i);
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
                self.get_scilla_port(usize::try_into(i)?)
            );
            node_config.consensus.scilla_lib_dir =
                scilla::Runner::get_scilla_lib_dir(&self.base_dir);

            cfg.nodes = Vec::new();
            cfg.nodes.push(node_config);
            cfg.p2p_port = 0;
            // Now write the config.
            let mut path = PathBuf::from(&self.config_dir);
            path.push(&data_dir_name);
            path.push("config.yaml");
            println!("Writing node {0} .. ", i);
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

    pub async fn run_component(
        &mut self,
        component: &Component,
        collector: &mut Collector,
    ) -> Result<()> {
        match component {
            Component::Scilla => {
                // Generate a collector
                self.generate_config().await?;
                let config_files = (0..self.how_many)
                    .map(|x| format!("{0}/{1}{2}/config.yaml", self.config_dir, DATADIR_PREFIX, x))
                    .collect::<Vec<String>>();
                for (idx, _) in config_files.iter().enumerate() {
                    collector
                        .start_scilla(
                            &self.base_dir,
                            idx,
                            self.get_scilla_port(usize::try_into(idx)?),
                        )
                        .await?;
                }
                Ok(())
            }
            Component::ZQ2 => {
                // Generate a collector
                self.generate_config().await?;
                let config_files = (0..self.how_many)
                    .map(|x| format!("{0}/{1}{2}/config.yaml", self.config_dir, DATADIR_PREFIX, x))
                    .collect::<Vec<String>>();
                for (idx, _) in config_files.iter().enumerate() {
                    collector
                        .start_zq2_node(
                            &self.base_dir,
                            idx,
                            &self.secret_keys[idx],
                            &config_files[idx],
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

pub fn generate_secret_key_from_index(index: usize) -> Result<SecretKey> {
    assert_ne!(
        index, 0,
        "index must be non-zero when generating secret key"
    );
    let padded_key = format!("{:0>64}", index);
    SecretKey::from_hex(&padded_key).map_err(|err| anyhow!(Box::new(err)))
}
