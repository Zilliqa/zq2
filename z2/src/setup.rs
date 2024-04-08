//use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

use eyre::{eyre, Result};
use libp2p::PeerId;
use tokio::fs;
use toml;
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto::SecretKey;
use zilliqa::{cfg, crypto::NodePublicKey, state::Address};

use crate::collector;

const GENESIS_DEPOSIT: &str = "32000000000000000000";
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
}

impl Setup {
    pub fn new(how_many: usize, config_dir: &str, log_spec: &str) -> Result<Self> {
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
        })
    }

    pub async fn generate_config(&self) -> Result<()> {
        // We don't care if this fails - it probably already exists.
        let _ = fs::create_dir(&self.config_dir).await;

        // let first_key = self.secret_keys[0].node_public_key().to_string();
        //let first_peer_id = self.secret_keys[0]
        //    .to_libp2p_keypair()
        //    .public()
        //    .to_peer_id()
        //    .to_string();

        let p2p_keypair = self.secret_keys[0].to_libp2p_keypair();
        let peer_id_node_0 = PeerId::from_public_key(&p2p_keypair.public());
        let public_key_node_0 = self.secret_keys[0].node_public_key();

        // The genesis deposits.
        let mut genesis_deposits: Vec<(NodePublicKey, String, Address)> = Vec::new();
        for i in 0..self.how_many {
            genesis_deposits.push((
                self.secret_keys[i].node_public_key(),
                GENESIS_DEPOSIT.to_string(),
                self.node_addresses[i],
            ))
        }

        let mut genesis_accounts: Vec<(Address, String)> = Vec::new();
        genesis_accounts.push((
            Address::from_str("7E5F4552091A69125d5DfCb7b8C2659029395Bdf")?,
            "5000000000000000000000".to_string(),
        ));

        // Node vector
        println!("Writing config files to {0}", &self.config_dir);
        for i in 0..self.how_many {
            let mut cfg = zilliqa::cfg::Config::default();
            // from the oltp module ..
            // @todo should pass this in!
            cfg.otlp_collector_endpoint = Some("http://localhost:4317".to_string());
            let mut node_config = cfg::NodeConfig::default();
            node_config.json_rpc_port = usize::try_into(4201 + i)?;
            println!("Node {i} has RPC port {0}", node_config.json_rpc_port);
            node_config.disable_rpc = false;
            node_config.eth_chain_id = 700 | 0x8000;
            node_config
                .consensus
                .genesis_committee
                .push((public_key_node_0.clone(), peer_id_node_0.clone()));
            node_config.consensus.genesis_deposits = genesis_deposits.clone();
            node_config.consensus.genesis_accounts = genesis_accounts.clone();
            cfg.nodes = Vec::new();
            cfg.nodes.push(node_config);
            cfg.p2p_port = 0;
            // Now write the config.
            let mut path = PathBuf::from(&self.config_dir);
            let data_dir_name = format!("{0}{1}", DATADIR_PREFIX, i);
            path.push(&data_dir_name);
            let _ = fs::create_dir(&path).await;
            path.push("config.yaml");
            println!("Writing node {0} .. ", i);
            let config_str = toml::to_string(&cfg)?;
            fs::write(path, config_str).await?;
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        // Generate a collector
        self.generate_config().await?;
        let config_files = (0..self.how_many)
            .map(|x| format!("{0}/{1}{2}/config.yaml", self.config_dir, DATADIR_PREFIX, x))
            .collect::<Vec<String>>();

        self.collector = Some(
            collector::Collector::new(&self.secret_keys, &config_files, &self.log_spec).await?,
        );
        if let Some(mut c) = self.collector.take() {
            c.complete().await?;
        }
        Ok(())
    }
}

pub fn generate_secret_key() -> Result<SecretKey> {
    SecretKey::new().map_err(|err| eyre!(Box::new(err)))
}

pub fn generate_secret_key_from_index(index: usize) -> Result<SecretKey> {
    assert_ne!(
        index, 0,
        "index must be non-zero when generating secret key"
    );
    let padded_key = format!("{:0>64}", index);
    SecretKey::from_hex(&padded_key).map_err(|err| eyre!(Box::new(err)))
}
