use std::{fs, path::PathBuf};

use anyhow::Result;
use std::{fs, path::PathBuf};

pub mod bridge_node;
pub mod cfg;
pub mod client;
pub mod contracts;
pub mod event;
pub mod message;
pub mod signature;
pub mod validator_node;

pub fn read_config(config_file: &PathBuf) -> Result<cfg::Config> {
    let config_content = if config_file.exists() {
        fs::read_to_string(&config_file)?
    } else {
        panic!("Please specify a config file");
    };

    Ok(toml::from_str(&config_content)?)
}

// Creates the chain clients from the configuration. The first one is
// the ZQ2 one.
pub async fn create_chain_clients(
    config: &cfg::Config,
    signer: &PrivateKeySigner,
) -> Result<Vec<client::ChainClient>> {
    let mut chain_clients = vec![create_zq2_chain_client(config.clone(), &signer).await?];

    for chain_config in &config.chain_configs {
        chain_clients.push(
            client::ChainClient::new(
                &chain_config,
                config.zq2.validator_manager_address,
                signer.clone(),
            )
            .await?,
        );
    }

    Ok(chain_clients)
}

async fn create_zq2_chain_client(
    config: cfg::Config,
    signer: &PrivateKeySigner,
) -> Result<client::ChainClient> {
    client::ChainClient::new(
        &cfg::ChainConfig {
            rpc_url: config.zq2.rpc_url,
            chain_gateway_address: config.zq2.chain_gateway_address,
            chain_gateway_block_deployed: 0,
            block_instant_finality: false,
            legacy_gas_estimation: false,
        },
        config.zq2.validator_manager_address,
        signer.clone(),
    )
    .await
}
