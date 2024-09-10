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
                config.zq2.chain_gateway_address,
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
            estimate_gas: false,
            legacy_gas_estimation: true,
        },
        config.zq2.validator_manager_address,
        config.zq2.chain_gateway_address,
        signer.clone(),
    )
    .await
}

/// See: src/contracts/mod.rs
#[cfg(test)]
mod tests {
    use std::{fs::File, path::PathBuf, str::FromStr};

    use foundry_compilers::{
        artifacts::{
            output_selection::OutputSelection, EvmVersion, Optimizer, Remapping, Settings,
            SolcInput, Source,
        },
        solc::SolcLanguage,
    };

    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn compile_all() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        println!("CARGO_MANIFEST_DIR = {root:?}");
        let input = SolcInput {
            language: SolcLanguage::Solidity,
            sources: Source::read_all(
                ["ValidatorManager.sol"].map(|c| format!("contracts/src/{c}")),
            )
            .unwrap(),
            settings: Settings {
                remappings: vec![
                    Remapping {
                        context: None,
                        name: "@openzeppelin".to_owned(),
                        path: "../../vendor/openzeppelin-contracts/".to_owned(),
                    },
                    Remapping {
                        context: None,
                        name: "contracts".to_owned(),
                        path: "src".to_owned(),
                    },
                ],
                optimizer: Optimizer {
                    enabled: Some(true),
                    runs: Some(4294967295),
                    details: None,
                },
                output_selection: OutputSelection::complete_output_selection(),
                evm_version: Some(EvmVersion::Shanghai),
                ..Default::default()
            },
        };

        let mut solc =
            foundry_compilers::solc::Solc::find_or_install(&semver::Version::new(0, 8, 26))
                .unwrap();
        [
            "../../vendor/openzeppelin-contracts/contracts",
            "../../vendor/openzeppelin-contracts/lib",
        ]
        .iter()
        .for_each(|&path| {
            let _ = solc.allow_paths.insert(PathBuf::from_str(path).unwrap());
        });
        solc.base_path = Some(root.join("..").join("uccb").join("contracts"));

        let output = solc.compile_exact(&input).unwrap();
        let output_file = root
            .join("..")
            .join("uccb")
            .join("contracts")
            .join("compiled.json");

        if std::env::var_os("ZQ_CONTRACT_TEST_BLESS").is_some() {
            let file = File::create(output_file).unwrap();
            serde_json::to_writer_pretty(file, &output).unwrap();

            println!("`ValidatorManager.json` updated, please commit these changes");
        } else {
            let file = File::open(output_file).unwrap();
            let current_output = serde_json::from_reader(file).unwrap();

            assert_eq!(output, current_output);
        }
    }
}
