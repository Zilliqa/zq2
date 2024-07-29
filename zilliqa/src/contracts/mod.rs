use serde_json::Value;

pub mod deposit {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{contract, Contract};

    static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/deposit.sol", "Deposit"));
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static LEADER_AT_VIEW: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("leaderAtView").unwrap().clone());
    pub static TEMP_REMOVE_STAKER: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("tempRemoveStaker").unwrap().clone());
    pub static DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("deposit").unwrap().clone());
    pub static SET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setStake").unwrap().clone());
    pub static GET_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStake").unwrap().clone());
    pub static GET_REWARD_ADDRESS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getRewardAddress").unwrap().clone());
    pub static GET_PEER_ID: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getPeerId").unwrap().clone());
    pub static GET_STAKERS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("getStakers").unwrap().clone());
    pub static TOTAL_STAKE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("totalStake").unwrap().clone());
    pub static MIN_DEPOSIT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("_minimumStake").unwrap().clone());
}

pub mod shard {
    use ethabi::Constructor;
    use once_cell::sync::Lazy;

    use super::{contract, Contract};

    static CONTRACT: Lazy<Contract> = Lazy::new(|| contract("src/contracts/shard.sol", "Shard"));

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
}

pub mod intershard_bridge {
    use ethabi::{Constructor, Event, Function};
    use once_cell::sync::Lazy;

    use super::{contract, Contract};

    static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/intershard_bridge.sol", "IntershardBridge"));

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static BRIDGE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("bridge").unwrap().clone());
    pub static RELAYED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("Relayed").unwrap().clone());
}

pub mod shard_registry {
    use ethabi::{Constructor, Event, Function};
    use once_cell::sync::Lazy;

    use super::{contract, Contract};

    static CONTRACT: Lazy<Contract> =
        Lazy::new(|| contract("src/contracts/shard_registry.sol", "ShardRegistry"));

    pub static BYTECODE: Lazy<Vec<u8>> = Lazy::new(|| CONTRACT.bytecode.clone());
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());

    pub static ADD_SHARD: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("addShard").unwrap().clone());
    pub static SHARD_ADDED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("ShardAdded").unwrap().clone());

    pub static ADD_LINK: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("addLink").unwrap().clone());
    pub static LINK_ADDED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("LinkAdded").unwrap().clone());
}

const COMPILED: &str = include_str!("compiled.json");

fn contract(src: &str, name: &str) -> Contract {
    let compiled = serde_json::from_str::<Value>(COMPILED).unwrap();
    let contract = &compiled["contracts"][src][name];
    let abi = serde_json::from_value(contract["abi"].clone()).unwrap();
    let bytecode = hex::decode(contract["evm"]["bytecode"]["object"].as_str().unwrap()).unwrap();

    Contract { abi, bytecode }
}

struct Contract {
    abi: ethabi::Contract,
    bytecode: Vec<u8>,
}

/// This test asserts the contract binaries in this module are correct and reproducible, by recompiling the source
/// files and checking the result is the same. This means we can keep the compiled source code in-tree, while also
/// asserting in CI that the compiled source code is genuine. The tests only run when the `test_contract_bytecode`
/// feature is enabled.
#[cfg(test)]
mod tests {
    use std::{fs::File, path::PathBuf};

    use ethers::solc::{
        artifacts::{output_selection::OutputSelection, Optimizer, Settings, Source},
        remappings::Remapping,
        CompilerInput, EvmVersion, Solc,
    };
    use ethers_solc::CompilerOutput;

    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn compile_all() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let input = CompilerInput {
            language: "Solidity".to_owned(),
            sources: Source::read_all(
                [
                    "deposit.sol",
                    "intershard_bridge.sol",
                    "shard.sol",
                    "shard_registry.sol",
                ]
                .map(|c| format!("src/contracts/{c}")),
            )
            .unwrap(),
            settings: Settings {
                remappings: vec![Remapping {
                    context: None,
                    name: "@openzeppelin".to_owned(),
                    path: "../vendor/openzeppelin-contracts/".to_owned(),
                }],
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

        let solc = Solc::find_or_install_svm_version("0.8.23")
            .unwrap()
            .with_base_path(&root)
            .args(["--allow-paths", "../vendor"]);

        let output = solc.compile_exact(&input).unwrap();
        let output_file = root.join("src").join("contracts").join("compiled.json");

        if std::env::var_os("ZQ_CONTRACT_TEST_BLESS").is_some() {
            let file = File::create(output_file).unwrap();
            serde_json::to_writer_pretty(file, &output).unwrap();

            println!("`compiled.json` updated, please commit these changes");
        } else {
            let file = File::open(output_file).unwrap();
            let current_output: CompilerOutput = serde_json::from_reader(file).unwrap();

            assert_eq!(output, current_output);
        }
    }
}
