use std::path::PathBuf;

use alloy::{json_abi::JsonAbi, primitives::Bytes};
use foundry_compilers::{
    artifacts::{EvmVersion, Optimizer, Settings, SolcInput, Source},
    solc::{Solc, SolcLanguage},
};

pub fn compile_contract(path: &str, contract: &str) -> (JsonAbi, Bytes) {
    let path: PathBuf = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path).into();

    let solc_input = SolcInput::new(
        SolcLanguage::Solidity,
        Source::read_all_files(vec![path.clone()]).unwrap(),
        Settings {
            remappings: vec![format!(
                "@openzeppelin/contracts={}/../vendor/openzeppelin-contracts/contracts",
                env!("CARGO_MANIFEST_DIR")
            )
            .parse()
            .unwrap()],
            optimizer: Optimizer {
                enabled: Some(true),
                runs: Some(2usize.pow(32) - 1),
                details: None,
            },
            ..Default::default()
        },
    )
    .evm_version(EvmVersion::Shanghai); // ensure compatible with EVM version in exec.rs

    let mut solc = Solc::find_or_install(&semver::Version::new(0, 8, 28)).unwrap();
    solc.allow_paths
        .insert(PathBuf::from("../vendor/openzeppelin-contracts"));
    let mut output = solc.compile_exact(&solc_input).unwrap();

    if output.has_error() {
        for error in output.errors {
            eprintln!("{error}");
        }
        panic!("failed to compile contract");
    }

    let contract = output
        .contracts
        .remove(&path)
        .unwrap()
        .remove(contract)
        .unwrap();
    let evm = contract.evm.unwrap();

    (
        contract.abi.unwrap(),
        evm.bytecode.unwrap().into_bytes().unwrap(),
    )
}
