use std::collections::HashMap;

use serde::Deserialize;

#[derive(Deserialize)]
struct CombinedJson {
    contracts: HashMap<String, Contract>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Contract {
    abi: ethabi::Contract,
    bin: String,
    bin_runtime: String,
}

// Generated with `solc native_token.sol '@openzeppelin/=openzeppelin-contracts/' --base-path . --include-path ../../../vendor/ --combined-json abi,bin,bin-runtime > native_token.json`.
pub mod native_token {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{CombinedJson, Contract};

    const COMBINED_JSON: &str = include_str!("native_token.json");
    static CONTRACT: Lazy<Contract> = Lazy::new(|| {
        serde_json::from_str::<CombinedJson>(COMBINED_JSON)
            .unwrap()
            .contracts
            .remove("native_token.sol:NativeToken")
            .unwrap()
    });
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static BALANCE_OF: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("balanceOf").unwrap().clone());
    pub static SET_BALANCE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setBalance").unwrap().clone());
    pub static CREATION_CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin).unwrap());
    pub static CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin_runtime).unwrap());
}

// Generated with `solc shard.sol '@openzeppelin/=openzeppelin-contracts/' --base-path . --include-path ../../../vendor/ --combined-json abi,bin,bin-runtime > shard.json`.
#[allow(dead_code)] // define properties on the contract, even if they aren't currently invoked
pub mod shard {
    use ethabi::{Constructor, Function};
    use once_cell::sync::Lazy;

    use super::{CombinedJson, Contract};

    const COMBINED_JSON: &str = include_str!("shard.json");
    static CONTRACT: Lazy<Contract> = Lazy::new(|| {
        serde_json::from_str::<CombinedJson>(COMBINED_JSON)
            .unwrap()
            .contracts
            .remove("shard.sol:Shard")
            .unwrap()
    });
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static ADD_VALIDATOR: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("addValidator").unwrap().clone());
    pub static CONSENSUS_TIMEOUT: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("consensusTimeoutMs").unwrap().clone());
    pub static CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin_runtime).unwrap());
    pub static CREATION_CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin).unwrap());
}

// Generated with `solc shard_registry.sol '@openzeppelin/=openzeppelin-contracts/' --base-path . --include-path ../../../vendor/ --combined-json abi,bin,bin-runtime > shard_registry.json`.
#[allow(dead_code)]
pub mod shard_registry {
    use ethabi::{Constructor, Event, Function};
    use once_cell::sync::Lazy;

    use super::{CombinedJson, Contract};

    const COMBINED_JSON: &str = include_str!("shard_registry.json");
    static CONTRACT: Lazy<Contract> = Lazy::new(|| {
        serde_json::from_str::<CombinedJson>(COMBINED_JSON)
            .unwrap()
            .contracts
            .remove("shard_registry.sol:ShardRegistry")
            .unwrap()
    });
    pub static CONSTRUCTOR: Lazy<Constructor> =
        Lazy::new(|| CONTRACT.abi.constructor().unwrap().clone());
    pub static SHARD_ADDED_EVT: Lazy<Event> =
        Lazy::new(|| CONTRACT.abi.event("ShardAdded").unwrap().clone());
    pub static ADD_SHARD: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("addShard").unwrap().clone());
    pub static CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin_runtime).unwrap());
    pub static CREATION_CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin).unwrap());
}

/// These tests assert the contract binaries in this module are correct and reproducible, by recompiling the source
/// files and checking the result is the same. This means we can keep the compiled source code in-tree, while also
/// asserting in CI that the compiled source code is genuine. The tests only run when the `test_contract_bytecode`
/// feature is enabled.
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    // Obtained from https://binaries.soliditylang.org/linux-amd64/list.json.
    const SOLC_VERSION: &str = "v0.8.21+commit.d9974bed";
    const SOLC_HASH: &str = "00bebaa90cfcc8c807b6b48cd8e9423bdbe5b7054ca0e47cbe5d8dd1aa1dced3";

    use std::{
        fs::OpenOptions, io::Write, mem, os::unix::prelude::OpenOptionsExt, path::PathBuf,
        process::Command,
    };

    use serde_json::Value;
    use sha2::Digest;
    use sha3::Keccak256;

    use super::{native_token, shard, shard_registry};

    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn native_token() {
        test_contract(
            "native_token.sol",
            "native_token.sol:NativeToken",
            native_token::CODE.as_slice(),
            native_token::CREATION_CODE.as_slice(),
        )
    }

    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn shard() {
        test_contract(
            "shard.sol",
            "shard.sol:Shard",
            shard::CODE.as_slice(),
            shard::CREATION_CODE.as_slice(),
        )
    }

    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn shard_registry() {
        test_contract(
            "shard_registry.sol",
            "shard_registry.sol:ShardRegistry",
            shard_registry::CODE.as_slice(),
            shard_registry::CREATION_CODE.as_slice(),
        )
    }

    fn test_contract(filename: &str, json_key: &str, code: &[u8], creation_code: &[u8]) {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut solc = Vec::new();
        let solc_download_path = format!(
            "https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-{SOLC_VERSION}"
        );
        let response = ureq::get(&solc_download_path).call().unwrap();
        response.into_reader().read_to_end(&mut solc).unwrap();

        let expected_hash = hex::decode(SOLC_HASH).unwrap();
        let actual_hash = Keccak256::digest(&solc);
        assert_eq!(expected_hash, actual_hash.to_vec());

        let solc_path = temp_dir.path().join("solc");
        println!("{}", solc_path.to_string_lossy());
        let mut solc_file = OpenOptions::new()
            .mode(0o777)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&solc_path)
            .unwrap();
        solc_file.write_all(&solc).unwrap();
        mem::drop(solc_file); // Close the file.

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("contracts");
        let contract = root.join(filename);
        let vendor = root
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("vendor");

        let output = Command::new(solc_path)
            .current_dir(root)
            .arg(contract)
            .arg("@openzeppelin/=openzeppelin-contracts/")
            .arg("--base-path")
            .arg(".")
            .arg("--include-path")
            .arg(vendor)
            .arg("--combined-json")
            .arg("abi,bin,bin-runtime")
            .arg("--evm-version=paris")
            .output()
            .unwrap();

        eprintln!("{}", std::str::from_utf8(&output.stderr).unwrap());
        let combined_json: Value = serde_json::from_slice(&output.stdout).unwrap();
        let contract = combined_json["contracts"][&json_key].clone();

        let expected_code = hex::decode(contract["bin-runtime"].as_str().unwrap()).unwrap();
        assert_eq!(code.len(), expected_code.len());
        assert_eq!(code, expected_code);

        let expected_creation_code = hex::decode(contract["bin"].as_str().unwrap()).unwrap();
        assert_eq!(creation_code.len(), expected_creation_code.len());
        assert_eq!(creation_code, expected_creation_code);
    }
}
