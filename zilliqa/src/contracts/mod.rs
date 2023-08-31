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
    bin_runtime: String,
}

// Generated with `solc native_token.sol '@openzeppelin/=openzeppelin-contracts/' --base-path . --include-path ../../../vendor/ --combined-json abi,bin > native_token.json`.
pub mod native_token {
    use ethabi::Function;
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
    pub static BALANCE_OF: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("balanceOf").unwrap().clone());
    pub static SET_BALANCE: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setBalance").unwrap().clone());
    pub static TRANSFER: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("transfer").unwrap().clone());
    pub static CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin_runtime).unwrap());
}

// Generated with `solc gas_price.sol '@openzeppelin/=openzeppelin-contracts/' --base-path . --include-path ../../../vendor/ --combined-json abi,bin > gas_price.json`.
pub mod gas_price {
    use ethabi::Function;
    use once_cell::sync::Lazy;

    use super::{CombinedJson, Contract};

    const COMBINED_JSON: &str = include_str!("gas_price.json");
    static CONTRACT: Lazy<Contract> = Lazy::new(|| {
        serde_json::from_str::<CombinedJson>(COMBINED_JSON)
            .unwrap()
            .contracts
            .remove("gas_price.sol:GasPrice")
            .unwrap()
    });
    pub static SET_GAS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("setGas").unwrap().clone());

    pub static GET_GAS: Lazy<Function> =
        Lazy::new(|| CONTRACT.abi.function("value").unwrap().clone());
    pub static CODE: Lazy<Vec<u8>> = Lazy::new(|| hex::decode(&CONTRACT.bin_runtime).unwrap());
}


/// These tests assert the contract binaries in this module are correct and reproducible, by recompiling the source
/// files and checking the result is the same. This means we can keep the compiled source code in-tree, while also
/// asserting in CI that the compiled source code is genuine. The tests only run when the `test_contract_bytecode`
/// feature is enabled.
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    // Obtained from https://binaries.soliditylang.org/linux-amd64/list.json.
    const SOLC_VERSION: &str = "v0.8.20+commit.a1b79de6";
    const SOLC_HASH: &str = "d68fa7092d5af50c1dca4d6318f8a2470b11a766794814e505e3cc6a587deebb";

    use std::{
        fs::OpenOptions, io::Write, mem, os::unix::prelude::OpenOptionsExt, path::PathBuf,
        process::Command,
    };

    use serde_json::Value;
    use sha2::Digest;
    use sha3::Keccak256;

    use super::native_token;

    #[test]
    #[cfg_attr(not(feature = "test_contract_bytecode"), ignore)]
    fn native_token() {
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
        let contract = root.join("native_token.sol");
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
            .arg("abi,bin-runtime")
            .output()
            .unwrap();

        eprintln!("{}", std::str::from_utf8(&output.stderr).unwrap());
        let combined_json: Value = serde_json::from_slice(&output.stdout).unwrap();

        let bin = combined_json["contracts"]["native_token.sol:NativeToken"]["bin-runtime"]
            .as_str()
            .unwrap();
        let code = hex::decode(bin).unwrap();

        assert_eq!(native_token::CODE.as_slice(), code);
    }
}
