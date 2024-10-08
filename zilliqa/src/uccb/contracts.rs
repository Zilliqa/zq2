use alloy::json_abi::JsonAbi;

pub mod validator_manager {
    use alloy::{
        contract::{ContractInstance, Interface},
        primitives::Address,
    };
    use once_cell::sync::Lazy;

    use super::{read_contract_abi, JsonAbi};

    pub const ABI: Lazy<JsonAbi> = Lazy::new(|| {
        read_contract_abi(
            "../uccb/contracts/src/core/ValidatorManager.sol",
            "ValidatorManager",
        )
    });
    pub const INTERFACE: Lazy<Interface> = Lazy::new(|| Interface::new(ABI.clone()));

    pub fn instance<T, P, N>(address: Address, provider: P) -> ContractInstance<T, P, N> {
        ContractInstance::<T, P, N>::new(address, provider, INTERFACE.clone())
    }
}

pub mod chain_gateway {
    use alloy::{
        contract::{ContractInstance, Interface},
        primitives::Address,
    };
    use once_cell::sync::Lazy;

    use super::{read_contract_abi, JsonAbi};

    pub const ABI: Lazy<JsonAbi> = Lazy::new(|| {
        read_contract_abi(
            "../uccb/contracts/src/core/ChainGateway.sol",
            "ChainGateway",
        )
    });
    pub const INTERFACE: Lazy<Interface> = Lazy::new(|| Interface::new(ABI.clone()));

    pub fn instance<T, P, N>(address: Address, provider: P) -> ContractInstance<T, P, N> {
        ContractInstance::<T, P, N>::new(address, provider, INTERFACE.clone())
    }
}

const COMPILED: &str = include_str!("../../../uccb/contracts/compiled.json");

fn read_contract_abi(src: &str, name: &str) -> JsonAbi {
    let compiled = serde_json::from_str::<serde_json::Value>(COMPILED).unwrap();
    let contract = &compiled["contracts"][src][name];
    let abi = serde_json::from_value(contract["abi"].clone()).unwrap();

    serde_json::from_value(abi).unwrap()
}
