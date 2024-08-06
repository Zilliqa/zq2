use alloy::json_abi::JsonAbi;

pub mod validator_manager {
    use super::{read_contract_abi, JsonAbi};
    use alloy::{
        contract::{ContractInstance, Interface},
        primitives::Address,
    };

    use once_cell::sync::Lazy;

    pub const ABI: Lazy<JsonAbi> = Lazy::new(|| {
        read_contract_abi(include_str![
            "../../../uccb/contracts/out/ValidatorManager.sol/ValidatorManager.json"
        ])
    });
    pub const INTERFACE: Lazy<Interface> = Lazy::new(|| Interface::new(ABI.clone()));

    pub fn instance<T, P, N>(address: Address, provider: P) -> ContractInstance<T, P, N> {
        ContractInstance::<T, P, N>::new(address, provider, INTERFACE.clone())
    }
}

fn read_contract_abi(json_abi: &str) -> JsonAbi {
    let value = serde_json::from_str::<serde_json::Value>(json_abi).unwrap();
    serde_json::from_value(value["abi"].clone()).unwrap()
}
