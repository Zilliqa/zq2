use ethers::prelude::Contract;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use zilliqa::state::Address;

use crate::Network;

#[derive(Deserialize)]
struct CombinedJson {
    contracts: HashMap<String, ContractAa>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ContractAa {
    abi: ethabi::Contract,
}

#[zilliqa_macros::test]
async fn native_token(mut network: Network<'_>) {
    let wallet = network.random_wallet();

    let abi = include_str!("../../src/contracts/native_token.json");
    let abi = serde_json::from_str::<CombinedJson>(abi)
        .unwrap()
        .contracts
        .remove("native_token.sol:NativeToken")
        .unwrap()
        .abi;

    let contract = Contract::new(Address::NATIVE_TOKEN.0, abi.clone(), Arc::new(wallet));

    let name = contract
        .method::<_, String>("name", ())
        .unwrap()
        .call()
        .await
        .unwrap();
    let symbol = contract
        .method::<_, String>("symbol", ())
        .unwrap()
        .call()
        .await
        .unwrap();
    println!("{:?}", name);
    println!("{:?}", symbol);
}
