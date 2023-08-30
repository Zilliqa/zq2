use crate::CombinedJson;
use ethers::prelude::Contract;
use std::sync::Arc;

use zilliqa::state::Address;

use crate::Network;

#[zilliqa_macros::test]
async fn native_token(mut network: Network) {
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
    assert_eq!(name, "Zilliqa Native Token");
    let symbol = contract
        .method::<_, String>("symbol", ())
        .unwrap()
        .call()
        .await
        .unwrap();
    assert_eq!(symbol, "ZIL");
}
