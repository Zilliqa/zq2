use crate::CombinedJson;
use ethabi::Token;
use ethers::prelude::Contract;
use std::sync::Arc;

use zilliqa::state::Address;

use crate::Network;

use ethers::{
    providers::Middleware,
    types::{transaction::eip2718::TypedTransaction, TransactionRequest},
    utils::keccak256,
};

use primitive_types::H256;

#[zilliqa_macros::test]
async fn block_production(mut network: Network<'_>) {
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.view())
                    >= 5
            },
            50,
        )
        .await
        .unwrap();
}

#[zilliqa_macros::test]
async fn launch_shard(mut network: Network<'_>) {
    let wallet = network.random_wallet();

    let abi = include_str!("../../src/contracts/shard_registry.json");
    let abi = serde_json::from_str::<CombinedJson>(abi)
        .unwrap()
        .contracts
        .remove("shard_registry.sol:ShardRegistry")
        .unwrap()
        .abi;

    // TODO: deploy shard contract!

    let function = abi.function("addShard").unwrap();
    let tx_request = TransactionRequest::new()
        .to(Address::SHARD_CONTRACT.0)
        .data(
            function
                .encode_input(&[Token::Uint(10000), Token::Address(Address::ZERO)])
                .unwrap(),
        );

    let tx = wallet.send_transaction(tx_request, None).await.unwrap();

    network
        .run_until_async(
            || async {
                wallet
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();

    let receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();

    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.view())
                    >= 5
            },
            50,
        )
        .await
        .unwrap();
}
