use crate::CombinedJson;
use ethabi::Token;

use zilliqa::state::Address;

use crate::Network;

use ethers::{providers::Middleware, types::TransactionRequest};

#[zilliqa_macros::test]
async fn block_production(mut network: Network) {
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

    let index = network.add_node(false);

    network
        .run_until(
            |n| {
                n.node_at(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.view())
                    >= 10
            },
            500,
        )
        .await
        .unwrap();
    println!("Second block run completed");
}

#[zilliqa_macros::test]
async fn launch_shard(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    network
        .run_until_async(
            || async { wallet.get_block_number().await.unwrap().as_u64() >= 1 },
            50,
        )
        .await
        .unwrap();

    let shard_id = 80000u64;

    let shard_contract = include_str!("../../src/contracts/shard.json");
    let shard_contract = serde_json::from_str::<CombinedJson>(shard_contract)
        .unwrap()
        .contracts
        .remove("shard.sol:Shard")
        .unwrap();

    let shard_constructor = shard_contract.abi.constructor().unwrap();
    let deploy_shard_tx = TransactionRequest::new().data(
        shard_constructor
            .encode_input(
                hex::decode(shard_contract.bin).unwrap(),
                &[
                    Token::Uint((700 + 0x8000).into()),
                    Token::Uint(5000.into()),
                    Token::FixedBytes(vec![0x0]),
                ],
            )
            .unwrap(),
    );

    let tx = wallet
        .send_transaction(deploy_shard_tx, None)
        .await
        .unwrap();
    let hash = tx.tx_hash();

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

    let deploy_shard_receipt = wallet.get_transaction_receipt(hash).await.unwrap().unwrap();
    let shard_contract_address = deploy_shard_receipt.contract_address.unwrap();

    let registry_abi = include_str!("../../src/contracts/shard_registry.json");
    let registry_abi = serde_json::from_str::<CombinedJson>(registry_abi)
        .unwrap()
        .contracts
        .remove("shard_registry.sol:ShardRegistry")
        .unwrap()
        .abi;

    let function = registry_abi.function("addShard").unwrap();
    let tx_request = TransactionRequest::new()
        .to(Address::SHARD_CONTRACT.0)
        .data(
            function
                .encode_input(&[
                    Token::Uint(shard_id.into()),
                    Token::Address(shard_contract_address),
                ])
                .unwrap(),
        );

    // sanity check
    assert_eq!(network.children.len(), 0);

    let tx = wallet.send_transaction(tx_request, None).await.unwrap();
    let hash = tx.tx_hash();

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

    let included_block = wallet.get_block_number().await.unwrap();

    // finalize block
    network
        .run_until_async(
            || async { wallet.get_block_number().await.unwrap() >= included_block + 2 },
            50,
        )
        .await
        .unwrap();

    // check we've spawned a shard
    network
        .run_until(|n| n.children.contains_key(&shard_id), 50)
        .await
        .unwrap();

    // check every node has spawned a shard node
    network
        .run_until(
            |n| n.children.get(&shard_id).unwrap().nodes.len() == n.nodes.len(),
            50,
        )
        .await
        .unwrap();

    // check shard is producing blocks
    network
        .children
        .get_mut(&shard_id)
        .unwrap()
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
