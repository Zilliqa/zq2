use crate::{test_predicates, CombinedJson, Context};
use ethabi::Token;

use zilliqa::state::Address;

use crate::Network;

use ethers::types::U64;
use ethers::{providers::Middleware, types::TransactionRequest};

#[zilliqa_macros::test]
async fn block_production(mut network: Network) {
    test_predicates::produced_blocks!(5);
    network
        .run_until_async(produced_blocks, Context::index(network.random_index()), 50)
        .await
        .unwrap();

    let index = network.add_node(false).await;

    test_predicates::produced_blocks!(10, new_node);
    network
        .run_until_async(produced_blocks_new_node, Context::index(index), 500)
        .await
        .unwrap();
    println!("Second block run completed");
}

#[zilliqa_macros::test]
async fn launch_shard(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    network
        .run_until_async(
            test_predicates::wallet_block_above,
            Context::wallet_and_block(wallet.clone(), U64([1])),
            50,
        )
        .await
        .unwrap();

    let abi = include_str!("../../src/contracts/shard_registry.json");
    let abi = serde_json::from_str::<CombinedJson>(abi)
        .unwrap()
        .contracts
        .remove("shard_registry.sol:ShardRegistry")
        .unwrap()
        .abi;

    let shard_id = 80000u64;

    let function = abi.function("addShard").unwrap();
    let tx_request = TransactionRequest::new()
        .to(Address::SHARD_CONTRACT.0)
        .data(
            function
                .encode_input(&[Token::Uint(shard_id.into())])
                .unwrap(),
        );

    // sanity check
    assert_eq!(network.children.len(), 0);

    let tx = wallet.send_transaction(tx_request, None).await.unwrap();
    let hash = tx.tx_hash();

    network
        .run_until_async(
            test_predicates::got_tx_receipt,
            Context::wallet_and_hash(wallet.clone(), hash),
            50,
        )
        .await
        .unwrap();

    let finalized_block = wallet.get_block_number().await.unwrap() + 2;

    // finalize block
    network
        .run_until_async(
            test_predicates::wallet_block_above,
            Context::wallet_and_block(wallet.clone(), finalized_block),
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

    test_predicates::produced_blocks!(5);
    // check shard is producing blocks
    let child = network.children.get_mut(&shard_id).unwrap();
    child
        .run_until_async(produced_blocks, Context::index(child.random_index()), 50)
        .await
        .unwrap();
}
