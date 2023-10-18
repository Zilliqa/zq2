use crate::CombinedJson;
use ethabi::Token;

use zilliqa::state::Address;

use crate::Network;

use ethers::{
    providers::Middleware,
    types::{BlockNumber, TransactionRequest},
};

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

    // 0. Sanity check - make sure main network is running
    network
        .run_until_async(
            || async { wallet.get_block_number().await.unwrap().as_u64() >= 1 },
            50,
        )
        .await
        .unwrap();

    let child_shard_id = 80000u64;
    // This is necessary to maintain a supermajority once the main shard nodes join.
    // The size can be reduced once nodes stop joining the committee before they're
    // fully caught up.
    let child_shard_nodes = 10;

    // 1. Construct and launch a shard network
    let mut shard_network = Network::new_shard(
        network.rng.clone(),
        child_shard_nodes,
        false,
        child_shard_id,
        network.seed,
    );
    let shard_wallet = shard_network.genesis_wallet().await;

    network.children.insert(child_shard_id, shard_network);
    network
        .children
        .get_mut(&child_shard_id)
        .unwrap()
        .run_until_async(
            || async { shard_wallet.get_block_number().await.unwrap().as_u64() >= 1 },
            50,
        )
        .await
        .unwrap();

    // 2. Fetch shard's genesis hash
    let shard_genesis = shard_wallet
        .get_block(0)
        .await
        .unwrap()
        .unwrap()
        .hash
        .unwrap();

    // 3. Deploy shard contract for the shard on the main network
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
                    Token::FixedBytes(shard_genesis.0.to_vec()),
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

    // 4. Register the shard in the shard registry on the main shard
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
                    Token::Uint(child_shard_id.into()),
                    Token::Address(shard_contract_address),
                ])
                .unwrap(),
        );

    // sanity check - child shard exists and only has the nodes we manually spawned in it earlier
    assert_eq!(network.children.len(), 1);
    assert!(network.children.contains_key(&child_shard_id));
    assert_eq!(
        network.children.get(&child_shard_id).unwrap().nodes.len(),
        child_shard_nodes
    );

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

    // 5. Finalize the block on the main shard and check each main shard node has
    // spawned a child shard node in response
    network
        .run_until_async(
            || async { wallet.get_block_number().await.unwrap() >= included_block + 2 },
            50,
        )
        .await
        .unwrap();

    network
        .run_until(
            |n| {
                n.children.get(&child_shard_id).unwrap().nodes.len()
                    == n.nodes.len() + child_shard_nodes
            },
            50,
        )
        .await
        .unwrap();

    // 6. Check shard is still producing blocks
    let check_child_block = shard_wallet
        .get_block(BlockNumber::Latest)
        .await
        .unwrap()
        .unwrap()
        .number
        .unwrap();

    network
        .children
        .get_mut(&child_shard_id)
        .unwrap()
        .run_until_async(
            || async {
                shard_wallet
                    .get_block(BlockNumber::Latest)
                    .await
                    .unwrap()
                    .unwrap()
                    .number
                    .unwrap()
                    >= check_child_block + 5
            },
            500,
        )
        .await
        .unwrap();
}
