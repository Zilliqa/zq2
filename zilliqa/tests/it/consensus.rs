use crate::CombinedJson;
use crate::Network;
use ethabi::Token;
use ethers::{providers::Middleware, types::TransactionRequest};
use primitive_types::H160;
use tracing::*;
use zilliqa::state::Address;

// Test that all nodes can die and the network can restart (even if they startup at different
// times)
#[zilliqa_macros::test]
async fn network_can_die_restart(mut network: Network) {
    let start_block = 5;
    let finish_block = 10;

    // wait until at least 5 blocks have been produced
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index).get_finalized_height() >= start_block
            },
            50,
        )
        .await
        .unwrap();

    // Forcibly restart the network, with a random time delay between each node
    network.restart();

    // Panic if it can't progress to the target block
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index).get_finalized_height() >= finish_block
            },
            1000,
        )
        .await
        .expect("Failed to progress to target block");
}

fn get_block_number(n: &mut Network) -> u64 {
    let index = n.random_index();
    n.get_node(index).get_finalized_height()
}

// test that even with some consensus messages being dropped, the network can still proceed
// note: this drops all messages, not just consensus messages, but there should only be
// consensus messages in the network anyway
#[zilliqa_macros::test]
async fn block_production_even_when_lossy_network(mut network: Network) {
    let failure_rate = 0.1;
    let start_block = 5;
    let finish_block = 8;

    // wait until at least 5 blocks have been produced
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index).get_finalized_height() >= start_block
            },
            50,
        )
        .await
        .unwrap();

    // now, wait until block 15 has been produced, but dropping 10% of the messages.
    for _ in 0..1000 {
        network.randomly_drop_messages_then_tick(failure_rate).await;
        if get_block_number(&mut network) >= finish_block {
            break;
        }
    }

    assert!(
        get_block_number(&mut network) >= finish_block,
        "block number should be at least {}, but was {}",
        finish_block,
        get_block_number(&mut network)
    );
}

#[zilliqa_macros::test]
async fn block_production(mut network: Network) {
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.number())
                    >= 5
            },
            50,
        )
        .await
        .unwrap();

    info!("Adding networked node.");
    let index = network.add_node(true);

    network
        .run_until(
            |n| {
                n.node_at(index)
                    .get_latest_block()
                    .unwrap()
                    .map_or(0, |b| b.number())
                    >= 10
            },
            50000,
        )
        .await
        .unwrap();
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
                    .map_or(0, |b| b.number())
                    >= 5
            },
            50,
        )
        .await
        .unwrap();
}

// test that when a fork occurs in the network, the node which has forked correctly reverts its state
// and progresses.
#[zilliqa_macros::test]
async fn handle_forking_correctly(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    let start_block = 5;

    // wait until at least 5 blocks have been produced
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index).get_finalized_height() >= start_block
            },
            50,
        )
        .await
        .unwrap();

    // Now, we submit a transaction to the network, which will be included in the next block.
    // The next tick we do will drop the propose message going to all but node 0, after which we
    // should find find that node 0 executes the tx and the other nodes do not.
    // following this, the network should correct so that node 0 is forced to revert that block
    // and the TX will get included in the next block.
    let hash = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    //network.randomly_drop_messages_then_tick(failure_rate).await;
    network.drop_propose_messages_except_one().await;

    // Check that node 0 has executed the transaction while the others haven't

    //for _ in 0..1000 {
    //    if get_block_number(&mut network) >= finish_block {
    //        break;
    //    }
    //}

    network
        .run_until_async(
            || async {
                provider
                    .get_transaction_receipt(hash)
                    .await
                    .unwrap()
                    .is_some()
            },
            50,
        )
        .await
        .unwrap();
}
