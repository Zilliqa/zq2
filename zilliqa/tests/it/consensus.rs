use ethabi::Token;
use ethers::{
    prelude::DeploymentTxFactory,
    providers::Middleware,
    types::{BlockNumber, TransactionRequest},
};
use primitive_types::H160;
use tracing::*;
use zilliqa::{contracts, state::contract_addr};

use crate::{compile_contract, Network, Wallet};

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
            100,
        )
        .await
        .unwrap();
}

/// Helper function that sets up one child shard on the provided Network.
/// Returns: a wallet connected to the new shard.
async fn create_shard(network: &mut Network, wallet: &Wallet, child_shard_id: u64) -> Wallet {
    // * Sanity check - make sure main network is running
    network.run_until_block(wallet, 1.into(), 50).await;

    // * Construct and launch a shard network
    let child_shard_nodes = 4;
    let mut shard_network = Network::new_shard(
        network.rng.clone(),
        child_shard_nodes,
        false,
        child_shard_id,
        network.seed,
        None,
    );
    let shard_wallet = shard_network.genesis_wallet().await;

    let shard_node_keys: Vec<_> = shard_network
        .nodes
        .iter()
        .map(|node| node.secret_key)
        .collect();

    network.children.insert(child_shard_id, shard_network);

    // * Run a block or so to stabilise past genesis
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

    // * Add all new nodes to the parent network too -- all nodes must run main shard nodes
    for key in shard_node_keys {
        network.add_node_with_key(true, key);
    }
    network.run_until_block(wallet, 3.into(), 100).await;

    // * Fetch shard's genesis hash
    let shard_genesis = shard_wallet
        .get_block(0)
        .await
        .unwrap()
        .unwrap()
        .hash
        .unwrap();

    // * Deploy shard contract for the shard on the main network
    let deploy_shard_tx = TransactionRequest::new().data(
        contracts::shard::CONSTRUCTOR
            .encode_input(
                contracts::shard::BYTECODE.to_vec(),
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

    let deploy_shard_receipt = network.run_until_receipt(wallet, hash, 100).await;
    let shard_contract_address = deploy_shard_receipt.contract_address.unwrap();

    // * Register the shard in the shard registry on the main shard
    let tx_request = TransactionRequest::new()
        .to(contract_addr::SHARD_REGISTRY)
        .data(
            contracts::shard_registry::ADD_SHARD
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
    network.run_until_receipt(wallet, hash, 100).await;

    let included_block = wallet.get_block_number().await.unwrap();

    // * Finalize the block on the main shard and check each main shard node has
    // spawned a child shard node in response
    network
        .run_until_block(wallet, included_block + 2, 200)
        .await;

    network
        .run_until(
            |n| {
                n.children.get(&child_shard_id).unwrap().nodes.len()
                    == n.nodes.len() + child_shard_nodes
            },
            200,
        )
        .await
        .unwrap();

    // finally we return the child wallet for subsequent tests to use in
    // interacting with the new shard
    shard_wallet
}

#[zilliqa_macros::test]
async fn launch_shard(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let child_shard_id = 80000u64;
    let shard_wallet = create_shard(&mut network, &wallet, child_shard_id).await;

    // Check shard is still producing blocks
    let check_child_block = shard_wallet.get_block_number().await.unwrap();
    network
        .children
        .get_mut(&child_shard_id)
        .unwrap()
        .run_until_block(&shard_wallet, check_child_block + 2, 200)
        .await;
}

#[zilliqa_macros::test]
async fn cross_shard_contract_creation(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // 1. Create shard
    let child_shard_id = 80000u64;
    let shard_wallet = create_shard(&mut network, &wallet, child_shard_id).await;
    let shard_wallet_key = network
        .children
        .get(&child_shard_id)
        .unwrap()
        .genesis_key
        .clone();

    // 2. Fund the child_shard_wallet (on the main shard) so we can send a cross-shard
    // transaction from it. This is so we have funds on the child shard (since the child
    // wallet has genesis funds there). An equivalent alternative would have been to fund
    // the main shard wallet's address on the child shard and send the xshard tx from it.
    let xfer_hash = wallet
        .send_transaction(
            TransactionRequest::pay(shard_wallet.address(), 1_000_000_000_000_000_000_000u128),
            None,
        )
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, xfer_hash, 100).await;

    // 3. Send the cross-shard transaction
    let (abi, bytecode) = compile_contract("tests/it/contracts/CallMe.sol", "CallMe");
    let deployer = DeploymentTxFactory::new(abi, bytecode, wallet.clone())
        .deploy(())
        .unwrap();
    let inner_data = deployer.tx.data().unwrap().clone().to_vec();

    let gas_price = wallet.get_gas_price().await.unwrap();

    let data = contracts::intershard_bridge::BRIDGE
        .encode_input(&[
            Token::Uint(child_shard_id.into()),
            Token::Bool(true),
            Token::Address(H160::zero()),
            Token::Bytes(inner_data),
            Token::Uint(1_000_000u64.into()),
            Token::Uint(gas_price),
        ])
        .unwrap();
    let tx_request = TransactionRequest::new()
        .to(contract_addr::INTERSHARD_BRIDGE)
        .data(data);

    // Send it from the shard wallet's address
    let shard_wallet_connected_to_main = network.wallet_from_key(shard_wallet_key).await;
    let hash = shard_wallet_connected_to_main
        .send_transaction(tx_request, None)
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, hash, 100).await;

    // 4. Finalize that block on the main shard, so that the x-shard message gets sent
    network
        .run_until_block(&wallet, receipt.block_number.unwrap() + 3, 50)
        .await;

    // 5. Make sure the transaction gets included in the child network
    network
        .children
        .get_mut(&child_shard_id)
        .unwrap()
        .run_until_async(
            || async {
                let latest_block = shard_wallet
                    .get_block(BlockNumber::Latest)
                    .await
                    .unwrap()
                    .unwrap();
                for tx in latest_block.transactions {
                    let receipt = shard_wallet
                        .get_transaction_receipt(tx)
                        .await
                        .unwrap()
                        .unwrap();
                    if receipt.from == shard_wallet.address() && receipt.contract_address.is_some()
                    {
                        return true;
                    }
                }
                false
            },
            500,
        )
        .await
        .unwrap();
}

// test that when a fork occurs in the network, the node which has forked correctly reverts its state
// and progresses.
#[zilliqa_macros::test]
async fn handle_forking_correctly(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let _provider = wallet.provider();

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

    // Send a single TX to the network
    let hash = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    network.drop_propose_messages_except_one().await;

    // Check that node 0 has executed the transaction while the others haven't
    let first = network
        .get_node(0)
        .get_transaction_receipt(hash.into())
        .unwrap();
    let second = network
        .get_node(1)
        .get_transaction_receipt(hash.into())
        .unwrap();

    // Only the first node should have executed the transaction
    assert!(first.is_some());
    assert!(second.is_none());

    let original_receipt = first.unwrap();

    trace!("Running until the network has reverted the block");
    // Now we should be able to run the network until we get a different tx receipt from the first
    // node, which indicates that it has reverted the block
    network
        .run_until(
            |n| {
                let receipt = n.get_node(0).get_transaction_receipt(hash.into());
                match receipt {
                    Ok(Some(receipt)) => receipt.block_hash != original_receipt.block_hash,
                    _ => false,
                }
            },
            1000,
        )
        .await
        .unwrap();
}
