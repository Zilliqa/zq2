use alloy::eips::BlockId;
use ethabi::Token;
use ethers::{
    abi::FunctionExt,
    prelude::DeploymentTxFactory,
    providers::Middleware,
    types::{TransactionRequest, U64},
};
use primitive_types::{H160, H256, U256};
use tokio::sync::Mutex;
use tracing::*;
use zilliqa::{contracts, crypto::Hash, state::contract_addr};

use crate::{
    compile_contract, deploy_contract, deploy_contract_with_args, Network, NewNodeOptions, Wallet,
};

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
            100,
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
            100,
        )
        .await
        .unwrap();

    // now, wait until block 15 has been produced, but dropping 10% of the messages.
    for _ in 0..1000000 {
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

// Test that new node joining the network catches up on blocks
#[zilliqa_macros::test]
async fn block_production(mut network: Network) {
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index)
                    .get_block(BlockId::latest())
                    .unwrap()
                    .map_or(0, |b| b.number())
                    >= 5
            },
            50,
        )
        .await
        .unwrap();

    info!("Adding networked node.");
    let index = network.add_node();

    network
        .run_until(
            |n| {
                n.node_at(index)
                    .get_block(BlockId::latest())
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
async fn create_shard(
    network: &mut Network,
    wallet: &Wallet,
    child_shard_id: u64,
) -> (Wallet, H160) {
    // * Sanity check - make sure main network is running
    network.run_until_block(wallet, 1.into(), 50).await;

    let starting_children = network.children.len();

    // * Construct and launch a shard network
    let child_shard_nodes = 4;
    let mut shard_network = Network::new_shard(
        network.rng.clone(),
        child_shard_nodes,
        Some(network.resend_message.clone()),
        child_shard_id,
        network.seed,
        None,
        network.scilla_address.clone(),
        network.scilla_lib_dir.clone(),
        false,
    );
    let shard_wallet = shard_network.genesis_wallet().await;

    let shard_node_keys: Vec<_> = shard_network
        .nodes
        .iter()
        .map(|node| node.secret_key)
        .collect();

    shard_network
        .run_until_block(&shard_wallet, 3.into(), 50)
        .await;

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
    let initial_main_shard_nodes = network.nodes.len();
    for key in shard_node_keys {
        network.add_node_with_options(NewNodeOptions {
            secret_key: Some(key),
            ..Default::default()
        });
    }

    network.run_until_block(wallet, 10.into(), 200).await;
    assert_eq!(
        network.nodes.len(),
        initial_main_shard_nodes + child_shard_nodes
    ); // sanity check

    // * Fetch shard's genesis hash
    let shard_genesis = shard_wallet
        .get_block(0)
        .await
        .unwrap()
        .unwrap()
        .hash
        .unwrap();

    // * Deploy shard contract for the shard on the main network
    let (deploy_hash, _) = deploy_contract_with_args(
        "tests/it/contracts/LinkableShard.sol",
        "LinkableShard",
        [
            Token::Uint(child_shard_id.into()),
            Token::Uint((700 + 0x8000).into()),
            Token::Uint(5000.into()),
            Token::FixedBytes(shard_genesis.0.to_vec()),
            Token::Address(H160(contract_addr::SHARD_REGISTRY.into_array())),
        ]
        .as_slice(),
        wallet,
        network,
    )
    .await;

    let deploy_shard_receipt = network.run_until_receipt(wallet, deploy_hash, 100).await;
    let shard_contract_address = deploy_shard_receipt.contract_address.unwrap();

    // * Register the shard in the shard registry on the main shard
    let tx_request = TransactionRequest::new()
        .to(H160(contract_addr::SHARD_REGISTRY.into_array()))
        .data(
            contracts::shard_registry::ADD_SHARD
                .encode_input(&[
                    Token::Uint(child_shard_id.into()),
                    Token::Address(shard_contract_address),
                ])
                .unwrap(),
        );

    // sanity check - child shard exists and only has the nodes we manually spawned in it earlier
    assert_eq!(network.children.len(), starting_children + 1);
    assert!(network.children.contains_key(&child_shard_id));
    assert_eq!(
        network.children.get(&child_shard_id).unwrap().nodes.len(),
        child_shard_nodes
    );

    let tx = wallet.send_transaction(tx_request, None).await.unwrap();
    let hash = tx.tx_hash();
    network.run_until_receipt(wallet, hash, 130).await;

    let included_block = wallet.get_block_number().await.unwrap();

    // * Finalize the block on the main shard and check each main shard node has
    // spawned a child shard node in response
    network
        .run_until_block(wallet, included_block + 6, 200)
        .await;

    network
        .run_until(
            |n| {
                n.children.get(&child_shard_id).unwrap().nodes.len()
                    == initial_main_shard_nodes + child_shard_nodes
            },
            200,
        )
        .await
        .unwrap();

    // finally we return the child wallet for subsequent tests to use in
    // interacting with the new shard, as well as the contract's address
    // as a shortcut
    (shard_wallet, shard_contract_address)
}

#[zilliqa_macros::test]
async fn launch_shard(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    let child_shard_id = 80000u64;
    let (shard_wallet, _) = create_shard(&mut network, &wallet, child_shard_id).await;

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
async fn dynamic_cross_shard_link_creation(mut network: Network) {
    let main_wallet = network.genesis_wallet().await;

    let initial_value = 99u64;
    let custom_value = 100_000u64;

    // * Create two independent shards
    let shard_1_id = 80000u64;
    let shard_2_id = 90000u64;

    let (shard_1_wallet, shard_1_contract) =
        create_shard(&mut network, &main_wallet, shard_1_id).await;
    let (shard_2_wallet, _) = create_shard(&mut network, &main_wallet, shard_2_id).await;

    // * Create a (uni-directional) link from shard 1 to shard 2
    // potential TODO: consider caching the compilation of LinkableShard, otherwise this test compiles the
    // contract 3 times (twice in the create_shard calls + once here)
    let linkable_shard = compile_contract("tests/it/contracts/LinkableShard.sol", "LinkableShard");
    let add_link = linkable_shard.0.function("addLink").unwrap();
    let create_link_tx = TransactionRequest::new()
        .to(shard_1_contract)
        .data(
            add_link
                .encode_input(&[Token::Uint(shard_2_id.into())])
                .unwrap(),
        )
        .gas(100_000u64);
    let tx = main_wallet
        .send_transaction(create_link_tx, None)
        .await
        .unwrap();
    let hash = tx.tx_hash();
    let link_receipt = network.run_until_receipt(&main_wallet, hash, 200).await;
    assert!(link_receipt.status.unwrap() == 1.into());
    network
        .run_until_block(&main_wallet, link_receipt.block_number.unwrap() + 6, 300)
        .await; // Finalize
    network.children.get_mut(&shard_2_id).unwrap().tick().await; // handle all the LaunchLink messages
    network.children.get_mut(&shard_2_id).unwrap().tick().await; // ...and forward them back to parent
    network
        .run_until(
            |n| n.children.get(&shard_1_id).unwrap().nodes.len() == 12,
            200,
        )
        .await
        .unwrap();

    // * Send and verify a cross-shard tx from 1 to 2.
    // First, deploy a callable contract on 2
    let (hash, contract) = deploy_contract(
        "tests/it/contracts/SetGetContractValue.sol",
        "SetGetContractValue",
        &shard_2_wallet,
        network.children.get_mut(&shard_2_id).unwrap(),
    )
    .await;
    let contract_address = shard_2_wallet
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap()
        .contract_address
        .unwrap();

    // Then fund the shard 1 wallet on shard 2
    let xfer_hash = shard_2_wallet
        .send_transaction(
            TransactionRequest::pay(shard_1_wallet.address(), 100_000_000_000_000_000_000u128),
            None,
        )
        .await
        .unwrap()
        .tx_hash();
    network
        .children
        .get_mut(&shard_2_id)
        .unwrap()
        .run_until_receipt(&shard_2_wallet, xfer_hash, 200)
        .await;

    // Then send the actual cross-shard tx (from shard 1)
    let setter = contract.function("setUint256").unwrap();
    let inner_data = setter
        .encode_input(&[Token::Uint((custom_value).into())])
        .unwrap();

    let gas_price = shard_2_wallet.get_gas_price().await.unwrap();

    let data = contracts::intershard_bridge::BRIDGE
        .encode_input(&[
            Token::Uint(shard_2_id.into()),
            Token::Bool(false),
            Token::Address(contract_address),
            Token::Bytes(inner_data),
            Token::Uint(1_000_000u64.into()),
            Token::Uint(gas_price),
        ])
        .unwrap();
    let tx_request = TransactionRequest::new()
        .to(H160(contract_addr::INTERSHARD_BRIDGE.into_array()))
        .data(data);

    // Send it from the shard wallet's address
    let hash = shard_1_wallet
        .send_transaction(tx_request, None)
        .await
        .unwrap()
        .tx_hash();
    let receipt = network
        .children
        .get_mut(&shard_1_id)
        .unwrap()
        .run_until_receipt(&shard_1_wallet, hash, 200)
        .await;

    // Finalize the block on shard 1
    network
        .children
        .get_mut(&shard_1_id)
        .unwrap()
        .run_until_block(&shard_1_wallet, receipt.block_number.unwrap() + 6, 300)
        .await;

    let getter = contract.function("getUint256").unwrap();
    let get_call = TransactionRequest::new()
        .to(contract_address)
        .data(getter.selector());

    assert_eq!(
        U256::from_big_endian(
            shard_2_wallet
                .call(&get_call.clone().into(), None)
                .await
                .unwrap()
                .to_vec()
                .as_slice()
        ),
        U256::from(initial_value)
    );

    network.tick().await; // Forward all the messages between the shards

    // Now ensure it's been received on shard 2
    network
        .children
        .get_mut(&shard_2_id)
        .unwrap()
        .run_until_async(
            || async {
                U256::from_big_endian(
                    shard_2_wallet
                        .call(&get_call.clone().into(), None)
                        .await
                        .unwrap()
                        .to_vec()
                        .as_slice(),
                ) == U256::from(custom_value)
            },
            200,
        )
        .await
        .unwrap();
}

#[zilliqa_macros::test]
async fn cross_shard_contract_creation(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // 1. Create shard
    let child_shard_id = 80000u64;
    let (shard_wallet, _) = create_shard(&mut network, &wallet, child_shard_id).await;
    let shard_wallet_key = network
        .children
        .get(&child_shard_id)
        .unwrap()
        .genesis_key
        .clone();

    // stabilize shard
    network
        .children
        .get_mut(&child_shard_id)
        .unwrap()
        .run_until_block(&shard_wallet, 10.into(), 300)
        .await;

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
    network.run_until_receipt(&wallet, xfer_hash, 200).await;

    // 3. Send the cross-shard transaction
    let (abi, bytecode) = compile_contract("tests/it/contracts/CallMe.sol", "CallMe");
    let deployer = DeploymentTxFactory::new(abi, bytecode, wallet.clone())
        .deploy(())
        .unwrap();
    let inner_data = deployer.tx.data().unwrap().clone().to_vec();

    let gas_price = shard_wallet.get_gas_price().await.unwrap();

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
        .to(H160(contract_addr::INTERSHARD_BRIDGE.into_array()))
        .data(data);

    // Send it from the shard wallet's address
    let shard_wallet_connected_to_main = network.wallet_from_key(shard_wallet_key).await;
    let hash = shard_wallet_connected_to_main
        .send_transaction(tx_request, None)
        .await
        .unwrap()
        .tx_hash();
    let receipt = network.run_until_receipt(&wallet, hash, 200).await;

    // 4. Finalize that block on the main shard, so that the x-shard message gets sent
    network
        .run_until_block(&wallet, receipt.block_number.unwrap() + 6, 80)
        .await;

    // 5. Make sure the transaction gets included in the child network
    let latest_block = Mutex::new(shard_wallet.get_block_number().await.unwrap());
    network
        .children
        .get_mut(&child_shard_id)
        .unwrap()
        .run_until_async(
            || async {
                let mut latest_block = latest_block.lock().await;
                let next_block = *latest_block + 1;
                let Some(check_block) = shard_wallet.get_block(next_block).await.unwrap() else {
                    return false;
                };
                *latest_block = next_block;
                for tx in check_block.transactions {
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
            600,
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
            100,
        )
        .await
        .unwrap();

    // Send a single TX to the network
    let hash: H256 = wallet
        .send_transaction(TransactionRequest::pay(H160::random(), 10), None)
        .await
        .unwrap()
        .tx_hash();

    network.drop_propose_messages_except_one().await;

    // Check that node 0 has executed the transaction while the others haven't
    let first = network
        .get_node(0)
        .get_transaction_receipt(Hash(hash.0))
        .unwrap();
    let second = network
        .get_node(1)
        .get_transaction_receipt(Hash(hash.0))
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
                let receipt = n.get_node(0).get_transaction_receipt(Hash(hash.0));
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

// Test that zero account has correct initial funds, is the source of rewards and is the sink of gas
#[zilliqa_macros::test]
async fn zero_account_per_block_balance_updates(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    // Check inital account values
    let block_height = wallet.get_block_number().await.unwrap();
    assert_eq!(block_height, U64::from(0));

    // Amount assigned to genesis account
    let genesis_account_expected_balance = network
        .get_node(0)
        .config
        .consensus
        .genesis_accounts
        .clone()[0]
        .1
         .0;
    let genesis_account_balance: u128 = wallet
        .get_balance(wallet.address(), None)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(genesis_account_expected_balance, genesis_account_balance);

    // Total intial stake spread across 4 validators
    let genesis_deposits = network
        .get_node(0)
        .config
        .consensus
        .genesis_deposits
        .clone();
    let total_staked: u128 = genesis_deposits[0].2 .0 * 4;

    // Zero account balance plus genesis account plus initial stakes should equal total_native_token_supply
    let zero_account_balance: u128 = wallet
        .get_balance(H160::zero(), None)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    let total_native_token_supply = network
        .get_node(0)
        .config
        .consensus
        .total_native_token_supply
        .0;
    assert_eq!(
        total_native_token_supply,
        zero_account_balance + total_staked + genesis_account_balance
    );

    // Mine first block
    network.run_until_block(&wallet, 1.into(), 50).await;

    let block = wallet.get_block(1).await.unwrap().unwrap();
    assert_eq!(block.transactions.len(), 0);

    // Check proposer was rewarded
    let miner: H160 = block.author.unwrap();
    let miner_balance_before = wallet
        .get_balance(miner, Some((block.number.unwrap() - 1).into()))
        .await
        .unwrap();
    let miner_balance_after = wallet
        .get_balance(miner, Some(block.number.unwrap().into()))
        .await
        .unwrap();
    assert!(miner_balance_before < miner_balance_after);

    // Check reward came from zero account balance
    let zero_account = H160::zero();
    let zero_account_balance_before = wallet
        .get_balance(zero_account, Some((block.number.unwrap() - 1).into()))
        .await
        .unwrap();
    let zero_account_balance_after = wallet
        .get_balance(zero_account, Some(block.number.unwrap().into()))
        .await
        .unwrap();
    assert!(zero_account_balance_before > zero_account_balance_after);
    let zero_acount_balance_change_rewards_only =
        zero_account_balance_before - zero_account_balance_after;

    // Check gas is sunk to zero account
    let hash = wallet
        .send_transaction(TransactionRequest::pay(wallet.address(), 10), None)
        .await
        .unwrap()
        .tx_hash();
    network.run_until_receipt(&wallet, hash, 200).await;

    let receipt = provider
        .get_transaction_receipt(hash)
        .await
        .unwrap()
        .unwrap();
    let block = wallet
        .get_block(receipt.block_number.unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(block.transactions.len(), 1);

    let zero_account_balance_before = wallet
        .get_balance(zero_account, Some((block.number.unwrap() - 1).into()))
        .await
        .unwrap();
    let zero_account_balance_after = wallet
        .get_balance(zero_account, Some(block.number.unwrap().into()))
        .await
        .unwrap();
    let zero_acount_balance_change_with_gas_spent =
        zero_account_balance_before - zero_account_balance_after;

    assert_eq!(
        zero_acount_balance_change_with_gas_spent + block.gas_used,
        zero_acount_balance_change_rewards_only
    );
}
