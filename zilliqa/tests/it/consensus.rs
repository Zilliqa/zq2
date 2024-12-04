use alloy::eips::BlockId;
use ethers::{
    providers::Middleware,
    types::{TransactionRequest, U64},
};
use primitive_types::{H160, H256};
use tracing::*;
use zilliqa::{crypto::Hash, state::contract_addr};

use crate::Network;

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
                n.get_node(index).get_finalized_height().unwrap() >= start_block
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
                n.get_node(index).get_finalized_height().unwrap() >= finish_block
            },
            1000,
        )
        .await
        .expect("Failed to progress to target block");
}

fn get_block_number(n: &mut Network) -> u64 {
    let index = n.random_index();
    n.get_node(index).get_finalized_height().unwrap()
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
                n.get_node(index).get_finalized_height().unwrap() >= start_block
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
            100,
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
                n.get_node(index).get_finalized_height().unwrap() >= start_block
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
    let total_staked: u128 = genesis_deposits[0].stake.0 * 4;

    // Zero account balance plus genesis account plus initial stakes plus deposit contract should equal total_native_token_supply
    let zero_account_balance: u128 = wallet
        .get_balance(H160::zero(), None)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    let deposit_contract_balance: u128 = wallet
        .get_balance(H160::from_slice(&contract_addr::DEPOSIT_PROXY.0 .0), None)
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
        zero_account_balance + total_staked + genesis_account_balance + deposit_contract_balance
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
