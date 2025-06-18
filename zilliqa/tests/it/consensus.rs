use alloy::eips::BlockId;
use ethers::{
    providers::Middleware,
    types::{TransactionRequest, U64},
};
use primitive_types::{H160, H256, U256};
use tracing::*;
use zilliqa::{crypto::Hash, state::contract_addr};

use crate::{Network, get_reward_address, get_stakers};

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

fn get_block_number(n: &Network, index: usize) -> u64 {
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

    let index = network.random_index();

    // wait until at least 5 blocks have been produced
    network
        .run_until(
            |n| n.get_node(index).get_finalized_height().unwrap() >= start_block,
            100,
        )
        .await
        .unwrap();

    // now, wait until block 15 has been produced, but dropping 10% of the messages.
    for _ in 0..1000000 {
        network.randomly_drop_messages_then_tick(failure_rate).await;
        if get_block_number(&network, index) >= finish_block {
            break;
        }
    }

    assert!(
        get_block_number(&network, index) >= finish_block,
        "block number should be at least {}, but was {}",
        finish_block,
        get_block_number(&network, index)
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

    let init_nonce = wallet
        .get_transaction_count(wallet.address(), None)
        .await
        .unwrap();

    let gap_nonce = init_nonce + 3;
    let gap_txn_count = 10;
    for num in 0..gap_txn_count {
        wallet
            .send_transaction(
                TransactionRequest::pay(H160::random(), 0).nonce(gap_nonce + num),
                None,
            )
            .await
            .unwrap()
            .tx_hash();
    }

    let next_block_threshold = 7;

    // wait until another blocks have been produced
    network
        .run_until(
            |n| {
                let index = n.random_index();
                n.get_node(index).get_finalized_height().unwrap() >= next_block_threshold
            },
            100,
        )
        .await
        .unwrap();

    fn verify_queued(network: &Network, expected_count: usize, index: usize) {
        let queued_count: usize = {
            let node = network.get_node(index);
            let pool = node.consensus.transaction_pool.read();
            pool.preview_content()
                .queued
                .values()
                .map(|x| x.len())
                .sum()
        };
        assert_eq!(queued_count, expected_count);
    }

    // Ensure txns are queued on both nodes
    verify_queued(&network, gap_txn_count, 0);
    verify_queued(&network, gap_txn_count, 1);

    // Send a single TX to the network that triggers txns inclusion
    let hash: H256 = wallet
        .send_transaction(
            TransactionRequest::pay(H160::random(), 10).nonce(init_nonce),
            None,
        )
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
    network.run_until_synced(0).await;
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

    // Verify txns are still queued on both nodes
    verify_queued(&network, gap_txn_count, 0);
    verify_queued(&network, gap_txn_count, 1);
}

// Test that zero account has correct initial funds, is the source of rewards and is the sink of gas
#[zilliqa_macros::test]
async fn zero_account_per_block_balance_updates(mut network: Network) {
    let wallet = network.genesis_wallet().await;

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
        .get_balance(H160(contract_addr::DEPOSIT_PROXY.into_array()), None)
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
}

#[zilliqa_macros::test]
async fn gas_fees_should_be_transferred_to_zero_account(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let provider = wallet.provider();

    network.run_until_block(&wallet, 1.into(), 50).await;
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

    let mut total_rewards = U256::zero();
    let stakers = get_stakers(&wallet).await;
    for staker in stakers {
        let reward_address = get_reward_address(&wallet, &staker).await;
        let reward_address_balance_before = wallet
            .get_balance(reward_address, Some((block.number.unwrap() - 1).into()))
            .await
            .unwrap();
        let reward_address_balance_after = wallet
            .get_balance(reward_address, Some(block.number.unwrap().into()))
            .await
            .unwrap();

        total_rewards += reward_address_balance_after - reward_address_balance_before;
    }

    let zero_account = H160::zero();
    let zero_account_balance_before = wallet
        .get_balance(zero_account, Some((block.number.unwrap() - 1).into()))
        .await
        .unwrap();
    let zero_account_balance_after = wallet
        .get_balance(zero_account, Some(block.number.unwrap().into()))
        .await
        .unwrap();

    assert_eq!(
        zero_account_balance_after,
        zero_account_balance_before - total_rewards
            + (receipt.gas_used.unwrap() * receipt.effective_gas_price.unwrap())
    );
}

// Test transaction pool state consistency during consensus operations
#[zilliqa_macros::test]
async fn test_transaction_pool_state_consistency_during_consensus(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Wait for network to be ready
    network.run_until_block(&wallet, 1.into(), 50).await;

    // Create multiple transactions from the same account with sequential nonces
    let _sender = wallet.address();
    let mut transactions = Vec::new();

    for nonce in 0..5 {
        let tx_request = TransactionRequest {
            to: Some(H160::random().into()),
            value: Some(U256::from(10)),
            gas: Some(U256::from(21000)),
            gas_price: Some(U256::from(1000000000)), // 1 gwei
            nonce: Some(U256::from(nonce)),
            ..Default::default()
        };

        let pending_tx = wallet.send_transaction(tx_request, None).await.unwrap();
        transactions.push(pending_tx.tx_hash());
    }

    // Let some transactions get processed
    network.run_until_block(&wallet, 3.into(), 100).await;

    // Send more transactions while consensus is processing
    for nonce in 5..10 {
        let tx_request = TransactionRequest {
            to: Some(H160::random().into()),
            value: Some(U256::from(10)),
            gas: Some(U256::from(21000)),
            gas_price: Some(U256::from(1000000000)),
            nonce: Some(U256::from(nonce)),
            ..Default::default()
        };

        let pending_tx = wallet.send_transaction(tx_request, None).await.unwrap();
        transactions.push(pending_tx.tx_hash());
    }

    // Check that all nodes have consistent transaction pool states
    network.run_until_block(&wallet, 6.into(), 200).await;

    // Verify transaction pool consistency across nodes
    for index in network.nodes.iter().map(|x| x.index) {
        let node = network.get_node(index);
        let pool_status = node.consensus.transaction_pool.read().preview_status();

        // The pending count should be consistent and reasonable
        assert!(
            pool_status.pending <= 20,
            "Pending count too high: {}",
            pool_status.pending
        );

        // Check that we can query pool content without panics
        let _content = node.consensus.transaction_pool.read().preview_content();
    }
}

// Test rapid transaction submission during block production
#[zilliqa_macros::test]
async fn test_rapid_transaction_submission_during_block_production(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Wait for network to be ready
    network.run_until_block(&wallet, 1.into(), 50).await;

    // Submit many transactions rapidly
    let mut submitted_hashes = Vec::new();

    // Rapid submission while blocks are being produced
    for batch in 0..5 {
        // Submit a batch of transactions
        for i in 0..3 {
            let nonce = batch * 3 + i;
            let tx_request = TransactionRequest {
                to: Some(H160::random().into()),
                value: Some(U256::from(10)),
                gas: Some(U256::from(21000)),
                gas_price: Some(U256::from(1000000000 + i)), // Vary gas price
                nonce: Some(U256::from(nonce)),
                ..Default::default()
            };

            let pending_tx = wallet.send_transaction(tx_request, None).await.unwrap();
            submitted_hashes.push(pending_tx.tx_hash());
        }

        // Allow some processing time between batches
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Let the network process all transactions
    network.run_until_block(&wallet, 8.into(), 300).await;

    // Check transaction pool state consistency
    let mut total_processed = 0;
    let mut total_pending = 0;

    for index in network.nodes.iter().map(|x| x.index) {
        let node = network.get_node(index);
        let pool_status = node.consensus.transaction_pool.read().preview_status();
        total_pending += pool_status.pending + pool_status.queued;

        // Count how many of our transactions were processed
        for &hash in &submitted_hashes {
            if node
                .get_transaction_receipt(Hash(hash.0))
                .unwrap()
                .is_some()
            {
                total_processed += 1;
                break; // Only count once across all nodes
            }
        }
    }

    // Most transactions should have been processed or be pending
    let total_submitted = submitted_hashes.len();
    assert!(
        total_processed + total_pending as usize >= total_submitted / 2,
        "Too many transactions lost: processed={}, pending={}, submitted={}",
        total_processed,
        total_pending,
        total_submitted
    );
}

// Test transaction replacement scenarios during consensus
#[zilliqa_macros::test]
async fn test_transaction_replacement_during_consensus(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Wait for network to be ready
    network.run_until_block(&wallet, 1.into(), 50).await;

    // Submit initial transaction with low gas price
    let initial_tx = wallet
        .send_transaction(
            TransactionRequest {
                to: Some(H160::random().into()),
                value: Some(U256::from(100)),
                gas: Some(U256::from(21000)),
                gas_price: Some(U256::from(1000000000)), // 1 gwei
                nonce: Some(U256::from(0)),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

    // Wait a bit for the transaction to propagate
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Replace with higher gas price transaction
    let replacement_tx = wallet
        .send_transaction(
            TransactionRequest {
                to: Some(H160::random().into()),
                value: Some(U256::from(200)),
                gas: Some(U256::from(21000)),
                gas_price: Some(U256::from(2000000000)), // 2 gwei
                nonce: Some(U256::from(0)),              // Same nonce
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();

    // Submit more transactions with subsequent nonces
    for nonce in 1..5 {
        let tx_request = TransactionRequest {
            to: Some(H160::random().into()),
            value: Some(U256::from(10)),
            gas: Some(U256::from(21000)),
            gas_price: Some(U256::from(1500000000)),
            nonce: Some(U256::from(nonce)),
            ..Default::default()
        };

        let _pending_tx = wallet.send_transaction(tx_request, None).await.unwrap();
    }

    // Let the network process transactions
    network.run_until_block(&wallet, 5.into(), 200).await;

    // Verify that transaction replacement worked correctly
    for index in network.nodes.iter().map(|x| x.index) {
        let node = network.get_node(index);

        // Check if the replacement transaction was processed
        let initial_receipt = node
            .get_transaction_receipt(Hash(initial_tx.tx_hash().0))
            .unwrap();
        let replacement_receipt = node
            .get_transaction_receipt(Hash(replacement_tx.tx_hash().0))
            .unwrap();

        // Either the replacement was processed, or neither was processed yet
        if replacement_receipt.is_some() {
            assert!(
                initial_receipt.is_none(),
                "Both original and replacement transactions were processed on node {}",
                index
            );
        }

        // Verify pool state consistency
        let pool_status = node.consensus.transaction_pool.read().preview_status();
        let content = node.consensus.transaction_pool.read().preview_content();

        // Check that the pending count matches the actual content
        let actual_pending: usize = content.pending.values().map(|v| v.len()).sum();
        let actual_queued: usize = content.queued.values().map(|v| v.len()).sum();

        assert_eq!(
            actual_pending as u64, pool_status.pending,
            "Pending count mismatch on node {}: actual={}, reported={}",
            index, actual_pending, pool_status.pending
        );
        assert_eq!(
            actual_queued as u64, pool_status.queued,
            "Queued count mismatch on node {}: actual={}, reported={}",
            index, actual_queued, pool_status.queued
        );
    }
}

// Test transaction pool under network partition and healing
#[zilliqa_macros::test]
async fn test_transaction_pool_during_network_partition(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Wait for network to be ready
    network.run_until_block(&wallet, 2.into(), 50).await;

    // Submit some initial transactions
    let mut transaction_hashes = Vec::new();
    for nonce in 0..3 {
        let tx_request = TransactionRequest {
            to: Some(H160::random().into()),
            value: Some(U256::from(10)),
            gas: Some(U256::from(21000)),
            gas_price: Some(U256::from(1000000000)),
            nonce: Some(U256::from(nonce)),
            ..Default::default()
        };

        let pending_tx = wallet.send_transaction(tx_request, None).await.unwrap();
        transaction_hashes.push(pending_tx.tx_hash());
    }

    // Simulate network issues by dropping many messages
    for _ in 0..50 {
        network.randomly_drop_messages_then_tick(0.3).await; // Drop 30% of messages
    }

    // Submit more transactions during network issues
    for nonce in 3..6 {
        let tx_request = TransactionRequest {
            to: Some(H160::random().into()),
            value: Some(U256::from(10)),
            gas: Some(U256::from(21000)),
            gas_price: Some(U256::from(1000000000)),
            nonce: Some(U256::from(nonce)),
            ..Default::default()
        };

        let pending_tx = wallet.send_transaction(tx_request, None).await.unwrap();
        transaction_hashes.push(pending_tx.tx_hash());
    }

    // Allow network to heal and process transactions
    network.run_until_block(&wallet, 8.into(), 500).await;

    // Verify all nodes have consistent transaction pool states after healing
    let mut node_states = Vec::new();
    for index in network.nodes.iter().map(|x| x.index) {
        let node = network.get_node(index);
        let pool_status = node.consensus.transaction_pool.read().preview_status();
        let content = node.consensus.transaction_pool.read().preview_content();

        // Verify internal consistency
        let actual_pending: usize = content.pending.values().map(|v| v.len()).sum();
        let actual_queued: usize = content.queued.values().map(|v| v.len()).sum();

        assert_eq!(
            actual_pending as u64, pool_status.pending,
            "Node {} pending count inconsistent: {} vs {}",
            index, actual_pending, pool_status.pending
        );
        assert_eq!(
            actual_queued as u64, pool_status.queued,
            "Node {} queued count inconsistent: {} vs {}",
            index, actual_queued, pool_status.queued
        );

        node_states.push((pool_status.pending, pool_status.queued));
    }

    // All nodes should have reasonably similar pool states
    let avg_pending =
        node_states.iter().map(|(p, _)| *p).sum::<u64>() as f64 / node_states.len() as f64;
    for (i, (pending, _)) in node_states.iter().enumerate() {
        let diff = (*pending as f64 - avg_pending).abs();
        assert!(
            diff <= avg_pending * 0.5 + 5.0, // Allow 50% variance + 5 transactions
            "Node {} pending count too different from average: {} vs avg {}",
            i,
            pending,
            avg_pending
        );
    }
}
