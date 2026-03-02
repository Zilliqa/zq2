use std::collections::HashSet;

use alloy::{
    consensus::TypedTransaction,
    eips::{BlockId, eip2930::AccessList},
    network::TransactionBuilder,
    primitives::{Address, U256},
    providers::{Provider as _, WalletProvider},
    rpc::types::TransactionRequest,
};
use tracing::*;
use zilliqa::{crypto::Hash, state::contract_addr};

use crate::{Network, get_reward_address, get_stakers};

// Test that all nodes can die and the network can restart (even if they startup at different
// times)
#[zilliqa_macros::test]
async fn network_can_die_restart(mut network: Network) {
    // wait until at least 5 blocks have been produced
    network.run_until_block_finalized(5, 100).await.unwrap();
    // Forcibly restart the network, with a random time delay between each node
    network.restart();
    // Panic if it can't progress to the target block
    network.run_until_block_finalized(10, 1000).await.unwrap();
}

// Test that new node joining the network catches up on blocks
#[zilliqa_macros::test]
async fn block_production(mut network: Network) {
    network.run_until_block_finalized(5, 100).await.unwrap();

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
        .get_transaction_count(wallet.default_signer_address())
        .await
        .unwrap();

    let gap_nonce = init_nonce + 3;
    let gap_txn_count = 10;
    for num in 0..gap_txn_count {
        wallet
            .send_transaction(
                TransactionRequest::default()
                    .with_to(Address::random())
                    .with_value(U256::from(0))
                    .with_nonce(gap_nonce + num),
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
            let consensus = node.consensus.read();
            let pool = consensus.transaction_pool.read();
            pool.preview_content()
                .queued
                .values()
                .map(|x| x.len())
                .sum()
        };
        assert_eq!(queued_count, expected_count);
    }

    // Ensure txns are queued on both nodes
    verify_queued(&network, gap_txn_count as usize, 0);
    verify_queued(&network, gap_txn_count as usize, 1);

    // Send a single TX to the network that triggers txns inclusion
    let res = wallet
        .send_transaction(
            TransactionRequest::default()
                .with_to(Address::random())
                .with_value(U256::from(10))
                .with_nonce(init_nonce),
        )
        .await
        .unwrap();
    let hash = res.tx_hash();

    network.drop_propose_messages_except_one().await;

    let mut receipts = Vec::new();

    // Check that node 0 has executed the transaction
    let first = network
        .get_node(0)
        .get_transaction_receipt(Hash(hash.0))
        .unwrap();

    // For sure the first node should execute txn
    assert!(first.is_some());

    for node in network.nodes.iter() {
        let receipt = node.inner.get_transaction_receipt(Hash(hash.0)).unwrap();
        receipts.push(receipt);
    }

    // There must be nodes that didn't receive this block
    assert!(receipts.iter().any(|x| x.is_none()));

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
    verify_queued(&network, gap_txn_count as usize, 0);
    verify_queued(&network, gap_txn_count as usize, 1);
}

// Test that zero account has correct initial funds, is the source of rewards and is the sink of gas
#[zilliqa_macros::test]
async fn zero_account_per_block_balance_updates(mut network: Network) {
    let wallet = network.genesis_wallet_null().await;

    // Check initial account values
    let block_height = wallet.get_block_number().await.unwrap();
    assert_eq!(block_height, 0);

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
        .get_balance(wallet.default_signer_address())
        .await
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(genesis_account_expected_balance, genesis_account_balance);

    // Total initial stake spread across 4 validators
    let genesis_deposits = network
        .get_node(0)
        .config
        .consensus
        .genesis_deposits
        .clone();
    let total_staked: u128 = genesis_deposits[0].stake.0 * 4;

    // Zero account balance plus genesis account plus initial stakes plus deposit contract should equal total_native_token_supply
    let zero_account_balance: u128 = wallet
        .get_balance(Address::ZERO)
        .await
        .unwrap()
        .try_into()
        .unwrap();
    let deposit_contract_balance: u128 = wallet
        .get_balance(contract_addr::DEPOSIT_PROXY)
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
    network.run_until_block(&wallet, 1, 50).await;

    let block = wallet.get_block(1.into()).await.unwrap().unwrap();
    assert_eq!(block.transactions.len(), 0);

    // Check proposer was rewarded
    let miner = block.header.beneficiary;
    let miner_balance_before = wallet
        .get_balance(miner)
        .number(block.number() - 1)
        .await
        .unwrap();
    let miner_balance_after = wallet
        .get_balance(miner)
        .number(block.number())
        .await
        .unwrap();
    assert!(miner_balance_before < miner_balance_after);

    // Check reward came from zero account balance
    let zero_account = Address::ZERO;
    let zero_account_balance_before = wallet
        .get_balance(zero_account)
        .number(block.number() - 1)
        .await
        .unwrap();
    let zero_account_balance_after = wallet
        .get_balance(zero_account)
        .number(block.number())
        .await
        .unwrap();
    assert!(zero_account_balance_before > zero_account_balance_after);
}

#[zilliqa_macros::test]
async fn gas_fees_should_be_transferred_to_zero_account(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let chain_id = network.get_node(0).chain_id.eth;
    let gas_price = network.get_node(0).get_gas_price();
    let tx_legacy: TypedTransaction = TransactionRequest::default()
        .with_chain_id(chain_id)
        .to(wallet.default_signer_address())
        .value(U256::from(10))
        .nonce(0)
        .gas_limit(21_000)
        .gas_price(gas_price)
        .build_legacy()
        .unwrap()
        .into();
    let tx_eip1559: TypedTransaction = TransactionRequest::default()
        .with_chain_id(chain_id)
        .to(wallet.default_signer_address())
        .value(U256::from(10))
        .nonce(1)
        .gas_limit(21_000)
        .max_fee_per_gas(gas_price)
        .max_priority_fee_per_gas(gas_price)
        .build_1559()
        .unwrap()
        .into();
    let tx_eip2930: TypedTransaction = TransactionRequest::default()
        .with_chain_id(chain_id)
        .to(wallet.default_signer_address())
        .value(U256::from(10))
        .nonce(2)
        .gas_limit(21_000)
        .gas_price(gas_price)
        .access_list(AccessList::default())
        .build_2930()
        .unwrap()
        .into();

    for tx_request in [tx_legacy, tx_eip1559, tx_eip2930] {
        let tx = wallet.send_transaction(tx_request.into()).await.unwrap();
        let hash = tx.tx_hash();
        let receipt = network.run_until_receipt(&wallet, hash, 200).await;

        assert_eq!(receipt.gas_used, 21000);
        assert_eq!(receipt.effective_gas_price, gas_price);
        let block = wallet
            .get_block(receipt.block_number.unwrap().into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(block.transactions.len(), 1);

        let mut total_rewards = U256::ZERO;
        let stakers = get_stakers(&wallet).await;
        for staker in stakers {
            let reward_address = get_reward_address(&wallet, &staker).await.0.into();
            let reward_address_balance_before = wallet
                .get_balance(reward_address)
                .number(block.number() - 1)
                .await
                .unwrap();
            let reward_address_balance_after = wallet
                .get_balance(reward_address)
                .number(block.number())
                .await
                .unwrap();
            total_rewards += reward_address_balance_after - reward_address_balance_before;
        }

        let zero_account = Address::ZERO;
        let zero_account_balance_before = wallet
            .get_balance(zero_account)
            .number(block.number() - 1)
            .await
            .unwrap();
        let zero_account_balance_after = wallet
            .get_balance(zero_account)
            .number(block.number())
            .await
            .unwrap();
        let total_gas = U256::from(receipt.effective_gas_price) * U256::from(receipt.gas_used);
        assert_eq!(
            zero_account_balance_after,
            zero_account_balance_before - total_rewards + total_gas
        );
    }
}

// Test rapid transaction submission during block production
#[zilliqa_macros::test]
async fn test_rapid_transaction_submission_during_block_production(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Wait for network to be ready
    network.run_until_block(&wallet, 1, 50).await;

    // Submit many transactions rapidly
    let mut submitted_hashes = Vec::new();

    let mut current_block = 1u64;
    // Rapid submission while blocks are being produced
    for batch in 0..5 {
        // Submit a batch of transactions
        for i in 0..3 {
            let nonce = (batch * 3 + i) as u64;
            let tx_request = TransactionRequest::default()
                .with_to(Address::random())
                .with_value(U256::from(10))
                .with_gas_limit(21000)
                .with_gas_price(4_761_904_800_000u128 + batch * 3 + i)
                .with_nonce(nonce);

            let pending_tx = wallet.send_transaction(tx_request).await.unwrap();
            submitted_hashes.push(*pending_tx.tx_hash());
        }

        // Allow some processing time between batches
        network.run_until_block(&wallet, current_block, 50).await;
        current_block += 1;
    }

    // Let the network process all transactions
    network
        .run_until_block(&wallet, current_block + 5, 300)
        .await;

    // Check transaction pool state consistency
    let mut total_processed = HashSet::new();
    let mut total_pending = 0;

    for index in network.nodes.iter().map(|x| x.index) {
        let node = network.get_node(index);
        let consensus = node.consensus.read();
        let pool_status = consensus.transaction_pool.read().preview_status();
        total_pending += pool_status.pending + pool_status.queued;

        // Count how many of our transactions were processed
        for &hash in &submitted_hashes {
            if node
                .get_transaction_receipt(Hash(hash.0))
                .unwrap()
                .is_some()
            {
                total_processed.insert(hash);
            }
        }
    }

    // Most transactions should have been processed or be pending
    let total_submitted = submitted_hashes.len();
    assert!(
        total_processed.len() + total_pending as usize >= total_submitted / 2,
        "Too many transactions lost: processed={}, pending={}, submitted={}",
        total_processed.len(),
        total_pending,
        total_submitted
    );
}

// Test transaction replacement scenarios during consensus
#[zilliqa_macros::test]
async fn test_transaction_replacement_during_consensus(mut network: Network) {
    let wallet = network.genesis_wallet().await;

    // Wait for network to be ready
    network.run_until_block(&wallet, 1, 50).await;

    // Submit initial transaction with low gas price
    let initial_tx = wallet
        .send_transaction(
            TransactionRequest::default()
                .with_to(Address::random())
                .with_value(U256::from(100))
                .with_gas_limit(21000)
                .with_gas_price(4_761_904_800_000u128)
                .with_nonce(0),
        )
        .await
        .unwrap();

    // Wait a bit for the transaction to propagate
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Replace with higher gas price transaction
    let replacement_tx = wallet
        .send_transaction(
            TransactionRequest::default()
                .with_to(Address::random())
                .with_value(U256::from(200))
                .with_gas_limit(21000)
                .with_gas_price(4_761_904_800_000u128 * 2)
                .with_nonce(0),
        )
        .await
        .unwrap();

    // Submit more transactions with subsequent nonces
    for nonce in 1..5 {
        let tx_request = TransactionRequest::default()
            .with_to(Address::random())
            .with_value(U256::from(10))
            .with_gas_limit(21000)
            .with_gas_price(7_161_904_800_000u128)
            .with_nonce(nonce);
        let _pending_tx = wallet.send_transaction(tx_request).await.unwrap();
    }

    // Let the network process transactions
    network.run_until_block(&wallet, 5, 200).await;

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
                "Both original and replacement transactions were processed on node {index}"
            );
        }

        // Verify pool state consistency
        let pool_status = node
            .consensus
            .read()
            .transaction_pool
            .read()
            .preview_status();
        let content = node
            .consensus
            .read()
            .transaction_pool
            .read()
            .preview_content();

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
    network.run_until_block(&wallet, 2, 50).await;

    // Submit some initial transactions
    let mut transaction_hashes = Vec::new();
    for nonce in 0..3 {
        let tx_request = TransactionRequest::default()
            .with_to(Address::random())
            .with_value(U256::from(10))
            .with_gas_limit(21000)
            .with_gas_price(4_761_904_800_000u128)
            .nonce(nonce);
        let pending_tx = wallet.send_transaction(tx_request).await.unwrap();
        transaction_hashes.push(*pending_tx.tx_hash());
    }

    // Simulate network issues by dropping many messages
    for _ in 0..50 {
        network.randomly_drop_messages_then_tick(0.1).await; // Drop 30% of messages
    }

    // Submit more transactions during network issues
    for nonce in 3..6 {
        let tx_request = TransactionRequest::default()
            .with_to(Address::random())
            .with_value(U256::from(10))
            .with_gas_limit(21000)
            .with_gas_price(4_761_904_800_000u128)
            .nonce(nonce);
        let pending_tx = wallet.send_transaction(tx_request).await.unwrap();
        transaction_hashes.push(*pending_tx.tx_hash());
    }

    // Allow network to heal and process transactions
    network.run_until_block(&wallet, 8, 2500).await;

    // Verify all nodes have consistent transaction pool states after healing
    let mut node_states = Vec::new();
    for index in network.nodes.iter().map(|x| x.index) {
        let node = network.get_node(index);
        let consensus = node.consensus.read();
        let pool_status = consensus.transaction_pool.read().preview_status();
        let content = consensus.transaction_pool.read().preview_content();

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
            "Node {i} pending count too different from average: {pending} vs avg {avg_pending}"
        );
    }
}
