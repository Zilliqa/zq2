use std::collections::HashMap;

use alloy::{
    primitives::{Address, U256},
    providers::Provider as _,
};

use crate::{Network, get_reward_address, get_stakers};

#[zilliqa_macros::test]
async fn epoch_based_rewards(mut network: Network) {
    // We already have `distribute_rewards_every_epoch` enabled by default in `genesis_fork_default`
    // Let's create a network with blocks_per_epoch = 10 to see reward distribution at boundaries

    let wallet = network.genesis_wallet().await;

    // Check proposer's balance before the epoch boundary
    let stakers = get_stakers(&wallet).await;
    let mut reward_addresses = Vec::new();
    for staker in &stakers {
        reward_addresses.push(get_reward_address(&wallet, staker).await.0.into());
    }

    // Advance to block 1 so we can query initial balances
    network.run_until_block(&wallet, 1, 50).await;

    // Since genesis, balances should be static till the epoch boundary.
    let mut initial_balances = Vec::new();
    for addr in &reward_addresses {
        initial_balances.push(wallet.get_balance(*addr).number(1).await.unwrap());
    }

    // Advance to block 9 (right before the epoch boundary)
    network.run_until_block(&wallet, 9, 200).await;

    // Verify balances haven't changed (no block rewards yet)
    let mut balances_at_9 = Vec::new();
    for addr in &reward_addresses {
        balances_at_9.push(wallet.get_balance(*addr).number(9).await.unwrap());
    }

    assert_eq!(
        initial_balances, balances_at_9,
        "Balances changed before the epoch boundary!"
    );

    // Advance to block 10 (epoch boundary)
    network.run_until_block(&wallet, 10, 50).await;

    // Check balances at block 10, should be higher due to epoch rewards
    let mut balances_at_10 = Vec::new();
    for addr in &reward_addresses {
        balances_at_10.push(wallet.get_balance(*addr).number(10).await.unwrap());
    }

    let total_initial: U256 = initial_balances.iter().sum();
    let total_at_10: U256 = balances_at_10.iter().sum();

    assert!(
        total_at_10 > total_initial,
        "Total rewards should have increased at epoch boundary!"
    );
}

#[zilliqa_macros::test]
async fn state_root_consistent_within_epoch(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let blocks_per_epoch = network.get_node(0).config.consensus.blocks_per_epoch as usize;

    // Advance through two full epochs
    let target = blocks_per_epoch * 2;
    network.run_until_block(&wallet, target as u64, 400).await;

    // Collect state roots for all blocks in the range [0, target].
    // state_roots[i] corresponds to block i.
    let mut state_roots = Vec::new();
    for block_num in 0..=target {
        let block = wallet
            .get_block((block_num as u64).into())
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("block {block_num} not found"));
        state_roots.push(block.header.state_root);
    }

    // Within the first epoch (blocks 1 .. blocks_per_epoch-1), state root should not change
    // because there are no transactions and no rewards are distributed.
    for block_num in 1..blocks_per_epoch {
        assert_eq!(
            state_roots[block_num], state_roots[1],
            "State root changed at block {block_num} within the first epoch (expected same as block 1)"
        );
    }

    // At the first epoch boundary (block blocks_per_epoch), state root must change due to reward distribution.
    assert_ne!(
        state_roots[blocks_per_epoch],
        state_roots[blocks_per_epoch - 1],
        "State root should change at epoch boundary (block {blocks_per_epoch}) due to reward distribution"
    );

    // Within the second epoch (blocks blocks_per_epoch+1 .. blocks_per_epoch*2-1), state root
    // should stay the same.
    let second_epoch_first = blocks_per_epoch + 1;
    for block_num in (second_epoch_first + 1)..=(blocks_per_epoch * 2 - 1) {
        assert_eq!(
            state_roots[block_num], state_roots[second_epoch_first],
            "State root changed at block {block_num} within the second epoch"
        );
    }

    // At the second epoch boundary (block blocks_per_epoch*2), state root must change again.
    assert_ne!(
        state_roots[blocks_per_epoch * 2],
        state_roots[blocks_per_epoch * 2 - 1],
        "State root should change at second epoch boundary (block {target}) due to reward distribution"
    );
}

#[zilliqa_macros::test]
async fn warm_rewards_cache_on_restart(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let blocks_per_epoch = network.get_node(0).config.consensus.blocks_per_epoch;
    assert_eq!(blocks_per_epoch, 10, "test assumes blocks_per_epoch = 10");

    // Snapshot reward addresses before anything moves.
    let stakers = get_stakers(&wallet).await;
    let mut reward_addresses: Vec<Address> = Vec::new();
    for staker in &stakers {
        reward_addresses.push(get_reward_address(&wallet, staker).await.0.into());
    }

    // Advance mid-epoch. `run_until_block` observes any node, so node 0 may
    // trail by a block or two — read its head directly to size the assertion.
    network.run_until_block(&wallet, 5, 200).await;

    let node_head_before = network.get_node(0).consensus.read().head_block().number();
    assert!(
        node_head_before >= 1 && node_head_before < blocks_per_epoch,
        "node 0 should be mid-epoch, got head {node_head_before}"
    );
    let cache_len_before = network.get_node(0).consensus.read().rewards_cache_len();
    assert_eq!(
        cache_len_before as u64, node_head_before,
        "rewards cache should have one entry per block in the current epoch"
    );
    assert!(cache_len_before > 0, "cache should not be empty mid-epoch");

    // Balance snapshot just before restart — used to assert the epoch
    // distribution still fires after restart.
    let mut balances_before_restart = Vec::new();
    for addr in &reward_addresses {
        balances_before_restart.push(
            wallet
                .get_balance(*addr)
                .number(node_head_before)
                .await
                .unwrap(),
        );
    }

    // Restart the network. This wipes in-memory Consensus state; the cache
    // should be repopulated from the db by `warm_reward_cache_on_startup`.
    network.restart();

    let cache_len_after = network.get_node(0).consensus.read().rewards_cache_len();
    assert_eq!(
        cache_len_after, cache_len_before,
        "rewards cache not warmed after restart: before={cache_len_before}, after={cache_len_after}"
    );

    // Drive the network past the epoch boundary. If the cache weren't warmed,
    // the epoch payout at block 10 would either skip rewards for blocks 1..=5
    // or fall back to the per-hash db recompute path — either way the payout
    // would still need to land. Assert that it does.
    let wallet = network.genesis_wallet().await;
    network.run_until_block(&wallet, 10, 400).await;

    let mut balances_at_10 = Vec::new();
    for addr in &reward_addresses {
        balances_at_10.push(wallet.get_balance(*addr).number(10).await.unwrap());
    }

    let total_before: U256 = balances_before_restart.iter().sum();
    let total_at_10: U256 = balances_at_10.iter().sum();
    assert!(
        total_at_10 > total_before,
        "epoch-boundary reward distribution did not fire after restart"
    );
}

#[zilliqa_macros::test]
async fn epoch_and_legacy_rewards_match(mut network: Network) {
    let wallet = network.genesis_wallet().await;
    let blocks_per_epoch = network.get_node(0).config.consensus.blocks_per_epoch;
    assert_eq!(blocks_per_epoch, 10, "test assumes blocks_per_epoch = 10");

    let stakers = get_stakers(&wallet).await;
    let mut reward_addresses: Vec<Address> = Vec::new();
    for staker in &stakers {
        reward_addresses.push(get_reward_address(&wallet, staker).await.0.into());
    }

    let read_balance = |network: &Network, height: u64, addr: Address| -> U256 {
        let state = network
            .get_node(0)
            .consensus
            .read()
            .state_at(height)
            .unwrap()
            .unwrap_or_else(|| panic!("node 0 missing state at height {height}"));
        U256::from(state.get_account(addr).unwrap().balance)
    };
    let node0_head =
        |network: &mut Network| network.get_node(0).consensus.read().head_block().number();

    // Wait for node 0 (specifically) to reach block 9 so we can read its
    // state at that height.
    network
        .run_until(|n| node0_head(n) >= 9, 400)
        .await
        .unwrap();

    let mut balances_before: HashMap<Address, U256> = HashMap::new();
    for addr in &reward_addresses {
        balances_before.insert(*addr, read_balance(&network, 9, *addr));
    }
    let zero_balance_before = read_balance(&network, 9, Address::ZERO);

    // Cross the epoch boundary. Rewards for blocks 1..=10 are applied here.
    network
        .run_until(|n| node0_head(n) >= 10, 200)
        .await
        .unwrap();

    let mut balances_after: HashMap<Address, U256> = HashMap::new();
    for addr in &reward_addresses {
        balances_after.insert(*addr, read_balance(&network, 10, *addr));
    }
    let zero_balance_after = read_balance(&network, 10, Address::ZERO);

    let mut expected_delta: HashMap<Address, u128> = HashMap::new();
    let mut expected_rewards_issued: u128 = 0;
    {
        // Re-derive each block's reward through the same path the epoch
        // distribution uses on cache miss (`reward_from_db` via
        // `preview_reward_at`). Summing across the epoch should reproduce the
        // observed balance deltas exactly.
        let node = network.get_node(0);
        let consensus = node.consensus.read();

        for block_num in 1..=10u64 {
            let block = consensus
                .get_canonical_block_by_number(block_num)
                .unwrap()
                .unwrap_or_else(|| panic!("node 0 missing canonical block {block_num}"));
            let reward = consensus
                .preview_reward_at(block.hash())
                .expect("preview_reward_at should succeed");

            let (proposer_addr, proposer_amount) = reward.proposer;
            *expected_delta.entry(proposer_addr).or_insert(0) += proposer_amount;
            expected_rewards_issued += proposer_amount;

            for (addr, amount) in &reward.cosigners {
                *expected_delta.entry(*addr).or_insert(0) += *amount;
                expected_rewards_issued += *amount;
            }
        }
    }

    // Per-address deltas: actual balance diff must equal summed per-block reward.
    for addr in &reward_addresses {
        let before = balances_before[addr];
        let after = balances_after[addr];
        let actual_delta = after - before;
        let expected = U256::from(expected_delta.get(addr).copied().unwrap_or(0));
        assert_eq!(
            actual_delta, expected,
            "reward delta mismatch for address {addr:?}: actual={actual_delta}, expected={expected}"
        );
    }

    // Zero-account drain: under this fork the zero account funds rewards and
    // absorbs gas fees. With no txs in the epoch, gas fees are zero, so the
    // zero account should have decreased by exactly the sum of all rewards.
    let expected_zero_delta = U256::from(expected_rewards_issued);
    let actual_zero_delta = zero_balance_before - zero_balance_after;
    assert_eq!(
        actual_zero_delta, expected_zero_delta,
        "zero-account delta mismatch: actual={actual_zero_delta}, expected={expected_zero_delta}"
    );
}
