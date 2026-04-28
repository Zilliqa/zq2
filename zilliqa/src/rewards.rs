use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
};

use alloy::primitives::{Address, U256};
use anyhow::{Result, anyhow};
use opentelemetry::KeyValue;
use tracing::{debug, warn};

use crate::{
    cfg::{ConsensusConfig, ForkName},
    consensus::Consensus,
    crypto::{Hash, NodePublicKey},
    db::{self, BlockFilter, Db},
    message::Block,
    state::State,
    transaction::SignedTransaction,
};

#[derive(Debug, Clone)]
pub struct Reward {
    pub number: u64,
    pub parent_hash: Hash,
    pub proposer: (Address, u128),
    pub cosigners: Vec<(Address, u128)>,
    pub gas_fee: u128,
}

#[derive(Debug, Default)]
pub struct Rewards {
    by_hash: HashMap<Hash, Reward>,
    by_height: BinaryHeap<Reverse<(u64, Hash)>>,
}

impl Rewards {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rekey(&mut self, old_hash: Hash, new_hash: Hash) {
        if let Some(cum) = self.by_hash.remove(&old_hash) {
            self.by_hash.insert(new_hash, cum);
        }
    }

    pub fn insert(&mut self, hash: Hash, reward: Reward) {
        self.by_height.push(Reverse((reward.number, hash)));
        self.by_hash.insert(hash, reward);
    }

    pub fn get(&self, hash: &Hash) -> Option<&Reward> {
        self.by_hash.get(hash)
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Drops all cached rewards with height strictly below `min_height`.
    pub fn prune_below(&mut self, min_height: u64) {
        while let Some(Reverse((h, _))) = self.by_height.peek() {
            if *h >= min_height {
                break;
            }
            let Reverse((_, hash)) = self.by_height.pop().unwrap();
            self.by_hash.remove(&hash);
        }
    }

    pub fn apply_epoch<F>(
        &mut self,
        state: &mut State,
        head_hash: Hash,
        range_start: u64,
        mut compute_missing: F,
    ) -> Result<()>
    where
        F: FnMut(Hash) -> Result<Reward>,
    {
        let mut rewards_by_address = HashMap::new();
        let mut total_rewards_issued: u128 = 0;
        let mut total_gas_fees: u128 = 0;

        let mut hash = head_hash;

        loop {
            let reward = if let Some(r) = self.by_hash.get(&hash) {
                r.clone()
            } else {
                warn!(%hash, "reward cache miss, recomputing from db");
                let computed = compute_missing(hash)?;
                self.insert(hash, computed.clone());
                computed
            };

            if reward.number < range_start {
                break;
            }

            // 1. Fold proposer reward
            let (proposer_addr, proposer_amount) = reward.proposer;
            let entry = rewards_by_address.entry(proposer_addr).or_insert(0u128);
            *entry = (*entry)
                .checked_add(proposer_amount)
                .ok_or_else(|| anyhow!("overflow crediting proposer reward"))?;

            total_rewards_issued = total_rewards_issued
                .checked_add(proposer_amount)
                .ok_or_else(|| anyhow!("overflow accumulating total rewards"))?;

            // 2. Fold cosigner rewards
            for (addr, amount) in &reward.cosigners {
                let entry = rewards_by_address.entry(*addr).or_insert(0u128);
                *entry = (*entry)
                    .checked_add(*amount)
                    .ok_or_else(|| anyhow!("overflow crediting cosigner reward"))?;

                total_rewards_issued = total_rewards_issued
                    .checked_add(*amount)
                    .ok_or_else(|| anyhow!("overflow accumulating total rewards"))?;
            }

            // 3. Fold gas fees
            total_gas_fees = total_gas_fees
                .checked_add(reward.gas_fee)
                .ok_or_else(|| anyhow!("overflow accumulating epoch gas fees"))?;

            let next_hash = reward.parent_hash;
            if reward.number == range_start {
                break;
            }
            hash = next_hash;
        }

        // Distribute grouped rewards using a single mutation per address
        for (addr, amount) in rewards_by_address {
            state.mutate_account(addr, |a| {
                a.balance = a
                    .balance
                    .checked_add(amount)
                    .ok_or_else(|| anyhow!("overflow crediting reward"))?;
                Ok(())
            })?;
        }

        // Rewards are funded from the zero account; gas fees are always sunk
        // into the zero account under this fork (transfer_gas_fee_to_zero_account
        // is always true when distribute_rewards_every_epoch is active).
        state.mutate_account(Address::ZERO, |a| {
            a.balance = a
                .balance
                .checked_sub(total_rewards_issued)
                .ok_or_else(|| anyhow!("zero account underflow funding rewards"))?;
            a.balance = a
                .balance
                .checked_add(total_gas_fees)
                .ok_or_else(|| anyhow!("zero account overflow receiving gas fees"))?;
            Ok(())
        })?;

        Ok(())
    }
}

pub fn compute_reward_at(
    parent_state: &State,
    config: &ConsensusConfig,
    committee: &[NodePublicKey],
    proposer: NodePublicKey,
    block: &Block,
    gas_fee: u128,
) -> Result<Reward> {
    let earned_reward = opentelemetry::global::meter("zilliqa")
        .f64_counter("validator_earned_reward")
        .with_unit("ZIL")
        .build();

    let rewards_per_block: u128 = *config.rewards_per_hour / config.blocks_per_hour as u128;
    let half = rewards_per_block / 2;

    let proposer_address = parent_state
        .get_reward_address(proposer)?
        .ok_or_else(|| anyhow!("proposer has no reward address"))?;
    let proposer_entry = (proposer_address, half);
    let attributes = [
        KeyValue::new("address", format!("{proposer_address:?}")),
        KeyValue::new("role", "proposer"),
    ];
    earned_reward.add((half as f64) / 1e18, &attributes);

    let cosigner_stake: Vec<(Option<Address>, u128)> = committee
        .iter()
        .enumerate()
        .filter(|(i, _)| block.header.qc.cosigned[*i])
        .map(|(_, pk)| {
            let reward_address = parent_state.get_reward_address(*pk)?;
            let stake = parent_state
                .get_stake(*pk, block.header)?
                .ok_or_else(|| anyhow!("missing stake for cosigner"))?
                .get();
            Ok::<_, anyhow::Error>((reward_address, stake))
        })
        .collect::<Result<Vec<_>>>()?;

    let total_cosigner_stake: u128 = cosigner_stake.iter().map(|(_, s)| *s).sum();
    if total_cosigner_stake == 0 {
        return Err(anyhow!("total stake is 0"));
    }

    let mut cosigners: Vec<(Address, u128)> = Vec::new();
    for (maybe_addr, stake) in &cosigner_stake {
        if let Some(addr) = maybe_addr {
            let amount = (U256::from(half) * U256::from(*stake) / U256::from(total_cosigner_stake))
                .to::<u128>();
            cosigners.push((*addr, amount));

            let attributes = [
                KeyValue::new("address", format!("{addr:?}")),
                KeyValue::new("role", "cosigner"),
            ];
            earned_reward.add((amount as f64) / 1e18, &attributes);
        }
    }

    Ok(Reward {
        number: block.number(),
        parent_hash: block.parent_hash(),
        proposer: proposer_entry,
        cosigners,
        gas_fee,
    })
}

/// Sum the gas fees paid by a single block's receipts.
pub fn compute_block_gas_fees(data: &db::BlockAndReceiptsAndTransactions) -> Result<u128> {
    let tx_map: HashMap<Hash, &SignedTransaction> = data
        .transactions
        .iter()
        .map(|tx| (tx.hash, &tx.tx))
        .collect();

    data.receipts.iter().try_fold(0u128, |acc, receipt| {
        let tx = tx_map
            .get(&receipt.tx_hash)
            .ok_or_else(|| anyhow!("missing tx for receipt in gas fee computation"))?;
        let gas_fee = receipt.gas_used.0 as u128 * tx.gas_price_per_evm_gas();
        acc.checked_add(gas_fee)
            .ok_or_else(|| anyhow!("Overflow in gas fee computation"))
    })
}

pub fn reward_from_db(
    db: &Db,
    state: &State,
    config: &ConsensusConfig,
    hash: Hash,
) -> Result<Reward> {
    let data = db
        .get_block_and_receipts_and_transactions(BlockFilter::Hash(hash))?
        .ok_or_else(|| anyhow!("missing block in db for reward recomputation: {hash}"))?;

    let parent = db
        .get_block(BlockFilter::Hash(data.block.parent_hash()))?
        .ok_or_else(|| {
            anyhow!(
                "missing parent block for reward recomputation: {}",
                data.block.parent_hash()
            )
        })?;

    let grandparent_mix_hash = db
        .get_block(BlockFilter::Hash(parent.parent_hash()))
        .ok()
        .flatten()
        .and_then(|b| b.header.mix_hash);

    let parent_state = state.at_root(parent.state_root_hash().into());
    let committee = parent_state.get_stakers(data.block.header)?;
    let proposer = Consensus::leader_at_state(
        &parent_state,
        &parent,
        grandparent_mix_hash,
        data.block.view(),
    )
    .ok_or_else(|| {
        anyhow!(
            "no leader for block {} view {}",
            data.block.number(),
            data.block.view()
        )
    })?;

    let gas_fee = compute_block_gas_fees(&data)?;
    compute_reward_at(
        &parent_state,
        config,
        &committee,
        proposer.public_key,
        &data.block,
        gas_fee,
    )
}

pub fn warm_reward_cache_on_startup(consensus: &Consensus) -> Result<()> {
    let Some(fork_activation_height) = consensus
        .state
        .forks
        .find_height_fork_first_activated(ForkName::DistributeRewardsEveryEpoch)
    else {
        return Ok(());
    };

    let head = consensus.head_block();
    if !consensus
        .state
        .forks
        .get(head.number())
        .distribute_rewards_every_epoch
    {
        return Ok(());
    }

    let blocks_per_epoch = consensus.config.consensus.blocks_per_epoch;
    let epoch_start = (head.number() / blocks_per_epoch) * blocks_per_epoch + 1;
    let range_start = std::cmp::max(std::cmp::max(fork_activation_height, 1), epoch_start);
    if range_start > head.number() {
        return Ok(());
    }

    let data = consensus
        .db
        .get_canonical_blocks_and_receipts_and_transactions_by_height_range(
            range_start..=head.number(),
        )?;

    let mut rewards = consensus.rewards.lock();
    for item in data {
        let reward = reward_from_db(
            &consensus.db,
            &consensus.state,
            &consensus.config.consensus,
            item.block.hash(),
        )?;
        rewards.insert(item.block.hash(), reward);
    }
    Ok(())
}

pub fn apply_for_blocks_in_epoch(
    consensus: &Consensus,
    state: &mut State,
    block: &Block,
    parent: &Block,
    committee: &[NodePublicKey],
    cumulative_gas_fee: u128,
) -> Result<()> {
    let parent_state = state.at_root(parent.state_root_hash().into());
    let grandparent_mix_hash = consensus
        .db
        .get_block(BlockFilter::Hash(parent.parent_hash()))
        .ok()
        .flatten()
        .and_then(|b| b.header.mix_hash);
    let proposer =
        Consensus::leader_at_state(&parent_state, parent, grandparent_mix_hash, block.view())
            .ok_or_else(|| {
                anyhow!(
                    "no leader for block {} view {}",
                    block.number(),
                    block.view()
                )
            })?;

    let reward = compute_reward_at(
        &parent_state,
        &consensus.config.consensus,
        committee,
        proposer.public_key,
        block,
        cumulative_gas_fee,
    )?;

    let mut rewards = consensus.rewards.lock();
    rewards.insert(block.hash(), reward);

    let blocks_per_epoch = consensus.config.consensus.blocks_per_epoch;
    if block.number().is_multiple_of(blocks_per_epoch) {
        let fork_activation_height = consensus
            .state
            .forks
            .find_height_fork_first_activated(ForkName::DistributeRewardsEveryEpoch)
            .ok_or_else(|| anyhow!("Missing activation height for DistributeRewardsEveryEpoch"))?;
        let epoch_start = block.number() - blocks_per_epoch + 1;
        let range_start = std::cmp::max(std::cmp::max(fork_activation_height, 1), epoch_start);

        rewards.apply_epoch(state, block.hash(), range_start, |h| {
            reward_from_db(
                &consensus.db,
                &consensus.state,
                &consensus.config.consensus,
                h,
            )
        })?;
    }
    Ok(())
}

fn apply_reward(state: &mut State, reward: &Reward) -> Result<u128> {
    let mut total_rewards_issued: u128 = 0;

    let (proposer_addr, proposer_amount) = reward.proposer;
    state.mutate_account(proposer_addr, |a| {
        a.balance = a
            .balance
            .checked_add(proposer_amount)
            .ok_or_else(|| anyhow!("overflow crediting proposer reward"))?;
        Ok(())
    })?;
    total_rewards_issued = total_rewards_issued
        .checked_add(proposer_amount)
        .ok_or_else(|| anyhow!("overflow accumulating total rewards"))?;

    for (addr, amount) in &reward.cosigners {
        state.mutate_account(*addr, |a| {
            a.balance = a
                .balance
                .checked_add(*amount)
                .ok_or_else(|| anyhow!("overflow crediting cosigner reward"))?;
            Ok(())
        })?;
        total_rewards_issued = total_rewards_issued
            .checked_add(*amount)
            .ok_or_else(|| anyhow!("overflow accumulating total rewards"))?;
    }

    Ok(total_rewards_issued)
}

pub fn apply_for_single_block(
    parent_block: &Block,
    at_state: &mut State,
    config: &ConsensusConfig,
    committee: &[NodePublicKey],
    proposer: NodePublicKey,
    block: &Block,
) -> Result<()> {
    debug!("apply late rewards in view {}", block.view());

    let parent_state = at_state.at_root(parent_block.state_root_hash().into());
    // Gas fees on the legacy path are handled by the caller; pass 0 here so
    // `Reward::gas_fee` is unused.
    let reward = compute_reward_at(&parent_state, config, committee, proposer, block, 0)?;
    let total_rewards_issued = apply_reward(at_state, &reward)?;

    // ZIP-9: Fund rewards amount from zero account
    at_state.mutate_account(Address::ZERO, |a| {
        a.balance = a
            .balance
            .checked_sub(total_rewards_issued)
            .ok_or(anyhow!("No funds left in zero account"))?;
        Ok(())
    })?;

    Ok(())
}
