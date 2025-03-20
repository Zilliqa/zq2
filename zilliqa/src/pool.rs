use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};

use alloy::primitives::Address;
use anyhow::{Result, anyhow};
use tracing::debug;

use crate::{
    cfg::TxnPoolConfig,
    crypto::Hash,
    pool::TxAddResult::ValidationFailed,
    state::State,
    time::SystemTime,
    transaction::{SignedTransaction, ValidationOutcome, VerifiedTransaction},
};

/// The result of trying to add a transaction to the mempool. The argument is
/// a human-readable string to be returned to the user.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TxAddResult {
    /// Transaction was successfully added to the mempool
    AddedToMempool,
    /// Transaction was a duplicate
    Duplicate(Hash),
    /// Bad signature
    CannotVerifySignature,
    /// Transaction failed to validate
    ValidationFailed(ValidationOutcome),
    /// Nonce was too low at the point we tried to actually add the txn to the pool - (got, expected)
    NonceTooLow(u64, u64),
    /// This txn has same nonce, lower gas price as one already in the mempool
    SameNonceButLowerGasPrice,
}

/// For transaction status returns
pub enum PendingOrQueued {
    Pending,
    Queued,
}

impl TxAddResult {
    pub fn was_added(&self) -> bool {
        matches!(self, Self::AddedToMempool)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TxIndex {
    /// from_address, nonce (unique for that address)
    Nonced(Address, u64),
    /// source_shard, nonce (unique for the bridge from that shard)
    Intershard(u64, u64),
}
impl TxIndex {
    fn next(&self) -> Option<TxIndex> {
        match self {
            TxIndex::Nonced(address, nonce) => Some(TxIndex::Nonced(*address, nonce + 1)),
            _ => None,
        }
    }
}

trait MempoolIndex {
    fn mempool_index(&self) -> TxIndex;
}

impl MempoolIndex for VerifiedTransaction {
    fn mempool_index(&self) -> TxIndex {
        match &self.tx {
            SignedTransaction::Intershard { tx, .. } => {
                TxIndex::Intershard(tx.source_chain, tx.bridge_nonce)
            }
            tx => {
                let Some(nonce) = tx.nonce() else {
                    unreachable!("intershard matched by outer expression")
                };
                TxIndex::Nonced(self.signer, nonce)
            }
        }
    }
}

type GasCollection = BTreeMap<u128, BTreeSet<TxIndex>>;

/// A pool that manages uncommitted transactions.
///
/// It provides transactions to the chain via [`TransactionPool::best_transaction`].
#[derive(Clone, Debug)]
pub struct TransactionPool {
    config: TxnPoolConfig,
    /// All transactions in the pool. These transactions are all valid, or might become
    /// valid at some point in the future.
    transactions: BTreeMap<TxIndex, VerifiedTransaction>,
    /// A map of transaction hash to index into `transactions`.
    /// Used for querying transactions from the pool by their hash.
    hash_to_index: BTreeMap<Hash, TxIndex>,
    /// Keeps transactions sorted by gas_price, each gas_price index can contain more than one txn
    /// These are candidates to be included in the next block
    gas_index: GasCollection,
    /// Tracks number of transactions per sender
    sender_txn_counter: HashMap<Address, u64>,
    /// Keeps track of timestamp and txn hash when transaction was added
    insertion_times: BTreeSet<(SystemTime, Hash)>,
}

impl TransactionPool {
    pub fn new(config: TxnPoolConfig) -> Self {
        Self {
            config,
            transactions: BTreeMap::new(),
            hash_to_index: BTreeMap::new(),
            gas_index: GasCollection::new(),
            sender_txn_counter: HashMap::new(),
            insertion_times: BTreeSet::new(),
        }
    }
}

/// A wrapper for (gas price, sender, nonce), stored in the `ready` heap of [TransactionPool].
/// The [PartialEq], [PartialOrd] and [Ord] implementations only consider the gas price.
#[derive(Clone, Copy, Debug)]
struct ReadyItem {
    gas_price: u128,
}

impl PartialEq for ReadyItem {
    fn eq(&self, other: &Self) -> bool {
        self.gas_price == other.gas_price
    }
}

impl Eq for ReadyItem {}

impl PartialOrd for ReadyItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReadyItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.gas_price.cmp(&other.gas_price)
    }
}

impl From<&VerifiedTransaction> for ReadyItem {
    fn from(txn: &VerifiedTransaction) -> Self {
        ReadyItem {
            gas_price: txn.tx.gas_price_per_evm_gas(),
        }
    }
}

// Represents currently pending txns for inclusion in the next block(s), as well as the ones that are being scheduled for future execution.
pub struct TxPoolContent<'a> {
    pub pending: Vec<&'a VerifiedTransaction>,
    pub queued: Vec<&'a VerifiedTransaction>,
}

impl TransactionPool {
    /// Pop a *ready* transaction out of the pool, maximising the gas price.
    ///
    /// Ready means that the transaction has a nonce equal to the sender's current nonce or it has a nonce that is
    /// consecutive with a previously returned transaction, from the same sender.
    ///
    /// If the returned transaction is executed, the caller must call [TransactionPool::mark_executed] to inform the
    /// pool that the account's nonce has been updated and further transactions from this signer may now be ready.
    pub fn best_transaction(&self, state: &State) -> Result<Option<&VerifiedTransaction>> {
        for (_, gas_txns) in self.gas_index.iter().rev() {
            let same_price_iter = gas_txns.iter();
            for tx_index in same_price_iter {
                let txn = self
                    .transactions
                    .get(tx_index)
                    .ok_or(anyhow!("Unable to find txn in global index!"))?;

                let tx_cost = txn.tx.maximum_validation_cost()?;
                let account = state.must_get_account(txn.signer);

                // We're not going to propose txn this time
                if tx_cost > account.balance || txn.tx.nonce().unwrap_or_default() > account.nonce {
                    continue;
                }

                return Ok(Some(txn));
            }
        }
        Ok(None)
    }

    /// Returns whether the transaction is pending or queued
    pub fn get_pending_or_queued(
        &self,
        state: &State,
        txn: &VerifiedTransaction,
    ) -> Result<Option<PendingOrQueued>> {
        if txn.tx.nonce() == Some(state.get_account(txn.signer)?.nonce) || txn.tx.nonce().is_none()
        {
            Ok(Some(PendingOrQueued::Pending))
        } else if self.hash_to_index.contains_key(&txn.hash) {
            Ok(Some(PendingOrQueued::Queued))
        } else {
            Ok(None)
        }
    }

    /// Returns a list of txns that are pending for inclusion in the next block
    pub fn pending_transactions(&self, state: &State) -> Result<Vec<&VerifiedTransaction>> {
        // Keeps track of [account, cumulative_txns_cost]
        let mut tracked_accounts = HashMap::new();

        let mut ready = self.gas_index.clone();

        let mut pending_txns = Vec::new();

        // Find all transactions that are pending for inclusion in the next block
        while !ready.is_empty() {
            // It's safe to unwrap since ready must have at least one non-empty same-gas-price set
            let tx_index = *ready.iter().next_back().unwrap().1.iter().next().unwrap();

            let txn = self
                .transactions
                .get(&tx_index)
                .ok_or(anyhow!("Unable to find transaction in global index!"))?;

            Self::remove_from_gas_index(&mut ready, txn);

            let cum_cost = tracked_accounts
                .get(&txn.signer)
                .cloned()
                .unwrap_or(u128::default());

            let tx_cost = txn.tx.maximum_validation_cost()?;

            if cum_cost + tx_cost > state.get_account(txn.signer)?.balance {
                continue;
            }

            pending_txns.push(txn);
            tracked_accounts.insert(txn.signer, cum_cost + tx_cost);

            let Some(next) = tx_index.next() else {
                continue;
            };

            if let Some(next_txn) = self.transactions.get(&next) {
                Self::add_to_gas_index(&mut ready, next_txn);
            }
        }

        Ok(pending_txns)
    }

    pub fn preview_content(&self, state: &State) -> Result<TxPoolContent> {
        let mut pending = self.pending_transactions(state)?;
        let mut pending_hashes = BTreeSet::new();

        // Remove intershard txns and fill pending_hashes for lookups
        pending.retain(|txn| match &txn.tx {
            SignedTransaction::Intershard { .. } => false,
            _ => {
                pending_hashes.insert(txn.hash);
                true
            }
        });

        // Find remaining transactions that are scheduled for execution in the future
        let mut queued: Vec<&VerifiedTransaction> = Vec::new();

        for (index, txn) in self.transactions.iter() {
            if let TxIndex::Intershard(_, _) = index {
                continue;
            }
            if pending_hashes.contains(&txn.hash) {
                continue;
            }
            queued.push(txn);
        }

        Ok(TxPoolContent { pending, queued })
    }

    pub fn pending_transaction_count(&self, account: Address, mut account_nonce: u64) -> u64 {
        while self
            .transactions
            .contains_key(&TxIndex::Nonced(account, account_nonce))
        {
            account_nonce += 1;
        }

        account_nonce
    }

    /// Returns a pair (did_we_add_it, message).
    /// If we return false, it's safe to say that txn validation failed.
    pub fn insert_transaction(
        &mut self,
        txn: VerifiedTransaction,
        account_nonce: u64,
        now: SystemTime,
    ) -> TxAddResult {
        if txn.tx.nonce().is_some_and(|n| n < account_nonce) {
            debug!(
                "Nonce is too low. Txn hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {account_nonce}",
                txn.hash,
                txn.signer,
                txn.tx.nonce()
            );
            // This transaction is permanently invalid, so there is nothing to do.
            // unwrap() is safe because we checked above that it was some().
            return TxAddResult::NonceTooLow(txn.tx.nonce().unwrap(), account_nonce);
        }

        let is_replacement = if let Some(existing_txn) = self.transactions.get(&txn.mempool_index())
        {
            // Only proceed if the new transaction is better. Note that if they are
            // equally good, we prioritise the existing transaction to avoid the need
            // to broadcast a new transaction to the network.
            // N.B.: This will in theory never affect intershard/nonceless transactions - since
            // with the current bridge design it is not possible to broadcast a different one while
            // keeping the same nonce. So for those, it will always discard the new (identical)
            // one.
            if ReadyItem::from(existing_txn) >= ReadyItem::from(&txn) {
                debug!(
                    "Received txn with the same nonce but lower gas price. Txn hash: {:?}, from: {:?}, nonce: {:?}, gas_price: {:?}",
                    txn.hash,
                    txn.signer,
                    txn.tx.nonce(),
                    txn.tx.gas_price_per_evm_gas()
                );
                return TxAddResult::SameNonceButLowerGasPrice;
            }

            Self::remove_from_gas_index(&mut self.gas_index, existing_txn);
            // Remove the existing transaction from `hash_to_index` if we're about to replace it.
            self.hash_to_index.remove(&existing_txn.hash);
            // Decrease the count of transactions tracked by this sender
            self.decrease_counter_for_user(existing_txn.signer);
            true
        } else {
            false
        };

        // If it's a transaction that will increase the count in the pool
        if !is_replacement {
            // Check global counter
            if self.transactions.len() + 1 > self.config.maximum_global_size as usize {
                return ValidationFailed(ValidationOutcome::GlobalTransactionCountExceeded);
            }
            // Check total number of slots for senders
            if !self.sender_txn_counter.contains_key(&txn.signer)
                && self.sender_txn_counter.len() + 1
                    > self.config.total_slots_for_all_senders as usize
            {
                return ValidationFailed(ValidationOutcome::TotalNumberOfSlotsExceeded);
            }
            // Check per sender counter
            let sender_counter = self
                .sender_txn_counter
                .get(&txn.signer)
                .copied()
                .unwrap_or_default();
            if sender_counter + 1 > self.config.maximum_txn_count_per_sender {
                return ValidationFailed(ValidationOutcome::TransactionCountExceededForSender);
            }
        }

        // If this transaction either has a nonce equal to the account's current nonce,
        // or no nonce at all (and is thus executable at any point),
        // then it is added to the transactions sorted by gas_price collection.
        if txn.tx.nonce().is_none() || txn.tx.nonce().is_some_and(|n| n == account_nonce) {
            Self::add_to_gas_index(&mut self.gas_index, &txn);
        }

        debug!(
            "Txn added to mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {account_nonce}",
            txn.hash,
            txn.signer,
            txn.tx.nonce()
        );

        // Increase the counter for a sender
        *self.sender_txn_counter.entry(txn.signer).or_insert(0) += 1;
        // Finally we insert it into the tx store and the hash reverse-index
        self.hash_to_index.insert(txn.hash, txn.mempool_index());
        self.insertion_times.insert((now, txn.hash));
        self.transactions.insert(txn.mempool_index(), txn);
        TxAddResult::AddedToMempool
    }

    fn remove_from_gas_index(gas_index: &mut GasCollection, txn: &VerifiedTransaction) {
        let gas_key = txn.tx.gas_price_per_evm_gas();

        let Some(same_gas_txns) = gas_index.get_mut(&gas_key) else {
            return;
        };

        same_gas_txns.remove(&txn.mempool_index());
        if same_gas_txns.is_empty() {
            gas_index.remove(&gas_key);
        }
    }

    fn add_to_gas_index(gas_index: &mut GasCollection, txn: &VerifiedTransaction) {
        let gas_key = txn.tx.gas_price_per_evm_gas();

        gas_index
            .entry(gas_key)
            .and_modify(|existing| {
                existing.insert(txn.mempool_index());
            })
            .or_insert_with(|| {
                let mut set = BTreeSet::new();
                set.insert(txn.mempool_index());
                set
            });
    }

    /// Insert a transaction which the caller guarantees is ready to be mined. Breaking this guarantee will cause
    /// problems. It is likely that the only way to be sure of this guarantee is that you just obtained this
    /// transaction from `best_transaction` and have the same account state as when you made that call.
    pub fn insert_ready_transaction(&mut self, txn: VerifiedTransaction) -> Result<()> {
        if let SignedTransaction::Intershard { .. } = &txn.tx {
            Self::add_to_gas_index(&mut self.gas_index, &txn);
            self.hash_to_index.insert(txn.hash, txn.mempool_index());
            self.transactions.insert(txn.mempool_index(), txn);
            return Ok(());
        }

        // Remove txn with a higher nonce from ready set before plugging this one back
        let next_index = TxIndex::Nonced(txn.signer, txn.tx.nonce().unwrap() + 1);
        let mut next_txn = None;
        for (_, gas_price_set) in self.gas_index.iter() {
            for index in gas_price_set.iter() {
                if next_index == *index {
                    next_txn = Some(
                        self.transactions
                            .get(index)
                            .ok_or(anyhow!("Unable to find txn in global index!"))?,
                    );
                    break;
                }
            }
        }
        if let Some(txn) = next_txn {
            Self::remove_from_gas_index(&mut self.gas_index, txn);
        }

        *self.sender_txn_counter.entry(txn.signer).or_insert(0) += 1;
        Self::add_to_gas_index(&mut self.gas_index, &txn);
        self.hash_to_index.insert(txn.hash, txn.mempool_index());
        self.transactions.insert(txn.mempool_index(), txn);
        Ok(())
    }

    pub fn get_transaction(&self, hash: Hash) -> Option<&VerifiedTransaction> {
        let tx_index = self.hash_to_index.get(&hash)?;
        self.transactions.get(tx_index)
    }

    /// Update the pool after a transaction has been executed.
    ///
    /// It is important to call this for all executed transactions, otherwise permanently invalidated transactions
    /// will be left indefinitely in the pool.
    pub fn mark_executed(&mut self, txn: &VerifiedTransaction) {
        let tx_index = txn.mempool_index();
        self.transactions.remove(&tx_index);
        self.hash_to_index.remove(&txn.hash);
        Self::remove_from_gas_index(&mut self.gas_index, txn);

        self.decrease_counter_for_user(txn.signer);
        if let Some(next) = tx_index.next().and_then(|idx| self.transactions.get(&idx)) {
            Self::add_to_gas_index(&mut self.gas_index, next);
        }
    }

    fn decrease_counter_for_user(&mut self, sender: Address) {
        if let Some(counter) = self.sender_txn_counter.get_mut(&sender) {
            *counter = counter.saturating_sub(1);
            if *counter == 0 {
                self.sender_txn_counter.remove(&sender);
            }
        }
    }

    /// Remove expired transactions
    pub fn remove_expired(&mut self, now: SystemTime) -> Result<()> {
        let cutoff = now
            .checked_sub(Duration::from_secs(
                3600 * self.config.remove_expired_txns_after_hrs,
            ))
            .ok_or(anyhow!("Error while calculating cutoff point"))?;
        let expired_items = self
            .insertion_times
            .iter()
            .take_while(|(insertion_time, _)| insertion_time < &cutoff)
            .cloned()
            .collect::<Vec<_>>();
        for expired in expired_items {
            self.insertion_times.remove(&expired);
            if let Some(tx_index) = self.hash_to_index.get(&expired.1) {
                if let Some(txn) = self.transactions.remove(tx_index) {
                    self.mark_executed(&txn);
                }
            }
        }

        Ok(())
    }

    /// Check the ready transactions in arbitrary order, for one that is Ready
    pub fn has_txn_ready(&self) -> bool {
        !self.gas_index.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::Add, path::PathBuf, sync::Arc, time::Duration};

    use alloy::{
        consensus::TxLegacy,
        primitives::{Address, Bytes, PrimitiveSignature, TxKind, U256},
    };
    use anyhow::Result;
    use rand::{seq::SliceRandom, thread_rng};

    use super::{TransactionPool, TxAddResult};
    use crate::{
        cfg::{NodeConfig, TxnPoolConfig},
        crypto::Hash,
        db::Db,
        state::State,
        time::SystemTime,
        transaction::{
            EvmGas, SignedTransaction, TxIntershard, ValidationOutcome, VerifiedTransaction,
        },
    };

    fn transaction(from_addr: Address, nonce: u8, gas_price: u128) -> VerifiedTransaction {
        VerifiedTransaction {
            tx: SignedTransaction::Legacy {
                tx: TxLegacy {
                    chain_id: Some(0),
                    nonce: nonce as u64,
                    gas_price,
                    gas_limit: 1,
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
                sig: PrimitiveSignature::new(U256::from(1), U256::from(1), false),
            },
            signer: from_addr,
            hash: Hash::builder()
                .with(from_addr.as_slice())
                .with([nonce])
                .finalize(),
        }
    }

    fn intershard_transaction(
        from_shard: u8,
        shard_nonce: u8,
        gas_price: u128,
    ) -> VerifiedTransaction {
        VerifiedTransaction {
            tx: SignedTransaction::Intershard {
                tx: TxIntershard {
                    chain_id: 0,
                    bridge_nonce: shard_nonce as u64,
                    source_chain: from_shard as u64,
                    gas_price,
                    gas_limit: EvmGas(0),
                    to_addr: None,
                    payload: vec![],
                },
                from: Address::ZERO,
            },
            signer: Address::ZERO,
            hash: Hash::builder()
                .with([shard_nonce])
                .with([from_shard])
                .finalize(),
        }
    }

    fn get_in_memory_state() -> Result<State> {
        let node_config = NodeConfig::default();

        let db = Db::new::<PathBuf>(None, 0, 0)?;
        let db = Arc::new(db);

        State::new_with_genesis(db.state_trie()?, node_config, db.clone())
    }

    fn create_acc(state: &mut State, address: Address, balance: u128, nonce: u64) -> Result<()> {
        let mut acc = state.get_account(address)?;
        acc.balance = balance;
        acc.nonce = nonce;
        state.save_account(address, acc)
    }

    fn get_pool() -> TransactionPool {
        let config = TxnPoolConfig {
            maximum_txn_count_per_sender: 5,
            maximum_global_size: 10,
            total_slots_for_all_senders: 5,
            remove_expired_txns_after_hrs: 24,
        };
        TransactionPool::new(config)
    }

    #[test]
    fn nonces_returned_in_order() -> Result<()> {
        let mut pool = get_pool();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(transaction(from, 1, 1), 0, SystemTime::now());

        let tx = pool.best_transaction(&state)?;
        assert_eq!(tx, None);

        pool.insert_transaction(transaction(from, 2, 2), 0, SystemTime::now());
        pool.insert_transaction(transaction(from, 0, 0), 0, SystemTime::now());

        let tx = pool.best_transaction(&state)?.unwrap().clone();
        assert_eq!(tx.tx.nonce().unwrap(), 0);
        pool.mark_executed(&tx);
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;

        let tx = pool.best_transaction(&state)?.unwrap().clone();
        assert_eq!(tx.tx.nonce().unwrap(), 1);
        pool.mark_executed(&tx);
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;

        let tx = pool.best_transaction(&state)?.unwrap().clone();
        assert_eq!(tx.tx.nonce().unwrap(), 2);
        pool.mark_executed(&tx);
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn nonces_returned_in_order_same_gas() -> Result<()> {
        let mut pool = get_pool();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        const COUNT: u64 = 5;

        let mut nonces = (0..COUNT).collect::<Vec<_>>();
        let mut rng = thread_rng();
        nonces.shuffle(&mut rng);

        for i in 0..COUNT {
            pool.insert_transaction(
                transaction(from, nonces[i as usize] as u8, 3),
                0,
                SystemTime::now(),
            );
        }

        for i in 0..COUNT {
            let tx = pool.best_transaction(&state)?.unwrap().clone();
            assert_eq!(tx.tx.nonce().unwrap(), i);
            pool.mark_executed(&tx);
            state.mutate_account(from, |acc| {
                acc.nonce += 1;
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn ordered_by_gas_price() -> Result<()> {
        let mut pool = get_pool();
        let from1 = "0x0000000000000000000000000000000000000001".parse()?;
        let from2 = "0x0000000000000000000000000000000000000002".parse()?;
        let from3 = "0x0000000000000000000000000000000000000003".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from1, 100, 0)?;
        create_acc(&mut state, from2, 100, 0)?;
        create_acc(&mut state, from3, 100, 0)?;

        pool.insert_transaction(intershard_transaction(0, 0, 1), 0, SystemTime::now());
        pool.insert_transaction(transaction(from1, 0, 2), 0, SystemTime::now());
        pool.insert_transaction(transaction(from2, 0, 3), 0, SystemTime::now());
        pool.insert_transaction(transaction(from3, 0, 0), 0, SystemTime::now());
        pool.insert_transaction(intershard_transaction(0, 1, 5), 0, SystemTime::now());
        assert_eq!(pool.transactions.len(), 5);

        let tx = pool.best_transaction(&state)?.unwrap().clone();
        assert_eq!(tx.tx.gas_price_per_evm_gas(), 5);
        pool.mark_executed(&tx);
        let tx = pool.best_transaction(&state)?.unwrap().clone();
        assert_eq!(tx.tx.gas_price_per_evm_gas(), 3);

        pool.mark_executed(&tx);
        let tx = pool.best_transaction(&state)?.unwrap().clone();

        assert_eq!(tx.tx.gas_price_per_evm_gas(), 2);
        pool.mark_executed(&tx);
        let tx = pool.best_transaction(&state)?.unwrap().clone();

        assert_eq!(tx.tx.gas_price_per_evm_gas(), 1);
        pool.mark_executed(&tx);
        let tx = pool.best_transaction(&state)?.unwrap().clone();

        assert_eq!(tx.tx.gas_price_per_evm_gas(), 0);
        pool.mark_executed(&tx);

        assert_eq!(pool.transactions.len(), 0);
        Ok(())
    }

    #[test]
    fn update_nonce_discards_invalid_transaction() -> Result<()> {
        let mut pool = get_pool();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(transaction(from, 0, 0), 0, SystemTime::now());
        pool.insert_transaction(transaction(from, 1, 0), 0, SystemTime::now());

        pool.mark_executed(&transaction(from, 0, 0));
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;

        assert_eq!(
            pool.best_transaction(&state)?.unwrap().tx.nonce().unwrap(),
            1
        );
        Ok(())
    }

    #[test]
    fn too_expensive_tranactions_are_not_proposed() -> Result<()> {
        let mut pool = get_pool();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(transaction(from, 0, 1), 0, SystemTime::now());
        pool.insert_transaction(transaction(from, 1, 200), 0, SystemTime::now());

        assert_eq!(
            pool.best_transaction(&state)?.unwrap().tx.nonce().unwrap(),
            0
        );
        pool.mark_executed(&transaction(from, 0, 1));
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;

        // Sender has insufficient funds at this point
        assert_eq!(pool.best_transaction(&state)?, None);

        // Increase funds of sender to satisfy txn fee
        let mut acc = state.must_get_account(from);
        acc.balance = 500;
        state.save_account(from, acc)?;

        assert_eq!(
            pool.best_transaction(&state)?.unwrap().tx.nonce().unwrap(),
            1
        );
        Ok(())
    }

    #[test]
    fn preview_content_test() -> Result<()> {
        let mut pool = get_pool();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(intershard_transaction(0, 0, 100), 0, SystemTime::now());
        pool.insert_transaction(transaction(from, 0, 1), 0, SystemTime::now());
        pool.insert_transaction(transaction(from, 1, 1), 1, SystemTime::now());
        pool.insert_transaction(transaction(from, 2, 1), 2, SystemTime::now());
        pool.insert_transaction(transaction(from, 3, 200), 3, SystemTime::now());
        pool.insert_transaction(transaction(from, 10, 1), 3, SystemTime::now());

        let content = pool.preview_content(&state)?;

        assert_eq!(content.pending.len(), 3);
        assert_eq!(content.pending[0].tx.nonce().unwrap(), 0);
        assert_eq!(content.pending[1].tx.nonce().unwrap(), 1);
        assert_eq!(content.pending[2].tx.nonce().unwrap(), 2);

        assert_eq!(content.queued.len(), 2);
        assert_eq!(content.queued[0].tx.nonce().unwrap(), 3);
        assert_eq!(content.queued[1].tx.nonce().unwrap(), 10);

        Ok(())
    }

    #[test]
    fn global_counter_exceeded() -> Result<()> {
        let mut pool = get_pool();

        let mut state = get_in_memory_state()?;

        const COUNT: usize = 5;

        let addresses = std::iter::repeat_with(|| Address::random())
            .take(COUNT)
            .collect::<Vec<_>>();

        for address in addresses.iter() {
            create_acc(&mut state, *address, 100, 0)?;
            for nonce in 0..2 {
                assert_eq!(
                    TxAddResult::AddedToMempool,
                    pool.insert_transaction(transaction(*address, nonce, 1), 0, SystemTime::now())
                );
            }
        }

        // Can't add the following one due to global limit being exceeded
        let rand_addr = Address::random();
        create_acc(&mut state, rand_addr, 100, 0)?;
        assert_eq!(
            TxAddResult::ValidationFailed(ValidationOutcome::GlobalTransactionCountExceeded),
            pool.insert_transaction(transaction(rand_addr, 0, 1), 0, SystemTime::now())
        );

        // Remove all txns sent by one sender
        pool.mark_executed(&transaction(addresses[0], 0, 1));
        pool.mark_executed(&transaction(addresses[0], 1, 1));
        // And try to insert again - it should succeed
        assert_eq!(
            TxAddResult::AddedToMempool,
            pool.insert_transaction(transaction(rand_addr, 0, 1), 0, SystemTime::now())
        );

        Ok(())
    }

    #[test]
    fn per_sender_counter_exceeded() -> Result<()> {
        let mut pool = get_pool();

        let mut state = get_in_memory_state()?;

        const COUNT: u8 = 5;

        let address = Address::random();
        create_acc(&mut state, address, 100, 0)?;

        for nonce in 0..COUNT {
            assert_eq!(
                TxAddResult::AddedToMempool,
                pool.insert_transaction(transaction(address, nonce, 1), 0, SystemTime::now())
            );
        }

        // Can't add the following one due to per user limit being exceeded
        assert_eq!(
            TxAddResult::ValidationFailed(ValidationOutcome::TransactionCountExceededForSender),
            pool.insert_transaction(transaction(address, COUNT, 1), 0, SystemTime::now())
        );

        // Remove a single txn
        pool.mark_executed(&transaction(address, 0, 1));
        // And try to insert again - it should succeed
        assert_eq!(
            TxAddResult::AddedToMempool,
            pool.insert_transaction(transaction(address, COUNT, 1), 0, SystemTime::now())
        );

        Ok(())
    }

    #[test]
    fn replacement_not_affect_counter() -> Result<()> {
        let mut pool = get_pool();

        let mut state = get_in_memory_state()?;

        const COUNT: u8 = 5;

        let address = Address::random();
        create_acc(&mut state, address, 100, 0)?;

        for nonce in 0..COUNT {
            assert_eq!(
                TxAddResult::AddedToMempool,
                pool.insert_transaction(transaction(address, nonce, 1), 0, SystemTime::now())
            );
        }

        // Can't add the following one due to per user limit being exceeded
        assert_eq!(
            TxAddResult::ValidationFailed(ValidationOutcome::TransactionCountExceededForSender),
            pool.insert_transaction(transaction(address, COUNT, 1), 0, SystemTime::now())
        );

        // Try replacing existing one with higher gas price
        assert_eq!(
            TxAddResult::AddedToMempool,
            pool.insert_transaction(transaction(address, 0, 2), 0, SystemTime::now())
        );

        Ok(())
    }

    #[test]
    fn total_slots_per_senders_exceeded() -> Result<()> {
        let mut pool = get_pool();

        let mut state = get_in_memory_state()?;

        const COUNT: usize = 5;

        let addresses = std::iter::repeat_with(|| Address::random())
            .take(COUNT)
            .collect::<Vec<_>>();

        for address in addresses.iter() {
            create_acc(&mut state, *address, 100, 0)?;
            assert_eq!(
                TxAddResult::AddedToMempool,
                pool.insert_transaction(transaction(*address, 0, 1), 0, SystemTime::now())
            );
        }

        // Can't add the following one due to total number of slots per all senders being exceeded
        let rand_addr = Address::random();
        create_acc(&mut state, rand_addr, 100, 0)?;
        assert_eq!(
            TxAddResult::ValidationFailed(ValidationOutcome::TotalNumberOfSlotsExceeded),
            pool.insert_transaction(transaction(rand_addr, 0, 1), 0, SystemTime::now())
        );

        // Remove a single txn
        pool.mark_executed(&transaction(addresses[0], 0, 1));
        // And try to insert again - it should succeed
        assert_eq!(
            TxAddResult::AddedToMempool,
            pool.insert_transaction(transaction(rand_addr, 0, 1), 0, SystemTime::now())
        );

        Ok(())
    }

    #[test]
    fn expired_txns_are_removed() -> Result<()> {
        let mut pool = get_pool();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        let now = SystemTime::UNIX_EPOCH;

        pool.insert_transaction(transaction(from, 0, 1), 0, now);

        let tx = pool.best_transaction(&state)?;
        assert!(tx.is_some());

        let cutoff_time = now.add(Duration::from_secs(3601 * 24));

        pool.insert_transaction(
            transaction(from, 1, 1),
            0,
            cutoff_time.add(Duration::from_secs(1)),
        );

        pool.remove_expired(cutoff_time)?;

        assert_eq!(pool.transactions.len(), 1);

        pool.remove_expired(cutoff_time.add(Duration::from_secs(3601 * 24)))?;

        assert_eq!(pool.transactions.len(), 0);

        Ok(())
    }
}
