use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
};

use alloy::primitives::Address;
use anyhow::{Result, anyhow};
use tracing::{debug, warn};

use crate::{
    crypto::Hash,
    state::State,
    transaction::{SignedTransaction, ValidationOutcome, VerifiedTransaction},
};

/// The result of trying to add a transaction to the mempool. The argument is
/// a human-readable string to be returned to the user.
#[derive(Debug, Copy, Clone)]
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
#[derive(Clone, Debug, Default)]
pub struct TransactionPool {
    /// All transactions in the pool. These transactions are all valid, or might become
    /// valid at some point in the future.
    transactions: BTreeMap<TxIndex, VerifiedTransaction>,
    /// A map of transaction hash to index into `transactions`.
    /// Used for querying transactions from the pool by their hash.
    hash_to_index: BTreeMap<Hash, TxIndex>,
    /// Keeps transactions sorted by gas_price, each gas_price index can contain more than one txn
    /// These are candidates to be included in the next block
    gas_index: GasCollection,
    /// Keeps transactions created at this node that will be broadcast
    transactions_to_broadcast: VecDeque<VerifiedTransaction>,
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
                if let Some(txn) = self.transactions.get(tx_index) {
                    let tx_cost = txn.tx.maximum_validation_cost()?;
                    let account = state.must_get_account(txn.signer);

                    // We're not going to propose txn this time
                    if tx_cost > account.balance
                        || txn.tx.nonce().unwrap_or_default() > account.nonce
                    {
                        continue;
                    }

                    return Ok(Some(txn));
                } else {
                    warn!("Unable to find txn in global index!");
                    continue;
                }
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
        let mut tracked_balances = HashMap::new();

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

            let balance = if let Some(balance) = tracked_balances.get(&txn.signer) {
                *balance
            } else {
                let account = state.get_account(txn.signer)?;
                tracked_balances.insert(txn.signer, account.balance);
                account.balance
            };

            let tx_cost = txn.tx.maximum_validation_cost()?;

            if tx_cost > balance {
                continue;
            }
            tracked_balances.insert(txn.signer, balance.saturating_sub(tx_cost));
            pending_txns.push(txn);

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
        from_broadcast: bool,
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

        if let Some(existing_txn) = self.transactions.get(&txn.mempool_index()) {
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
        }

        // If this transaction either has a nonce equal to the account's current nonce,
        // or no nonce at all (and is thus executable at any point),
        // then it is added to the transactions sorted by gas_price collection.
        if txn.tx.nonce().is_none() || txn.tx.nonce().is_some_and(|n| n == account_nonce) {
            Self::add_to_gas_index(&mut self.gas_index, &txn);
        }

        // If this is a transaction created at this node, add it to broadcast vector
        if !from_broadcast {
            self.store_broadcast_txn(&txn);
        }

        debug!(
            "Txn added to mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {account_nonce}",
            txn.hash,
            txn.signer,
            txn.tx.nonce()
        );

        // Finally we insert it into the tx store and the hash reverse-index
        self.hash_to_index.insert(txn.hash, txn.mempool_index());
        self.transactions.insert(txn.mempool_index(), txn);

        TxAddResult::AddedToMempool
    }

    fn store_broadcast_txn(&mut self, txn: &VerifiedTransaction) {
        self.transactions_to_broadcast.push_back(txn.clone());
    }

    pub fn pull_txns_to_broadcast(&mut self) -> Result<Vec<SignedTransaction>> {
        const MAX_BATCH_SIZE: usize = 1000;
        const BATCH_SIZE_THRESHOLD: usize = 921 * 1024; // 90% of max_transmit_size().

        if self.transactions_to_broadcast.is_empty() {
            return Ok(Vec::new());
        }

        let mut batch_count = 0usize;
        let mut batch_size = BATCH_SIZE_THRESHOLD;

        for tx in self.transactions_to_broadcast.iter() {
            batch_size = batch_size.saturating_sub(tx.encoded_size());
            batch_count += 1;
            // batch by number or size
            if batch_size == 0 || batch_count == MAX_BATCH_SIZE {
                break;
            }
        }

        let selected = self
            .transactions_to_broadcast
            .drain(0..batch_count)
            .map(|tx| tx.tx)
            .collect();
        Ok(selected)
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
                    next_txn = self.transactions.get(index);
                    break;
                }
            }
        }
        if let Some(txn) = next_txn {
            Self::remove_from_gas_index(&mut self.gas_index, txn);
        }

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

        if let Some(next) = tx_index.next().and_then(|idx| self.transactions.get(&idx)) {
            Self::add_to_gas_index(&mut self.gas_index, next);
        }
    }

    /// Check the ready transactions in arbitrary order, for one that is Ready
    pub fn has_txn_ready(&self) -> bool {
        !self.gas_index.is_empty()
    }

    pub fn clear(&mut self) {
        self.transactions.clear();
        self.hash_to_index.clear();
        self.gas_index.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use alloy::{
        consensus::TxLegacy,
        primitives::{Address, Bytes, PrimitiveSignature, TxKind, U256},
    };
    use anyhow::Result;
    use rand::{seq::SliceRandom, thread_rng};

    use super::TransactionPool;
    use crate::{
        cfg::NodeConfig,
        crypto::Hash,
        db::Db,
        state::State,
        transaction::{EvmGas, SignedTransaction, TxIntershard, VerifiedTransaction},
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

        let db = Db::new::<PathBuf>(None, 0, 0, None)?;
        let db = Arc::new(db);

        State::new_with_genesis(db.state_trie()?, node_config, db.clone())
    }

    fn create_acc(state: &mut State, address: Address, balance: u128, nonce: u64) -> Result<()> {
        let mut acc = state.get_account(address)?;
        acc.balance = balance;
        acc.nonce = nonce;
        state.save_account(address, acc)
    }

    #[test]
    fn nonces_returned_in_order() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(transaction(from, 1, 1), 0, false);

        let tx = pool.best_transaction(&state)?;
        assert_eq!(tx, None);

        pool.insert_transaction(transaction(from, 2, 2), 0, false);
        pool.insert_transaction(transaction(from, 0, 0), 0, false);

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
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        const COUNT: u64 = 100;

        let mut nonces = (0..COUNT).collect::<Vec<_>>();
        let mut rng = thread_rng();
        nonces.shuffle(&mut rng);

        for i in 0..COUNT {
            pool.insert_transaction(transaction(from, nonces[i as usize] as u8, 3), 0, false);
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
        let mut pool = TransactionPool::default();
        let from1 = "0x0000000000000000000000000000000000000001".parse()?;
        let from2 = "0x0000000000000000000000000000000000000002".parse()?;
        let from3 = "0x0000000000000000000000000000000000000003".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from1, 100, 0)?;
        create_acc(&mut state, from2, 100, 0)?;
        create_acc(&mut state, from3, 100, 0)?;

        pool.insert_transaction(intershard_transaction(0, 0, 1), 0, false);
        pool.insert_transaction(transaction(from1, 0, 2), 0, false);
        pool.insert_transaction(transaction(from2, 0, 3), 0, false);
        pool.insert_transaction(transaction(from3, 0, 0), 0, false);
        pool.insert_transaction(intershard_transaction(0, 1, 5), 0, false);
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
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(transaction(from, 0, 0), 0, false);
        pool.insert_transaction(transaction(from, 1, 0), 0, false);

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
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(transaction(from, 0, 1), 0, false);
        pool.insert_transaction(transaction(from, 1, 200), 0, false);

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
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(intershard_transaction(0, 0, 100), 0, false);
        pool.insert_transaction(transaction(from, 0, 1), 0, false);
        pool.insert_transaction(transaction(from, 1, 1), 1, false);
        pool.insert_transaction(transaction(from, 2, 1), 2, false);
        pool.insert_transaction(transaction(from, 3, 200), 3, false);
        pool.insert_transaction(transaction(from, 10, 1), 3, false);

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
    fn benchmark_preview_content() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 1_000_000, 0)?;

        // Insert 100 pending transactions
        for nonce in 0u64..100u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), nonce, false);
        }

        // Insert 100 queued transactions
        for nonce in 101u64..201u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), 0, false);
        }

        // Benchmark the preview_content method
        let start = std::time::Instant::now();
        let content = pool.preview_content(&state)?;
        let duration = start.elapsed();

        // Verify the results
        assert_eq!(content.pending.len(), 100);
        assert_eq!(content.queued.len(), 100);

        println!(
            "Benchmark completed: preview_content took {:?} to execute.",
            duration
        );

        Ok(())
    }

    #[test]
    fn benchmark_pending_transactions() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        create_acc(&mut state, from, 1_000_000, 0)?;

        // Insert 100 pending transactions
        for nonce in 0u64..100u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), nonce, false);
        }

        // Insert 100 queued transactions
        for nonce in 101u64..201u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), 0, false);
        }

        // Benchmark the preview_content method
        let start = std::time::Instant::now();
        let _result = pool.pending_transactions(&state)?;
        let duration = start.elapsed();

        println!(
            "Benchmark completed: pending_transactions took {:?} to execute.",
            duration
        );
        Ok(())
    }
}
