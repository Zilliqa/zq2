use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap, HashSet},
};

use alloy::primitives::Address;
use tracing::debug;

use crate::{
    crypto::Hash,
    transaction::{SignedTransaction, ValidationOutcome, VerifiedTransaction},
};

/// The result of trying to add a transaction to the mempool. The argument is
/// a human-readable string to be returned to the user.
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

/// A pool that manages uncommitted transactions.
///
/// It provides transactions to the chain via [`TransactionPool::best_transaction`].
#[derive(Clone, Debug, Default)]
pub struct TransactionPool {
    /// All transactions in the pool. These transactions are all valid, or might become
    /// valid at some point in the future.
    transactions: BTreeMap<TxIndex, VerifiedTransaction>,
    /// Indices into `transactions`, sorted by gas price. This contains indices of transactions which are immediately
    /// executable, because they have a nonce equal to the account's nonce or are nonceless.
    /// It may also contain stale (invalidated) transactions, which are evicted lazily.
    ready: BinaryHeap<ReadyItem>,
    /// A map of transaction hash to index into `transactions`.
    /// Used for querying transactions from the pool by their hash.
    hash_to_index: BTreeMap<Hash, TxIndex>,
}

/// A wrapper for (gas price, sender, nonce), stored in the `ready` heap of [TransactionPool].
/// The [PartialEq], [PartialOrd] and [Ord] implementations only consider the gas price.
#[derive(Clone, Copy, Debug)]
struct ReadyItem {
    gas_price: u128,
    tx_index: TxIndex,
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
            tx_index: txn.mempool_index(),
        }
    }
}

// Represents currently pending txns for inclusion in the next block(s), as well as the ones that are being scheduled for future execution.
pub struct TxPoolContent {
    pub pending: Vec<VerifiedTransaction>,
    pub queued: Vec<VerifiedTransaction>,
}

impl TransactionPool {
    /// Pop a *ready* transaction out of the pool, maximising the gas price.
    ///
    /// Ready means that the transaction has a nonce equal to the sender's current nonce or it has a nonce that is
    /// consecutive with a previously returned transaction, from the same sender.
    ///
    /// If the returned transaction is executed, the caller must call [TransactionPool::mark_executed] to inform the
    /// pool that the account's nonce has been updated and further transactions from this signer may now be ready.
    pub fn best_transaction(&mut self) -> Option<VerifiedTransaction> {
        loop {
            let ReadyItem { tx_index, .. } = self.ready.pop()?;
            let Some(transaction) = self.transactions.remove(&tx_index) else {
                // A transaction might have been ready, but it might have gotten popped
                // or the sender's nonce might have increased, making it invalid. In this case,
                // we will have removed the transaction from `transactions` (in `update_nonce`
                // or `pop_transaction`), but a stale reference would still exist in the heap.
                //
                // We loop until we find a transaction that hasn't been made invalid.
                continue;
            };
            // Don't forget to pop the index too
            self.hash_to_index.remove(&transaction.hash);

            return Some(transaction);
        }
    }

    /// Returns a list of txns that are pending for inclusion in the next block
    pub fn pending_hashes(&self) -> Vec<Hash> {
        let mut pending_hash = Vec::<Hash>::new();
        let mut pending_set = HashSet::new();
        let mut ready = self.ready.clone();
        // Find all transactions that are pending for inclusion in the next block
        while let Some(ReadyItem { tx_index, .. }) = ready.pop() {
            // We don't include nonceless txns because the way we present results on API level requires having proper nonce
            if let TxIndex::Intershard(_, _) = tx_index {
                continue;
            }

            // A transaction might have been ready, but it might have gotten popped
            // or the sender's nonce might have increased, making it invalid. In this case,
            // we will have a stale reference would still exist in the heap.
            let Some(txn) = self.transactions.get(&tx_index) else {
                continue;
            };

            if !pending_set.insert(txn.hash) {
                continue;
            }

            pending_hash.push(txn.hash);

            let Some(next) = tx_index.next() else {
                continue;
            };

            if let Some(next_txn) = self.transactions.get(&next) {
                ready.push(next_txn.into());
            }
        }

        pending_hash
    }

    pub fn preview_content(&self) -> TxPoolContent {
        // First make a copy of 'ready' transactions
        let mut ready = self.ready.clone();

        let mut pending = Vec::new();
        let mut pending_set = HashSet::new();

        // Find all transactions that are pending for inclusion in the next block
        while let Some(ReadyItem { tx_index, .. }) = ready.pop() {
            // We don't include nonceless txns because the way we present results on API level requires having proper nonce
            if let TxIndex::Intershard(_, _) = tx_index {
                continue;
            }

            // A transaction might have been ready, but it might have gotten popped
            // or the sender's nonce might have increased, making it invalid. In this case,
            // we will have a stale reference would still exist in the heap.
            //
            let Some(txn) = self.transactions.get(&tx_index) else {
                continue;
            };

            if !pending_set.insert(&txn.hash) {
                continue;
            }

            pending.push(txn.clone());

            let Some(next) = tx_index.next() else {
                continue;
            };

            if let Some(next_txn) = self.transactions.get(&next) {
                ready.push(next_txn.into());
            }
        }

        // Find remaining transactions that are scheduled for execution in the future
        let mut queued: Vec<VerifiedTransaction> = Vec::new();

        for (index, txn) in self.transactions.iter() {
            if let TxIndex::Intershard(_, _) = index {
                continue;
            }
            if pending_set.contains(&txn.hash) {
                continue;
            }
            queued.push(txn.clone());
        }

        TxPoolContent { pending, queued }
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
    ) -> TxAddResult {
        if txn.tx.nonce().is_some_and(|n| n < account_nonce) {
            debug!("Nonce is too low. Txn hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {account_nonce}", txn.hash, txn.signer, txn.tx.nonce());
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
                debug!("Received txn with the same nonce but lower gas price. Txn hash: {:?}, from: {:?}, nonce: {:?}, gas_price: {:?}", txn.hash, txn.signer, txn.tx.nonce(), txn.tx.gas_price_per_evm_gas());
                return TxAddResult::SameNonceButLowerGasPrice;
            }
            // Remove the existing transaction from `hash_to_index` if we're about to replace it.
            self.hash_to_index.remove(&existing_txn.hash);
        }

        // If this transaction either has a nonce equal to the account's current nonce,
        // or no nonce at all (and is thus executable at any point),
        // then it is added to the ready heap.
        if txn.tx.nonce().is_none() || txn.tx.nonce().is_some_and(|n| n == account_nonce) {
            self.ready.push((&txn).into());
        }

        debug!("Txn added to mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {account_nonce}", txn.hash, txn.signer, txn.tx.nonce());

        // Finally we insert it into the tx store and the hash reverse-index
        self.hash_to_index.insert(txn.hash, txn.mempool_index());
        self.transactions.insert(txn.mempool_index(), txn);
        TxAddResult::AddedToMempool
    }

    /// Insert a transaction which the caller guarantees is ready to be mined. Breaking this guarantee will cause
    /// problems. It is likely that the only way to be sure of this guarantee is that you just obtained this
    /// transaction from `best_transaction` and have the same account state as when you made that call.
    pub fn insert_ready_transaction(&mut self, txn: VerifiedTransaction) {
        self.ready.push((&txn).into());
        self.hash_to_index.insert(txn.hash, txn.mempool_index());
        self.transactions.insert(txn.mempool_index(), txn);
    }

    pub fn get_transaction(&self, hash: Hash) -> Option<&VerifiedTransaction> {
        let tx_index = self.hash_to_index.get(&hash)?;
        self.transactions.get(tx_index)
    }

    pub fn pop_transaction(&mut self, hash: Hash) -> Option<VerifiedTransaction> {
        let tx_index = self.hash_to_index.remove(&hash)?;
        self.transactions.remove(&tx_index)
    }

    /// Update the pool after a transaction has been executed.
    ///
    /// It is important to call this for all executed transactions, otherwise permanently invalidated transactions
    /// will be left indefinitely in the pool.
    pub fn mark_executed(&mut self, txn: &VerifiedTransaction) {
        let tx_index = txn.mempool_index();
        self.transactions.remove(&tx_index);
        self.hash_to_index.remove(&txn.hash);

        if let Some(next) = tx_index.next().and_then(|idx| self.transactions.get(&idx)) {
            self.ready.push(next.into());
        }
    }

    /// Clear the transaction pool, returning all remaining transactions in an unspecified order.
    pub fn drain(&mut self) -> impl Iterator<Item = VerifiedTransaction> {
        self.ready.clear();
        self.hash_to_index.clear();
        std::mem::take(&mut self.transactions).into_values()
    }

    /// Check the ready transactions in arbitrary order, for one that is Ready
    pub fn has_txn_ready(&self) -> bool {
        for ReadyItem { tx_index, .. } in self.ready.iter() {
            // A transaction might have been ready, but it might have gotten popped
            // or the sender's nonce might have increased, making it invalid. In this case,
            // we will have a stale reference would still exist in the heap.
            let Some(_) = self.transactions.get(tx_index) else {
                continue;
            };

            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        consensus::TxLegacy,
        primitives::{Address, Bytes, Parity, Signature, TxKind, U256},
    };
    use rand::{seq::SliceRandom, thread_rng};

    use super::TransactionPool;
    use crate::{
        crypto::Hash,
        transaction::{EvmGas, SignedTransaction, TxIntershard, VerifiedTransaction},
    };

    fn transaction(from_addr: Address, nonce: u8, gas_price: u128) -> VerifiedTransaction {
        VerifiedTransaction {
            tx: SignedTransaction::Legacy {
                tx: TxLegacy {
                    chain_id: Some(0),
                    nonce: nonce as u64,
                    gas_price,
                    gas_limit: 0,
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
                sig: Signature::from_rs_and_parity(
                    U256::from(1),
                    U256::from(1),
                    Parity::Parity(false),
                )
                .unwrap(),
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

    #[test]
    fn nonces_returned_in_order() {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        pool.insert_transaction(transaction(from, 1, 1), 0);

        let tx = pool.best_transaction();
        assert_eq!(tx, None);

        pool.insert_transaction(transaction(from, 2, 2), 0);
        pool.insert_transaction(transaction(from, 0, 0), 0);

        let tx = pool.best_transaction().unwrap();
        assert_eq!(tx.tx.nonce().unwrap(), 0);
        pool.mark_executed(&tx);

        let tx = pool.best_transaction().unwrap();
        assert_eq!(tx.tx.nonce().unwrap(), 1);
        pool.mark_executed(&tx);

        let tx = pool.best_transaction().unwrap();
        assert_eq!(tx.tx.nonce().unwrap(), 2);
        pool.mark_executed(&tx);
    }

    #[test]
    fn nonces_returned_in_order_same_gas() {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        const COUNT: u64 = 100;

        let mut nonces = (0..COUNT).collect::<Vec<_>>();
        let mut rng = thread_rng();
        nonces.shuffle(&mut rng);

        for i in 0..COUNT {
            pool.insert_transaction(transaction(from, nonces[i as usize] as u8, 3), 0);
        }

        for i in 0..COUNT {
            let tx = pool.best_transaction().unwrap();
            assert_eq!(tx.tx.nonce().unwrap(), i);
            pool.mark_executed(&tx);
        }
    }

    #[test]
    fn ordered_by_gas_price() {
        let mut pool = TransactionPool::default();
        let from1 = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let from2 = "0x0000000000000000000000000000000000000002"
            .parse()
            .unwrap();
        let from3 = "0x0000000000000000000000000000000000000003"
            .parse()
            .unwrap();

        pool.insert_transaction(intershard_transaction(0, 0, 1), 0);
        pool.insert_transaction(transaction(from1, 0, 2), 0);
        pool.insert_transaction(transaction(from2, 0, 3), 0);
        pool.insert_transaction(transaction(from3, 0, 0), 0);
        pool.insert_transaction(intershard_transaction(0, 1, 5), 0);
        assert_eq!(pool.transactions.len(), 5);

        assert_eq!(
            pool.best_transaction().unwrap().tx.gas_price_per_evm_gas(),
            5
        );
        assert_eq!(
            pool.best_transaction().unwrap().tx.gas_price_per_evm_gas(),
            3
        );
        assert_eq!(
            pool.best_transaction().unwrap().tx.gas_price_per_evm_gas(),
            2
        );
        assert_eq!(
            pool.best_transaction().unwrap().tx.gas_price_per_evm_gas(),
            1
        );
        assert_eq!(
            pool.best_transaction().unwrap().tx.gas_price_per_evm_gas(),
            0
        );
        assert_eq!(pool.transactions.len(), 0);
    }

    #[test]
    fn pop_removes_transaction() {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        assert_eq!(pool.transactions.len(), 0);
        let normal_tx = transaction(from, 0, 1);
        let xshard_tx = intershard_transaction(0, 0, 1);
        pool.insert_transaction(normal_tx.clone(), 0);
        assert_eq!(pool.transactions.len(), 1);
        pool.insert_transaction(xshard_tx.clone(), 0);
        assert_eq!(pool.transactions.len(), 2);
        assert_eq!(pool.pop_transaction(normal_tx.hash), Some(normal_tx));
        assert_eq!(pool.transactions.len(), 1);
        assert_eq!(pool.pop_transaction(xshard_tx.hash), Some(xshard_tx));
        assert_eq!(pool.transactions.len(), 0);
        assert_eq!(pool.best_transaction(), None);
    }

    #[test]
    fn update_nonce_discards_invalid_transaction() {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        pool.insert_transaction(transaction(from, 0, 0), 0);
        pool.insert_transaction(transaction(from, 1, 0), 0);

        pool.mark_executed(&transaction(from, 0, 0));

        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 1);
    }

    #[test]
    fn preview_content_test() {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        pool.insert_transaction(transaction(from, 0, 1), 0);
        pool.insert_transaction(transaction(from, 1, 1), 1);
        pool.insert_transaction(transaction(from, 2, 1), 2);
        pool.insert_transaction(transaction(from, 10, 1), 3);

        let content = pool.preview_content();

        assert_eq!(content.pending.len(), 3);
        assert_eq!(content.pending[0].tx.nonce().unwrap(), 0);
        assert_eq!(content.pending[1].tx.nonce().unwrap(), 1);
        assert_eq!(content.pending[2].tx.nonce().unwrap(), 2);

        assert_eq!(content.queued.len(), 1);
        assert_eq!(content.queued[0].tx.nonce().unwrap(), 10);
    }
}
