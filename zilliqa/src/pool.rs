use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
};

use tracing::*;

use crate::{
    crypto::Hash,
    state::Address,
    transaction::{SignedTransaction, VerifiedTransaction},
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
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
            nonced_tx => {
                let nonce = match nonced_tx {
                    SignedTransaction::Legacy { tx, .. } => tx.nonce,
                    SignedTransaction::Eip2930 { tx, .. } => tx.nonce,
                    SignedTransaction::Eip1559 { tx, .. } => tx.nonce,
                    SignedTransaction::Zilliqa { tx, .. } => tx.nonce,
                    SignedTransaction::Intershard { .. } => {
                        unreachable!("Will have been matched in outer match statement.")
                    }
                };
                TxIndex::Nonced(self.signer, nonce)
            }
        }
    }
}

/// A pool that manages uncommitted transactions.
///
/// It provides transactions to the chain via [`TransactionPool::best_transaction`].
#[derive(Debug, Default)]
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
#[derive(Debug)]
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
            gas_price: txn.tx.gas_price(),
            tx_index: txn.mempool_index(),
        }
    }
}

impl TransactionPool {
    /// Pop a *ready* transaction out of the pool, maximising the gas price.
    ///
    /// Ready means that the transaction has a nonce equal to the sender's current nonce or it has a nonce that is
    /// consecutive with a previously returned transaction, from the same sender.
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

            // If we've popped a nonced transaction, that may have made a subsequent one valid
            if let Some(next) = tx_index.next().and_then(|idx| self.transactions.get(&idx)) {
                self.ready.push(next.into());
            }

            return Some(transaction);
        }
    }

    pub fn insert_transaction(&mut self, txn: VerifiedTransaction, account_nonce: u64) -> bool {
        if txn.tx.nonce().is_some_and(|n| n < account_nonce) {
            // This transaction is permanently invalid, so there is nothing to do.
            return false;
        }

        if let Some(tx_nonce) = txn.tx.nonce() {
            if let Some(existing_txn) = self
                .transactions
                .get(&TxIndex::Nonced(txn.signer, tx_nonce))
            {
                // There is already a transaction in the mempool with the same signer
                // and nonce. Only proceed if this one is better. Note that if they are
                // equally good, we prioritise the existing transaction to avoid the need
                // to broadcast a new transaction to the network.
                if ReadyItem::from(existing_txn) >= ReadyItem::from(&txn) {
                    return false;
                } else {
                    // Remove the existing transaction from `hash_to_index` if we're about to replace it.
                    self.hash_to_index.remove(&existing_txn.hash);
                }
            }
        } else {
            // now we've confirmed it's nonceless, so ensure its index isn't duplicate
            if let Some(existing_nonceless_txn) = self.transactions.get(&txn.mempool_index()) {
                warn!(tx = ?existing_nonceless_txn, "Duplicate-indexed nonceless transactions encountered, this shouldn't happen. Ignoring the new one.");
                return false;
            }
        }

        // If this transaction either has a nonce equal to the account's current nonce,
        // or no nonce at all (and is thus executable at any point),
        // then it is added to the ready heap.
        if txn.tx.nonce().is_none() || txn.tx.nonce().is_some_and(|n| n == account_nonce) {
            self.ready.push((&txn).into());
        }

        // Finally we insert it into the tx store and the hash reverse-index
        self.hash_to_index.insert(txn.hash, txn.mempool_index());
        self.transactions.insert(txn.mempool_index(), txn);

        true
    }

    pub fn get_transaction(&self, hash: Hash) -> Option<&VerifiedTransaction> {
        let tx_index = self.hash_to_index.get(&hash)?;
        self.transactions.get(tx_index)
    }

    pub fn pop_transaction(&mut self, hash: Hash) -> Option<VerifiedTransaction> {
        let tx_index = self.hash_to_index.get(&hash)?;
        self.transactions.remove(tx_index)
    }

    /// Update the pool after a transaction has been executed.
    ///
    /// It is important to call this for all executed transactions, otherwise permanently invalidated transactions
    /// will be left indefinitely in the pool.
    pub fn update_nonce(&mut self, txn: &VerifiedTransaction) {
        let Some(nonce) = txn.tx.nonce() else { return }; // nothing to do if there's no nonce

        self.transactions
            .remove(&TxIndex::Nonced(txn.signer, nonce)); // if this existed, it's now invalid
        self.hash_to_index.remove(&txn.hash); // cleanup index too

        if let Some(next_txn) = self
            .transactions
            .get(&TxIndex::Nonced(txn.signer, nonce + 1))
        {
            // if THIS exists, it's now valid
            self.ready.push(next_txn.into());
        }
    }

    /// Clear the transaction pool, returning all remaining transactions in an unspecified order.
    pub fn drain(&mut self) -> impl Iterator<Item = VerifiedTransaction> {
        self.ready.clear();
        self.hash_to_index.clear();
        std::mem::take(&mut self.transactions).into_values()
    }

    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.transactions.len()
    }
}

#[cfg(test)]
mod tests {
    use primitive_types::H160;

    use super::TransactionPool;
    use crate::{
        crypto::Hash,
        state::Address,
        transaction::{
            EthSignature, SignedTransaction, TxIntershard, TxLegacy, VerifiedTransaction,
        },
    };

    fn transaction(from_addr: Address, nonce: u8, gas_price: u128) -> VerifiedTransaction {
        VerifiedTransaction {
            tx: SignedTransaction::Legacy {
                tx: TxLegacy {
                    chain_id: Some(0),
                    nonce: nonce as u64,
                    gas_price,
                    gas_limit: 0,
                    to_addr: None,
                    amount: 0,
                    payload: vec![],
                },
                sig: EthSignature {
                    r: [0; 32],
                    s: [0; 32],
                    y_is_odd: false,
                },
            },
            signer: from_addr,
            hash: Hash::compute([from_addr.as_bytes(), &[nonce]]),
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
                    gas_limit: 0,
                    to_addr: None,
                    payload: vec![],
                },
                from: H160::zero(),
            },
            signer: H160::zero(),
            hash: Hash::compute([[shard_nonce], [from_shard]]),
        }
    }

    #[test]
    fn nonces_returned_in_order() {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        pool.insert_transaction(transaction(from, 1, 1), 0);
        pool.insert_transaction(transaction(from, 2, 2), 0);
        pool.insert_transaction(transaction(from, 0, 0), 0);

        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 0);
        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 1);
        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 2);
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
        assert_eq!(pool.size(), 5);

        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 5);
        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 3);
        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 2);
        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 1);
        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 0);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn pop_removes_transaction() {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234"
            .parse()
            .unwrap();

        assert_eq!(pool.size(), 0);
        let normal_tx = transaction(from, 0, 1);
        let xshard_tx = intershard_transaction(0, 0, 1);
        pool.insert_transaction(normal_tx.clone(), 0);
        assert_eq!(pool.size(), 1);
        pool.insert_transaction(xshard_tx.clone(), 0);
        assert_eq!(pool.size(), 2);
        assert_eq!(pool.pop_transaction(normal_tx.hash), Some(normal_tx));
        assert_eq!(pool.size(), 1);
        assert_eq!(pool.pop_transaction(xshard_tx.hash), Some(xshard_tx));
        assert_eq!(pool.size(), 0);
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

        pool.update_nonce(&transaction(from, 0, 0));

        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 1);
    }
}
