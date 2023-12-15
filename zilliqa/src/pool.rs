use std::{
    cmp::Ordering,
    collections::{BTreeMap, BinaryHeap},
};

use crate::{crypto::Hash, state::Address, transaction::VerifiedTransaction};

/// A pool that manages uncommitted transactions.
///
/// It provides transactions to the chain via [`TransactionPool::best_transaction`].
#[derive(Debug, Default)]
pub struct TransactionPool {
    /// All transactions in the pool, indexed by (sender, nonce). These transactions are all valid, or might become
    /// valid at some point in the future.
    transactions: BTreeMap<(Address, u64), VerifiedTransaction>,
    /// Indices into `transactions`, sorted by gas price. This contains indices of transactions which are immediately
    /// executable, because they have a nonce equal to the account's nonce.
    ready: BinaryHeap<ReadyItem>,
    /// A map of transaction hash to index into `transactions`. Used for querying transactions from the pool by their
    /// hash.
    hash_to_index: BTreeMap<Hash, (Address, u64)>,
}

/// A wrapper for (gas price, sender, nonce), stored in the `ready` heap of [TransactionPool].
/// The [PartialEq], [PartialOrd] and [Ord] implementations only consider the gas price.
#[derive(Debug)]
struct ReadyItem {
    gas_price: u128,
    from_addr: Address,
    nonce: u64,
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
            from_addr: txn.signer,
            nonce: txn.tx.nonce(),
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
            let Some(ReadyItem {
                from_addr, nonce, ..
            }) = self.ready.pop()
            else {
                return None;
            };
            let Some(transaction) = self.transactions.remove(&(from_addr, nonce)) else {
                // A transaction might have been ready, but then we learnt that the sender's nonce increased, making it
                // invalid. In this case, we will have removed the transaction from `transactions` in `update_nonce`.
                // We loop until we find a transaction that hasn't been made invalid.
                continue;
            };
            self.hash_to_index.remove(&transaction.hash);

            if let Some(next_txn) = self.transactions.get(&(from_addr, nonce + 1)) {
                self.ready.push(next_txn.into());
            }

            return Some(transaction);
        }
    }

    pub fn insert_transaction(&mut self, txn: VerifiedTransaction, account_nonce: u64) -> bool {
        if txn.tx.nonce() < account_nonce {
            // This transaction is permanently invalid, so there is nothing to do.
            return false;
        }

        if let Some(existing_txn) = self.transactions.get(&(txn.signer, txn.tx.nonce())) {
            // There is already a transaction in the mempool with the same signer and nonce. Only proceed if this one
            // is better. Note that if they are equally good, we prioritise the existing transaction to avoid the need
            // to broadcast a new transaction to the network.
            if ReadyItem::from(existing_txn) >= ReadyItem::from(&txn) {
                return false;
            } else {
                // Remove the existing transaction from `hash_to_index` if we're about to replace it.
                self.hash_to_index.remove(&existing_txn.hash);
            }
        }

        if txn.tx.nonce() == account_nonce {
            // This transaction has a nonce equal to the account's current nonce, so it is ready to be executed.
            self.ready.push((&txn).into());
        }

        self.hash_to_index
            .insert(txn.hash, (txn.signer, txn.tx.nonce()));
        self.transactions.insert((txn.signer, txn.tx.nonce()), txn);

        true
    }

    pub fn get_transaction(&self, hash: Hash) -> Option<&VerifiedTransaction> {
        let Some((addr, nonce)) = self.hash_to_index.get(&hash) else {
            return None;
        };

        self.transactions.get(&(*addr, *nonce))
    }

    /// Update the pool after a transaction has been executed.
    ///
    /// It is important to call this for all executed transactions, otherwise permanently invalidated transactions
    /// will be left indefinitely in the pool.
    pub fn update_nonce(&mut self, txn: &VerifiedTransaction) {
        // Remove a transaction from this sender with the previous nonce, if it exists.
        self.transactions.remove(&(txn.signer, txn.tx.nonce()));

        if let Some(next_txn) = self.transactions.get(&(txn.signer, txn.tx.nonce() + 1)) {
            self.ready.push(next_txn.into());
        }
    }

    /// Clear the transaction pool, returning all remaining transactions in an unspecified order.
    pub fn drain(&mut self) -> impl Iterator<Item = VerifiedTransaction> {
        self.ready.clear();
        self.hash_to_index.clear();
        std::mem::take(&mut self.transactions).into_values()
    }
}

#[cfg(test)]
mod tests {
    use super::TransactionPool;
    use crate::{
        crypto::Hash,
        state::Address,
        transaction::{EthSignature, SignedTransaction, TxLegacy, VerifiedTransaction},
    };

    fn transaction(from_addr: Address, nonce: u64, gas_price: u128) -> VerifiedTransaction {
        VerifiedTransaction {
            tx: SignedTransaction::Legacy {
                tx: TxLegacy {
                    chain_id: Some(0),
                    nonce,
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
            hash: Hash::ZERO,
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

        assert_eq!(pool.best_transaction().unwrap().tx.nonce(), 0);
        assert_eq!(pool.best_transaction().unwrap().tx.nonce(), 1);
        assert_eq!(pool.best_transaction().unwrap().tx.nonce(), 2);
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

        pool.insert_transaction(transaction(from1, 0, 1), 0);
        pool.insert_transaction(transaction(from2, 0, 2), 0);
        pool.insert_transaction(transaction(from3, 0, 0), 0);

        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 2);
        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 1);
        assert_eq!(pool.best_transaction().unwrap().tx.gas_price(), 0);
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

        assert_eq!(pool.best_transaction().unwrap().tx.nonce(), 1);
    }
}
