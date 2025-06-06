use std::{
    cmp::min,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    ops::Bound::*,
};

use alloy::primitives::Address;
use anyhow::Result;
use itertools::Itertools;
use tracing::debug;

use crate::{
    crypto::Hash,
    state::{Account, State},
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct PendingQueueKey {
    // Field order is crucial here since we need to sort by gas price first
    // When we derive Ord, the fields are used in order from top to bottom
    highest_gas_price: u128,
    address: Address,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
struct NoncelessTransactionKey {
    // Field order is crucial here since we need to sort by gas price first
    // When we derive Ord, the fields are used in order from top to bottom
    highest_gas_price: u128,
    hash: Hash,
}

impl From<VerifiedTransaction> for NoncelessTransactionKey {
    fn from(txn: VerifiedTransaction) -> Self {
        NoncelessTransactionKey {
            highest_gas_price: txn.gas_price,
            hash: txn.hash,
        }
    }
}

impl From<&VerifiedTransaction> for NoncelessTransactionKey {
    fn from(txn: &VerifiedTransaction) -> Self {
        NoncelessTransactionKey {
            highest_gas_price: txn.gas_price,
            hash: txn.hash,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransactionsAccount {
    // Account address
    address: Address,
    // The actual account's balance
    balance_account: u128,
    // The account's remaining balance after all pending transactions
    balance_after_pending: i128,
    // The account's actual nonce
    nonce_account: u64,
    // The largest pending transaction nonce plus one
    nonce_after_pending: u64,
    // All transactions with nonces, sorted by nonce
    nonced_transactions: BTreeMap<u64, VerifiedTransaction>,
    // All transactions without nonces, sorted by gas price
    nonceless_transactions_pending: BTreeMap<NoncelessTransactionKey, VerifiedTransaction>,
    nonceless_transactions_queued: BTreeMap<NoncelessTransactionKey, VerifiedTransaction>,
}

impl TransactionsAccount {
    // Common code for recalculating after changes
    fn maintain(&mut self) {
        if self.balance_after_pending >= 0 {
            // Add transactions to pending queue if there's balance and they're valid
            let nonceless_iterator = self.nonceless_transactions_queued.iter().rev().map(|x| x.1);
            let nonced_iterator = self
                .nonced_transactions
                .range((Included(self.nonce_after_pending), Unbounded))
                .map(|x| x.1);

            let queue = nonceless_iterator.merge_by(nonced_iterator, |a, b| {
                a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas()
            });

            for txn in queue {
                if self.balance_after_pending >= txn.tx.gas_price_per_evm_gas() as i128 {
                    self.balance_after_pending += txn.tx.gas_price_per_evm_gas() as i128;
                    if txn.tx.nonce().is_some() {
                        self.nonce_after_pending += 1;
                    } else {
                        let txn_key: NoncelessTransactionKey = txn.into();
                        self.nonceless_transactions_pending.insert(txn_key, txn);
                        self.nonceless_transactions_queued.remove(&txn_key);
                    }
                } else {
                    break;
                }
            }
        } else {
            // Remove transactions from the pending queue if there's not enough balance
            let nonceless_iterator = self.nonceless_transactions_pending.iter().map(|x| x.1);
            let nonced_iterator = self
                .nonced_transactions
                .range((Unbounded, Excluded(self.nonce_after_pending)))
                .map(|x| x.1)
                .rev();

            let pending = nonceless_iterator.merge_by(nonced_iterator, |a, b| {
                a.tx.gas_price_per_evm_gas() <= b.tx.gas_price_per_evm_gas()
            });

            for txn in pending {
                if self.balance_after_pending < 0 {
                    self.balance_after_pending -= txn.tx.gas_price_per_evm_gas() as i128;
                    if txn.tx.nonce().is_some() {
                        self.nonce_after_pending -= 1;
                    } else {
                        let txn_key: NoncelessTransactionKey = txn.into();
                        self.nonceless_transactions_queued.insert(txn_key, *txn);
                        self.nonceless_transactions_pending.remove(&txn_key);
                    }
                } else {
                    break;
                }
            }
        }
    }
    fn insert_txn(&mut self, txn: VerifiedTransaction) {
        if txn.tx.nonce().is_some() {
            let nonce = txn.tx.nonce().unwrap();
            let gas_price = txn.tx.gas_price_per_evm_gas() as i128;
            assert!(!self.nonced_transactions.contains_key(&nonce));
            self.nonced_transactions.insert(nonce, txn);
            if nonce == self.nonce_after_pending && self.balance_after_pending <= gas_price {
                self.nonce_after_pending += 1;
                self.balance_after_pending -= gas_price;
            }
            self.maintain();
        } else {
            let gas_price = txn.tx.gas_price_per_evm_gas() as i128;
            let worst_pending_nonceless = self
                .nonceless_transactions_pending
                .first_key_value()
                .map_or(-1, |v| v.txn.tx.gas_price_per_evm_gas() as i128);
            let highest_pending_nonced = self
                .nonced_transactions
                .get(&(self.nonce_after_pending - 1))
                .map_or(-1, |txn| txn.tx.gas_price_per_evm_gas() as i128);
            if gas_price > worst_pending_nonceless || gas_price > worst_pending_nonceless {
                self.balance_after_pending -= gas_price;
                self.nonceless_transactions_pending.insert(txn.into(), txn);
                self.maintain();
            } else {
                self.nonceless_transactions_queued.insert(txn.into(), txn);
            }
        }
    }
    fn update_txn(&mut self, new_txn: VerifiedTransaction) {
        if new_txn.tx.nonce().is_some() {
            let nonce = new_txn.tx.nonce().unwrap();
            let new_gas_price = new_txn.tx.gas_price_per_evm_gas() as i128;
            assert!(self.nonced_transactions.contains_key(&nonce));
            let old_txn = self.nonced_transactions.insert(nonce, new_txn).unwrap();
            if nonce < self.nonce_after_pending {
                self.balance_after_pending -=
                    new_gas_price - old_txn.tx.gas_price_per_evm_gas() as i128;
            }
            self.maintain();
        } else {
            if let std::collections::btree_map::Entry::Occupied(mut entry) =
                self.nonceless_transactions_queued.entry(new_txn.into())
            {
                entry.insert(new_txn);
            } else if let std::collections::btree_map::Entry::Occupied(mut entry) =
                self.nonceless_transactions_pending.entry(new_txn.into())
            {
                let old_txn = entry.get();
                self.balance_after_pending += old_txn.tx.gas_price_per_evm_gas() as i128;
                entry.insert(new_txn);
                self.balance_after_pending -= new_txn.tx.gas_price_per_evm_gas() as i128;
                self.maintain();
            }
        }
    }
    fn get_pending(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        let nonceless_iterator = self
            .nonceless_transactions_pending
            .iter()
            .map(|x| x.1)
            .rev();
        let nonced_iterator = self
            .nonced_transactions
            .range((Unbounded, Excluded(self.nonce_after_pending)))
            .map(|x| x.1);

        nonceless_iterator.merge_by(nonced_iterator, |a, b| {
            a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas()
        })
    }
    fn get_queue(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        let nonceless_iterator = self.nonceless_transactions_queued.iter().rev().map(|x| x.1);
        let nonced_iterator = self
            .nonced_transactions
            .range((Included(self.nonce_after_pending), Unbounded))
            .map(|x| x.1);

        nonceless_iterator.merge_by(nonced_iterator, |a, b| {
            a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas()
        })
    }
    fn peek_best_txn(&self) -> Option<&VerifiedTransaction> {
        self.get_pending().next()
    }
    fn pop_best_if(
        &mut self,
        predicate: impl Fn(&VerifiedTransaction) -> bool,
    ) -> Option<VerifiedTransaction> {
        // TODO: Handle nonceless transactions
        // // Get the best entry
        let best_nonced_entry = match self.nonced_transactions.first_entry() {
            Some(entry) if *entry.key() < self.nonce_after_pending => Some(entry),
            Some(_) => None,
            None => None,
        };
        let best_nonceless_entry = self.nonceless_transactions_pending.last_entry();
        let best_entry = match (best_nonced_entry, best_nonceless_entry) {
            (Some(nonced_entry), Some(nonceless_entry)) => {
                if nonced_entry.get().tx.gas_price_per_evm_gas()
                    >= nonceless_entry.get().tx.gas_price_per_evm_gas()
                {
                    nonced_entry
                } else {
                    nonceless_entry
                }
            }
            (Some(nonced_entry), None) => nonced_entry,
            (None, Some(nonceless_entry)) => nonceless_entry,
            (None, None) => return None,
        };
        // Check the predicate and remove if appropriate
        if predicate(best_entry.get()) {
            let result = best_entry.remove();
            self.balance_after_pending += result.tx.gas_price_per_evm_gas() as i128;
            if Some(self.nonce_after_pending - 1) == result.tx.nonce() {
                self.nonce_after_pending = 0; // This was the last nonced transaction
            }
            self.maintain();
            Some(result)
        } else {
            None
        }
    }
    fn update_balance(&mut self, new_balance: u128) {
        assert!(new_balance <= i128::MAX as u128);
        let balance_delta = new_balance - self.balance_account;
        self.balance_after_pending += balance_delta as i128;
        self.maintain();
    }
    // If we're updating the nonce, the the balance has changed and probably the transactions too so let's fully recalculate
    fn update_nonce_and_balance(&mut self, new_nonce: u64, new_balance: u128) {
        assert!(new_balance <= i128::MAX as u128);
        assert!(new_nonce > self.nonce_account);
        if new_nonce == self.nonce_account && new_balance == self.balance_account {
            return;
        }
        self.nonce_account = new_nonce;
        self.balance_account = new_balance;
        self.balance_after_pending = self.balance_account as i128;
        self.nonce_after_pending = self.nonce_account + 1;
        self.nonced_transactions = self
            .nonced_transactions
            .split_off(&self.nonce_after_pending);
        self.nonceless_transactions_queued
            .append(&mut self.nonceless_transactions_pending);
        self.maintain();
    }
    fn get_pending_transactions(&self) -> Vec<&VerifiedTransaction> {
        self.get_pending().collect()
    }
    fn get_queued_transactions(&self) -> Vec<&VerifiedTransaction> {
        self.get_queue().collect()
    }
    fn get_pending_or_queued(&self, txn: &VerifiedTransaction) -> Option<PendingOrQueued> {
        assert!(txn.signer == self.address);
        if self.nonceless_transactions_queued.contains_key(&txn.into()) {
            return Some(PendingOrQueued::Queued);
        }
        if self
            .nonceless_transactions_pending
            .contains_key(&txn.into())
        {
            return Some(PendingOrQueued::Pending);
        }
        if !self
            .nonced_transactions
            .contains_key(&txn.tx.nonce().unwrap())
        {
            return None;
        } else {
            if txn.tx.nonce().unwrap() < self.nonce_after_pending {
                Some(PendingOrQueued::Pending)
            } else {
                Some(PendingOrQueued::Queued)
            }
        }
    }
    fn get_txn_by_nonce(&self, nonce: u64) -> Option<&VerifiedTransaction> {
        self.nonced_transactions.get(&nonce)
    }
    fn get_pending_queue_key(&self) -> Option<PendingQueueKey> {
        if let Some(best_transaction) = self.peek_best_txn() {
            Some(PendingQueueKey {
                highest_gas_price: best_transaction.tx.gas_price_per_evm_gas(),
                address: best_transaction.signer,
            })
        } else {
            None
        }
    }
}

/// Private implementation of the transaction pool
#[derive(Clone, Debug, Default)]
struct TransactionPoolCore {
    all_transactions: HashMap<Address, TransactionsAccount>,
    pending_account_queue: BTreeSet<PendingQueueKey>,
    hash_to_txn_map: HashMap<Hash, VerifiedTransaction>,
}

impl TransactionPoolCore {
    fn update_with_state(&mut self, state: &State) {
        // For now, we're polling for updates in all accounts
        // But in future we expect to receive account change notifications
        for (address, transactions_account) in self.all_transactions.iter_mut() {
            let old_nonce = transactions_account.nonce_account;
            let old_balance = transactions_account.balance_account;
            let new_account = state.get_account(*address).unwrap();
            let new_nonce = new_account.nonce;
            let new_balance = new_account.balance;
            if old_nonce != new_nonce {
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.remove(&pending_queue_key);
                }
                transactions_account.update_nonce_and_balance(new_nonce, new_balance);
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.insert(pending_queue_key);
                }
            } else if old_balance != new_balance {
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.remove(&pending_queue_key);
                }
                transactions_account.update_balance(new_balance);
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.insert(pending_queue_key);
                }
            }
        }
    }

    fn update_with_account(&mut self, account_address: &Address, account_data: &Account) {
        let transactions_account = self.all_transactions.get_mut(account_address).unwrap();
        let old_nonce = transactions_account.nonce_account;
        let old_balance = transactions_account.balance_account;
        let new_account = account_data;
        let new_nonce = new_account.nonce;
        let new_balance = new_account.balance;
        if old_nonce != new_nonce {
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.remove(&pending_queue_key);
            }
            transactions_account.update_nonce_and_balance(new_nonce, new_balance);
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.insert(pending_queue_key);
            }
        } else if old_balance != new_balance {
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.remove(&pending_queue_key);
            }
            transactions_account.update_balance(new_balance);
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.insert(pending_queue_key);
            }
        }
    }

    fn pending_transactions_unordered(&self) -> Vec<&VerifiedTransaction> {
        self.pending_account_queue
            .iter()
            .flat_map(|key| {
                self.all_transactions
                    .get(&key.address)
                    .unwrap()
                    .get_pending_transactions()
            })
            .collect()
    }

    fn get_pending_or_queued(&self, txn: &VerifiedTransaction) -> Option<PendingOrQueued> {
        match self.all_transactions.get(&txn.signer) {
            Some(account) => account.get_pending_or_queued(txn),
            None => None,
        }
    }

    fn get_pending_transaction_count(&self, account_address: &Address) -> u64 {
        // This could be slightly faster by keeping track of the number but it'll do for now
        match self.all_transactions.get(account_address) {
            Some(account) => account.get_pending_transactions().len() as u64,
            None => 0,
        }
    }

    fn get_txn_by_address_and_nonce(
        &self,
        address: &Address,
        nonce: u64,
    ) -> Option<&VerifiedTransaction> {
        match self.all_transactions.get(address) {
            Some(account) => account.get_txn_by_nonce(nonce),
            None => None,
        }
    }

    fn get_transaction_by_hash(&self, hash: &Hash) -> Option<&VerifiedTransaction> {
        self.hash_to_txn_map.get(hash)
    }

    fn update_txn(&mut self, txn: VerifiedTransaction) {
        let transactions_account = self.all_transactions.get_mut(&txn.signer).unwrap();
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.remove(&pending_queue_key);
        }
        transactions_account.update_txn(txn);
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.insert(pending_queue_key);
        }
    }

    fn add_txn(&mut self, txn: VerifiedTransaction, account: &Account) {
        let transactions_account =
            self.all_transactions
                .entry(txn.signer)
                .or_insert_with(|| TransactionsAccount {
                    address: txn.signer,
                    balance_account: account.balance,
                    balance_after_pending: account.balance as i128,
                    nonce_account: account.nonce,
                    nonce_after_pending: account.nonce,
                    nonced_transactions: BTreeMap::new(),
                    nonceless_transactions_pending: BTreeMap::new(),
                    nonceless_transactions_queued: BTreeMap::new(),
                });
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.remove(&pending_queue_key);
        }
        transactions_account.insert_txn(txn.clone());
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.insert(pending_queue_key);
        }
        self.hash_to_txn_map.insert(txn.hash, txn);
    }

    fn preview_content(&self) -> TxPoolContent<'_> {
        // There doesn't appear to be a used call chain for this, maybe delete it?
        // It's not necessarily the fastest but no point optimising it if unused
        let pending_txns = self.pending_transactions_unordered();
        let queued_txns = self
            .all_transactions
            .values()
            .flat_map(|v| v.get_queued_transactions())
            .collect_vec();
        TxPoolContent {
            pending: pending_txns,
            queued: queued_txns,
        }
    }

    fn any_pending(&self) -> bool {
        self.pending_account_queue.len() > 0
    }

    fn clear(&mut self) {
        self.pending_account_queue.clear();
        self.all_transactions.clear();
        self.hash_to_txn_map.clear();
    }

    fn peek_best_txn(&self) -> Option<&VerifiedTransaction> {
        let best_account_key = match self.pending_account_queue.first() {
            Some(key) => key,
            None => return None,
        };

        let best_account = self
            .all_transactions
            .get(&best_account_key.address)
            .unwrap();

        best_account.peek_best_txn()
    }

    pub fn pop_best_if(
        &mut self,
        predicate: impl Fn(&VerifiedTransaction) -> bool,
    ) -> Option<VerifiedTransaction> {
        let best_account_key = match self.pending_account_queue.first() {
            Some(key) => key,
            None => return None,
        };

        let transactions_account = self
            .all_transactions
            .get_mut(&best_account_key.address)
            .unwrap();

        let old_pending_queue_key = transactions_account.get_pending_queue_key();
        let result = transactions_account.pop_best_if(predicate);
        if let Some(ref txn) = result {
            if let Some(pending_queue_key) = old_pending_queue_key {
                self.pending_account_queue.remove(&pending_queue_key);
            }
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.insert(pending_queue_key);
            }
            self.hash_to_txn_map.remove(&txn.hash);
        }
        result
    }
}

/// A pool that manages uncommitted transactions.
///
/// It provides transactions to the chain via [`TransactionPool::best_transaction`].
#[derive(Clone, Debug, Default)]
pub struct TransactionPool {
    core: TransactionPoolCore,
    /// Keeps transactions created at this node that will be broadcast
    transactions_to_broadcast: VecDeque<SignedTransaction>,
}

// Represents currently pending txns for inclusion in the next block(s), as well as the ones that are being scheduled for future execution.
pub struct TxPoolContent<'a> {
    pub pending: Vec<&'a VerifiedTransaction>,
    pub queued: Vec<&'a VerifiedTransaction>,
}

impl TransactionPool {
    pub fn best_transaction(&mut self, state: &State) -> Result<Option<&VerifiedTransaction>> {
        self.core.update_with_state(state);
        Ok(self.core.peek_best_txn())
    }

    pub fn get_transaction(&mut self, hash: &Hash) -> Result<Option<&VerifiedTransaction>> {
        Ok(self.core.get_transaction_by_hash(hash))
    }

    /// Returns whether the transaction is pending or queued
    /// The result is not guaranteed to be in any particular order
    pub fn get_pending_or_queued(
        &mut self,
        state: &State,
        txn: &VerifiedTransaction,
    ) -> Result<Option<PendingOrQueued>> {
        self.core.update_with_state(state);
        Ok(self.core.get_pending_or_queued(txn))
    }

    /// Returns a list of txns that are pending for inclusion in the next block
    /// The result is not guaranteed to be in any particular order
    pub fn pending_transactions_unordered(
        &mut self,
        state: &State,
    ) -> Result<Vec<&VerifiedTransaction>> {
        self.core.update_with_state(state);
        Ok(self.core.pending_transactions_unordered())
    }

    pub fn preview_content(&mut self, state: &State) -> Result<TxPoolContent> {
        self.core.update_with_state(state);
        Ok(self.core.preview_content())
    }

    pub fn pending_transaction_count(
        &mut self,
        account_address: &Address,
        account_data: &Account,
    ) -> u64 {
        self.core.update_with_account(account_address, account_data);
        self.core.get_pending_transaction_count(account_address)
    }

    /// Returns a pair (did_we_add_it, message).
    /// If we return false, it's safe to say that txn validation failed.
    pub fn insert_transaction(
        &mut self,
        txn: VerifiedTransaction,
        account: &Account,
        from_broadcast: bool,
    ) -> TxAddResult {
        if let Some(transaction_nonce) = txn.tx.nonce() {
            if transaction_nonce < account.nonce {
                debug!(
                    "Nonce is too low. Txn hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                    txn.hash, txn.signer, transaction_nonce, account.nonce,
                );
                // This transaction is permanently invalid, so there is nothing to do.
                // unwrap() is safe because we checked above that it was some().
                return TxAddResult::NonceTooLow(transaction_nonce.unwrap(), account.nonce);
            }
        }

        let existing_transaction = match txn.tx.nonce(){
            Some(nonce) => self
                .core
                .get_txn_by_address_and_nonce(&txn.signer, nonce),
            None => None,
        }
        if let Some(existing_txn) = existing_transaction
        {
            // Only proceed if the new transaction is better. Note that if they are
            // equally good, we prioritise the existing transaction to avoid the need
            // to broadcast a new transaction to the network.
            // N.B.: This will in theory never affect intershard/nonceless transactions - since
            // with the current bridge design it is not possible to broadcast a different one while
            // keeping the same nonce. So for those, it will always discard the new (identical)
            // one.
            if txn.signer == existing_txn.signer
                && transaction_nonce.unwrap() == existing_txn.tx.nonce().unwrap()
                && txn.tx.gas_price_per_evm_gas() < existing_txn.tx.gas_price_per_evm_gas()
            {
                debug!(
                    "Received txn with the same nonce but lower gas price. Txn hash: {:?}, from: {:?}, nonce: {:?}, gas_price: {:?}",
                    txn.hash,
                    txn.signer,
                    transaction_nonce,
                    txn.tx.gas_price_per_evm_gas()
                );
                return TxAddResult::SameNonceButLowerGasPrice;
            } else {
                debug!(
                    "Txn updated in mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                    txn.hash, txn.signer, transaction_nonce, account.nonce,
                );
                self.core.update_txn(txn.clone());
            }
        } else {
            debug!(
                "Txn added to mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                txn.hash, txn.signer, transaction_nonce, account.nonce,
            );
            self.core.add_txn(txn.clone(), account);
        }

        // If this is a transaction created at this node, add it to broadcast vector
        if !from_broadcast {
            self.store_broadcast_txn(txn.tx.clone());
        }

        TxAddResult::AddedToMempool
    }

    fn store_broadcast_txn(&mut self, txn: SignedTransaction) {
        self.transactions_to_broadcast.push_back(txn);
    }

    pub fn pull_txns_to_broadcast(&mut self) -> Result<Vec<SignedTransaction>> {
        const MAX_BATCH_SIZE: usize = 1000;

        if self.transactions_to_broadcast.is_empty() {
            return Ok(Vec::new());
        }

        let max_take = min(self.transactions_to_broadcast.len(), MAX_BATCH_SIZE);

        let ret_vec = self
            .transactions_to_broadcast
            .drain(..max_take)
            .collect::<Vec<_>>();

        Ok(ret_vec)
    }

    pub fn pop_best_if(
        &mut self,
        state: &State,
        predicate: impl Fn(&VerifiedTransaction) -> bool,
    ) -> Option<VerifiedTransaction> {
        self.core.update_with_state(state);
        self.core.pop_best_if(predicate)
    }

    /// Check the ready transactions in arbitrary order, for one that is Ready
    pub fn has_txn_ready(&self) -> bool {
        self.core.any_pending()
    }

    pub fn clear(&mut self) {
        self.core.clear();
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
