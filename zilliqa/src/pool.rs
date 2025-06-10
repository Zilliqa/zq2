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
            highest_gas_price: txn.tx.gas_price_per_evm_gas(),
            hash: txn.hash,
        }
    }
}

impl From<&VerifiedTransaction> for NoncelessTransactionKey {
    fn from(txn: &VerifiedTransaction) -> Self {
        NoncelessTransactionKey {
            highest_gas_price: txn.tx.gas_price_per_evm_gas(),
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
    // state transition functions
    // these move transactions from pending to queued and vice versa
    // they should leave everything consistent
    fn queue_to_pending_nonced(&mut self, txn: VerifiedTransaction) {
        let nonce = txn.tx.nonce().unwrap();
        let gas = txn.tx.gas_price_per_evm_gas();
        assert!(self.nonce_after_pending == nonce);
        assert!(self.nonced_transactions.contains_key(&nonce));
        self.nonce_after_pending += 1;
        self.balance_after_pending -= gas as i128;
    }
    fn pending_to_queue_nonced(&mut self, txn: VerifiedTransaction) {
        let nonce = txn.tx.nonce().unwrap();
        let gas = txn.tx.gas_price_per_evm_gas();
        assert!(self.nonce_after_pending == nonce + 1);
        assert!(self.nonced_transactions.contains_key(&nonce));
        self.nonce_after_pending -= 1;
        self.balance_after_pending += gas as i128;
    }
    fn queue_to_pending_nonceless(&mut self, key: NoncelessTransactionKey) {
        let transaction = self.nonceless_transactions_queued.remove(&key).unwrap();
        self.balance_after_pending -= transaction.tx.gas_price_per_evm_gas() as i128;
        let prev_value = self.nonceless_transactions_pending.insert(key, transaction);
        assert!(prev_value.is_none());
    }
    fn pending_to_queue_nonceless(&mut self, key: NoncelessTransactionKey) {
        let transaction = self.nonceless_transactions_pending.remove(&key).unwrap();
        self.balance_after_pending += transaction.tx.gas_price_per_evm_gas() as i128;
        let prev_value = self.nonceless_transactions_queued.insert(key, transaction);
        assert!(prev_value.is_none());
    }
    fn get_first_queued_nonced(&self) -> Option<&VerifiedTransaction> {
        self.nonced_transactions.get(&(self.nonce_after_pending))
    }
    fn get_last_pending_nonced(&self) -> Option<&VerifiedTransaction> {
        self.nonced_transactions
            .get(&(self.nonce_after_pending - 1))
    }
    fn get_highest_gas_queued_nonceless(&self) -> Option<&VerifiedTransaction> {
        self.nonceless_transactions_queued
            .last_key_value()
            .map(|(_k, v)| v)
    }
    fn get_lowest_gas_pending_nonceless(&self) -> Option<&VerifiedTransaction> {
        self.nonceless_transactions_pending
            .first_key_value()
            .map(|(_k, v)| v)
    }
    /// Update pending transactions after changes
    fn maintain(&mut self) {
        let dbg_total_txns_before = self.get_transaction_count();
        if self.balance_after_pending >= 0 {
            // Add transactions to pending queue if there's balance and they're valid
            loop {
                let balance_after_pending = self.balance_after_pending;
                let first_queued_nonced = self
                    .get_first_queued_nonced()
                    .filter(|x| x.tx.gas_price_per_evm_gas() as i128 <= balance_after_pending);
                let highest_gas_queued_nonceless = self
                    .get_highest_gas_queued_nonceless()
                    .filter(|x| x.tx.gas_price_per_evm_gas() as i128 <= balance_after_pending);
                match (first_queued_nonced, highest_gas_queued_nonceless) {
                    (None, None) => break,
                    (None, Some(y)) => self.queue_to_pending_nonceless(y.into()),
                    (Some(x), None) => self.queue_to_pending_nonced(x.clone()),
                    (Some(x), Some(y)) => {
                        if x.tx.gas_price_per_evm_gas() >= y.tx.gas_price_per_evm_gas() {
                            self.queue_to_pending_nonced(x.clone())
                        } else {
                            self.queue_to_pending_nonceless(y.into())
                        }
                    }
                }
            }
        } else {
            // Remove transactions from the pending queue if there's not enough balance
            while self.balance_after_pending < 0 {
                let last_pending_nonced = self.get_last_pending_nonced();
                let lowest_gas_pending_nonceless = self.get_lowest_gas_pending_nonceless();
                match (last_pending_nonced, lowest_gas_pending_nonceless) {
                    (None, None) => break,
                    (None, Some(y)) => self.pending_to_queue_nonceless(y.into()),
                    (Some(x), None) => self.pending_to_queue_nonced(x.clone()),
                    (Some(x), Some(y)) => {
                        if x.tx.gas_price_per_evm_gas() < y.tx.gas_price_per_evm_gas() {
                            self.pending_to_queue_nonced(x.clone())
                        } else {
                            self.pending_to_queue_nonceless(y.into())
                        }
                    }
                }
            }
        }
        assert_eq!(dbg_total_txns_before, self.get_transaction_count());
    }
    fn insert_nonced_txn(&mut self, txn: VerifiedTransaction) {
        assert!(txn.tx.nonce().is_some());
        let nonce = txn.tx.nonce().unwrap();
        let gas_price = txn.tx.gas_price_per_evm_gas() as i128;
        assert!(!self.nonced_transactions.contains_key(&nonce));
        self.nonced_transactions.insert(nonce, txn);
        // If it can pend, put it in pending and then pop it again if necessary
        if nonce == self.nonce_after_pending {
            self.nonce_after_pending += 1;
            self.balance_after_pending -= gas_price;
        }
        self.maintain();
    }
    fn insert_unnonced_txn(&mut self, txn: VerifiedTransaction) {
        assert!(txn.tx.nonce().is_none());
        let gas_price = txn.tx.gas_price_per_evm_gas() as i128;
        // Put it in pending and then pop it again if necessary
        self.nonceless_transactions_pending
            .insert((&txn).into(), txn.clone());
        self.balance_after_pending -= gas_price;
        self.maintain();
    }
    fn insert_txn(&mut self, txn: VerifiedTransaction) {
        if txn.tx.nonce().is_some() {
            self.insert_nonced_txn(txn);
        } else {
            self.insert_unnonced_txn(txn);
        }
    }
    fn update_txn(&mut self, new_txn: VerifiedTransaction) {
        if let Some(nonce) = new_txn.tx.nonce() {
            let new_gas_price = new_txn.tx.gas_price_per_evm_gas() as i128;
            assert!(self.nonced_transactions.contains_key(&nonce));
            let old_txn = self.nonced_transactions.insert(nonce, new_txn).unwrap();
            if nonce < self.nonce_after_pending {
                self.balance_after_pending -=
                    new_gas_price - old_txn.tx.gas_price_per_evm_gas() as i128;
            }
            self.maintain();
        } else {
            unreachable!("Cannot update transaction without nonce")
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
    fn get_queued(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        let nonceless_iterator = self.nonceless_transactions_queued.iter().rev().map(|x| x.1);
        let nonced_iterator = self
            .nonced_transactions
            .range((Included(self.nonce_after_pending), Unbounded))
            .map(|x| x.1);

        nonceless_iterator.merge_by(nonced_iterator, |a, b| {
            a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas()
        })
    }
    fn get_pending_transaction_count(&self) -> u64 {
        let nonced_pending_count = if self.nonce_after_pending > 0
            && self
                .nonced_transactions
                .contains_key(&(self.nonce_after_pending - 1))
        {
            self.nonce_after_pending - self.nonced_transactions.first_key_value().unwrap().0
        } else {
            0
        };
        let nonceless_pending_count = self.nonceless_transactions_pending.len() as u64;
        nonced_pending_count + nonceless_pending_count
    }
    fn get_queued_transaction_count(&self) -> u64 {
        self.get_transaction_count() as u64 - self.get_pending_transaction_count()
    }
    fn get_transaction_count(&self) -> usize {
        self.nonced_transactions.len()
            + self.nonceless_transactions_queued.len()
            + self.nonceless_transactions_pending.len()
    }
    fn is_empty(&self) -> bool {
        self.nonceless_transactions_pending.is_empty()
            && self.nonced_transactions.is_empty()
            && self.nonceless_transactions_queued.is_empty()
    }
    fn has_pending_transactions(&self) -> bool {
        self.get_pending_transaction_count() > 0
    }
    fn peek_best_txn(&self) -> Option<&VerifiedTransaction> {
        self.get_pending().next()
    }
    fn pop_best_if(
        &mut self,
        predicate: impl Fn(&VerifiedTransaction) -> bool,
    ) -> Option<VerifiedTransaction> {
        // // Get the best entry
        let best_nonced_entry = match self.nonced_transactions.first_entry() {
            Some(entry) if *entry.key() < self.nonce_after_pending => Some(entry),
            Some(_) => None,
            None => None,
        };
        let best_nonceless_entry = self.nonceless_transactions_pending.last_entry();

        if best_nonced_entry.is_none() && best_nonceless_entry.is_none() {
            return None;
        } else {
            let best_nonced_gas = best_nonced_entry
                .as_ref()
                .map_or(0, |x| x.get().tx.gas_price_per_evm_gas());
            let best_nonceless_gas = best_nonceless_entry
                .as_ref()
                .map_or(0, |x| x.get().tx.gas_price_per_evm_gas());
            if best_nonced_gas < best_nonceless_gas {
                if let Some(best_nonceless_entry) = best_nonceless_entry {
                    if predicate(best_nonceless_entry.get()) {
                        let result = best_nonceless_entry.remove();
                        self.balance_after_pending += result.tx.gas_price_per_evm_gas() as i128;
                        self.maintain();
                        Some(result)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                if let Some(best_nonced_entry) = best_nonced_entry {
                    if predicate(best_nonced_entry.get()) {
                        let result = best_nonced_entry.remove();
                        self.nonce_account = result.tx.nonce().unwrap();
                        self.balance_after_pending += result.tx.gas_price_per_evm_gas() as i128;
                        self.maintain();
                        Some(result)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }
    // Must be followed by maintain()
    fn update_balance(&mut self, new_balance: u128) {
        assert!(new_balance < i128::MAX as u128);
        let balance_delta = new_balance as i128 - self.balance_account as i128;
        self.balance_account = new_balance;
        self.balance_after_pending += balance_delta;
    }
    // Must be followed by maintain()
    fn update_nonce(&mut self, new_nonce: u64) -> Vec<Hash> {
        assert!(new_nonce >= self.nonce_account);
        self.complete_txns_below_nonce(new_nonce)
    }
    fn update_with_account(&mut self, account: &Account) -> Vec<Hash> {
        self.update_balance(account.balance);
        let result = self.update_nonce(account.nonce);
        self.maintain();
        result
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

    fn mark_executed(&mut self, txn: &VerifiedTransaction) -> Vec<Hash> {
        if let Some(nonce) = txn.tx.nonce() {
            let removed_txn_hashes = self.complete_txns_below_nonce(nonce + 1);
            self.maintain();
            return removed_txn_hashes;
        } else {
            if let Some(txn) = self.nonceless_transactions_pending.remove(&txn.into()) {
                self.balance_after_pending += txn.tx.gas_price_per_evm_gas() as i128;
                self.maintain();
                return vec![txn.hash];
            } else {
                self.nonceless_transactions_queued.remove(&txn.into());
                return vec![txn.hash];
            }
        }
    }
    /// Remove all transactions with nonces less than to the given nonce
    /// Must be followed by maintain()
    fn complete_txns_below_nonce(&mut self, nonce: u64) -> Vec<Hash> {
        // Optimisation for when there's nothing to do
        if nonce == self.nonce_account {
            return Vec::new();
        }
        // split the transactions into ones to keep and ones to discard (which are annoyingly returned the wrong way round)
        let transactions_to_retain = self.nonced_transactions.split_off(&(nonce));
        // Get removed transaction hashes to return
        let removed_txn_hashes = self
            .nonced_transactions
            .values()
            .map(|tx| tx.hash)
            .collect();
        // discard transactions which were queued but now aren't
        // since we only need to adjust for previously pending transactions
        self.nonced_transactions
            .split_off(&self.nonce_after_pending);
        // removed discarded transactions from balance
        for discarded_tx in self.nonced_transactions.values() {
            self.balance_after_pending += discarded_tx.tx.gas_price_per_evm_gas() as i128;
        }
        // Put the cut down transaction list back in place
        self.nonced_transactions = transactions_to_retain;
        // put the counters right again
        self.nonce_after_pending = std::cmp::max(self.nonce_after_pending, nonce);
        self.nonce_account = std::cmp::max(self.nonce_account, nonce);

        return removed_txn_hashes;
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
            if old_nonce != new_nonce || old_balance != new_balance {
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.remove(&pending_queue_key);
                }
                let removed_txn_hashes = transactions_account.update_with_account(&new_account);
                for hash in removed_txn_hashes {
                    self.hash_to_txn_map.remove(&hash);
                }
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.insert(pending_queue_key);
                }
            }
        }
        self.all_transactions.retain(|_k, v| !v.is_empty());
    }

    fn update_with_account(&mut self, account_address: &Address, account_data: &Account) {
        let transactions_account = self.all_transactions.get_mut(account_address).unwrap();
        let old_nonce = transactions_account.nonce_account;
        let old_balance = transactions_account.balance_account;
        let new_account = account_data;
        let new_nonce = new_account.nonce;
        let new_balance = new_account.balance;
        if old_nonce != new_nonce || old_balance != new_balance {
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.remove(&pending_queue_key);
            }
            let removed_txn_hashes = transactions_account.update_with_account(&new_account);
            for hash in removed_txn_hashes {
                self.hash_to_txn_map.remove(&hash);
            }
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.insert(pending_queue_key);
            }
            if transactions_account.is_empty() {
                self.all_transactions.remove(account_address);
            }
        }
    }

    fn pending_transactions_unordered(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        self.all_transactions
            .values()
            .map(|x| x.get_pending())
            .flatten()
    }

    fn queued_transactions_unordered(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        self.all_transactions
            .values()
            .map(|x| x.get_queued())
            .flatten()
    }

    // Potentially slow, depending on merge behaviour
    fn pending_transactions_ordered(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        self.all_transactions
            .values()
            .map(|x| x.get_pending())
            .kmerge_by(|a, b| a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas())
    }

    // Potentially slow, depending on merge behaviour
    fn queued_transactions_ordered(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        self.all_transactions
            .values()
            .map(|x| x.get_queued())
            .kmerge_by(|a, b| a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas())
    }

    fn get_pending_or_queued(&self, txn: &VerifiedTransaction) -> Option<PendingOrQueued> {
        match self.all_transactions.get(&txn.signer) {
            Some(account) => account.get_pending_or_queued(txn),
            None => None,
        }
    }

    fn account_pending_transaction_count(&self, account_address: &Address) -> u64 {
        match self.all_transactions.get(account_address) {
            Some(account) => account.get_pending_transaction_count() as u64,
            None => 0,
        }
    }

    fn account_transaction_count(&self, account_address: &Address) -> u64 {
        match self.all_transactions.get(account_address) {
            Some(account) => account.get_transaction_count() as u64,
            None => 0,
        }
    }

    fn pending_transaction_count(&self) -> u64 {
        self.all_transactions
            .values()
            .map(|x| x.get_pending_transaction_count() as u64)
            .sum()
    }

    fn transaction_count(&self) -> u64 {
        self.all_transactions
            .values()
            .map(|x| x.get_transaction_count() as u64)
            .sum()
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
        transactions_account.update_with_account(account);
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.insert(pending_queue_key);
        }
        self.hash_to_txn_map.insert(txn.hash, txn);
    }

    fn preview_content(&self) -> TxPoolContent {
        let pending_txns: HashMap<Address, Vec<VerifiedTransaction>> = self
            .all_transactions
            .iter()
            .map(|(address, transactions)| {
                (*address, transactions.get_pending().cloned().collect())
            })
            .collect();
        let queued_txns: HashMap<Address, Vec<VerifiedTransaction>> = self
            .all_transactions
            .iter()
            .map(|(address, transactions)| (*address, transactions.get_queued().cloned().collect()))
            .collect();
        TxPoolContent {
            pending: pending_txns,
            queued: queued_txns,
        }
    }

    fn preview_content_from(&self, address: &Address) -> TxPoolContentFrom {
        let pending_txns: Vec<VerifiedTransaction> = self
            .all_transactions
            .get(address)
            .map_or(Vec::new(), |x| x.get_pending().cloned().collect());
        let queued_txns: Vec<VerifiedTransaction> = self
            .all_transactions
            .get(address)
            .map_or(Vec::new(), |x| x.get_queued().cloned().collect());
        TxPoolContentFrom {
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
        let best_account_key = match self.pending_account_queue.last() {
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
        let best_account_key = self.pending_account_queue.last().cloned()?;

        let transactions_account = self
            .all_transactions
            .get_mut(&best_account_key.address.clone())
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
            if transactions_account.is_empty() {
                self.all_transactions.remove(&best_account_key.address);
            }
            self.hash_to_txn_map.remove(&txn.hash);
        }
        result
    }

    pub fn mark_executed(&mut self, txn: &VerifiedTransaction) {
        let address = txn.signer;
        if let Some(account) = self.all_transactions.get_mut(&address) {
            self.pending_account_queue
                .remove(&account.get_pending_queue_key().unwrap());
            let removed_txn_hashes = account.mark_executed(txn);
            for hash in removed_txn_hashes {
                self.hash_to_txn_map.remove(&hash);
            }
            if let Some(key) = account.get_pending_queue_key() {
                self.pending_account_queue.insert(key);
            }
            if account.is_empty() {
                self.all_transactions.remove(&address);
            }
        }
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
#[derive(Clone)]
pub struct TxPoolContent {
    pub pending: HashMap<Address, Vec<VerifiedTransaction>>,
    pub queued: HashMap<Address, Vec<VerifiedTransaction>>,
}

#[derive(Clone)]
pub struct TxPoolContentFrom {
    pub pending: Vec<VerifiedTransaction>,
    pub queued: Vec<VerifiedTransaction>,
}

#[derive(Clone)]
pub struct TxPoolStatus {
    pub pending: u64,
    pub queued: u64,
}

impl TransactionPool {
    pub fn update_with_state(&mut self, state: &State) {
        self.core.update_with_state(state);
    }
    pub fn update_with_account(&mut self, account_address: &Address, account_data: &Account) {
        self.core.update_with_account(account_address, account_data);
    }
    pub fn best_transaction(&self) -> Option<&VerifiedTransaction> {
        self.core.peek_best_txn()
    }

    pub fn pending_transactions_ordered(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        self.core.pending_transactions_ordered()
    }

    pub fn queued_transactions_ordered(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        self.core.queued_transactions_ordered()
    }

    pub fn get_transaction(&mut self, hash: &Hash) -> Option<&VerifiedTransaction> {
        self.core.get_transaction_by_hash(hash)
    }

    /// Returns whether the transaction is pending or queued
    /// The result is not guaranteed to be in any particular order
    pub fn get_pending_or_queued(
        &self,
        txn: &VerifiedTransaction,
    ) -> Result<Option<PendingOrQueued>> {
        Ok(self.core.get_pending_or_queued(txn))
    }

    pub fn preview_content(&self) -> TxPoolContent {
        self.core.preview_content()
    }

    pub fn preview_content_from(&self, address: &Address) -> TxPoolContentFrom {
        self.core.preview_content_from(address)
    }

    pub fn preview_status(&self) -> TxPoolStatus {
        let pending_count = self.pending_transaction_count();
        let total_count = self.transaction_count();
        TxPoolStatus {
            pending: pending_count,
            queued: total_count - pending_count,
        }
    }

    pub fn account_pending_transaction_count(&self, account_address: &Address) -> u64 {
        self.core.account_pending_transaction_count(account_address)
    }

    pub fn account_total_transaction_count(&self, account_address: &Address) -> u64 {
        self.core.account_transaction_count(account_address)
    }

    pub fn pending_transaction_count(&self) -> u64 {
        self.core.pending_transaction_count()
    }

    pub fn transaction_count(&self) -> u64 {
        self.core.transaction_count()
    }

    pub fn mark_executed(&mut self, txn: &VerifiedTransaction) {
        self.core.mark_executed(txn);
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
                return TxAddResult::NonceTooLow(transaction_nonce, account.nonce);
            }
        }

        let existing_transaction = match txn.tx.nonce() {
            Some(nonce) => self.core.get_txn_by_address_and_nonce(&txn.signer, nonce),
            None => None,
        };
        if let Some(existing_txn) = existing_transaction {
            // Only proceed if the new transaction is better. Note that if they are
            // equally good, we prioritise the existing transaction to avoid the need
            // to broadcast a new transaction to the network.
            // N.B.: This will in theory never affect intershard/nonceless transactions - since
            // with the current bridge design it is not possible to broadcast a different one while
            // keeping the same nonce. So for those, it will always discard the new (identical)
            // one.
            if txn.signer == existing_txn.signer
                && txn.tx.nonce().unwrap() == existing_txn.tx.nonce().unwrap()
                && txn.tx.gas_price_per_evm_gas() < existing_txn.tx.gas_price_per_evm_gas()
            {
                debug!(
                    "Received txn with the same nonce but lower gas price. Txn hash: {:?}, from: {:?}, nonce: {:?}, gas_price: {:?}",
                    txn.hash,
                    txn.signer,
                    txn.tx.nonce(),
                    txn.tx.gas_price_per_evm_gas()
                );
                return TxAddResult::SameNonceButLowerGasPrice;
            } else {
                debug!(
                    "Txn updated in mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                    txn.hash,
                    txn.signer,
                    txn.tx.nonce(),
                    account.nonce,
                );
                self.core.update_txn(txn.clone());
            }
        } else {
            debug!(
                "Txn added to mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                txn.hash,
                txn.signer,
                txn.tx.nonce(),
                account.nonce,
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
        predicate: impl Fn(&VerifiedTransaction) -> bool,
    ) -> Option<VerifiedTransaction> {
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
    use itertools::Itertools;
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

    fn create_acc(
        state: &mut State,
        address: Address,
        balance: u128,
        nonce: u64,
    ) -> Result<crate::state::Account> {
        let mut acc = state.get_account(address)?;
        acc.balance = balance;
        acc.nonce = nonce;
        state.save_account(address, acc.clone())?;
        Ok(acc)
    }

    #[test]
    #[rustfmt::skip]
    #[allow(clippy::line_too_long)]
    fn test_internal_add_txns() -> Result<()> {
        let mut state = get_in_memory_state()?;

        let mut pool = TransactionPool::default();

        let acc1_addr = "0x0000000000000000000000000000000000000001".parse()?;
        let acc1_balance = 30;
        let acc1_nonce = 0;
        let acc1 = create_acc(&mut state, acc1_addr, acc1_balance, acc1_nonce)?;

        let txn1 = transaction(acc1_addr, 0, 10);
        let txn2 = transaction(acc1_addr, 1, 10);
        let txn3 = transaction(acc1_addr, 2, 10);
        let txn4 = transaction(acc1_addr, 3, 10);
        let txn5 = transaction(acc1_addr, 4, 10);
        let txn6 = transaction(acc1_addr, 5, 10);

        // Initially insert a bunch of transactions with nonces too high
        pool.insert_transaction(txn4.clone(), &acc1, false);
        pool.insert_transaction(txn2.clone(), &acc1, false);
        pool.insert_transaction(txn3.clone(), &acc1, false);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 30);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 30);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions.len(), 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 0);

        // Add the lowest transaction and now they should get added up to the balance
        pool.insert_transaction(txn1.clone(), &acc1, false);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions.len(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 30);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_after_pending, 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn1, &txn2, &txn3]);

        // Increase the balance by 5 and nothing else should change
        state.mutate_account(acc1_addr, |acc| {
            acc.balance += 5;
            Ok(())
        })?;
        assert_eq!(state.get_account(acc1_addr).unwrap().balance, 35);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions.len(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 35);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 5);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_after_pending, 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn1, &txn2, &txn3]);

        // increase the balance by another 5 and now they should all be pending
        state.mutate_account(acc1_addr, |acc| {
            acc.balance += 5;
            Ok(())
        })?;
        assert_eq!(state.get_account(acc1_addr).unwrap().balance, 40);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 40);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_after_pending, 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions.len(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn1, &txn2, &txn3, &txn4]);

        // add another two, and they shouldn't pend
        pool.insert_transaction(txn5.clone(), &acc1, false);
        pool.insert_transaction(txn6.clone(), &acc1, false);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 40);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_after_pending, 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions.len(), 6);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn1, &txn2, &txn3, &txn4]);

        // pop a transaction off the front and one of the next two should get added
        pool.pop_best_if(|txn| {
            assert_eq!(txn, &txn1);
            true
        });
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 40);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_after_pending, 5);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions.len(), 5);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn2, &txn3, &txn4, &txn5]);

        // increase the nonce and the last one should get added
        state.mutate_account(acc1_addr, |acc| {
            acc.nonce =2;
            Ok(())
        })?;
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 40);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 2);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_after_pending, 6);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions.len(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn3, &txn4, &txn5, &txn6]);

        Ok(())
    }

    #[test]
    fn nonces_returned_in_order() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, from, 100, 0)?;

        pool.insert_transaction(transaction(from, 1, 1), &acc, false);

        pool.update_with_state(&state);
        let tx = pool.best_transaction();
        assert_eq!(tx, None);

        pool.insert_transaction(transaction(from, 2, 2), &acc, false);
        pool.insert_transaction(transaction(from, 0, 0), &acc, false);

        let tx = pool.best_transaction().unwrap().clone();
        assert_eq!(tx.tx.nonce().unwrap(), 0);
        pool.mark_executed(&tx);
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;
        pool.update_with_state(&state);

        let tx = pool.best_transaction().unwrap().clone();
        assert_eq!(tx.tx.nonce().unwrap(), 1);
        pool.mark_executed(&tx);
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;
        pool.update_with_state(&state);

        let tx = pool.best_transaction().unwrap().clone();
        assert_eq!(tx.tx.nonce().unwrap(), 2);
        pool.mark_executed(&tx);
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;
        pool.update_with_state(&state);

        Ok(())
    }

    #[test]
    fn nonces_returned_in_order_same_gas() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, from, 100, 0)?;
        pool.update_with_state(&state);

        const COUNT: u64 = 100;

        let mut nonces = (0..COUNT).collect::<Vec<_>>();
        let mut rng = thread_rng();
        nonces.shuffle(&mut rng);

        for i in 0..COUNT {
            pool.insert_transaction(transaction(from, nonces[i as usize] as u8, 3), &acc, false);
        }

        for i in 0..COUNT {
            let tx = pool.best_transaction().unwrap().clone();
            assert_eq!(tx.tx.nonce().unwrap(), i);
            pool.mark_executed(&tx);
            state.mutate_account(from, |acc| {
                acc.nonce += 1;
                Ok(())
            })?;
            pool.update_with_state(&state);
        }
        Ok(())
    }

    #[test]
    fn ordered_by_gas_price() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from0 = "0x0000000000000000000000000000000000000000".parse()?;
        let from1 = "0x0000000000000000000000000000000000000001".parse()?;
        let from2 = "0x0000000000000000000000000000000000000002".parse()?;
        let from3 = "0x0000000000000000000000000000000000000003".parse()?;

        let mut state = get_in_memory_state()?;
        let acc0 = create_acc(&mut state, from0, 100, 0)?;
        let acc1 = create_acc(&mut state, from1, 100, 0)?;
        let acc2 = create_acc(&mut state, from2, 100, 0)?;
        let acc3 = create_acc(&mut state, from3, 100, 0)?;
        pool.update_with_state(&state);

        pool.insert_transaction(intershard_transaction(0, 0, 1), &acc0, false);
        pool.insert_transaction(transaction(from1, 0, 2), &acc1, false);
        pool.insert_transaction(transaction(from2, 0, 3), &acc2, false);
        pool.insert_transaction(transaction(from3, 0, 0), &acc3, false);
        pool.insert_transaction(intershard_transaction(0, 1, 5), &acc0, false);
        assert_eq!(pool.transaction_count(), 5);

        let tx = pool.best_transaction().unwrap().clone();
        assert_eq!(tx.tx.gas_price_per_evm_gas(), 5);
        pool.mark_executed(&tx);
        let tx = pool.best_transaction().unwrap().clone();
        assert_eq!(tx.tx.gas_price_per_evm_gas(), 3);

        pool.mark_executed(&tx);
        let tx = pool.best_transaction().unwrap().clone();

        assert_eq!(tx.tx.gas_price_per_evm_gas(), 2);
        pool.mark_executed(&tx);
        let tx = pool.best_transaction().unwrap().clone();

        assert_eq!(tx.tx.gas_price_per_evm_gas(), 1);
        pool.mark_executed(&tx);
        let tx = pool.best_transaction().unwrap().clone();

        assert_eq!(tx.tx.gas_price_per_evm_gas(), 0);
        pool.mark_executed(&tx);

        assert_eq!(pool.transaction_count(), 0);
        Ok(())
    }

    #[test]
    fn update_nonce_discards_invalid_transaction() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, from, 100, 0)?;
        pool.update_with_state(&state);

        pool.insert_transaction(transaction(from, 0, 0), &acc, false);
        pool.insert_transaction(transaction(from, 1, 0), &acc, false);

        pool.mark_executed(&transaction(from, 0, 0));
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;
        pool.update_with_state(&state);

        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 1);
        Ok(())
    }

    #[test]
    fn too_expensive_tranactions_are_not_proposed() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, from, 100, 0)?;
        pool.update_with_state(&state);

        pool.insert_transaction(transaction(from, 0, 1), &acc, false);
        pool.insert_transaction(transaction(from, 1, 200), &acc, false);

        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 0);
        pool.mark_executed(&transaction(from, 0, 1));
        state.mutate_account(from, |acc| {
            acc.nonce += 1;
            Ok(())
        })?;
        pool.update_with_state(&state);

        // Sender has insufficient funds at this point
        assert_eq!(pool.best_transaction(), None);

        // Increase funds of sender to satisfy txn fee
        let mut acc = state.must_get_account(from);
        acc.balance = 500;
        state.save_account(from, acc)?;
        pool.update_with_state(&state);

        assert_eq!(pool.best_transaction().unwrap().tx.nonce().unwrap(), 1);
        Ok(())
    }

    #[test]
    fn pending_queued_test() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, from, 100, 0)?;
        pool.update_with_state(&state);

        let txn0 = intershard_transaction(0, 0, 100);
        let txn1 = transaction(from, 0, 1);
        let txn2 = transaction(from, 1, 1);
        let txn3 = transaction(from, 2, 1);
        let txn4 = transaction(from, 3, 200);
        let txn5 = transaction(from, 10, 1);

        pool.insert_transaction(txn0.clone(), &acc, false);
        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);
        pool.insert_transaction(txn4.clone(), &acc, false);
        pool.insert_transaction(txn5.clone(), &acc, false);

        let pending: Vec<_> = pool.pending_transactions_ordered().cloned().collect();
        let queued: Vec<_> = pool.pending_transactions_ordered().cloned().collect();

        assert_eq!(pending.len(), 4);
        assert_eq!(pending[0], txn0);
        assert_eq!(pending[1], txn1);
        assert_eq!(pending[2], txn2);
        assert_eq!(pending[3], txn3);

        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0], txn4);
        assert_eq!(queued[1], txn5);

        Ok(())
    }

    #[test]
    fn benchmark_preview_content() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, from, 1_000_000, 0)?;
        pool.update_with_state(&state);

        // Insert 100 pending transactions
        for nonce in 0u64..100u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), &acc, false);
        }

        // Insert 100 queued transactions
        for nonce in 101u64..201u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), &acc, false);
        }

        // Benchmark the preview_content method
        let start = std::time::Instant::now();
        let content = pool.preview_content();
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
        let acc = create_acc(&mut state, from, 1_000_000, 0)?;
        pool.update_with_state(&state);

        // Insert 100 pending transactions
        for nonce in 0u64..100u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), &acc, false);
        }

        // Insert 100 queued transactions
        for nonce in 101u64..201u64 {
            pool.insert_transaction(transaction(from, nonce as u8, 1), &acc, false);
        }

        // Benchmark the preview_content method
        let start = std::time::Instant::now();
        let _result: Vec<_> = pool.pending_transactions_ordered().collect();
        let duration = start.elapsed();

        println!(
            "Benchmark completed: pending_transactions took {:?} to execute.",
            duration
        );
        Ok(())
    }
}
