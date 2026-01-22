use std::{
    cmp::{Ordering, min},
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    time::Duration,
};

use alloy::primitives::Address;
use anyhow::Result;
use itertools::Itertools;
use tracing::debug;

use crate::{
    crypto::Hash,
    state::{Account, State},
    time::SystemTime,
    transaction::{SignedTransaction, ValidationOutcome, VerifiedTransaction},
};

/// Transaction pool limits
const GLOBAL_TXN_POOL_SIZE_LIMIT: u64 = 1_000_000;
const TOTAL_SENDERS_COUNT_LIMIT: usize = 50_000;
const MAX_TXNS_PER_SENDER: u64 = 20000;

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
    // All transactions with nonces, sorted by nonce
    nonced_transactions_pending: BTreeMap<u64, VerifiedTransaction>,
    nonced_transactions_queued: BTreeMap<u64, VerifiedTransaction>,
    // All transactions without nonces, sorted by gas price
    nonceless_transactions_pending: BTreeMap<NoncelessTransactionKey, VerifiedTransaction>,
    nonceless_transactions_queued: BTreeMap<NoncelessTransactionKey, VerifiedTransaction>,
}

impl TransactionsAccount {
    // state transition functions
    // these move transactions from pending to queued and vice versa
    // they should leave everything consistent
    fn queue_to_pending_nonced(&mut self) {
        let (_k, transaction) = self.nonced_transactions_queued.pop_first().unwrap();
        if let Some(highest_pending_nonce) = self
            .nonced_transactions_pending
            .last_key_value()
            .map(|(k, _v)| k)
        {
            debug_assert!(
                transaction.tx.nonce().unwrap() == highest_pending_nonce + 1,
                "Attempt to move nonced transaction to pending with non-sequential nonce"
            );
        }
        self.balance_after_pending -= transaction.tx.maximum_validation_cost().unwrap() as i128;
        let prev_value = self
            .nonced_transactions_pending
            .insert(transaction.tx.nonce().unwrap(), transaction);
        debug_assert!(prev_value.is_none());
    }
    fn pending_to_queue_nonced(&mut self) {
        let (_k, transaction) = self.nonced_transactions_pending.pop_last().unwrap();
        self.balance_after_pending += transaction.tx.maximum_validation_cost().unwrap() as i128;
        let prev_value = self
            .nonced_transactions_queued
            .insert(transaction.tx.nonce().unwrap(), transaction);
        debug_assert!(prev_value.is_none());
    }
    fn queue_to_pending_nonceless(&mut self, key: NoncelessTransactionKey) {
        let transaction = self.nonceless_transactions_queued.remove(&key).unwrap();
        self.balance_after_pending -= transaction.tx.maximum_validation_cost().unwrap() as i128;
        let prev_value = self.nonceless_transactions_pending.insert(key, transaction);
        debug_assert!(prev_value.is_none());
    }
    fn pending_to_queue_nonceless(&mut self, key: NoncelessTransactionKey) {
        let transaction = self.nonceless_transactions_pending.remove(&key).unwrap();
        self.balance_after_pending += transaction.tx.maximum_validation_cost().unwrap() as i128;
        let prev_value = self.nonceless_transactions_queued.insert(key, transaction);
        debug_assert!(prev_value.is_none());
    }
    fn get_first_queued_nonced(&self) -> Option<&VerifiedTransaction> {
        let next_queueable_nonce = match self
            .get_last_pending_nonced()
            .map(|tx| tx.tx.nonce().unwrap() + 1)
        {
            Some(nonce) => nonce,
            None => self.nonce_account,
        };
        self.nonced_transactions_queued
            .first_key_value()
            .filter(|(_k, v)| v.tx.nonce().unwrap() == next_queueable_nonce)
            .map(|(_k, v)| v)
    }
    fn get_last_pending_nonced(&self) -> Option<&VerifiedTransaction> {
        self.nonced_transactions_pending
            .last_key_value()
            .map(|(_k, v)| v)
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
                    (Some(_), None) => self.queue_to_pending_nonced(),
                    (Some(x), Some(y)) => {
                        if x.tx.gas_price_per_evm_gas() >= y.tx.gas_price_per_evm_gas() {
                            self.queue_to_pending_nonced()
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
                    (Some(_), None) => self.pending_to_queue_nonced(),
                    (Some(x), Some(y)) => {
                        if x.tx.gas_price_per_evm_gas() < y.tx.gas_price_per_evm_gas() {
                            self.pending_to_queue_nonced()
                        } else {
                            self.pending_to_queue_nonceless(y.into())
                        }
                    }
                }
            }
        }
        debug_assert!(dbg_total_txns_before == self.get_transaction_count());
    }
    fn full_recalculate(&mut self) {
        self.nonced_transactions_queued
            .append(&mut self.nonced_transactions_pending);
        self.nonceless_transactions_queued
            .append(&mut self.nonceless_transactions_pending);
        self.balance_after_pending = self.balance_account as i128;
        self.maintain();
    }
    fn insert_nonced_txn(&mut self, txn: VerifiedTransaction) {
        debug_assert!(txn.tx.nonce().is_some());
        let nonce = txn.tx.nonce().unwrap();
        debug_assert!(!self.nonced_transactions_pending.contains_key(&nonce));
        let existing_txn = self.nonced_transactions_queued.insert(nonce, txn);
        debug_assert!(
            existing_txn.is_none(),
            "JCVH: Attempt to double insert a transaction"
        );
        self.maintain();
    }
    fn insert_unnonced_txn(&mut self, txn: VerifiedTransaction) {
        debug_assert!(txn.tx.nonce().is_none());
        let gas_price = txn.tx.maximum_validation_cost().unwrap() as i128;
        // Put it in pending and then pop it again if necessary
        let existing_txn = self
            .nonceless_transactions_pending
            .insert((&txn).into(), txn.clone());
        debug_assert!(
            existing_txn.is_none(),
            "BQHN: Attempt to double insert a transaction"
        );
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
    /// Returns hash of updated transaction
    fn update_txn(&mut self, new_txn: VerifiedTransaction) -> Option<Hash> {
        if let Some(nonce) = new_txn.tx.nonce() {
            if let std::collections::btree_map::Entry::Occupied(mut entry) =
                self.nonced_transactions_pending.entry(nonce)
            {
                let new_gas_price = new_txn.tx.maximum_validation_cost().unwrap() as i128;
                let old_txn = entry.insert(new_txn);
                self.balance_after_pending -=
                    new_gas_price - old_txn.tx.maximum_validation_cost().unwrap() as i128;
                self.maintain();
                return Some(old_txn.hash);
            }
            if let std::collections::btree_map::Entry::Occupied(mut entry) =
                self.nonced_transactions_queued.entry(nonce)
            {
                let old_txn = entry.insert(new_txn);
                self.maintain();
                return Some(old_txn.hash);
            }
            unreachable!("YMGL: Transaction not found")
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
        let nonced_iterator = self.nonced_transactions_pending.iter().map(|x| x.1);

        nonceless_iterator.merge_by(nonced_iterator, |a, b| {
            a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas()
        })
    }
    fn get_queued(&self) -> impl Iterator<Item = &VerifiedTransaction> {
        let nonceless_iterator = self.nonceless_transactions_queued.iter().rev().map(|x| x.1);
        let nonced_iterator = self.nonced_transactions_queued.iter().map(|x| x.1);

        nonceless_iterator.merge_by(nonced_iterator, |a, b| {
            a.tx.gas_price_per_evm_gas() > b.tx.gas_price_per_evm_gas()
        })
    }
    fn get_pending_transaction_count(&self) -> u64 {
        let nonced_pending_count = self.nonced_transactions_pending.len();
        let nonceless_pending_count = self.nonceless_transactions_pending.len();
        (nonced_pending_count + nonceless_pending_count) as u64
    }
    fn get_transaction_count(&self) -> usize {
        self.nonced_transactions_queued.len()
            + self.nonced_transactions_pending.len()
            + self.nonceless_transactions_queued.len()
            + self.nonceless_transactions_pending.len()
    }
    fn is_empty(&self) -> bool {
        self.nonced_transactions_queued.is_empty()
            && self.nonced_transactions_pending.is_empty()
            && self.nonceless_transactions_pending.is_empty()
            && self.nonceless_transactions_queued.is_empty()
    }
    fn peek_best_txn(&self) -> Option<&VerifiedTransaction> {
        self.get_pending().next()
    }
    fn pop_best_if(
        &mut self,
        predicate: impl Fn(&VerifiedTransaction) -> bool,
    ) -> Option<VerifiedTransaction> {
        let transaction = match self.peek_best_txn() {
            Some(txn) if predicate(txn) => txn.clone(),
            _ => return None,
        };
        if transaction.tx.nonce().is_some() {
            self.nonced_transactions_pending.pop_first().unwrap();
            self.balance_after_pending += transaction.tx.maximum_validation_cost().unwrap() as i128;
            self.nonce_account += 1;
        } else {
            self.nonceless_transactions_pending.pop_last().unwrap();
            self.balance_after_pending += transaction.tx.maximum_validation_cost().unwrap() as i128;
        }
        self.maintain();
        Some(transaction)
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
        let old_nonce = self.nonce_account;
        let lowest_existing_nonce = self
            .nonced_transactions_pending
            .first_key_value()
            .or(self.nonced_transactions_queued.first_key_value())
            .and_then(|x| x.1.tx.nonce());
        match new_nonce.cmp(&old_nonce) {
            Ordering::Less => {
                self.nonce_account = new_nonce;
                if Some(old_nonce) == lowest_existing_nonce {
                    self.full_recalculate();
                }
            }
            Ordering::Equal => (),
            Ordering::Greater => {
                if let Some(lowest_existing_nonce) = lowest_existing_nonce {
                    match new_nonce.cmp(&lowest_existing_nonce) {
                        std::cmp::Ordering::Less => self.nonce_account = new_nonce,
                        std::cmp::Ordering::Equal => {
                            self.nonce_account = new_nonce;
                            self.full_recalculate();
                        }
                        std::cmp::Ordering::Greater => panic!(
                            "Nonce cannot be increased above lowest transaction nonce in pool"
                        ),
                    }
                }
            }
        }
        vec![]
    }
    fn update_with_account(&mut self, account: &Account) -> Vec<Hash> {
        self.update_balance(account.balance);
        let result = self.update_nonce(account.nonce);
        self.maintain();
        result
    }
    fn get_pending_or_queued(&self, txn: &VerifiedTransaction) -> Option<PendingOrQueued> {
        debug_assert!(txn.signer == self.address);
        if self
            .nonceless_transactions_pending
            .contains_key(&txn.into())
        {
            return Some(PendingOrQueued::Pending);
        }
        if self.nonceless_transactions_queued.contains_key(&txn.into()) {
            return Some(PendingOrQueued::Queued);
        }
        if let Some(nonce) = txn.tx.nonce() {
            if self.nonced_transactions_pending.contains_key(&nonce) {
                return Some(PendingOrQueued::Pending);
            }
            if self.nonced_transactions_queued.contains_key(&nonce) {
                return Some(PendingOrQueued::Queued);
            }
        }
        None
    }
    fn get_txn_by_nonce(&self, nonce: u64) -> Option<&VerifiedTransaction> {
        self.nonced_transactions_pending
            .get(&nonce)
            .or_else(|| self.nonced_transactions_queued.get(&nonce))
    }
    fn get_pending_queue_key(&self) -> Option<PendingQueueKey> {
        self.peek_best_txn()
            .map(|best_transaction| PendingQueueKey {
                highest_gas_price: best_transaction.tx.gas_price_per_evm_gas(),
                address: best_transaction.signer,
            })
    }

    #[allow(clippy::collapsible_else_if)] // Clearer semantics
    fn delete_transactions<I>(&mut self, txns: I) -> Vec<VerifiedTransaction>
    where
        I: IntoIterator<Item = VerifiedTransaction>,
    {
        let mut recalculate_needed = false;
        let mut result = Vec::new();
        for txn in txns {
            if let Some(nonce) = txn.tx.nonce() {
                if let Some(removed_txn) = self.nonced_transactions_pending.remove(&nonce) {
                    result.push(removed_txn);
                    recalculate_needed = true;
                } else if let Some(removed_txn) = self.nonced_transactions_queued.remove(&nonce) {
                    result.push(removed_txn);
                }
            } else {
                if let Some(removed_txn) =
                    self.nonceless_transactions_pending.remove(&(&txn).into())
                {
                    result.push(removed_txn);
                    recalculate_needed = true;
                } else if let Some(removed_txn) =
                    self.nonceless_transactions_queued.remove(&(&txn).into())
                {
                    result.push(removed_txn);
                }
            }
        }
        if recalculate_needed {
            self.full_recalculate();
        }
        result
    }

    fn mark_executed(&mut self, txn: &VerifiedTransaction) -> Vec<Hash> {
        if let std::collections::btree_map::Entry::Occupied(entry) =
            self.nonceless_transactions_pending.entry(txn.into())
        {
            let old_txn = entry.remove();
            let gas = old_txn.tx.gas_price_per_evm_gas();
            self.balance_after_pending += gas as i128;
            self.maintain();
            return vec![old_txn.hash];
        }
        if let std::collections::btree_map::Entry::Occupied(entry) =
            self.nonceless_transactions_queued.entry(txn.into())
        {
            let old_txn = entry.remove();
            self.maintain();
            return vec![old_txn.hash];
        }
        let Some(nonce_to_remove) = txn.tx.nonce() else {
            tracing::warn!(
                "Transaction could not be marked executed since it was not in pool: {:?}",
                txn
            );
            return vec![];
        };
        if let Some(lowest_nonce) = self
            .nonced_transactions_pending
            .first_key_value()
            .or(self.nonced_transactions_queued.first_key_value())
            .map(|x| x.1.tx.nonce().unwrap())
        {
            if let Some(txn) = self.nonced_transactions_pending.remove(&nonce_to_remove) {
                self.nonce_account = txn.tx.nonce().unwrap() + 1;
                if txn.tx.nonce().unwrap() == lowest_nonce {
                    self.nonce_account += 1;
                    self.balance_after_pending += txn.tx.maximum_validation_cost().unwrap() as i128;
                    self.maintain();
                } else {
                    self.full_recalculate();
                    tracing::warn!("Pending transaction remove was not lowest nonce")
                }
                vec![txn.hash]
            } else if let Some(txn) = self.nonced_transactions_queued.remove(&nonce_to_remove) {
                if txn.tx.nonce().unwrap() == lowest_nonce {
                    self.maintain();
                } else {
                    self.maintain();
                    tracing::warn!("Queued transaction removed was not lowest nonce")
                }
                vec![txn.hash]
            } else {
                tracing::warn!(
                    "Transaction could not be marked executed since it was not in pool: {:?}",
                    txn
                );
                vec![]
            }
        } else {
            tracing::warn!("No nonced transactions in pool");
            vec![]
        }
    }
}

/// Private implementation of the transaction pool
/// The pool is a set of pools for individual accounts (all_transactions), each of which maintains
/// its own pending lists of nonced and nonceless transactions.
/// When pending transactions are queried they just need to be merged from the individual accounts.
#[derive(Clone, Debug)]
struct TransactionPoolCore {
    all_transactions: HashMap<Address, TransactionsAccount>,
    pending_account_queue: BTreeSet<PendingQueueKey>,
    hash_to_txn_map: HashMap<Hash, (VerifiedTransaction, SystemTime)>, // Also tracks insertion times
    oldest_insertion_time: Option<SystemTime>, // For efficiency, this is only updated during clear_old_transactions
    pool_expiry_time_minimum: Duration, // Transactions are allowed to remain at least this long in the pool
    expiry_time_clearout_threshold: Duration, // When oldest_insertion_time reaches this age, a clearout is initiated
    // Keeps track of the total number of transactions in the pool for speed
    total_transactions_counter: usize,
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
                self.total_transactions_counter -= removed_txn_hashes.len();
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
        if let Some(transactions_account) = self.all_transactions.get_mut(account_address) {
            let old_nonce = transactions_account.nonce_account;
            let old_balance = transactions_account.balance_account;
            let new_account = account_data;
            let new_nonce = new_account.nonce;
            let new_balance = new_account.balance;
            if old_nonce != new_nonce || old_balance != new_balance {
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.remove(&pending_queue_key);
                }
                let removed_txn_hashes = transactions_account.update_with_account(new_account);
                self.total_transactions_counter -= removed_txn_hashes.len();
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
            Some(account) => account.get_pending_transaction_count(),
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
            .map(|x| x.get_pending_transaction_count())
            .sum()
    }

    fn transaction_count(&self) -> u64 {
        self.total_transactions_counter as u64
    }

    pub fn senders_count(&self) -> usize {
        self.all_transactions.len()
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
        self.hash_to_txn_map.get(hash).map(|(txn, _)| txn)
    }

    fn update_txn(&mut self, txn: VerifiedTransaction) {
        let transactions_account = self.all_transactions.get_mut(&txn.signer).unwrap();
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.remove(&pending_queue_key);
        }
        let old_hash = transactions_account.update_txn(txn.clone()).unwrap();
        self.hash_to_txn_map.remove(&old_hash);
        self.hash_to_txn_map
            .insert(txn.hash, (txn, SystemTime::now()));
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.insert(pending_queue_key);
        }
        self.clear_old_transactions();
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
                    nonced_transactions_pending: BTreeMap::new(),
                    nonced_transactions_queued: BTreeMap::new(),
                    nonceless_transactions_pending: BTreeMap::new(),
                    nonceless_transactions_queued: BTreeMap::new(),
                });
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.remove(&pending_queue_key);
        }
        transactions_account.insert_txn(txn.clone());
        self.total_transactions_counter += 1;
        if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
            self.pending_account_queue.insert(pending_queue_key);
        }
        self.hash_to_txn_map
            .insert(txn.hash, (txn, SystemTime::now()));
        self.oldest_insertion_time.get_or_insert(SystemTime::now());
        self.clear_old_transactions();
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
        !self.pending_account_queue.is_empty()
    }

    fn clear(&mut self) {
        self.pending_account_queue.clear();
        self.all_transactions.clear();
        self.hash_to_txn_map.clear();
        self.total_transactions_counter = 0;
        self.oldest_insertion_time = None;
    }

    fn peek_best_txn(&self) -> Option<&VerifiedTransaction> {
        let best_account_key = self.pending_account_queue.last()?;

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
            self.total_transactions_counter -= 1;
            if let Some(pending_queue_key) = old_pending_queue_key {
                self.pending_account_queue.remove(&pending_queue_key);
            }
            if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                self.pending_account_queue.insert(pending_queue_key);
            }
            if transactions_account.is_empty() {
                self.all_transactions.remove(&best_account_key.address);
            }
            self.hash_to_txn_map.remove(&txn.hash).unwrap();
        }
        result
    }

    pub fn mark_executed(&mut self, txn: &VerifiedTransaction) {
        let address = txn.signer;
        if let Some(account) = self.all_transactions.get_mut(&address) {
            if let Some(pending_queue_key) = account.get_pending_queue_key() {
                self.pending_account_queue.remove(&pending_queue_key);
            }
            let removed_txn_hashes = account.mark_executed(txn);
            self.total_transactions_counter -= removed_txn_hashes.len();
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

    fn delete_transactions<I>(&mut self, txns: I)
    where
        I: IntoIterator<Item = VerifiedTransaction>,
    {
        let mut to_delete: HashMap<Address, Vec<VerifiedTransaction>> = HashMap::new();
        for txn in txns {
            let address = txn.signer;
            to_delete.entry(address).or_default().push(txn);
        }
        for (address, txns) in to_delete {
            if let Some(transactions_account) = self.all_transactions.get_mut(&address) {
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.remove(&pending_queue_key);
                }
                let removed_txns = transactions_account.delete_transactions(txns);
                self.total_transactions_counter -= removed_txns.len();
                if let Some(pending_queue_key) = transactions_account.get_pending_queue_key() {
                    self.pending_account_queue.insert(pending_queue_key);
                }
                if transactions_account.is_empty() {
                    self.all_transactions.remove(&address);
                }
                for txn in removed_txns {
                    self.hash_to_txn_map.remove(&txn.hash);
                }
            }
        }
    }

    fn clear_old_transactions(&mut self) {
        if self
            .oldest_insertion_time
            .is_none_or(|x| x.elapsed().unwrap() < self.expiry_time_clearout_threshold)
        {
            // No transactions older than maximum age, so no need to clear
            return;
        }
        let oldest_allowable_insertion_time = SystemTime::now()
            .checked_sub(self.pool_expiry_time_minimum)
            .unwrap();
        let mut transactions_to_delete = Vec::new();
        self.oldest_insertion_time = None;
        for (txn, insertion_time) in self.hash_to_txn_map.values() {
            if *insertion_time < oldest_allowable_insertion_time {
                transactions_to_delete.push(txn.clone());
            } else {
                self.oldest_insertion_time = Some(
                    self.oldest_insertion_time
                        .map_or(*insertion_time, |x| min(x, *insertion_time)),
                )
            }
        }
        self.delete_transactions(transactions_to_delete);
    }
}

impl Default for TransactionPoolCore {
    fn default() -> Self {
        Self {
            all_transactions: HashMap::new(),
            pending_account_queue: BTreeSet::new(),
            hash_to_txn_map: HashMap::new(),
            oldest_insertion_time: None,
            pool_expiry_time_minimum: Duration::from_secs(60 * 60 * 24),
            expiry_time_clearout_threshold: Duration::from_secs(60 * 60 * 48),
            total_transactions_counter: 0,
        }
    }
}

/// This struct wraps the transaction pool to separate the methods needed by the wider application
/// from the internal implementation details.
#[derive(Clone, Debug, Default)]
pub struct TransactionPool {
    core: TransactionPoolCore,
    /// Keeps transactions created at this node that will be broadcast
    transactions_to_broadcast: VecDeque<VerifiedTransaction>,
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

    pub fn get_transaction(&self, hash: &Hash) -> Option<&VerifiedTransaction> {
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
        // check for duplicates
        if self.core.hash_to_txn_map.contains_key(&txn.hash) {
            tracing::warn!(
                "Transaction with this hash is already in the pool. Txn hash: {:?}, from: {:?}, account nonce: {:?}",
                txn.hash,
                txn.signer,
                account.nonce,
            );
            self.update_with_account(&txn.signer, account);
            return TxAddResult::Duplicate(txn.hash);
        }

        if let Some(transaction_nonce) = txn.tx.nonce()
            && transaction_nonce < account.nonce
        {
            debug!(
                "Nonce is too low. Txn hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                txn.hash, txn.signer, transaction_nonce, account.nonce,
            );
            // This transaction is permanently invalid, so there is nothing to do.
            // unwrap() is safe because we checked above that it was some().
            self.update_with_account(&txn.signer, account);
            return TxAddResult::NonceTooLow(transaction_nonce, account.nonce);
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
                self.update_with_account(&txn.signer, account);
                return TxAddResult::SameNonceButLowerGasPrice;
            } else {
                debug!(
                    "Txn updated in mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                    txn.hash,
                    txn.signer,
                    txn.tx.nonce(),
                    account.nonce,
                );
                self.update_with_account(&txn.signer, account);
                self.core.update_txn(txn.clone());
            }
        } else {
            // Check global size
            if self.core.transaction_count() + 1 > GLOBAL_TXN_POOL_SIZE_LIMIT {
                return TxAddResult::ValidationFailed(
                    ValidationOutcome::GlobalTransactionCountExceeded,
                );
            }

            // Check total number of senders
            if self.core.senders_count() + 1 > TOTAL_SENDERS_COUNT_LIMIT {
                return TxAddResult::ValidationFailed(
                    ValidationOutcome::TotalNumberOfSlotsExceeded,
                );
            }

            // Check total number of slots for senders
            if self.account_total_transaction_count(&txn.signer) + 1 > MAX_TXNS_PER_SENDER {
                return TxAddResult::ValidationFailed(
                    ValidationOutcome::TransactionCountExceededForSender,
                );
            }

            debug!(
                "Txn added to mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                txn.hash,
                txn.signer,
                txn.tx.nonce(),
                account.nonce,
            );
            self.core.add_txn(txn.clone(), account);
            self.update_with_account(&txn.signer, account);
        }

        // If this is a transaction created at this node, add it to broadcast vector
        if !from_broadcast {
            self.store_broadcast_txn(&txn);
        }

        TxAddResult::AddedToMempool
    }

    // Like insert transaction, but if the transaction is already there, we always overwrite it
    pub fn insert_transaction_forced(
        &mut self,
        txn: VerifiedTransaction,
        account: &Account,
        from_broadcast: bool,
    ) -> TxAddResult {
        // check for duplicates
        if self.core.hash_to_txn_map.contains_key(&txn.hash) {
            tracing::warn!(
                "Transaction with this hash is already in the pool. Txn hash: {:?}, from: {:?}, account nonce: {:?}",
                txn.hash,
                txn.signer,
                account.nonce,
            );
            self.update_with_account(&txn.signer, account);
            return TxAddResult::Duplicate(txn.hash);
        }

        if let Some(transaction_nonce) = txn.tx.nonce()
            && transaction_nonce < account.nonce
        {
            debug!(
                "Nonce is too low. Txn hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                txn.hash, txn.signer, transaction_nonce, account.nonce,
            );
            // This transaction is permanently invalid, so there is nothing to do.
            // unwrap() is safe because we checked above that it was some().
            self.update_with_account(&txn.signer, account);
            return TxAddResult::NonceTooLow(transaction_nonce, account.nonce);
        }

        let existing_transaction = match txn.tx.nonce() {
            Some(nonce) => self.core.get_txn_by_address_and_nonce(&txn.signer, nonce),
            None => None,
        };
        if let Some(_existing_txn) = existing_transaction {
            debug!(
                "Txn updated in mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                txn.hash,
                txn.signer,
                txn.tx.nonce(),
                account.nonce,
            );
            self.update_with_account(&txn.signer, account);
            self.core.update_txn(txn.clone());
        } else {
            debug!(
                "Txn added to mempool. Hash: {:?}, from: {:?}, nonce: {:?}, account nonce: {:?}",
                txn.hash,
                txn.signer,
                txn.tx.nonce(),
                account.nonce,
            );
            self.core.add_txn(txn.clone(), account);
            self.update_with_account(&txn.signer, account);
        }

        // If this is a transaction created at this node, add it to broadcast vector
        if !from_broadcast {
            self.store_broadcast_txn(&txn);
        }

        TxAddResult::AddedToMempool
    }

    fn store_broadcast_txn(&mut self, txn: &VerifiedTransaction) {
        self.transactions_to_broadcast.push_back(txn.clone());
    }

    pub fn pull_txns_to_broadcast(&mut self) -> Result<Vec<SignedTransaction>> {
        const MAX_BATCH_SIZE: usize = 1000;
        const BATCH_SIZE_THRESHOLD: usize = 972 * 1024; // 95% of max_transmit_size().

        if self.transactions_to_broadcast.is_empty() {
            return Ok(Vec::new());
        }

        let mut batch_count = 0usize;
        let mut batch_size = BATCH_SIZE_THRESHOLD;

        for tx in self.transactions_to_broadcast.iter() {
            // batch by number or size
            if let Some(balance_size) = batch_size.checked_sub(tx.encoded_size()) {
                batch_size = balance_size;
                batch_count += 1;
                if batch_count == MAX_BATCH_SIZE {
                    break;
                }
            } else {
                break;
            };
        }

        let selected = self
            .transactions_to_broadcast
            .drain(0..batch_count)
            .map(|tx| tx.tx)
            .collect();
        Ok(selected)
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
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };

    use alloy::{
        consensus::TxLegacy,
        primitives::{Address, Bytes, Signature, TxKind, U256},
    };
    use anyhow::Result;
    use itertools::Itertools;
    use rand::{seq::SliceRandom, thread_rng};

    use super::TransactionPool;
    use crate::{
        cfg::NodeConfig,
        crypto::Hash,
        db::Db,
        pool::{PendingOrQueued, TxAddResult},
        state::State,
        transaction::{EvmGas, SignedTransaction, TxIntershard, VerifiedTransaction},
    };

    fn transaction(from_addr: Address, nonce: u64, gas_price: u128) -> VerifiedTransaction {
        let tx = SignedTransaction::Legacy {
            tx: TxLegacy {
                chain_id: Some(0),
                nonce,
                gas_price,
                gas_limit: 1,
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::new(),
            },
            sig: Signature::new(U256::from(1), U256::from(1), false),
        };
        let cbor_size = cbor4ii::serde::to_vec(Vec::with_capacity(4096), &tx)
            .map(|b| b.len())
            .unwrap_or_default();
        VerifiedTransaction {
            cbor_size,
            tx,
            signer: from_addr,
            hash: Hash::builder()
                .with(from_addr.as_slice())
                .with(nonce.to_le_bytes())
                .finalize(),
        }
    }

    fn intershard_transaction(
        from_shard: u8,
        shard_nonce: u8,
        gas_price: u128,
    ) -> VerifiedTransaction {
        let tx = SignedTransaction::Intershard {
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
        };
        let cbor_size = cbor4ii::serde::to_vec(Vec::with_capacity(4096), &tx)
            .map(|b| b.len())
            .unwrap_or_default();
        VerifiedTransaction {
            cbor_size,
            tx,
            signer: Address::ZERO,
            hash: Hash::builder()
                .with([shard_nonce])
                .with([from_shard])
                .finalize(),
        }
    }

    fn get_in_memory_state() -> Result<State> {
        let node_config = NodeConfig::default();

        let db = Db::new::<PathBuf>(None, 0, None, crate::cfg::DbConfig::default())?;
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
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions_pending.len(), 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonced_transactions_queued.len(), 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 0);

        // Add the lowest transaction and now they should get added up to the balance
        pool.insert_transaction(txn1.clone(), &acc1, false);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 30);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn1, &txn2, &txn3]);

        // Increase the balance by 5 and nothing else should change
        state.mutate_account(acc1_addr, |acc| {
            acc.balance += 5;
            Ok(())
        })?;
        assert_eq!(state.get_account(acc1_addr).unwrap().balance, 35);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 3);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 35);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 5);
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
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn1, &txn2, &txn3, &txn4]);

        // add another two, and they shouldn't pend
        pool.insert_transaction(txn5.clone(), &acc1, false);
        pool.insert_transaction(txn6.clone(), &acc1, false);
        pool.core.update_with_state(&state);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 40);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn1, &txn2, &txn3, &txn4]);

        // pop a transaction off the front and one of the next two should get added
        pool.pop_best_if(|txn| {
            assert_eq!(txn, &txn1);
            true
        });
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_account, 40);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().nonce_account, 1);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().balance_after_pending, 0);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending_transaction_count(), 4);
        assert_eq!(pool.core.all_transactions.get(&acc1_addr).unwrap().get_pending().collect_vec(), vec![&txn2, &txn3, &txn4, &txn5]);

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
            pool.insert_transaction(transaction(from, nonces[i as usize], 3), &acc, false);
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
        let queued: Vec<_> = pool.queued_transactions_ordered().cloned().collect();

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
    fn benchmark_pending_transactions() -> Result<()> {
        let mut pool = TransactionPool::default();
        let from = "0x0000000000000000000000000000000000001234".parse()?;

        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, from, 1_000_000, 0)?;
        pool.update_with_state(&state);

        // Insert 100 pending transactions
        for nonce in 0u64..100u64 {
            pool.insert_transaction(transaction(from, nonce, 1), &acc, false);
        }

        // Insert 100 queued transactions
        for nonce in 101u64..201u64 {
            pool.insert_transaction(transaction(from, nonce, 1), &acc, false);
        }

        // Benchmark the preview_content method
        let start = std::time::Instant::now();
        let _result: Vec<_> = pool.pending_transactions_ordered().collect();
        let duration = start.elapsed();

        println!("Benchmark completed: pending_transactions took {duration:?} to execute.");
        Ok(())
    }

    // Helper function to create a transaction with custom hash
    fn transaction_with_hash(
        from_addr: Address,
        nonce: u8,
        gas_price: u128,
        hash_suffix: u8,
    ) -> VerifiedTransaction {
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
                sig: Signature::new(U256::from(1), U256::from(1), false),
            },
            signer: from_addr,
            hash: Hash::builder()
                .with(from_addr.as_slice())
                .with([nonce, hash_suffix])
                .finalize(),
            cbor_size: 0,
        }
    }

    #[test]
    fn test_duplicate_transaction_handling() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn = transaction(addr, 0, 10);

        // First insertion should succeed
        let result1 = pool.insert_transaction(txn.clone(), &acc, false);
        assert!(matches!(result1, TxAddResult::AddedToMempool));

        // Second insertion of same transaction should be handled gracefully
        let result2 = pool.insert_transaction(txn.clone(), &acc, false);
        assert!(matches!(result2, TxAddResult::Duplicate(_))); // Same txn, no change

        assert_eq!(pool.transaction_count(), 1);
        Ok(())
    }

    #[test]
    fn test_nonce_too_low_rejection() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 5)?; // Account nonce is 5

        let txn = transaction(addr, 3, 10); // Transaction nonce is 3 (too low)

        let result = pool.insert_transaction(txn, &acc, false);
        assert!(matches!(result, TxAddResult::NonceTooLow(3, 5)));
        assert_eq!(pool.transaction_count(), 0);
        Ok(())
    }

    #[test]
    fn test_gas_price_replacement() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn_low = transaction_with_hash(addr, 0, 10, 1);
        let txn_high = transaction_with_hash(addr, 0, 20, 2);
        let txn_same = transaction_with_hash(addr, 0, 10, 3);

        // Insert low gas price transaction
        let result1 = pool.insert_transaction(txn_low.clone(), &acc, false);
        assert!(matches!(result1, TxAddResult::AddedToMempool));

        // Insert higher gas price transaction with same nonce - should replace
        let result2 = pool.insert_transaction(txn_high.clone(), &acc, false);
        assert!(matches!(result2, TxAddResult::AddedToMempool));

        // Insert same gas price transaction - should be rejected
        let result3 = pool.insert_transaction(txn_same, &acc, false);
        assert!(matches!(result3, TxAddResult::SameNonceButLowerGasPrice));

        // Pool should contain only the high gas price transaction
        assert_eq!(pool.transaction_count(), 1);
        assert_eq!(pool.best_transaction().unwrap().hash, txn_high.hash);
        Ok(())
    }

    #[test]
    fn test_insufficient_balance_queuing() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 25, 0)?; // Balance only covers 2.5 transactions at gas price 10

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 10);
        let txn3 = transaction(addr, 2, 10);
        let txn4 = transaction(addr, 3, 10);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);
        pool.insert_transaction(txn4.clone(), &acc, false);

        // Only first 2 transactions should be pending due to balance constraint
        let pending: Vec<_> = pool.pending_transactions_ordered().cloned().collect();
        let queued: Vec<_> = pool.queued_transactions_ordered().cloned().collect();

        assert_eq!(pending.len(), 2);
        assert_eq!(queued.len(), 2);
        assert_eq!(pending[0], txn1);
        assert_eq!(pending[1], txn2);
        Ok(())
    }

    #[test]
    fn test_nonceless_transaction_ordering() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 1000, 0)?;

        // Create nonceless transactions with different gas prices
        let txn1 = intershard_transaction(1, 1, 5);
        let txn2 = intershard_transaction(2, 2, 15);
        let txn3 = intershard_transaction(3, 3, 10);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);

        // Should be ordered by gas price (highest first)
        let pending: Vec<_> = pool.pending_transactions_ordered().cloned().collect();
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0], txn2); // gas price 15
        assert_eq!(pending[1], txn3); // gas price 10
        assert_eq!(pending[2], txn1); // gas price 5
        Ok(())
    }

    #[test]
    fn test_mixed_nonce_nonceless_ordering() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 1000, 0)?;

        let txn_nonce = transaction(addr, 0, 12);
        let txn_nonceless_high = intershard_transaction(1, 1, 15);
        let txn_nonceless_low = intershard_transaction(2, 2, 8);

        pool.insert_transaction(txn_nonce.clone(), &acc, false);
        pool.insert_transaction(txn_nonceless_high.clone(), &acc, false);
        pool.insert_transaction(txn_nonceless_low.clone(), &acc, false);

        let pending: Vec<_> = pool.pending_transactions_ordered().cloned().collect();
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0], txn_nonceless_high); // gas price 15
        assert_eq!(pending[1], txn_nonce); // gas price 12
        assert_eq!(pending[2], txn_nonceless_low); // gas price 8
        Ok(())
    }

    #[test]
    fn test_account_balance_updates() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 15, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 10);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);

        // Initially, only first transaction should be pending due to balance
        assert_eq!(pool.pending_transaction_count(), 1);

        // Increase balance
        let new_acc = create_acc(&mut state, addr, 25, 0)?;
        pool.update_with_account(&addr, &new_acc);

        // Now both should be pending
        assert_eq!(pool.pending_transaction_count(), 2);
        Ok(())
    }

    #[test]
    fn test_pop_best_with_predicate() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 20);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);

        // Pop best transaction only if gas price > 15
        let popped = pool.pop_best_if(|tx| tx.tx.gas_price_per_evm_gas() > 15);
        assert!(popped.is_none()); // Should be None because best tx has gas price 10

        // Pop best transaction only if gas price > 5
        let popped = pool.pop_best_if(|tx| tx.tx.gas_price_per_evm_gas() > 5);
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().hash, txn1.hash);

        dbg!(&pool);
        assert_eq!(pool.transaction_count(), 1);
        assert_eq!(pool.best_transaction().unwrap().hash, txn2.hash);
        Ok(())
    }

    #[test]
    fn test_mark_executed_removes_transaction() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = intershard_transaction(1, 1, 15);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);

        assert_eq!(pool.transaction_count(), 2);

        // Mark nonceless transaction as executed
        pool.mark_executed(&txn2);
        assert_eq!(pool.transaction_count(), 1);

        // Mark nonced transaction as executed
        pool.mark_executed(&txn1);
        assert_eq!(pool.transaction_count(), 0);
        Ok(())
    }

    #[test]
    fn test_transaction_broadcast_queue() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 20);

        // Insert without broadcast flag
        pool.insert_transaction(txn1.clone(), &acc, false);

        // Insert with broadcast flag (from network)
        pool.insert_transaction(txn2.clone(), &acc, true);

        let to_broadcast = pool.pull_txns_to_broadcast()?;
        assert_eq!(to_broadcast.len(), 1); // Only txn1 should be in broadcast queue
        assert_eq!(to_broadcast[0], txn1.tx);

        // Second call should return empty
        let to_broadcast2 = pool.pull_txns_to_broadcast()?;
        assert_eq!(to_broadcast2.len(), 0);
        Ok(())
    }

    #[test]
    fn test_get_pending_or_queued_status() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 15, 0)?; // Limited balance

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 10);
        let txn3 = intershard_transaction(1, 1, 5);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);

        // txn1 should be pending (enough balance)
        let status1 = pool.get_pending_or_queued(&txn1)?;
        assert!(matches!(status1, Some(PendingOrQueued::Pending)));

        // txn2 should be queued (insufficient balance)
        let status2 = pool.get_pending_or_queued(&txn2)?;
        assert!(matches!(status2, Some(PendingOrQueued::Queued)));

        // txn3 (nonceless) should be pending
        let status3 = pool.get_pending_or_queued(&txn3)?;
        assert!(matches!(status3, Some(PendingOrQueued::Pending)));
        Ok(())
    }

    #[test]
    fn test_pool_content_preview() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr1 = "0x0000000000000000000000000000000000000001".parse()?;
        let addr2 = "0x0000000000000000000000000000000000000002".parse()?;
        let mut state = get_in_memory_state()?;
        let acc1 = create_acc(&mut state, addr1, 50, 0)?;
        let acc2 = create_acc(&mut state, addr2, 50, 0)?;

        let txn1 = transaction(addr1, 0, 10);
        let txn2 = transaction(addr1, 1, 50); // Will be queued due to balance
        let txn3 = transaction(addr2, 0, 20);

        pool.insert_transaction(txn1.clone(), &acc1, false);
        pool.insert_transaction(txn2.clone(), &acc1, false);
        pool.insert_transaction(txn3.clone(), &acc2, false);

        let content = pool.preview_content();

        // Check pending transactions
        assert_eq!(content.pending.get(&addr1).unwrap().len(), 1);
        assert_eq!(content.pending.get(&addr2).unwrap().len(), 1);

        // Check queued transactions
        assert_eq!(content.queued.get(&addr1).unwrap().len(), 1);
        assert_eq!(content.queued.get(&addr2).unwrap().len(), 0);

        let content_from = pool.preview_content_from(&addr1);
        assert_eq!(content_from.pending.len(), 1);
        assert_eq!(content_from.queued.len(), 1);
        Ok(())
    }

    #[test]
    fn test_pool_clear() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = intershard_transaction(1, 1, 15);

        pool.insert_transaction(txn1, &acc, false);
        pool.insert_transaction(txn2, &acc, false);

        assert_eq!(pool.transaction_count(), 2);
        assert!(pool.has_txn_ready());

        pool.clear();

        assert_eq!(pool.transaction_count(), 0);
        assert!(!pool.has_txn_ready());
        assert!(pool.best_transaction().is_none());
        Ok(())
    }

    #[test]
    fn test_account_counts() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr1 = "0x0000000000000000000000000000000000000001".parse()?;
        let addr2 = "0x0000000000000000000000000000000000000002".parse()?;
        let mut state = get_in_memory_state()?;
        let acc1 = create_acc(&mut state, addr1, 100, 0)?;
        let acc2 = create_acc(&mut state, addr2, 20, 0)?;

        let txn1 = transaction(addr1, 0, 10);
        let txn2 = transaction(addr1, 1, 10);
        let txn3 = transaction(addr2, 0, 30); // Will be queued due to insufficient balance

        pool.insert_transaction(txn1, &acc1, false);
        pool.insert_transaction(txn2, &acc1, false);
        pool.insert_transaction(txn3, &acc2, false);

        assert_eq!(pool.account_total_transaction_count(&addr1), 2);
        assert_eq!(pool.account_pending_transaction_count(&addr1), 2);

        assert_eq!(pool.account_total_transaction_count(&addr2), 1);
        assert_eq!(pool.account_pending_transaction_count(&addr2), 0);

        let status = pool.preview_status();
        assert_eq!(status.pending, 2);
        assert_eq!(status.queued, 1);
        Ok(())
    }

    #[test]
    fn test_get_transaction_by_hash_basic() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = intershard_transaction(1, 1, 15);
        let non_existent_hash = Hash::builder().with([99, 99, 99]).finalize();

        // Initially, no transactions should be found
        assert!(pool.get_transaction(&txn1.hash).is_none());
        assert!(pool.get_transaction(&txn2.hash).is_none());
        assert!(pool.get_transaction(&non_existent_hash).is_none());

        // Add transactions
        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);

        // Now they should be retrievable by hash
        let retrieved_txn1 = pool.get_transaction(&txn1.hash);
        let retrieved_txn2 = pool.get_transaction(&txn2.hash);

        assert!(retrieved_txn1.is_some());
        assert!(retrieved_txn2.is_some());
        assert_eq!(retrieved_txn1.unwrap().hash, txn1.hash);
        assert_eq!(retrieved_txn2.unwrap().hash, txn2.hash);
        assert_eq!(retrieved_txn1.unwrap().signer, txn1.signer);
        assert_eq!(retrieved_txn2.unwrap().signer, txn2.signer);

        // Non-existent hash should still return None
        assert!(pool.get_transaction(&non_existent_hash).is_none());

        Ok(())
    }

    #[test]
    fn test_get_transaction_by_hash_after_execution() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 20);
        let txn3 = intershard_transaction(1, 1, 15);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);

        // All should be retrievable initially
        assert!(pool.get_transaction(&txn1.hash).is_some());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        // Mark txn1 as executed
        pool.mark_executed(&txn1);

        // txn1 should no longer be retrievable, others should still be
        assert!(pool.get_transaction(&txn1.hash).is_none());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        // Mark txn3 (nonceless) as executed
        pool.mark_executed(&txn3);

        // txn3 should no longer be retrievable
        assert!(pool.get_transaction(&txn1.hash).is_none());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_none());

        Ok(())
    }

    #[test]
    fn test_get_transaction_by_hash_after_pop() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 30);
        let txn2 = transaction(addr, 1, 20);
        let txn3 = transaction(addr, 2, 10);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);

        // All should be retrievable initially
        assert!(pool.get_transaction(&txn1.hash).is_some());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        // Pop best transaction (should be txn1 with highest gas price)
        let popped = pool.pop_best_if(|_| true);
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().hash, txn1.hash);

        // txn1 should no longer be retrievable after popping
        assert!(pool.get_transaction(&txn1.hash).is_none());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        // Pop with a predicate that should reject the next best
        let popped2 = pool.pop_best_if(|tx| tx.tx.gas_price_per_evm_gas() > 25);
        assert!(popped2.is_none()); // Should be None because txn2 has gas price 20

        // txn2 should still be retrievable since it wasn't popped
        assert!(pool.get_transaction(&txn2.hash).is_some());

        Ok(())
    }

    #[test]
    fn test_get_transaction_by_hash_after_replacement() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn_low = transaction_with_hash(addr, 0, 10, 1);
        let txn_high = transaction_with_hash(addr, 0, 20, 2);

        // Insert low gas price transaction
        pool.insert_transaction(txn_low.clone(), &acc, false);

        // Should be retrievable by its hash
        assert!(pool.get_transaction(&txn_low.hash).is_some());
        assert!(pool.get_transaction(&txn_high.hash).is_none());

        // Insert higher gas price transaction with same nonce (should replace)
        pool.insert_transaction(txn_high.clone(), &acc, false);

        // Old transaction should no longer be retrievable, new one should be
        assert!(pool.get_transaction(&txn_low.hash).is_none());
        assert!(pool.get_transaction(&txn_high.hash).is_some());

        // Verify the retrieved transaction is correct
        let retrieved = pool.get_transaction(&txn_high.hash).unwrap();
        assert_eq!(retrieved.hash, txn_high.hash);
        assert_eq!(retrieved.tx.gas_price_per_evm_gas(), 20);

        Ok(())
    }

    #[test]
    fn test_get_transaction_by_hash_after_clear() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = intershard_transaction(1, 1, 15);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);

        // Both should be retrievable initially
        assert!(pool.get_transaction(&txn1.hash).is_some());
        assert!(pool.get_transaction(&txn2.hash).is_some());

        // Clear the pool
        pool.clear();

        // No transactions should be retrievable after clearing
        assert!(pool.get_transaction(&txn1.hash).is_none());
        assert!(pool.get_transaction(&txn2.hash).is_none());
        assert_eq!(pool.transaction_count(), 0);

        Ok(())
    }

    #[test]
    fn test_get_transaction_by_hash_consistency_during_state_updates() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 15, 0)?; // Limited balance

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 10); // Will be queued due to balance
        let txn3 = intershard_transaction(1, 1, 5);

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);

        // All should be retrievable regardless of pending/queued status
        assert!(pool.get_transaction(&txn1.hash).is_some());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        // Update balance to allow all transactions to be pending
        let new_acc = create_acc(&mut state, addr, 100, 0)?;
        pool.update_with_account(&addr, &new_acc);

        // All should still be retrievable after balance update
        assert!(pool.get_transaction(&txn1.hash).is_some());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        // Reduce balance again
        let limited_acc = create_acc(&mut state, addr, 12, 0)?;
        pool.update_with_account(&addr, &limited_acc);

        // All should still be retrievable even if some are queued again
        assert!(pool.get_transaction(&txn1.hash).is_some());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        Ok(())
    }

    #[test]
    fn test_get_transaction_by_hash_multiple_accounts() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr1 = "0x0000000000000000000000000000000000000001".parse()?;
        let addr2 = "0x0000000000000000000000000000000000000002".parse()?;
        let mut state = get_in_memory_state()?;
        let acc1 = create_acc(&mut state, addr1, 100, 0)?;
        let acc2 = create_acc(&mut state, addr2, 100, 0)?;

        let txn1_acc1 = transaction(addr1, 0, 10);
        let txn2_acc1 = transaction(addr1, 1, 20);
        let txn1_acc2 = transaction(addr2, 1, 15);
        let txn2_acc2 = intershard_transaction(1, 1, 5);

        assert!(matches!(
            pool.insert_transaction(txn1_acc1.clone(), &acc1, false),
            TxAddResult::AddedToMempool
        ));
        assert!(matches!(
            pool.insert_transaction(txn2_acc1.clone(), &acc1, false),
            TxAddResult::AddedToMempool
        ));
        assert!(matches!(
            pool.insert_transaction(txn1_acc2.clone(), &acc2, false),
            TxAddResult::AddedToMempool
        ));
        assert!(matches!(
            pool.insert_transaction(txn2_acc2.clone(), &acc2, false),
            TxAddResult::AddedToMempool
        ));

        // All transactions from both accounts should be retrievable
        assert!(pool.get_transaction(&txn1_acc1.hash).is_some());
        assert!(pool.get_transaction(&txn2_acc1.hash).is_some());
        assert!(pool.get_transaction(&txn1_acc2.hash).is_some());
        assert!(pool.get_transaction(&txn2_acc2.hash).is_some());

        // Execute a transaction from account 1
        pool.mark_executed(&txn1_acc1);

        // Only that specific transaction should be removed
        assert!(pool.get_transaction(&txn1_acc1.hash).is_none());
        assert!(pool.get_transaction(&txn2_acc1.hash).is_some());
        assert!(pool.get_transaction(&txn1_acc2.hash).is_some());
        assert!(pool.get_transaction(&txn2_acc2.hash).is_some());

        // Remove first transaction from account 2
        let new_acc2 = create_acc(&mut state, addr2, 100, 1)?;
        pool.update_with_account(&addr2, &new_acc2);
        pool.mark_executed(&txn1_acc2);

        // Account 2's first transaction should be removed, others should remain
        assert!(pool.get_transaction(&txn1_acc1.hash).is_none());
        assert!(pool.get_transaction(&txn2_acc1.hash).is_some());
        assert!(
            pool.core
                .get_txn_by_address_and_nonce(&txn1_acc2.signer, txn1_acc2.tx.nonce().unwrap())
                .is_none()
        );
        assert!(pool.get_transaction(&txn1_acc2.hash).is_none());
        assert!(pool.get_transaction(&txn2_acc2.hash).is_some());

        Ok(())
    }

    #[test]
    fn pool_benchmark_insert_ascending_nonces() -> Result<()> {
        let mut pool = TransactionPool::default();
        let mut state = get_in_memory_state()?;

        // Create 1000 accounts
        let mut accounts = Vec::new();
        for i in 0..1000 {
            let addr: Address = format!("0x{i:040x}").parse()?;
            let acc = create_acc(&mut state, addr, 1_000_000, 0)?;
            accounts.push((addr, acc));
        }

        let start = Instant::now();
        let target_duration = Duration::from_secs(1);
        let mut transaction_count = 0;
        let mut account_idx = 0;
        let mut nonce = 0;

        // Insert transactions for 1 second in ascending nonce order
        while start.elapsed() < target_duration {
            let (addr, acc) = &accounts[account_idx % accounts.len()];
            let txn = transaction(*addr, nonce, 10);
            pool.insert_transaction(txn, acc, false);

            transaction_count += 1;
            nonce += 1;

            // Move to next account after every 1000 transactions to simulate realistic usage
            if nonce % 1000 == 0 {
                account_idx += 1;
                nonce = 0;
            }
        }

        let duration = start.elapsed();
        let time_per_op = duration.as_nanos() / transaction_count as u128;

        println!(
            "Timing: Insert transactions (ascending nonces) - {transaction_count} ops in {duration:?} = {time_per_op} ns/op"
        );

        Ok(())
    }

    #[test]
    fn pool_benchmark_insert_descending_nonces() -> Result<()> {
        let mut pool = TransactionPool::default();
        let mut state = get_in_memory_state()?;

        // Create 1000 accounts
        let mut accounts = Vec::new();
        for i in 0..1000 {
            let addr: Address = format!("0x{i:040x}").parse()?;
            let acc = create_acc(&mut state, addr, 1_000_000, 0)?;
            accounts.push((addr, acc));
        }

        let start = Instant::now();
        let target_duration = Duration::from_secs(1);
        let mut transaction_count = 0;
        let mut account_idx = 0;
        let mut nonce = 999; // Start from high nonce and go down

        // Insert transactions for 1 second in descending nonce order
        while start.elapsed() < target_duration {
            let (addr, acc) = &accounts[account_idx % accounts.len()];
            let txn = transaction(*addr, nonce, 10);
            pool.insert_transaction(txn, acc, false);

            transaction_count += 1;

            if nonce > 0 {
                nonce -= 1;
            } else {
                // Move to next account and reset nonce
                account_idx += 1;
                nonce = 999;
            }
        }

        let duration = start.elapsed();
        let time_per_op = duration.as_nanos() / transaction_count as u128;

        println!(
            "Timing: Insert transactions (descending nonces) - {transaction_count} ops in {duration:?} = {time_per_op} ns/op"
        );

        Ok(())
    }

    #[test]
    fn pool_benchmark_operations_on_large_pool() -> Result<()> {
        let mut pool = TransactionPool::default();
        let mut state = get_in_memory_state()?;

        // Create 100 accounts with 100 transactions each
        let mut accounts = Vec::new();
        for i in 0..100 {
            let addr: Address = format!("0x{i:040x}").parse()?;
            let acc = create_acc(&mut state, addr, 1_000_000, 0)?;
            accounts.push((addr, acc));
        }

        // Insert transactions
        for (addr, acc) in &accounts {
            for nonce in 0..100 {
                let txn = transaction(*addr, nonce, 10);
                pool.insert_transaction(txn, acc, false);
            }
        }

        let target_duration = Duration::from_secs(1);

        // Benchmark getting all pending transactions for 1 second
        let start = Instant::now();
        let mut operations = 0;
        while start.elapsed() < target_duration {
            let _pending: Vec<_> = pool.pending_transactions_ordered().collect();
            operations += 1;
        }
        let duration = start.elapsed();
        let time_per_op = duration.as_nanos() / operations as u128;
        println!(
            "Timing: Get all pending transactions - {operations} ops in {duration:?} = {time_per_op} ns/op"
        );

        // Benchmark getting pending transaction count for 1 second
        let start = Instant::now();
        let mut operations = 0;
        while start.elapsed() < target_duration {
            let _count = pool.pending_transaction_count();
            operations += 1;
        }
        let duration = start.elapsed();
        let time_per_op = duration.as_nanos() / operations as u128;
        println!(
            "Timing: Get pending transaction count - {operations} ops in {duration:?} = {time_per_op} ns/op"
        );

        // Benchmark getting best transaction for 1 second
        let start = Instant::now();
        let mut operations = 0;
        while start.elapsed() < target_duration {
            let _best = pool.best_transaction();
            operations += 1;
        }
        let duration = start.elapsed();
        let time_per_op = duration.as_nanos() / operations as u128;
        println!(
            "Timing: Get best transaction - {operations} ops in {duration:?} = {time_per_op} ns/op"
        );

        // Benchmark popping transactions for 1 second
        let mut test_pool = pool.clone();
        let start = Instant::now();
        let mut operations = 0;
        let mut transactions = Vec::new();
        while start.elapsed() < target_duration {
            let best = test_pool.pop_best_if(|_| true);
            operations += 1;
            if let Some(tx) = best {
                transactions.push(tx);
            } else {
                break;
            }
        }
        let duration = start.elapsed();
        let time_per_op = duration.as_nanos() / operations as u128;
        println!(
            "Timing: Popping best transaction - {operations} ops in {duration:?} = {time_per_op} ns/op"
        );

        Ok(())
    }

    #[test]
    fn test_state_update_during_fork_handling() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        // Insert some transactions
        pool.insert_transaction(transaction(addr, 0, 10), &acc, false);
        pool.insert_transaction(transaction(addr, 1, 10), &acc, false);
        pool.insert_transaction(transaction(addr, 2, 10), &acc, false);

        // Simulate what happens during fork handling:
        // 1. remove some transactions (simulating block execution)
        pool.pop_best_if(|_| true);
        pool.pop_best_if(|_| true);

        // 2. Immediately re-insert transactions (simulating fork revert)
        // But use the OLD account state for insertion
        let old_acc = create_acc(&mut state, addr, 100, 0)?;
        let txn0 = transaction(addr, 0, 10);
        let txn1 = transaction(addr, 1, 10);

        // This pattern might cause counting issues
        pool.insert_transaction(txn0, &old_acc, true);
        pool.insert_transaction(txn1, &old_acc, true);

        Ok(())
    }

    #[test]
    fn test_transaction_expiry_basic() -> Result<()> {
        use std::time::Duration;

        use crate::time::{advance, sync_with_fake_time};

        sync_with_fake_time(|| {
            let mut pool = TransactionPool::default();
            let addr = "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap();
            let mut state = get_in_memory_state().unwrap();
            let acc = create_acc(&mut state, addr, 100, 0).unwrap();

            // Set shorter expiry times for testing
            pool.core.pool_expiry_time_minimum = Duration::from_secs(5);
            pool.core.expiry_time_clearout_threshold = Duration::from_secs(10);

            let txn1 = transaction(addr, 0, 10);
            let txn2 = transaction(addr, 1, 20);

            // Insert transactions at time 0
            pool.insert_transaction(txn1.clone(), &acc, false);
            pool.insert_transaction(txn2.clone(), &acc, false);

            assert_eq!(pool.transaction_count(), 2);
            assert!(pool.get_transaction(&txn1.hash).is_some());
            assert!(pool.get_transaction(&txn2.hash).is_some());

            // Advance time by 5 seconds - transactions should still be there
            advance(Duration::from_secs(5));

            // Trigger a potential cleanup by adding another transaction
            let txn3 = transaction(addr, 2, 15);
            pool.insert_transaction(txn3.clone(), &acc, false);

            assert_eq!(pool.transaction_count(), 3);
            assert!(pool.get_transaction(&txn1.hash).is_some());
            assert!(pool.get_transaction(&txn2.hash).is_some());

            // Advance time by another 10 seconds (total 15 seconds)
            // This should exceed expiry_time_clearout_threshold and trigger cleanup
            advance(Duration::from_secs(10));

            // Add another transaction to trigger cleanup
            let txn4 = transaction(addr, 3, 25);
            pool.insert_transaction(txn4.clone(), &acc, false);

            // The first two transactions should be expired and removed
            assert_eq!(pool.transaction_count(), 1);
            assert!(pool.get_transaction(&txn1.hash).is_none());
            assert!(pool.get_transaction(&txn2.hash).is_none());
            assert!(pool.get_transaction(&txn3.hash).is_none());
            assert!(pool.get_transaction(&txn4.hash).is_some());
        });
        Ok(())
    }

    #[test]
    fn test_transaction_expiry_with_mixed_ages() -> Result<()> {
        use std::time::Duration;

        use crate::time::{advance, sync_with_fake_time};

        sync_with_fake_time(|| {
            let mut pool = TransactionPool::default();
            let addr = "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap();
            let mut state = get_in_memory_state().unwrap();
            let acc = create_acc(&mut state, addr, 200, 0).unwrap();

            pool.core.pool_expiry_time_minimum = Duration::from_secs(10);
            pool.core.expiry_time_clearout_threshold = Duration::from_secs(15);

            // Insert first batch of transactions
            let txn1 = transaction(addr, 0, 10);
            let txn2 = transaction(addr, 1, 20);
            pool.insert_transaction(txn1.clone(), &acc, false);
            pool.insert_transaction(txn2.clone(), &acc, false);

            // Advance time by 8 seconds
            advance(Duration::from_secs(8));

            // Insert more transactions (these will be newer)
            let txn3 = transaction(addr, 2, 15);
            let txn4 = transaction(addr, 3, 25);
            pool.insert_transaction(txn3.clone(), &acc, false);
            pool.insert_transaction(txn4.clone(), &acc, false);

            assert_eq!(pool.transaction_count(), 4);

            // Advance time by another 8 seconds (total 16 seconds from start)
            // This should trigger cleanup of the first batch
            advance(Duration::from_secs(8));

            // Add a new transaction to trigger the cleanup check
            let txn5 = transaction(addr, 4, 30);
            pool.insert_transaction(txn5.clone(), &acc, false);

            // First two transactions should be expired, others should remain
            assert_eq!(pool.transaction_count(), 3);
            assert!(pool.get_transaction(&txn1.hash).is_none());
            assert!(pool.get_transaction(&txn2.hash).is_none());
            assert!(pool.get_transaction(&txn3.hash).is_some());
            assert!(pool.get_transaction(&txn4.hash).is_some());
            assert!(pool.get_transaction(&txn5.hash).is_some());
        });
        Ok(())
    }

    #[test]
    fn test_expiry_across_multiple_accounts() -> Result<()> {
        use std::time::Duration;

        use crate::time::{advance, sync_with_fake_time};

        sync_with_fake_time(|| {
            let mut pool = TransactionPool::default();
            let addr1 = "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap();
            let addr2 = "0x0000000000000000000000000000000000000002"
                .parse()
                .unwrap();
            let mut state = get_in_memory_state().unwrap();
            let acc1 = create_acc(&mut state, addr1, 100, 0).unwrap();
            let acc2 = create_acc(&mut state, addr2, 100, 0).unwrap();

            pool.core.pool_expiry_time_minimum = Duration::from_secs(5);
            pool.core.expiry_time_clearout_threshold = Duration::from_secs(10);

            // Insert transactions from both accounts
            let txn1_acc1 = transaction(addr1, 0, 10);
            let txn1_acc2 = transaction(addr2, 0, 15);
            pool.insert_transaction(txn1_acc1.clone(), &acc1, false);
            pool.insert_transaction(txn1_acc2.clone(), &acc2, false);

            // Advance time to trigger expiry
            advance(Duration::from_secs(15));

            // Add new transaction to trigger cleanup
            let txn2_acc1 = transaction(addr1, 1, 20);
            pool.insert_transaction(txn2_acc1.clone(), &acc1, false);

            // Old transactions should be expired
            assert!(pool.get_transaction(&txn1_acc1.hash).is_none());
            assert!(pool.get_transaction(&txn1_acc2.hash).is_none());
            assert!(pool.get_transaction(&txn2_acc1.hash).is_some());
            assert_eq!(pool.transaction_count(), 1);
        });
        Ok(())
    }

    #[test]
    fn test_no_premature_expiry() -> Result<()> {
        use std::time::Duration;

        use crate::time::{advance, sync_with_fake_time};

        sync_with_fake_time(|| {
            let mut pool = TransactionPool::default();
            let addr = "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap();
            let mut state = get_in_memory_state().unwrap();
            let acc = create_acc(&mut state, addr, 100, 0).unwrap();

            pool.core.pool_expiry_time_minimum = Duration::from_secs(2);
            pool.core.expiry_time_clearout_threshold = Duration::from_secs(4);

            let txn1 = transaction(addr, 0, 10);
            pool.insert_transaction(txn1.clone(), &acc, false);

            // Advance time, but not enough to trigger clearout threshold
            advance(Duration::from_secs(3));

            // Add another transaction - should not trigger cleanup
            let txn2 = transaction(addr, 1, 20);
            pool.insert_transaction(txn2.clone(), &acc, false);

            // Both transactions should still be there
            assert_eq!(pool.transaction_count(), 2);
            assert!(pool.get_transaction(&txn1.hash).is_some());
            assert!(pool.get_transaction(&txn2.hash).is_some());
        });
        Ok(())
    }

    #[test]
    fn test_bulk_transaction_deletion() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr1 = "0x0000000000000000000000000000000000000001".parse()?;
        let addr2 = "0x0000000000000000000000000000000000000002".parse()?;
        let mut state = get_in_memory_state()?;
        let acc1 = create_acc(&mut state, addr1, 200, 0)?;
        let acc2 = create_acc(&mut state, addr2, 200, 0)?;

        // Insert multiple transactions from both accounts
        let txn1_acc1 = transaction(addr1, 0, 10);
        let txn2_acc1 = transaction(addr1, 1, 20);
        let txn3_acc1 = transaction(addr1, 2, 15);
        let txn1_acc2 = transaction(addr2, 0, 25);
        let txn2_acc2 = transaction(addr2, 1, 30);

        pool.insert_transaction(txn1_acc1.clone(), &acc1, false);
        pool.insert_transaction(txn2_acc1.clone(), &acc1, false);
        pool.insert_transaction(txn3_acc1.clone(), &acc1, false);
        pool.insert_transaction(txn1_acc2.clone(), &acc2, false);
        pool.insert_transaction(txn2_acc2.clone(), &acc2, false);

        assert_eq!(pool.transaction_count(), 5);

        // Use the internal delete_transactions method to bulk delete
        let to_delete = vec![txn1_acc1.clone(), txn2_acc1.clone(), txn2_acc2.clone()];
        pool.core.delete_transactions(to_delete);

        // Should have 2 transactions remaining
        assert_eq!(pool.transaction_count(), 2);

        // Check which transactions remain
        assert!(pool.get_transaction(&txn1_acc1.hash).is_none());
        assert!(pool.get_transaction(&txn2_acc1.hash).is_none());
        assert!(pool.get_transaction(&txn1_acc2.hash).is_some());
        assert!(pool.get_transaction(&txn3_acc1.hash).is_some());
        assert!(pool.get_transaction(&txn2_acc2.hash).is_none());

        // Verify pending queue is updated correctly
        assert!(pool.has_txn_ready());
        let best = pool.best_transaction().unwrap();
        // Should be txn2_acc2 with highest gas price (30)
        assert_eq!(best.hash, txn1_acc2.hash);

        Ok(())
    }

    #[test]
    fn test_deletion_of_nonexistent_transactions() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 100, 0)?;

        let txn1 = transaction(addr, 0, 10);
        let txn2 = transaction(addr, 1, 20);
        let txn_nonexistent = transaction(addr, 5, 15); // Never inserted

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);

        assert_eq!(pool.transaction_count(), 2);

        // Try to delete a mix of existing and non-existing transactions
        let to_delete = vec![txn1.clone(), txn_nonexistent.clone()];
        pool.core.delete_transactions(to_delete);

        // Should have removed only the existing transaction
        assert_eq!(pool.transaction_count(), 1);
        assert!(pool.get_transaction(&txn1.hash).is_none());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn_nonexistent.hash).is_none());

        Ok(())
    }

    #[test]
    fn test_deletion_maintains_pool_consistency() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr = "0x0000000000000000000000000000000000000001".parse()?;
        let mut state = get_in_memory_state()?;
        let acc = create_acc(&mut state, addr, 50, 0)?; // Limited balance

        // Insert transactions that will have mixed pending/queued status
        let txn1 = transaction(addr, 0, 20); // Will be pending
        let txn2 = transaction(addr, 1, 20); // Will be pending
        let txn3 = transaction(addr, 2, 20); // Will be queued (insufficient balance)

        pool.insert_transaction(txn1.clone(), &acc, false);
        pool.insert_transaction(txn2.clone(), &acc, false);
        pool.insert_transaction(txn3.clone(), &acc, false);

        // Verify initial state
        assert_eq!(pool.pending_transaction_count(), 2);
        assert_eq!(pool.transaction_count(), 3);

        // Delete one pending transaction
        pool.core.delete_transactions(vec![txn1.clone()]);

        // Pool should maintain consistency
        assert_eq!(pool.transaction_count(), 2);
        assert_eq!(pool.pending_transaction_count(), 0);
        assert!(pool.get_transaction(&txn1.hash).is_none());
        assert!(pool.get_transaction(&txn2.hash).is_some());
        assert!(pool.get_transaction(&txn3.hash).is_some());

        Ok(())
    }

    #[test]
    fn test_deletion_updates_pending_queue_keys() -> Result<()> {
        let mut pool = TransactionPool::default();
        let addr1 = "0x0000000000000000000000000000000000000001".parse()?;
        let addr2 = "0x0000000000000000000000000000000000000002".parse()?;
        let mut state = get_in_memory_state()?;
        let acc1 = create_acc(&mut state, addr1, 100, 0)?;
        let acc2 = create_acc(&mut state, addr2, 100, 0)?;

        let txn1_acc1 = transaction(addr1, 0, 30); // Highest gas price
        let txn2_acc1 = transaction(addr1, 1, 10);
        let txn1_acc2 = transaction(addr2, 0, 20);

        pool.insert_transaction(txn1_acc1.clone(), &acc1, false);
        pool.insert_transaction(txn2_acc1.clone(), &acc1, false);
        pool.insert_transaction(txn1_acc2.clone(), &acc2, false);

        // Best transaction should be txn1_acc1 (highest gas price)
        assert_eq!(pool.best_transaction().unwrap().hash, txn1_acc1.hash);

        dbg!(&pool.core.pending_account_queue);
        dbg!(&pool.core.peek_best_txn());

        // Delete the best transaction from account 1
        pool.core.delete_transactions(vec![txn1_acc1.clone()]);

        dbg!(&pool.core.pending_account_queue);
        dbg!(&pool.core.peek_best_txn());

        // Best transaction should now be txn1_acc2 (gas price 20)
        let best = pool.best_transaction().unwrap();
        assert_eq!(best.hash, txn1_acc2.hash);
        assert_eq!(best.tx.gas_price_per_evm_gas(), 20);

        Ok(())
    }

    #[test]
    fn test_expiry_during_high_activity() -> Result<()> {
        use std::time::Duration;

        use crate::time::{advance, sync_with_fake_time};

        sync_with_fake_time(|| {
            let mut pool = TransactionPool::default();
            let addr = "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap();
            let mut state = get_in_memory_state().unwrap();
            let acc = create_acc(&mut state, addr, 1000, 0).unwrap();

            pool.core.pool_expiry_time_minimum = Duration::from_secs(5);
            pool.core.expiry_time_clearout_threshold = Duration::from_secs(8);

            // Insert initial transactions
            for nonce in 0..10 {
                let txn = transaction(addr, nonce, 10);
                pool.insert_transaction(txn, &acc, false);
            }
            assert_eq!(pool.transaction_count(), 10);

            // Advance time by 5 seconds
            advance(Duration::from_secs(5));

            // Insert more transactions (mixed ages now)
            for nonce in 10..15 {
                let txn = transaction(addr, nonce, 10);
                pool.insert_transaction(txn, &acc, false);
            }
            assert_eq!(pool.transaction_count(), 15);

            // Advance time by another 4 seconds (total 9 seconds)
            // This should trigger cleanup of the first batch
            advance(Duration::from_secs(4));

            // Insert one more transaction to trigger cleanup
            let final_txn = transaction(addr, 15, 10);
            pool.insert_transaction(final_txn.clone(), &acc, false);

            // Should have removed the first 10 transactions (they're older than 5 seconds)
            // and kept the newer ones
            assert_eq!(pool.transaction_count(), 6); // 5 from second batch + 1 new
        });
        Ok(())
    }

    #[test]
    fn test_oldest_insertion_time_tracking() -> Result<()> {
        use std::time::Duration;

        use crate::time::{advance, sync_with_fake_time};

        sync_with_fake_time(|| {
            let mut pool = TransactionPool::default();
            let addr = "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap();
            let mut state = get_in_memory_state().unwrap();
            let acc = create_acc(&mut state, addr, 100, 0).unwrap();

            // Initially no oldest insertion time
            assert!(pool.core.oldest_insertion_time.is_none());

            // Insert first transaction
            let txn1 = transaction(addr, 0, 10);
            pool.insert_transaction(txn1.clone(), &acc, false);

            // Should now have an oldest insertion time
            assert!(pool.core.oldest_insertion_time.is_some());

            // Advance time and insert another
            advance(Duration::from_secs(5));
            let txn2 = transaction(addr, 1, 20);
            pool.insert_transaction(txn2.clone(), &acc, false);

            // Clear the pool
            pool.clear();

            // Oldest insertion time should be reset
            assert!(pool.core.oldest_insertion_time.is_none());
        });
        Ok(())
    }
}
