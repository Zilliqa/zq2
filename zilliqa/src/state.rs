use std::{
    borrow::Cow,
    collections::{hash_map::DefaultHasher, BTreeMap},
    hash::{Hash, Hasher},
};

use anyhow::{anyhow, Result};
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, BlsOrEcdsaPublicKey, BlsOrEcdsaSignature};

#[derive(Debug, Clone, Default, Hash)]
pub struct State {
    accounts: BTreeMap<Address, Account>,
}

impl State {
    pub fn new() -> State {
        Default::default()
    }

    // TODO(#85): Fix this implementation. "The internal algorithm is not specified, and so it and its hashes should not be
    // relied upon over releases."
    pub fn root_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.accounts.hash(&mut hasher);
        hasher.finish()
    }

    pub fn get_account(&self, address: Address) -> Cow<'_, Account> {
        self.accounts
            .get(&address)
            .map(Cow::Borrowed)
            .unwrap_or(Cow::Owned(Account::default()))
    }

    pub fn get_account_mut(&mut self, address: Address) -> &mut Account {
        self.accounts.entry(address).or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(pub H160);

impl Address {
    /// Address of the contract which allows you to deploy other contracts.
    pub const DEPLOY_CONTRACT: Address = Address(H160::zero());

    pub fn from_bytes(bytes: [u8; 20]) -> Address {
        Address(bytes.into())
    }

    pub fn from_slice(bytes: &[u8]) -> Address {
        let mut bytes = bytes.to_owned();
        // FIXME: Awfully inefficient
        while bytes.len() < 20 {
            bytes.insert(0, 0);
        }
        Address(H160::from_slice(&bytes))
    }

    pub fn as_bytes(&self) -> [u8; 20] {
        *self.0.as_fixed_bytes()
    }
}

#[derive(Debug, Clone, Default, Hash)]
pub struct Account {
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage: BTreeMap<H256, H256>,
}

/// A transaction body, broadcast before execution and then persisted as part of a block after the transaction is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub signature: Option<BlsOrEcdsaSignature>,
    pub pubkey: Option<BlsOrEcdsaPublicKey>,
    pub from_addr: Address,
    pub to_addr: Address,
    pub contract_address: Option<Address>,
    pub amount: u128,
    pub payload: Vec<u8>,
}

impl Transaction {
    pub fn hash(&self) -> crypto::Hash {
        crypto::Hash::compute(&[
            &self.nonce.to_be_bytes(),
            &self.gas_price.to_be_bytes(),
            &self.gas_limit.to_be_bytes(),
            &self.from_addr.as_bytes(),
            &self.to_addr.as_bytes(),
            &self.amount.to_be_bytes(),
            &self.payload,
        ])
    }

    pub fn verify(&self) -> Result<()> {
        match (self.pubkey, self.signature) {
            (Some(pubkey), Some(sig)) => pubkey.verify(self.hash().as_bytes(), sig),
            _ => Err(anyhow!("Transaction is unsigned"))
        }
    }
}
