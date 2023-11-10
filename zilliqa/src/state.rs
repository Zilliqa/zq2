use anyhow::{anyhow, Result};
use core::fmt;
use eth_trie::{EthTrie as PatriciaTrie, Trie};
use ethabi::Token;
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use sled::Tree;
use std::convert::TryInto;
use std::fmt::{Display, LowerHex};
use std::sync::Arc;
use std::{hash::Hash, str::FromStr};

use crate::{cfg::ConsensusConfig, contracts, crypto, db::SledDb};

#[derive(Debug)]
/// The state of the blockchain, consisting of:
/// -  state - a database of Map<Address, Map<key,value>>
/// -  accounts, Map<Address, Account>
/// where an address is a 20-byte array representing a user.
/// where Account is (nonce, code, storage_root)
/// the storage root is used to index into the state
/// all the keys are hashed and stored in the same sled tree
pub struct State {
    db: Arc<SledDb>,
    accounts: PatriciaTrie<SledDb>,
}

impl State {
    pub fn new(database: Tree) -> State {
        let db = Arc::new(SledDb::new(database));
        Self {
            db: db.clone(),
            accounts: PatriciaTrie::new(db),
        }
    }

    pub fn new_at_root(database: Tree, root_hash: H256) -> Self {
        Self::new(database).at_root(root_hash)
    }

    pub fn new_with_genesis(database: Tree, config: ConsensusConfig) -> Result<State> {
        let db = Arc::new(SledDb::new(database));
        let mut state = Self {
            db: db.clone(),
            accounts: PatriciaTrie::new(db),
        };

        let shard_data = if config.is_main {
            contracts::shard_registry::CONSTRUCTOR.encode_input(
                contracts::shard_registry::CREATION_CODE.to_vec(),
                &[Token::Uint(config.consensus_timeout.as_millis().into())],
            )?
        } else {
            contracts::shard::CONSTRUCTOR.encode_input(
                contracts::shard::CREATION_CODE.to_vec(),
                &[
                    Token::Uint(config.main_shard_id.unwrap().into()),
                    Token::Uint(config.consensus_timeout.as_millis().into()),
                ],
            )?
        };
        state.force_deploy_contract(shard_data, Some(Address::SHARD_CONTRACT))?;

        let native_token_data = contracts::native_token::CONSTRUCTOR
            .encode_input(contracts::native_token::CREATION_CODE.to_vec(), &[])?;
        state.force_deploy_contract(native_token_data, Some(Address::NATIVE_TOKEN))?;

        let gas_price_data = contracts::gas_price::CONSTRUCTOR
            .encode_input(contracts::gas_price::CREATION_CODE.to_vec(), &[])?;
        state.force_deploy_contract(gas_price_data, Some(Address::GAS_PRICE))?;

        let _ = state.set_gas_price(default_gas_price().into());

        if config.genesis_accounts.is_empty() {
            panic!("No genesis accounts provided");
        }

        for (address, balance) in config.genesis_accounts {
            state.set_native_balance(address, balance.parse()?)?;
            let account_new = state.get_account(address)?;
            state.save_account(address, account_new)?;
        }

        Ok(state)
    }

    pub fn at_root(&self, root_hash: H256) -> Self {
        let db = self.db.clone();
        Self {
            db,
            accounts: self.accounts.at_root(root_hash),
        }
    }

    pub fn set_to_root(&mut self, root_hash: H256) {
        self.accounts = self.accounts.at_root(root_hash);
    }

    pub fn try_clone(&mut self) -> Result<Self> {
        let root_hash = self.accounts.root_hash()?;
        Ok(self.at_root(root_hash))
    }

    pub fn root_hash(&mut self) -> Result<crypto::Hash> {
        Ok(crypto::Hash(
            self.accounts.root_hash()?.as_bytes().try_into()?,
        ))
    }

    /// Canonical method to obtain trie key for an account node
    fn account_key(address: Address) -> Vec<u8> {
        Keccak256::digest(address.as_bytes()).to_vec()
    }

    /// Canonical method to obtain trie key for an account's storage trie's storage node
    fn account_storage_key(address: Address, index: H256) -> Vec<u8> {
        let mut h = Keccak256::new();
        h.update(address.as_bytes());
        h.update(index.as_bytes());
        h.finalize().to_vec()
    }

    /// Fetch an Account struct.
    /// Note: use get_account_storage to obtain a specific storage value.
    /// If modifying a raw account, ensure you call save_account afterwards.
    /// Returns an error on failures to access the state tree, or decode the account; or an empty
    /// account if one didn't exist yet
    pub fn get_account(&self, address: Address) -> Result<Account> {
        Ok(self
            .accounts
            .get(&Self::account_key(address))?
            .map(|bytes| bincode::deserialize::<Account>(&bytes))
            .unwrap_or(Ok(Account::default()))?)
    }

    /// As get_account, but panics if account cannot be read.
    pub fn must_get_account(&self, address: Address) -> Account {
        self.get_account(address).unwrap_or_else(|e| {
            panic!("Failed to read account {address:?} from state storage: {e:?}")
        })
    }

    /// If using this to modify the account, ensure save_account gets called
    fn get_account_trie(&self, address: Address) -> Result<PatriciaTrie<SledDb>> {
        Ok(match self.get_account(address)?.storage_root {
            Some(root) => PatriciaTrie::new(self.db.clone()).at_root(root),
            None => PatriciaTrie::new(self.db.clone()),
        })
    }

    /// Returns an error if there are any issues fetching the account from the state trie
    pub fn get_account_storage(&self, address: Address, index: H256) -> Result<H256> {
        match self.get_account_trie(address)?.get(&Self::account_storage_key(address, index)) {
            // from_slice will only panic if vec.len != H256::len_bytes, i.e. 32
            Ok(Some(vec)) if vec.len() == 32 => Ok(H256::from_slice(&vec)),
            // empty storage location
            Ok(None) => Ok(H256::zero()),
            // invalid value in storage
            Ok(Some(vec)) => Err(anyhow!(
                "Invalid storage for account {address:?} at index {index}: expected 32 bytes, got value {vec:?}"
            )),
            // any other error fetching
            Err(e) => Err(anyhow!(
                "Failed to fetch storage for account {address:?} at index {index}: {e}",
            )),
        }
    }

    /// Panics if account or storage cannot be read.
    pub fn must_get_account_storage(&self, address: Address, index: H256) -> H256 {
        self.get_account_storage(address, index).expect(
            "Failed to read storage index {index} for account {address:?} from state storage",
        )
    }

    pub fn set_account_storage(
        &mut self,
        address: Address,
        index: H256,
        value: H256,
    ) -> Result<()> {
        let mut account = self.get_account(address)?;
        let mut trie = self.get_account_trie(address)?;
        trie.insert(&Self::account_storage_key(address, index), value.as_bytes())?;
        account.storage_root = Some(trie.root_hash()?);
        self.save_account(address, account)?;

        Ok(())
    }

    pub fn remove_account_storage(&mut self, address: Address, index: H256) -> Result<bool> {
        let mut account = self.get_account(address)?;
        let mut trie = self.get_account_trie(address)?;
        let ret = trie.remove(&Self::account_storage_key(address, index))?;
        account.storage_root = Some(trie.root_hash()?);
        self.save_account(address, account)?;

        Ok(ret)
    }

    pub fn clear_account_storage(&mut self, address: Address) -> Result<()> {
        let account = self.get_account(address)?;
        self.save_account(
            address,
            Account {
                storage_root: None,
                ..account
            },
        )
    }

    /// Returns an error if there are any issues accessing the storage trie
    pub fn try_has_account(&self, address: Address) -> Result<bool> {
        Ok(self.accounts.contains(&Self::account_key(address))?)
    }

    /// Returns false if the account cannot be accessed in the storage trie
    pub fn has_account(&self, address: Address) -> bool {
        self.try_has_account(address).unwrap_or(false)
    }

    pub fn save_account(&mut self, address: Address, account: Account) -> Result<()> {
        Ok(self
            .accounts
            .insert(&Self::account_key(address), &bincode::serialize(&account)?)?)
    }

    pub fn delete_account(&mut self, address: Address) -> Result<bool> {
        Ok(self.accounts.remove(&Self::account_key(address))?)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(pub H160);

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl From<H160> for Address {
    fn from(h: H160) -> Address {
        Address(h)
    }
}

impl Address {
    pub const ZERO: Address = Address(H160::zero());
    pub fn zero() -> Address {
        Address(H160::zero())
    }

    /// Address of the native token ERC-20 contract.
    pub const NATIVE_TOKEN: Address = Address(H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL"));

    pub const SHARD_CONTRACT: Address = Address(H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0ZQSHARD"));

    /// Address of the gas contract
    pub const GAS_PRICE: Address = Address(H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0GAS"));

    /// Gas fees go here
    pub const COLLECTED_FEES: Address = Address(H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0FEE"));

    pub fn is_balance_transfer(to: Address) -> bool {
        to == Address::NATIVE_TOKEN
    }

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

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Address(s.parse()?))
    }
}

#[derive(Debug, Clone, Default, Hash, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    #[serde(with = "serde_bytes")]
    pub code: Vec<u8>,
    pub storage_root: Option<H256>,
}

pub fn default_gas() -> u64 {
    10000000
}

pub fn default_gas_price() -> u64 {
    1000000
}
