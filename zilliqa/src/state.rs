use std::{convert::TryInto, hash::Hash, sync::Arc};

use anyhow::{anyhow, Result};
use eth_trie::{EthTrie as PatriciaTrie, Trie};
use ethabi::Token;
use primitive_types::{H160, H256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{cfg::ConsensusConfig, contracts, crypto, db::TrieStorage};

#[derive(Debug)]
/// The state of the blockchain, consisting of:
/// -  state - a database of Map<Address, Map<key,value>>
/// -  accounts, Map<Address, Account>
/// where an address is a 20-byte array representing a user.
/// where Account is (nonce, code, storage_root)
/// the storage root is used to index into the state
/// all the keys are hashed and stored in the same sled tree
pub struct State {
    db: Arc<TrieStorage>,
    accounts: PatriciaTrie<TrieStorage>,
}

impl State {
    pub fn new(trie: TrieStorage) -> State {
        let db = Arc::new(trie);
        Self {
            db: db.clone(),
            accounts: PatriciaTrie::new(db),
        }
    }

    pub fn new_at_root(trie: TrieStorage, root_hash: H256) -> Self {
        Self::new(trie).at_root(root_hash)
    }

    pub fn new_with_genesis(trie: TrieStorage, config: ConsensusConfig) -> Result<State> {
        let db = Arc::new(trie);
        let mut state = Self {
            db: db.clone(),
            accounts: PatriciaTrie::new(db),
        };

        if config.is_main {
            let shard_data = contracts::shard_registry::CONSTRUCTOR.encode_input(
                contracts::shard_registry::BYTECODE.to_vec(),
                &[Token::Uint(config.consensus_timeout.as_millis().into())],
            )?;
            state.force_deploy_contract(shard_data, Some(contract_addr::SHARD_CONTRACT))?;
        };

        let native_token_data = contracts::native_token::CONSTRUCTOR
            .encode_input(contracts::native_token::BYTECODE.to_vec(), &[])?;
        state.force_deploy_contract(native_token_data, Some(contract_addr::NATIVE_TOKEN))?;

        let gas_price_data = contracts::gas_price::CONSTRUCTOR
            .encode_input(contracts::gas_price::BYTECODE.to_vec(), &[])?;
        state.force_deploy_contract(gas_price_data, Some(contract_addr::GAS_PRICE))?;

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
    fn get_account_trie(&self, address: Address) -> Result<PatriciaTrie<TrieStorage>> {
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

pub type Address = H160;

pub mod contract_addr {
    use primitive_types::H160;

    use super::Address;

    /// Address of the native token ERC-20 contract.
    pub const NATIVE_TOKEN: Address = H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0ZIL");
    pub const SHARD_CONTRACT: Address = H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0ZQSHARD");
    /// Address of the gas contract
    pub const GAS_PRICE: Address = H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0GAS");
    /// Gas fees go here
    pub const COLLECTED_FEES: Address = H160(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0FEE");
}

#[derive(Debug, Clone, Default, Hash, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    #[serde(with = "serde_bytes")]
    pub code: Vec<u8>,
    pub storage_root: Option<H256>,
    pub is_scilla: bool,
}

pub fn default_gas() -> u64 {
    10000000
}

pub fn default_gas_price() -> u64 {
    1000000
}
