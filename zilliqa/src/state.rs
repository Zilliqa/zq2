use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_primitives::{Address, B256};
use anyhow::{anyhow, Result};
use eth_trie::{EthTrie as PatriciaTrie, Trie};
use ethabi::Token;
use revm::primitives::ResultAndState;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{
    cfg::ConsensusConfig, contracts, crypto, db::TrieStorage, inspector, message::BlockHeader,
    scilla::Scilla, transaction::EvmGas,
};

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
    /// The Scilla interpreter interface. Note that it is lazily initialized - This is a bit of a hack to ensure that
    /// tests which don't invoke Scilla, don't spawn the Scilla communication threads or TCP listeners.
    scilla: Arc<OnceLock<Mutex<Scilla>>>,
    scilla_address: String,
    local_address: String,
    pub block_gas_limit: EvmGas,
    pub gas_price: u128,
}

impl State {
    pub fn new(trie: TrieStorage, config: &ConsensusConfig) -> State {
        let db = Arc::new(trie);
        Self {
            db: db.clone(),
            accounts: PatriciaTrie::new(db),
            scilla: Arc::new(OnceLock::new()),
            scilla_address: config.scilla_address.clone(),
            local_address: config.local_address.clone(),
            block_gas_limit: config.eth_block_gas_limit,
            gas_price: config.gas_price,
        }
    }

    pub fn scilla(&self) -> MutexGuard<'_, Scilla> {
        self.scilla
            .get_or_init(|| {
                Mutex::new(Scilla::new(
                    self.scilla_address.clone(),
                    self.local_address.clone(),
                ))
            })
            .lock()
            .unwrap()
    }

    pub fn new_at_root(trie: TrieStorage, root_hash: B256, config: ConsensusConfig) -> Self {
        Self::new(trie, &config).at_root(root_hash)
    }

    pub fn new_with_genesis(trie: TrieStorage, config: ConsensusConfig) -> Result<State> {
        let mut state = State::new(trie, &config);

        if config.is_main {
            let shard_data = contracts::shard_registry::CONSTRUCTOR.encode_input(
                contracts::shard_registry::BYTECODE.to_vec(),
                &[Token::Uint(config.consensus_timeout.as_millis().into())],
            )?;
            state.force_deploy_contract_evm(shard_data, Some(contract_addr::SHARD_REGISTRY))?;
        };

        let intershard_bridge_data = contracts::intershard_bridge::BYTECODE.to_vec();
        state.force_deploy_contract_evm(
            intershard_bridge_data,
            Some(contract_addr::INTERSHARD_BRIDGE),
        )?;

        if config.genesis_accounts.is_empty() {
            panic!("No genesis accounts provided");
        }

        for (address, balance) in config.genesis_accounts {
            let balance: u128 = balance.parse()?;
            state.mutate_account(address, |a| a.balance = balance)?;
        }

        let deposit_data = contracts::deposit::CONSTRUCTOR.encode_input(
            contracts::deposit::BYTECODE.to_vec(),
            &[Token::Uint(config.minimum_stake.into())],
        )?;

        state.force_deploy_contract_evm(deposit_data, Some(contract_addr::DEPOSIT))?;

        for (pub_key, peer_id, stake, reward_address) in config.genesis_deposits {
            let data = contracts::deposit::SET_STAKE.encode_input(&[
                Token::Bytes(pub_key.as_bytes()),
                Token::Bytes(peer_id.to_bytes()),
                Token::Address(ethabi::Address::from(reward_address.into_array())),
                Token::Uint(ethabi::Uint::from_dec_str(&stake)?),
            ])?;
            let ResultAndState {
                result,
                state: result_state,
            } = state.apply_transaction_evm(
                Address::ZERO,
                Some(contract_addr::DEPOSIT),
                config.gas_price,
                config.eth_block_gas_limit,
                0,
                data,
                None,
                0,
                BlockHeader::default(),
                inspector::noop(),
            )?;
            if !result.is_success() {
                return Err(anyhow!("setting stake failed: {result:?}"));
            }
            state.apply_delta_evm(&result_state)?;
        }

        Ok(state)
    }

    pub fn at_root(&self, root_hash: B256) -> Self {
        Self {
            db: self.db.clone(),
            accounts: self.accounts.at_root(root_hash),
            scilla: self.scilla.clone(),
            scilla_address: self.scilla_address.clone(),
            local_address: self.local_address.clone(),
            block_gas_limit: self.block_gas_limit,
            gas_price: self.gas_price,
        }
    }

    pub fn set_to_root(&mut self, root_hash: B256) {
        self.accounts = self.accounts.at_root(root_hash);
    }

    pub fn try_clone(&mut self) -> Result<Self> {
        let root_hash = self.accounts.root_hash()?;
        Ok(self.at_root(root_hash))
    }

    pub fn root_hash(&mut self) -> Result<crypto::Hash> {
        Ok(crypto::Hash(self.accounts.root_hash()?.into()))
    }

    /// Canonical method to obtain trie key for an account node
    pub fn account_key(address: Address) -> B256 {
        <[u8; 32]>::from(Keccak256::digest(address)).into()
    }

    /// Canonical method to obtain trie key for an account's storage trie's storage node
    pub fn account_storage_key(address: Address, index: B256) -> B256 {
        let mut h = Keccak256::new();
        h.update(address);
        h.update(index);
        <[u8; 32]>::from(h.finalize()).into()
    }

    /// Fetch an Account struct.
    /// Note: use get_account_storage to obtain a specific storage value.
    /// If modifying a raw account, ensure you call save_account afterwards.
    /// Returns an error on failures to access the state tree, or decode the account; or an empty
    /// account if one didn't exist yet
    pub fn get_account(&self, address: Address) -> Result<Account> {
        Ok(self
            .accounts
            .get(&Self::account_key(address).0)?
            .map(|bytes| bincode::deserialize::<Account>(&bytes))
            .unwrap_or(Ok(Account::default()))?)
    }

    /// As get_account, but panics if account cannot be read.
    pub fn must_get_account(&self, address: Address) -> Account {
        self.get_account(address).unwrap_or_else(|e| {
            panic!("Failed to read account {address:?} from state storage: {e:?}")
        })
    }

    pub fn mutate_account<F: FnOnce(&mut Account) -> R, R>(
        &mut self,
        address: Address,
        mutation: F,
    ) -> Result<R> {
        let mut account = self.get_account(address)?;
        let result = mutation(&mut account);
        self.save_account(address, account)?;
        Ok(result)
    }

    /// If using this to modify the account, ensure save_account gets called
    pub fn get_account_trie(&self, address: Address) -> Result<PatriciaTrie<TrieStorage>> {
        let account = self.get_account(address)?;
        Ok(PatriciaTrie::new(self.db.clone()).at_root(account.storage_root))
    }

    /// Returns an error if there are any issues fetching the account from the state trie
    pub fn get_account_storage(&self, address: Address, index: B256) -> Result<B256> {
        match self.get_account_trie(address)?.get(&Self::account_storage_key(address, index).0) {
            // from_slice will only panic if vec.len != B256::len_bytes, i.e. 32
            Ok(Some(vec)) if vec.len() == 32 => Ok(B256::from_slice(&vec)),
            // empty storage location
            Ok(None) => Ok(B256::ZERO),
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

    /// Returns an error if there are any issues accessing the storage trie
    pub fn has_account(&self, address: Address) -> Result<bool> {
        // if address == Address::ZERO {
        //     let key = Self::account_key(address);
        //     println!("Getting zero address {address} for some reason... Hash is {}, and account at zero address is: {:?}", hex::encode(&key.0), self.get_account(address)?);
        // }
        if let Err(e) = self.accounts.contains(&Self::account_key(address).0) {
            println!("Error getting account {address} (key {}): {e:?}. Trie's root hash: {}", hex::encode(&Self::account_key(address).0), hex::encode(&self.accounts.root_hash.0));
            println!("Available accounts at current root:");
            for (account_key, serialized_account) in self.accounts.iter() {
                println!("key: {}, account: {:?}", hex::encode(&account_key), bincode::deserialize::<Account>(&serialized_account).unwrap());
            }
        }

        Ok(self.accounts.contains(&Self::account_key(address).0)?)
    }

    pub fn save_account(&mut self, address: Address, account: Account) -> Result<()> {
        Ok(self.accounts.insert(
            &Self::account_key(address).0,
            &bincode::serialize(&account)?,
        )?)
    }
}

pub mod contract_addr {
    use alloy_primitives::Address;

    /// For intershard transactions, call this address
    pub const INTERSHARD_BRIDGE: Address = Address::new(*b"\0\0\0\0\0\0\0\0ZQINTERSHARD");
    /// Address of the shard registry - only present on the root shard.
    pub const SHARD_REGISTRY: Address = Address::new(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0ZQSHARD");
    pub const DEPOSIT: Address = Address::new(*b"\0\0\0\0\0\0\0\0\0\0ZILDEPOSIT");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: u128,
    pub code: Code,
    pub storage_root: B256,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: 0,
            code: Code::default(),
            storage_root: EMPTY_ROOT_HASH,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Code {
    Evm(#[serde(with = "serde_bytes")] Vec<u8>),
    Scilla {
        code: String,
        init_data: String,
        types: BTreeMap<String, (String, u8)>,
    },
}

impl Default for Code {
    fn default() -> Self {
        Code::Evm(Vec::new())
    }
}

impl Code {
    pub fn is_eoa(&self) -> bool {
        matches!(self, Code::Evm(c) if c.is_empty())
    }

    pub fn evm_code_ref(&self) -> Option<&[u8]> {
        match self {
            Code::Evm(code) => Some(code.as_slice()),
            _ => None,
        }
    }

    pub fn evm_code(self) -> Option<Vec<u8>> {
        match self {
            Code::Evm(code) => Some(code),
            _ => None,
        }
    }

    pub fn scilla_code_and_init_data(self) -> Option<(String, String)> {
        match self {
            Code::Scilla {
                code, init_data, ..
            } => Some((code, init_data)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScillaValue {
    Bytes(Vec<u8>),
    Map(BTreeMap<String, ScillaValue>),
}

impl ScillaValue {
    pub fn map() -> Self {
        ScillaValue::Map(BTreeMap::new())
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            ScillaValue::Bytes(b) => Some(b),
            ScillaValue::Map(_) => None,
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, ScillaValue>> {
        match self {
            ScillaValue::Map(m) => Some(m),
            ScillaValue::Bytes(_) => None,
        }
    }

    pub fn as_map_mut(&mut self) -> Option<&mut BTreeMap<String, ScillaValue>> {
        match self {
            ScillaValue::Map(m) => Some(m),
            ScillaValue::Bytes(_) => None,
        }
    }
}
