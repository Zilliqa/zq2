use std::{
    collections::BTreeMap,
    fmt::Display,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use alloy::{
    consensus::EMPTY_ROOT_HASH,
    primitives::{Address, B256},
};
use anyhow::{anyhow, Result};
use eth_trie::{EthTrie as PatriciaTrie, Trie};
use ethabi::Token;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::{
    block_store::BlockStore,
    cfg::{Amount, NodeConfig, ScillaExtLibsPath},
    contracts, crypto,
    db::TrieStorage,
    message::{BlockHeader, MAX_COMMITTEE_SIZE},
    node::ChainId,
    scilla::{ParamValue, Scilla, Transition},
    serde_util::vec_param_value,
    transaction::EvmGas,
};

#[derive(Clone, Debug)]
/// The state of the blockchain, consisting of:
/// -  state - a database of Map<Address, Map<key,value>>
/// -  accounts, Map<Address, Account>
///
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
    scilla_lib_dir: String,
    pub scilla_ext_libs_path: ScillaExtLibsPath,
    pub block_gas_limit: EvmGas,
    pub gas_price: u128,
    pub chain_id: ChainId,
    pub block_store: Arc<BlockStore>,
}

/// Obtained from [State] with [State::at_block]. Allows you to query accounts from the state and execute transactions.
#[derive(Clone, Debug)]
pub struct StateProvider {
    state: State,
}

impl Deref for StateProvider {
    type Target = State;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl State {
    pub fn new(trie: TrieStorage, config: &NodeConfig, block_store: Arc<BlockStore>) -> State {
        let db = Arc::new(trie);
        let consensus_config = &config.consensus;
        Self {
            db: db.clone(),
            accounts: PatriciaTrie::new(db),
            scilla: Arc::new(OnceLock::new()),
            scilla_address: consensus_config.scilla_address.clone(),
            local_address: consensus_config.local_address.clone(),
            scilla_lib_dir: consensus_config.scilla_stdlib_dir.clone(),
            scilla_ext_libs_path: consensus_config.scilla_ext_libs_path.clone(),
            block_gas_limit: consensus_config.eth_block_gas_limit,
            gas_price: *consensus_config.gas_price,
            chain_id: ChainId::new(config.eth_chain_id),
            block_store,
        }
    }

    pub fn scilla(&self) -> MutexGuard<'_, Scilla> {
        self.scilla
            .get_or_init(|| {
                Mutex::new(Scilla::new(
                    self.scilla_address.clone(),
                    self.local_address.clone(),
                    self.scilla_lib_dir.clone(),
                ))
            })
            .lock()
            .unwrap()
    }

    /// Creates a new [State] and deploys the genesis contracts. The root hash of the state with these contracts is
    /// also returned.
    pub fn new_with_genesis_contracts(
        trie: TrieStorage,
        config: &NodeConfig,
        block_store: Arc<BlockStore>,
    ) -> Result<(State, B256)> {
        let mut state = State::new(trie, config, block_store).at_block(BlockHeader::default());

        if config.consensus.is_main {
            let shard_data = contracts::shard_registry::CONSTRUCTOR.encode_input(
                contracts::shard_registry::BYTECODE.to_vec(),
                &[Token::Uint(
                    config.consensus.consensus_timeout.as_millis().into(),
                )],
            )?;
            state.force_deploy_contract_evm(shard_data, Some(contract_addr::SHARD_REGISTRY))?;
        };

        let intershard_bridge_data = contracts::intershard_bridge::BYTECODE.to_vec();
        state.force_deploy_contract_evm(
            intershard_bridge_data,
            Some(contract_addr::INTERSHARD_BRIDGE),
        )?;

        let zero_account_balance = config
            .consensus
            .total_native_token_supply
            .0
            .checked_sub(
                config
                    .consensus
                    .genesis_accounts
                    .iter()
                    .fold(0, |acc, item: &(Address, Amount)| acc + item.1 .0),
            )
            .expect("Genesis accounts sum to more than total native token supply")
            .checked_sub(
                config
                    .consensus
                    .genesis_deposits
                    .iter()
                    .fold(0, |acc, item| acc + item.stake.0),
            )
            .expect(
                "Genesis accounts + genesis deposits sum to more than total native token supply",
            );
        state.mutate_account(Address::ZERO, |a| {
            a.balance = zero_account_balance;
            Ok(())
        })?;

        for (address, balance) in &config.consensus.genesis_accounts {
            state.mutate_account(*address, |a| {
                a.balance = **balance;
                Ok(())
            })?;
        }

        let initial_stakers: Vec<_> = config
            .consensus
            .genesis_deposits
            .iter()
            .map(|deposit| {
                Token::Tuple(vec![
                    Token::Bytes(deposit.public_key.as_bytes()),
                    Token::Bytes(deposit.peer_id.to_bytes()),
                    Token::Address(ethabi::Address::from(deposit.reward_address.into_array())),
                    Token::Address(ethabi::Address::from(deposit.control_address.into_array())),
                    Token::Uint((*deposit.stake).into()),
                ])
            })
            .collect();
        let deposit_data = contracts::deposit::CONSTRUCTOR.encode_input(
            contracts::deposit::BYTECODE.to_vec(),
            &[
                Token::Uint((*config.consensus.minimum_stake).into()),
                Token::Uint(MAX_COMMITTEE_SIZE.into()),
                Token::Uint(config.consensus.blocks_per_epoch.into()),
                Token::Array(initial_stakers),
            ],
        )?;
        state.force_deploy_contract_evm(deposit_data, Some(contract_addr::DEPOSIT))?;

        let root_hash = state.root_hash()?;

        Ok((state.state, root_hash.into()))
    }

    fn at_root(&self, root_hash: B256) -> Self {
        Self {
            db: self.db.clone(),
            accounts: self.accounts.at_root(root_hash),
            scilla: self.scilla.clone(),
            scilla_address: self.scilla_address.clone(),
            local_address: self.local_address.clone(),
            scilla_lib_dir: self.scilla_lib_dir.clone(),
            scilla_ext_libs_path: self.scilla_ext_libs_path.clone(),
            block_gas_limit: self.block_gas_limit,
            gas_price: self.gas_price,
            chain_id: self.chain_id,
            block_store: self.block_store.clone(),
        }
    }

    pub fn at_block(&self, block: BlockHeader) -> StateProvider {
        StateProvider {
            state: State {
                db: self.db.clone(),
                accounts: self.accounts.at_root(block.state_root_hash.into()),
                scilla: self.scilla.clone(),
                scilla_address: self.scilla_address.clone(),
                local_address: self.local_address.clone(),
                scilla_lib_dir: self.scilla_lib_dir.clone(),
                scilla_ext_libs_path: self.scilla_ext_libs_path.clone(),
                block_gas_limit: self.block_gas_limit,
                gas_price: self.gas_price,
                chain_id: self.chain_id,
                block_store: self.block_store.clone(),
            },
        }
    }
}

/// Calculate the trie key for an account
fn account_key(address: Address) -> B256 {
    <[u8; 32]>::from(Keccak256::digest(address)).into()
}

/// Calculate the trie key an EVM storage slot
pub fn account_storage_key(address: Address, index: B256) -> B256 {
    let mut h = Keccak256::new();
    h.update(address);
    h.update(index);
    <[u8; 32]>::from(h.finalize()).into()
}

impl StateProvider {
    pub fn root_hash(&mut self) -> Result<crypto::Hash> {
        Ok(crypto::Hash(self.state.accounts.root_hash()?.into()))
    }

    /// Fetch an Account struct.
    /// Note: use get_account_storage to obtain a specific storage value.
    /// If modifying a raw account, ensure you call save_account afterwards.
    /// Returns an error on failures to access the state tree, or decode the account; or an empty
    /// account if one didn't exist yet
    pub fn get_account(&self, address: Address) -> Result<Account> {
        Ok(self
            .state
            .accounts
            .get(&account_key(address).0)?
            .map(|bytes| bincode::deserialize::<Account>(&bytes))
            .unwrap_or(Ok(Account::default()))?)
    }

    pub fn mutate_account<F: FnOnce(&mut Account) -> Result<R>, R>(
        &mut self,
        address: Address,
        mutation: F,
    ) -> Result<R> {
        let mut account = self.get_account(address)?;
        let result = mutation(&mut account)?;
        self.save_account(address, account)?;
        Ok(result)
    }

    pub fn get_account_trie(&self, address: Address) -> Result<PatriciaTrie<TrieStorage>> {
        let account = self.get_account(address)?;
        Ok(PatriciaTrie::new(self.state.db.clone()).at_root(account.storage_root))
    }

    pub fn get_account_storage(&self, address: Address, index: B256) -> Result<B256> {
        match self.get_account_trie(address)?.get(&account_storage_key(address, index).0) {
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

    pub fn has_account(&self, address: Address) -> Result<bool> {
        Ok(self.state.accounts.contains(&account_key(address).0)?)
    }

    fn save_account(&mut self, address: Address, account: Account) -> Result<()> {
        Ok(self
            .state
            .accounts
            .insert(&account_key(address).0, &bincode::serialize(&account)?)?)
    }
}

pub mod contract_addr {
    use alloy::primitives::Address;

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
pub struct ExternalLibrary {
    pub name: String,
    pub address: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInit(Vec<ParamValue>);

impl ContractInit {
    pub fn new(init: Vec<ParamValue>) -> Self {
        Self(init)
    }

    pub fn scilla_version(&self) -> Result<String> {
        for entry in &self.0 {
            if entry.name == "_scilla_version" {
                return Ok(entry.value.to_string());
            }
        }
        Ok(String::new())
    }

    pub fn is_library(&self) -> Result<bool> {
        for entry in &self.0 {
            if entry.name == "_library" {
                return Ok(entry.value["constructor"]
                    .as_str()
                    .map_or(false, |value| value == "True"));
            }
        }
        Ok(false)
    }

    pub fn external_libraries(&self) -> Result<Vec<ExternalLibrary>> {
        let mut external_libraries = Vec::new();
        for entry in &self.0 {
            if entry.name == "_extlibs" {
                if let Some(ext_libs) = entry.value.as_array() {
                    for ext_lib in ext_libs {
                        if let Some(lib) = ext_lib["arguments"].as_array() {
                            if lib.len() != 2 {
                                return Err(anyhow!("Invalid init."));
                            }
                            let lib_name = lib[0].as_str().ok_or_else(|| {
                                anyhow!("Invalid init. Library name is not an string")
                            })?;
                            let lib_address = lib[1].as_str().ok_or_else(|| {
                                anyhow!("Invalid init. Library address is not an string")
                            })?;
                            external_libraries.push(ExternalLibrary {
                                name: lib_name.to_string(),
                                address: lib_address.parse::<Address>()?,
                            });
                        } else {
                            return Err(anyhow!("Invalid init."));
                        }
                    }
                }
            }
        }
        Ok(external_libraries)
    }

    pub fn into_inner(self) -> Vec<ParamValue> {
        self.0
    }
}

impl Display for ContractInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(&self.0).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", json)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Code {
    Evm(#[serde(with = "serde_bytes")] Vec<u8>),
    Scilla {
        code: String,
        #[serde(with = "vec_param_value")]
        init_data: Vec<ParamValue>,
        types: BTreeMap<String, (String, u8)>,
        transitions: Vec<Transition>,
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

    pub fn scilla_code_and_init_data(self) -> Option<(String, Vec<ParamValue>)> {
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
