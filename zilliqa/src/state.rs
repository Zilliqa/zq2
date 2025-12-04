use std::{
    collections::BTreeMap,
    fmt::Display,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use alloy::{
    consensus::EMPTY_ROOT_HASH,
    primitives::{Address, B256},
};
use anyhow::{Result, anyhow};
use eth_trie::{EthTrie as PatriciaTrie, Trie};
use ethabi::Token;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tracing::{debug, info};

use crate::{
    cfg::{Amount, ConsensusConfig, Forks, NodeConfig, ReinitialiseParams, ScillaExtLibsPath},
    contracts::{self, Contract},
    crypto::{self, Hash},
    db::{BlockFilter, Db},
    error::ensure_success,
    message::{Block, BlockHeader, MAX_COMMITTEE_SIZE},
    node::ChainId,
    precompiles::ViewHistory,
    scilla::{ParamValue, Scilla, Transition},
    serde_util::vec_param_value,
    transaction::EvmGas,
    trie_storage::TrieStorage,
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
    sql: Arc<Db>,
    db: Arc<TrieStorage>,
    accounts: Arc<RwLock<PatriciaTrie<TrieStorage>>>,
    /// The Scilla interpreter interface. Note that it is lazily initialized - This is a bit of a hack to ensure that
    /// tests which don't invoke Scilla, don't spawn the Scilla communication threads or TCP listeners.
    scilla: Arc<OnceLock<Mutex<Scilla>>>,
    scilla_address: String,
    socket_dir: String,
    scilla_lib_dir: String,
    pub scilla_ext_libs_path: ScillaExtLibsPath,
    pub block_gas_limit: EvmGas,
    pub gas_price: u128,
    pub chain_id: ChainId,
    pub forks: Forks,
    pub finalized_view: u64,
    pub view_history: Arc<RwLock<ViewHistory>>,
    pub ckpt_finalized_view: Option<u64>,
    pub ckpt_view_history: Option<Arc<RwLock<ViewHistory>>>,
}

impl State {
    pub fn new(trie: TrieStorage, config: &NodeConfig, sql: Arc<Db>) -> Result<State> {
        let db = Arc::new(trie);
        let consensus_config = &config.consensus;
        Ok(Self {
            sql,
            db: db.clone(),
            accounts: Arc::new(RwLock::new(PatriciaTrie::new(db))),
            scilla: Arc::new(OnceLock::new()),
            scilla_address: consensus_config.scilla_address.clone(),
            socket_dir: consensus_config.scilla_server_socket_directory.clone(),
            scilla_lib_dir: consensus_config.scilla_stdlib_dir.clone(),
            scilla_ext_libs_path: consensus_config.scilla_ext_libs_path.clone(),
            block_gas_limit: consensus_config.eth_block_gas_limit,
            gas_price: *consensus_config.gas_price,
            chain_id: ChainId::new(config.eth_chain_id),
            forks: consensus_config.get_forks()?,
            finalized_view: 0,
            view_history: Arc::new(RwLock::new(ViewHistory::new())),
            ckpt_finalized_view: None,
            ckpt_view_history: None,
        })
    }

    pub fn scilla(&self) -> MutexGuard<'_, Scilla> {
        self.scilla
            .get_or_init(|| {
                Mutex::new(Scilla::new(
                    self.scilla_address.clone(),
                    self.socket_dir.clone(),
                    self.scilla_lib_dir.clone(),
                ))
            })
            .lock()
            .unwrap()
    }

    pub fn new_at_root(
        trie: TrieStorage,
        root_hash: B256,
        config: NodeConfig,
        sql: Arc<Db>,
    ) -> Result<Self> {
        Ok(Self::new(trie, &config, sql)?.at_root(root_hash))
    }

    pub fn new_with_genesis(trie: TrieStorage, config: NodeConfig, sql: Arc<Db>) -> Result<State> {
        let mut state = State::new(trie, &config, sql)?;

        if config.consensus.is_main {
            let shard_data = contracts::shard_registry::CONSTRUCTOR.encode_input(
                contracts::shard_registry::BYTECODE.to_vec(),
                &[Token::Uint(
                    config.consensus.consensus_timeout.as_millis().into(),
                )],
            )?;
            state.force_deploy_contract_evm(shard_data, Some(contract_addr::SHARD_REGISTRY), 0)?;
        };

        let intershard_bridge_data = contracts::intershard_bridge::BYTECODE.to_vec();
        state.force_deploy_contract_evm(
            intershard_bridge_data,
            Some(contract_addr::INTERSHARD_BRIDGE),
            0,
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
                    .fold(0, |acc, item: &(Address, Amount)| acc + item.1.0),
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

        // Set ZERO account to total available balance
        state.mutate_account(Address::ZERO, |a| {
            a.balance = zero_account_balance;
            Ok(())
        })?;

        // Set GENESIS account starting balances
        for (address, balance) in config.consensus.genesis_accounts.clone() {
            state.mutate_account(address, |a| {
                a.balance = *balance;
                Ok(())
            })?;
        }

        state.deploy_initial_deposit_contract(&config)?;

        let deposit_contract = Lazy::<contracts::Contract>::force(&contracts::deposit_v2::CONTRACT);
        let block_header = BlockHeader::genesis(Hash::ZERO);
        state.upgrade_deposit_contract(block_header, deposit_contract, None)?;

        // Check if any contracts are to be upgraded from genesis
        state.contract_upgrade_apply_state_change(&config.consensus, block_header)?;

        Ok(state)
    }

    /// If there are any contract updates to be performed then apply them to self
    pub fn contract_upgrade_apply_state_change(
        &mut self,
        config: &ConsensusConfig,
        block_header: BlockHeader,
    ) -> Result<()> {
        if let Some(deposit_v3_deploy_config) = &config.contract_upgrades.deposit_v3
            && deposit_v3_deploy_config.height == block_header.number
        {
            let deposit_v3_contract =
                Lazy::<contracts::Contract>::force(&contracts::deposit_v3::CONTRACT);
            self.upgrade_deposit_contract(block_header, deposit_v3_contract, None)?;
        }
        if let Some(deposit_v4_deploy_config) = &config.contract_upgrades.deposit_v4
            && deposit_v4_deploy_config.height == block_header.number
        {
            // The below account mutation fixes the Zero account's nonce in prototestnet and protomainnet.
            // Issue #2254 explains how the nonce was incorrect due to a bug in the ZQ1 persistence converter.
            // This code should run once for these networks in order for the deposit_v4 contract to be deployed, then this code can be removed.
            if self.chain_id.eth == 33103 || self.chain_id.eth == 32770 {
                self.mutate_account(Address::ZERO, |a| {
                    // Nonce 5 is the next address to not have any code deployed
                    a.nonce = 5;
                    Ok(())
                })?;
            }
            let deposit_v4_contract =
                Lazy::<contracts::Contract>::force(&contracts::deposit_v4::CONTRACT);
            self.upgrade_deposit_contract(block_header, deposit_v4_contract, None)?;
        }
        if let Some(deposit_v5_deploy_config) = &config.contract_upgrades.deposit_v5
            && deposit_v5_deploy_config.height == block_header.number
        {
            let deposit_v5_contract =
                Lazy::<contracts::Contract>::force(&contracts::deposit_v5::CONTRACT);
            let reinitialise_params = deposit_v5_deploy_config
                .reinitialise_params
                .clone()
                .unwrap_or(ReinitialiseParams::default());
            let deposit_v5_reinitialise_data = contracts::deposit_v5::REINITIALIZE
                .encode_input(&[Token::Uint(reinitialise_params.withdrawal_period.into())])?;
            self.upgrade_deposit_contract(
                block_header,
                deposit_v5_contract,
                Some(deposit_v5_reinitialise_data),
            )?;
        }
        if let Some(deposit_v6_deploy_config) = &config.contract_upgrades.deposit_v6
            && deposit_v6_deploy_config.height == block_header.number
        {
            let deposit_v6_contract =
                Lazy::<contracts::Contract>::force(&contracts::deposit_v6::CONTRACT);
            self.upgrade_deposit_contract(block_header, deposit_v6_contract, None)?;
        }
        if let Some(deposit_v7_deploy_config) = &config.contract_upgrades.deposit_v7
            && deposit_v7_deploy_config.height == block_header.number
        {
            let deposit_v7_contract =
                Lazy::<contracts::Contract>::force(&contracts::deposit_v7::CONTRACT);
            let reinitialise_params_opt = deposit_v7_deploy_config.reinitialise_params.clone();
            let deposit_v7_reinitialise_data_opt = match reinitialise_params_opt {
                Some(reinitialise_params) => Some(
                    contracts::deposit_v7::REINITIALIZE_2.encode_input(&[Token::Uint(
                        reinitialise_params.withdrawal_period.into(),
                    )])?,
                ),
                None => None,
            };
            self.upgrade_deposit_contract(
                block_header,
                deposit_v7_contract,
                deposit_v7_reinitialise_data_opt,
            )?;
        }
        Ok(())
    }

    /// Deploy DepositInit contract (deposit_v1.sol)
    /// Warning: staking will not work with this contact deployment alone. self.upgrade_deposit_contract() must be called in order to deploy a full Deposit implementation.
    fn deploy_initial_deposit_contract(&mut self, config: &NodeConfig) -> Result<Address> {
        // Deploy DepositInit
        let deposit_addr =
            self.force_deploy_contract_evm(contracts::deposit_init::BYTECODE.to_vec(), None, 0)?;

        let initial_stakers: Vec<_> = config
            .consensus
            .genesis_deposits
            .clone()
            .into_iter()
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
        let deposit_initialize_data = contracts::deposit_init::INITIALIZE.encode_input(&[
            Token::Uint((*config.consensus.minimum_stake).into()),
            Token::Uint(MAX_COMMITTEE_SIZE.into()),
            Token::Uint(config.consensus.blocks_per_epoch.into()),
            Token::Array(initial_stakers),
        ])?;
        let eip1967_constructor_data = contracts::eip1967_proxy::CONSTRUCTOR.encode_input(
            contracts::eip1967_proxy::BYTECODE.to_vec(),
            &[
                Token::Address(ethabi::Address::from(deposit_addr.into_array())),
                Token::Bytes(deposit_initialize_data),
            ],
        )?;

        let total_genesis_deposits = config
            .consensus
            .genesis_deposits
            .iter()
            .fold(0, |acc, item| acc + item.stake.0);

        // Deploy Eip1967 proxy pointing to DepositInit
        let eip1967_addr = self.force_deploy_contract_evm(
            eip1967_constructor_data,
            Some(contract_addr::DEPOSIT_PROXY),
            total_genesis_deposits,
        )?;
        debug!(
            "Deployed initial deposit contract version to {} and EIP 1967 deposit contract to {}",
            deposit_addr, eip1967_addr
        );

        Ok(deposit_addr)
    }

    /// Uses an Eip1967 proxy to update the deposit contract.
    /// Return new deposit implementation address
    pub fn upgrade_deposit_contract(
        &mut self,
        current_block: BlockHeader,
        contract: &Contract,
        reinitialise_data: Option<Vec<u8>>,
    ) -> Result<Address> {
        let current_version = self.deposit_contract_version(current_block)?;

        // Deploy latest deposit implementation
        let new_deposit_impl_addr =
            self.force_deploy_contract_evm(contract.bytecode.to_vec(), None, 0)?;
        let deposit_upgrade_to_and_call_data =
            contract.abi.function("upgradeToAndCall")?.encode_input(&[
                Token::Address(ethabi::Address::from(new_deposit_impl_addr.into_array())),
                Token::Bytes(
                    reinitialise_data
                        .unwrap_or(contracts::deposit::REINITIALIZE.encode_input(&[])?),
                ),
            ])?;

        // Apply update to eip 1967 proxy
        let result = self.call_contract_apply(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            deposit_upgrade_to_and_call_data,
            0,
            current_block,
        )?;
        ensure_success(result)?;

        let new_version = self.deposit_contract_version(current_block)?;
        info!(
            "EIP 1967 deposit contract proxy {} updated from version {} to new version {} with contract addr {}",
            contract_addr::DEPOSIT_PROXY,
            current_version,
            new_version,
            new_deposit_impl_addr
        );

        Ok(new_deposit_impl_addr)
    }

    pub fn at_root(&self, root_hash: B256) -> Self {
        Self {
            sql: self.sql.clone(),
            db: self.db.clone(),
            accounts: Arc::new(RwLock::new(self.accounts.read().at_root(root_hash))),
            scilla: self.scilla.clone(),
            scilla_address: self.scilla_address.clone(),
            socket_dir: self.socket_dir.clone(),
            scilla_lib_dir: self.scilla_lib_dir.clone(),
            scilla_ext_libs_path: self.scilla_ext_libs_path.clone(),
            block_gas_limit: self.block_gas_limit,
            gas_price: self.gas_price,
            chain_id: self.chain_id,
            forks: self.forks.clone(),
            finalized_view: self.finalized_view,
            view_history: self.view_history.clone(),
            ckpt_finalized_view: self.ckpt_finalized_view,
            ckpt_view_history: self.ckpt_view_history.clone(),
        }
    }

    pub fn set_to_root(&mut self, root_hash: B256) {
        let at_root = self.accounts.read().at_root(root_hash);
        self.accounts = Arc::new(RwLock::new(at_root));
    }

    pub fn try_clone(&self) -> Result<Self> {
        let root_hash = self.accounts.write().root_hash()?;
        Ok(self.at_root(root_hash))
    }

    pub fn root_hash(&self) -> Result<crypto::Hash> {
        let hash = self.accounts.write().root_hash()?;
        Ok(crypto::Hash(hash.into()))
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
        let Some(bytes) = self.accounts.read().get(&Self::account_key(address).0)? else {
            return Ok(Account::default());
        };

        let account = Account::try_from(bytes.as_slice())?;
        Ok(account)
    }

    /// As get_account, but panics if account cannot be read.
    pub fn must_get_account(&self, address: Address) -> Account {
        self.get_account(address).unwrap_or_else(|e| {
            panic!("Failed to read account {address:?} from state storage: {e:?}")
        })
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

    /// If using this to modify the account, ensure save_account gets called
    pub fn get_account_trie(&self, address: Address) -> Result<PatriciaTrie<TrieStorage>> {
        let account = self.get_account(address)?;
        Ok(PatriciaTrie::new(self.db.clone()).at_root(account.storage_root))
    }

    /// Returns an error if there are any issues fetching the account from the state trie
    pub fn get_account_storage(&self, address: Address, index: B256) -> Result<B256> {
        match self
            .get_account_trie(address)?
            .get(&Self::account_storage_key(address, index).0)
        {
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
        Ok(self
            .accounts
            .read()
            .contains(&Self::account_key(address).0)?)
    }

    pub fn save_account(&mut self, address: Address, account: Account) -> Result<()> {
        Ok(self.accounts.write().insert(
            &Self::account_key(address).0,
            &bincode::serde::encode_to_vec(&account, bincode::config::legacy())?,
        )?)
    }

    pub fn get_canonical_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        self.sql.get_block(BlockFilter::Height(number))
    }

    pub fn get_highest_canonical_block_number(&self) -> Result<Option<u64>> {
        self.sql.get_highest_canonical_block_number()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.read().iter().next().is_none()
    }
}

pub mod contract_addr {
    use alloy::primitives::Address;

    /// For intershard transactions, call this address
    pub const INTERSHARD_BRIDGE: Address = Address::new(*b"\0\0\0\0\0\0\0\0ZQINTERSHARD");
    /// Address of the shard registry - only present on the root shard.
    pub const SHARD_REGISTRY: Address = Address::new(*b"\0\0\0\0\0\0\0\0\0\0\0\0\0ZQSHARD");
    /// Address of EIP 1967 proxy for Deposit contract
    pub const DEPOSIT_PROXY: Address = Address::new(*b"\0\0\0\0\0ZILDEPOSITPROXY");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: u128,
    pub code: Code,
    pub storage_root: B256,
}

impl TryFrom<&[u8]> for Account {
    type Error = bincode::error::DecodeError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(bincode::serde::decode_from_slice::<Account, _>(
            bytes,
            bincode::config::legacy(), // for legacy compatibility
        )?
        .0)
    }
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
                return Ok(entry.value["constructor"].as_str() == Some("True"));
            }
        }
        Ok(false)
    }

    pub fn external_libraries(&self) -> Result<Vec<ExternalLibrary>> {
        let mut external_libraries = Vec::new();
        for entry in &self.0 {
            if entry.name == "_extlibs"
                && let Some(ext_libs) = entry.value.as_array()
            {
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
        Ok(external_libraries)
    }

    pub fn into_inner(self) -> Vec<ParamValue> {
        self.0
    }
}

impl Display for ContractInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(&self.0).map_err(|_| std::fmt::Error)?;
        write!(f, "{json}")
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

    pub fn scilla_code_and_init_data(&self) -> Option<(&str, &[ParamValue])> {
        match self {
            Code::Scilla {
                code, init_data, ..
            } => Some((code, init_data)),
            _ => None,
        }
    }

    pub fn is_scilla(&self) -> bool {
        matches!(self, Code::Scilla { .. })
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

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use crypto::Hash;
    use revm::primitives::FixedBytes;

    use super::*;
    use crate::{api::to_hex::ToHex, cfg::NodeConfig, db::Db, message::BlockHeader};

    #[test]
    fn deposit_contract_updateability() {
        let db = Db::new::<PathBuf>(None, 0, None, crate::cfg::DbConfig::default()).unwrap();
        let db = Arc::new(db);
        let config = NodeConfig::default();

        let mut state = State::new(db.state_trie().unwrap(), &config, db).unwrap();

        let deposit_init_addr = state.deploy_initial_deposit_contract(&config).unwrap();

        // Check initial deployment of DEPOSIT_V0
        let genesis_block_header = BlockHeader::genesis(Hash::ZERO);
        let stakers = state.get_stakers(genesis_block_header);
        // deposit init does not support getStakers()
        assert!(stakers.is_err());

        let version = state
            .deposit_contract_version(genesis_block_header)
            .unwrap();
        assert_eq!(version, 1);

        let proxy_storage_at = state
            .get_account_storage(
                contract_addr::DEPOSIT_PROXY,
                B256::from(
                    FixedBytes::try_from(
                        hex::decode(
                            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                        )
                        .unwrap()
                        .as_slice(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
        // this is the eip 1967 contract's _implementation storage spot for the proxy address. It should point to deposit init address.
        assert!(
            proxy_storage_at
                .to_hex()
                .contains(&deposit_init_addr.0.to_string().split_off(2))
        );

        // Update to deposit v2
        let deposit_v2 = Lazy::<contracts::Contract>::force(&contracts::deposit_v2::CONTRACT);
        let deposit_v2_addr = state
            .upgrade_deposit_contract(BlockHeader::genesis(Hash::ZERO), deposit_v2, None)
            .unwrap();

        let proxy_storage_at = state
            .get_account_storage(
                contract_addr::DEPOSIT_PROXY,
                B256::from(
                    FixedBytes::try_from(
                        hex::decode(
                            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                        )
                        .unwrap()
                        .as_slice(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
        // this is the eip 1967 contract's _implementation storage spot for the proxy address. It should now point to deposit v2 address.
        assert!(
            proxy_storage_at
                .to_hex()
                .contains(&deposit_v2_addr.0.to_string().split_off(2))
        );

        let version = state
            .deposit_contract_version(genesis_block_header)
            .unwrap();
        assert_eq!(version, 2);

        let stakers = state.get_stakers(genesis_block_header).unwrap();
        assert_eq!(stakers.len(), config.consensus.genesis_deposits.len());
    }
}
