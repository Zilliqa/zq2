use std::{
    collections::{BTreeMap, HashMap, hash_map::Entry},
    error::Error,
    fmt::{self, Display, Formatter},
    mem,
};

use alloy::primitives::{Address, Bytes, U256};
use anyhow::{Result, anyhow};
use eth_trie::Trie;
use revm::{
    Database, DatabaseRef,
    context_interface::DBErrorMarker,
    primitives::{B256, KECCAK_EMPTY},
    state::{AccountInfo, Bytecode, EvmState},
};
use tracing::{info, trace};

use super::{ScillaError, ScillaResult};
use crate::{
    cfg::Fork,
    message::Block,
    scilla::{split_storage_key, storage_key},
    state::{Account, Code, State},
    transaction::{EvmGas, ZilAmount},
};

#[derive(Debug)]
pub struct DatabaseError(anyhow::Error);

impl DBErrorMarker for DatabaseError {}

impl From<anyhow::Error> for DatabaseError {
    fn from(err: anyhow::Error) -> Self {
        DatabaseError(err)
    }
}

impl Display for DatabaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for DatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl Database for PendingState {
    type Error = DatabaseError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.pre_state.basic_ref(address, &self.fork)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.pre_state.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.pre_state.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.pre_state.block_hash_ref(number)
    }
}

impl DatabaseRef for PendingState {
    type Error = DatabaseError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.pre_state.basic_ref(address, &self.fork)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.pre_state.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.pre_state.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.pre_state.block_hash_ref(number)
    }
}

impl State {
    fn basic_ref(
        &self,
        address: Address,
        fork: &Fork,
    ) -> Result<Option<AccountInfo>, DatabaseError> {
        if !self.has_account(address)? {
            return Ok(None);
        }

        let account = self.get_account(address)?;
        let code_raw = if fork.prevent_zil_transfer_from_evm_to_scilla_contract {
            match account.code {
                Code::Evm(code) => code,
                Code::Scilla { code, .. } => code.as_bytes().to_vec(),
            }
        } else {
            account.code.evm_code().unwrap_or_default()
        };

        let code = Bytecode::new_raw(code_raw.into());
        let account_info = AccountInfo {
            balance: U256::from(account.balance),
            nonce: account.nonce,
            code_hash: code.hash_slow(),
            account_id: None,
            code: Some(code),
        };

        Ok(Some(account_info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, DatabaseError> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, DatabaseError> {
        let index = B256::new(index.to_be_bytes());

        let result = self.get_account_storage(address, index)?;

        Ok(U256::from_be_bytes(result.0))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, DatabaseError> {
        Ok(self
            .get_canonical_block_by_number(number)?
            .map(|block| B256::new(block.hash().0))
            .unwrap_or_default())
    }
}

#[derive(Debug, Clone)]
pub struct PendingState {
    pub pre_state: State,
    pub new_state: HashMap<Address, PendingAccount>,
    pub evm_state: Option<EvmState>,
    pub fork: Fork,
}

fn load_account<'a>(
    pre_state: &State,
    new_state: &'a mut HashMap<Address, PendingAccount>,
    evm_state: &Option<EvmState>,
    address: Address,
    remove_scilla_contracts_from_evm_delta: bool,
) -> Result<&'a mut PendingAccount> {
    let mut evm_account = evm_state
        .as_ref()
        .and_then(|evm_state| evm_state.get(&address));
    if remove_scilla_contracts_from_evm_delta
        && evm_account.is_some()
        && !new_state.contains_key(&address)
        && pre_state.get_account(address)?.code.is_scilla()
    {
        evm_account = None;
    }
    match (new_state.entry(address), evm_account) {
        (Entry::Occupied(entry), _) => Ok(entry.into_mut()),
        (Entry::Vacant(vac), Some(account)) => {
            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.to(),
                code: Code::Evm(if account.info.code_hash == KECCAK_EMPTY {
                    vec![]
                } else {
                    account
                        .info
                        .code
                        .as_ref()
                        .ok_or_else(|| anyhow!("account should have code"))?
                        .original_bytes()
                        .to_vec()
                }),
                storage_root: B256::ZERO,
            };
            let account = PendingAccount {
                account,
                storage: BTreeMap::new(),
                from_evm: true,
                touched: false,
            };
            Ok(vac.insert(account))
        }
        (Entry::Vacant(vac), None) => {
            let account = pre_state.get_account(address)?;
            Ok(vac.insert(account.into()))
        }
    }
}

impl PendingState {
    pub fn new(state: State, fork: Fork) -> Self {
        PendingState {
            pre_state: state,
            new_state: HashMap::new(),
            evm_state: None,
            fork,
        }
    }

    pub fn zil_chain_id(&self) -> u64 {
        self.pre_state.chain_id.zil()
    }

    pub fn get_canonical_block_by_number(&self, block_number: u64) -> Result<Option<Block>> {
        self.pre_state.get_canonical_block_by_number(block_number)
    }

    pub fn get_highest_canonical_block_number(&self) -> Result<Option<u64>> {
        self.pre_state.get_highest_canonical_block_number()
    }

    pub fn touch(&mut self, address: Address) {
        if let Some(account) = self.new_state.get_mut(&address) {
            account.mark_touch();
        }
    }

    pub fn load_account(&mut self, address: Address) -> Result<&mut PendingAccount> {
        load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
            self.fork.remove_scilla_contracts_from_evm_delta,
        )
    }

    pub fn load_var_info(&mut self, address: Address, variable: &str) -> Result<(&str, u8)> {
        let account = self.load_account(address)?;
        let Code::Scilla { types, .. } = &account.account.code else {
            return Err(anyhow!("not a scilla contract"));
        };
        let (ty, depth) = types
            .get(variable)
            .ok_or_else(|| anyhow!("missing type for variable: {variable}"))?;
        Ok((ty, *depth))
    }

    pub fn set_storage(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
        value: StorageValue,
    ) -> Result<()> {
        let account = load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
            self.fork.remove_scilla_contracts_from_evm_delta,
        )?;

        let mut current = account
            .storage
            .entry(var_name.to_owned())
            .or_insert_with(StorageValue::incomplete_map);
        for key in indices {
            let current_map = match current {
                StorageValue::Map { map, .. } => map,
                StorageValue::Value(Some(_)) => {
                    return Err(anyhow!("expected a map"));
                }
                StorageValue::Value(None) => {
                    unreachable!("deletes of whole maps are unsupported")
                }
            };
            let child = current_map
                .entry(key.clone())
                .or_insert_with(StorageValue::incomplete_map);
            current = child;
        }

        *current = value;

        Ok(())
    }

    pub fn load_storage(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
    ) -> Result<&mut Option<Bytes>> {
        let account = load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
            self.fork.remove_scilla_contracts_from_evm_delta,
        )?;

        fn get_cached<'a>(
            storage: &'a mut BTreeMap<String, StorageValue>,
            var_name: &str,
            indices: &[Vec<u8>],
        ) -> Result<(&'a mut StorageValue, bool)> {
            let mut cached = true;
            let mut current = storage.entry(var_name.to_owned()).or_insert_with(|| {
                cached = false;
                StorageValue::incomplete_map()
            });
            for key in indices {
                let current_map = match current {
                    StorageValue::Map { map, .. } => map,
                    StorageValue::Value(Some(_)) => {
                        return Err(anyhow!("expected a map"));
                    }
                    StorageValue::Value(None) => {
                        unreachable!("deletes of whole maps are unsupported")
                    }
                };
                let child = current_map.entry(key.clone()).or_insert_with(|| {
                    cached = false;
                    StorageValue::incomplete_map()
                });
                current = child;
            }
            Ok((current, cached))
        }

        let (value, cached) = get_cached(&mut account.storage, var_name, indices)?;

        if !cached {
            let value_from_disk = self
                .pre_state
                .get_account_trie(address)?
                .get(&storage_key(var_name, indices))?;

            *value = StorageValue::Value(value_from_disk.map(|b| b.into()));
        }

        match value {
            StorageValue::Map { .. } => Err(anyhow!("expected bytes")),
            StorageValue::Value(value) => Ok(value),
        }
    }

    pub fn load_storage_by_prefix(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
    ) -> Result<BTreeMap<Vec<u8>, StorageValue>> {
        let account = load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
            self.fork.remove_scilla_contracts_from_evm_delta,
        )?;

        let values_from_disk: Vec<_> = self
            .pre_state
            .get_account_trie(address)?
            .iter_by_prefix(&storage_key(var_name, indices))?
            .collect();

        let mut map = StorageValue::complete_map();
        let cached = account.storage.get(var_name);

        for (k, v) in values_from_disk.into_iter().flatten() {
            let (disk_var_name, disk_indices) = split_storage_key(&k)?;
            if var_name != disk_var_name {
                trace!(var_name, disk_var_name, "scilla var name mismatch");
                continue;
            }
            assert!(disk_indices.starts_with(indices));

            let mut current_value = &mut map;
            let mut current_cached = cached;

            let disk_indices_len = disk_indices.len();

            for index in disk_indices {
                if let Some(c) = current_cached {
                    match c {
                        StorageValue::Map { map, .. } => {
                            current_cached = map.get(&index);
                        }
                        StorageValue::Value(_) => {}
                    }
                }

                let map = match current_value {
                    StorageValue::Map { map, .. } => map,
                    StorageValue::Value(_) => {
                        return Err(anyhow!("expected map"));
                    }
                };
                current_value = map.entry(index).or_insert_with(StorageValue::complete_map);
            }

            *current_value = if let Some(cached) = current_cached {
                cached.clone()
            } else if disk_indices_len == 0 && self.fork.scilla_empty_maps_are_encoded_correctly {
                StorageValue::complete_map()
            } else {
                StorageValue::Value(Some(v.into()))
            };
        }

        let map = match map {
            StorageValue::Map { map, .. } => map,
            StorageValue::Value(_) => {
                return Err(anyhow!("expected map"));
            }
        };

        Ok(map)
    }

    #[track_caller]
    pub fn deduct_from_account(
        &mut self,
        address: Address,
        amount: ZilAmount,
        gas_used: EvmGas,
    ) -> Result<Option<ScillaResult>> {
        let caller = std::panic::Location::caller();
        let account = self.load_account(address)?;
        account.mark_touch();
        trace!(
            "account balance = {0} sub {1}",
            account.account.balance,
            amount.get()?
        );
        let Some(balance) = account.account.balance.checked_sub(amount.get()?) else {
            info!("insufficient balance: {caller}");
            return Ok(Some(ScillaResult {
                success: false,
                contract_address: None,
                logs: vec![],
                gas_used,
                transitions: vec![],
                accepted: None,
                errors: [(0, vec![ScillaError::BalanceTransferFailed])]
                    .into_iter()
                    .collect(),
                exceptions: vec![],
            }));
        };
        account.account.balance = balance;
        Ok(None)
    }

    pub fn finalize(&mut self) -> HashMap<Address, PendingAccount> {
        mem::take(&mut self.new_state)
    }
}

#[derive(Clone, Debug)]
pub struct PendingAccount {
    pub account: Account,
    pub storage: BTreeMap<String, StorageValue>,
    pub from_evm: bool,
    pub touched: bool,
}

impl PendingAccount {
    pub fn mark_touch(&mut self) {
        self.touched = true;
    }
}

#[derive(Debug, Clone)]
pub enum StorageValue {
    Map {
        map: BTreeMap<Vec<u8>, StorageValue>,
        complete: bool,
    },
    Value(Option<Bytes>),
}

impl StorageValue {
    pub fn incomplete_map() -> StorageValue {
        StorageValue::Map {
            map: BTreeMap::new(),
            complete: false,
        }
    }

    pub fn complete_map() -> StorageValue {
        StorageValue::Map {
            map: BTreeMap::new(),
            complete: true,
        }
    }
}

impl From<Account> for PendingAccount {
    fn from(account: Account) -> PendingAccount {
        PendingAccount {
            account,
            storage: BTreeMap::new(),
            from_evm: false,
            touched: false,
        }
    }
}
