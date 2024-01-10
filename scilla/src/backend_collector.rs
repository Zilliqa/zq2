use primitive_types::{H160, H256, U256};
use std::collections::HashMap;
use evm::backend::{Backend};
use tracing::field::debug;
use evm_ds::protos::evm_proto::{EvmResult, Storage, Apply};
use tracing::*;
use sha3::{Digest, Keccak256};

pub type Address = H160;

#[derive(Debug, Clone)]
pub struct Account {
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage_root: Option<H256>,
    pub is_scilla: bool,
}

// Structure that answers queries about the state by using the backend, while also collecting
// the state changes so it can generate an evm result
pub struct BackendCollector<'a, B: evm::backend::Backend>{
    pub backend: &'a B,
    // Map of cached (execution in progress) address to account and any dirty storage.
    // If the value is None, this means a deletion of that account and storage
    pub account_storage_cached: HashMap<Address, Option<(Account, HashMap<H256, H256>)>>,
}

impl<'a, B: Backend> BackendCollector<'a, B> {
    pub fn new(
        backend: &'a B,
    ) -> Self {
        Self {
            backend: backend,
            account_storage_cached: HashMap::new(),
        }
    }

    pub fn get_account_storage(&mut self, address: Address, key: H256) -> H256 {

        trace!("READ: {:?}, {:?}", address, key);

        // If the account does not exist, check the backend
        if !self.account_storage_cached.contains_key(&address) {
            trace!("Account not in cache, checking backend");
            self.backend.storage(address, key)
        } else {
            let entry = self.account_storage_cached.get_mut(&address).unwrap();

            debug!("Getting account storage: {:?} {:?}", address, entry);

            match entry {
                Some((_, storage)) => {
                    let storagex = storage.get(&key);

                    if storagex.is_none() {
                        trace!("Storage not in cache!");
                    } else {
                        trace!("Storage in cache");
                    }

                    storage.get(&key).cloned().unwrap_or(H256::zero())
                }
                None => {
                    error!("Queried storage in cache is None: {:?}", address);
                    H256::zero()
                }
            }
        }
    }

    pub fn update_account_storage(&mut self, address: Address, key: H256, value: H256) {

        trace!("WRITE: {:?}, {:?}, {:?},", address, key, value);

        // If the account does not exist, check the backend, then create it with empty code and storage
        if !self.account_storage_cached.contains_key(&address) {

            debug!("Creating account in cache: {:?}", address);

            let account = Account {
                nonce: self.backend.basic(address).nonce.as_u64(),
                code: self.backend.code(address),
                storage_root: None,
                is_scilla: true,
            };

            self.account_storage_cached.insert(
                address,
                Some(( account, HashMap::from([(key, value)]),
                )),
            );
        } else {

            let entry = self.account_storage_cached.get_mut(&address).unwrap();

            debug!("Updating account in cache: {:?} {:?}", address, entry);

            match entry {
                Some((_, storage)) => {
                    storage.insert(key, value);
                }
                None => {
                    error!("Account in cache is None: {:?}", address);
                }
            }
        }

    }

    /// Put data into the cache as a key, value. In order to be able to write and read arbitrary
    /// length data to the database (which expects K,V pairs of H256, H256), we:
    /// 1. Hash the key to H256
    /// 2. put the length of the value in bytes at this location
    /// 3. put the data at H256 + 1, H256 + 2, etc.
    pub fn update_account_storage_scilla(&mut self, address: Address, key: &str, value: &[u8]) {
        // Get or create a cached account with these details.

        debug!("Updating account storage: {:?}, {:?}, {:?},", address, key, value);

        // Hash key to H256
        let mut key = H256::from_slice(&Keccak256::digest(key.as_bytes()).to_vec());

        //let mut value_fixed_width = [0u8; 32];
        //value_fixed_width = [value.len() as u8; 32];
        let value_fixed_width = u64_to_h256(value.len() as u64);

        // Key, Value for the length of the proceeding value in bytes
        self.update_account_storage(address, key, value_fixed_width);

        for (i, chunk) in value.chunks(32).enumerate() {
            let mut value_fixed_width = [0u8; 32];
            //value_fixed_width = chunk.
            value_fixed_width[..chunk.len()].copy_from_slice(chunk); // todo check this
            debug!("*** Updating account storage: {:?}, {:?}, {:?},", address, key, value_fixed_width);
            let value = H256::from(value_fixed_width);
            key = increment_h256(key);
            self.update_account_storage(address, key, value);
        }
    }

    /// Get data from the cache as a key, value. In order to be able to write and read arbitrary
    /// length data to the database (which expects K,V pairs of H256, H256), we:
    /// 1. Hash the key to H256
    /// 2. put the length of the value in bytes at this location
    /// 3. put the data at H256 + 1, H256 + 2, etc.
    pub fn get_account_storage_scilla(&mut self, address: Address, key: &str) -> Vec<u8> {

        let mut key = H256::from_slice(&Keccak256::digest(key.as_bytes()).to_vec());
        let zero = H256::zero();

        match self.get_account_storage(address, key) {
            //zero => {
            //    trace!("Request for account storage was empty");
            //    return vec![];
            //}
            value => {
                //let mut value = value.as_bytes().to_vec();
                //let mut value_fixed_width = [0u8; 32];
                //value_fixed_width.copy_from_slice(&value);
                //let value = u32::from_be_bytes(value_fixed_width[0..3] as [u8; 4]);
                let value = h256_to_u64(value);

                debug!("Getting account storage: {:?}, {:?}, len: {:?},", address, key, value);

                let mut result = vec![];

                for i in 0..value {
                    key = increment_h256(key);
                    let value = self.get_account_storage(address, key.into());
                    result.extend_from_slice(&value.as_bytes());
                }
                return result;
            }
        }
    }

    pub fn create_account(&mut self, address: Address, code: Vec<u8>, is_scilla: bool) {
        // Insert empty slot into cache if it does not already exist, else just put the code there
        if let Some(Some((acct, _))) = self.account_storage_cached.get_mut(&address) {
            acct.code = code;
            return;
        }

        // Fall through
        self.account_storage_cached.insert(
            address,
            Some((
                Account {
                    nonce: 0,
                    code,
                    storage_root: None,
                    is_scilla,
                },
                HashMap::new(),
            )),
        );
    }

    pub fn get_code(&self, address: Address) -> Vec<u8> {
        if let Some(Some((acct, _))) = self.account_storage_cached.get(&address) {
            return acct.code.clone();
        }

        self.backend.code(address)
    }

    // Get the deltas from all of the operations so far
    pub fn get_result(self) -> EvmResult {
        let mut applys: Vec<Apply> = vec![];

        for (address, item) in self.account_storage_cached.into_iter() {
            match item {
                Some((acct, stor)) => {
                    applys.push(Apply::Modify {
                        address,
                        balance: U256::zero(),
                        nonce: U256::zero(),
                        code: acct.code,
                        storage: stor
                            .into_iter()
                            .map(|(key, value)| Storage { key, value })
                            .collect(),
                        reset_storage: false,
                    });
                }
                None => {
                    applys.push(Apply::Delete { address });
                }
            }
        }

        EvmResult {
            apply: applys,
            ..Default::default()
        }
    }
}
fn increment_h256(mut hash: H256) -> H256 {
    // To easily increment, just re-hash the hash
    H256::from_slice(&Keccak256::digest(&hash[..].to_vec()).to_vec())
}
fn u64_to_h256(value: u64) -> H256 {
    let mut hash = [0u8; 32];
    hash[24..32].copy_from_slice(&value.to_be_bytes()); // Big-endian
    hash.into()
}

fn h256_to_u64(hash: H256) -> u64 {
    let bytes = &hash[24..32]; // Extract the last 8 bytes
    u64::from_be_bytes(bytes.try_into().expect("Wrong length for u64 conversion!"))
}
