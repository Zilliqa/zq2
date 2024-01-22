use std::collections::HashMap;

use evm::backend::Backend;
use evm_ds::protos::evm_proto::{Apply, EvmResult, Storage};
use primitive_types::{H160, H256, U256};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use tracing::*;
use crate::types::Account;

pub type Address = H160;
type AccountStorage = HashMap<H256, H256>;

/// The backend collector acts as a cache during the scilla execution. It responds to queries about the state
/// and saves changes to the state. Once the execution is complete, it returns the state changes as an EvmResult
/// which can be applied in the same manner as the EVM flow.
/// The interface it exposes provides read and write of (key, value), where the key is a string and the value is
/// an unlimited length byte array.
/// Due to the way the EVM works, in which the value is always 32 bytes, we pack and unpack the data
/// into a number of hashes in a way which is hidden from scilla.

// Structure that answers queries about the state by using the backend, while also collecting
// the state changes so it can generate an evm result
pub struct BackendCollector<'a, B: evm::backend::Backend> {
    // Reference to the original backend
    pub backend: &'a B,
    // Map of cached (execution in progress) address to account and any dirty storage.
    // If the value is None, this means a deletion of that account and storage
    pub account_storage_cached: HashMap<Address, Option<(Account, AccountStorage)>>,
    pub events: Vec<Value>,
}

impl<'a, B: Backend> BackendCollector<'a, B> {
    pub fn new(backend: &'a B) -> Self {
        Self {
            backend,
            account_storage_cached: HashMap::new(),
            events: vec![],
        }
    }

    // todo: refactor this according to pr comments
    pub fn get_account_storage(&self, address: Address, key: H256) -> H256 {
        // If the account does not exist, check the backend
        if !self.account_storage_cached.contains_key(&address) {
            trace!("Account not in cache, checking backend");
            self.backend.storage(address, key)
        } else {
            let entry = self.account_storage_cached.get(&address).unwrap();

            match entry {
                Some((_, storage)) => storage.get(&key).cloned().unwrap_or(H256::zero()),
                None => {
                    error!("Queried storage in cache is None: {:?}", address);
                    H256::zero()
                }
            }
        }
    }

    // todo: refactor this according to pr comments
    fn update_account_storage(&mut self, address: Address, key: H256, value: H256) {
        // If the account does not exist, check the backend, then create it with empty code and storage
        if let std::collections::hash_map::Entry::Vacant(e) =
            self.account_storage_cached.entry(address)
        {
            let account = Account {
                nonce: self.backend.basic(address).nonce.as_u64(),
                code: self.backend.code(address),
                storage_root: None,
                is_scilla: true,
            };

            e.insert(Some((account, HashMap::from([(key, value)]))));
        } else {
            let entry = self.account_storage_cached.get_mut(&address).unwrap();

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
        trace!(
            "Updating account storage for scilla: KEY: {:?} VALUE: {:?} Lens: {} {}",
            key,
            value,
            key.len(),
            value.len()
        );
        let key_as_hash = H256::from_slice(&Keccak256::digest(key.as_bytes()));

        // To be able to recover the original keys, we will use the following scheme:
        // Hash of "0" will contain number of keys
        // Hash of "1" will contain the last key location
        // Subsequent locations will contain the keys themselves using the same format as the values
        // Note: First check if the key exists, if not, we need to add it to the linked list
        if self.get_account_storage(address, key_as_hash) == H256::zero() {
            let key_start = H256::from_slice(&Keccak256::digest("0".as_bytes()));

            // This should be H256::zero if first time accessed
            let keys_number = self.get_account_storage(address, key_start);
            let keys_number = h256_to_u64(keys_number) + 1;
            self.update_account_storage(address, key_start, u64_to_h256(keys_number));

            let mut key_pointer = increment_h256(key_start); // Next location contains end of list pointer
            let _value_pointer = self.get_account_storage(address, key_pointer);

            // Advance the pointer until it points at the next empty slot
            {
                key_pointer = increment_h256(key_pointer); // first location after end of key pointer

                // Read each already existing key and increment the pointer after
                for _i in 0..(keys_number - 1) {
                    let (_old_val, key) = self.read_compressed(address, key_pointer);
                    key_pointer = increment_h256(key);
                }
            }

            // Update the 'end of list' pointer
            self.update_account_storage(address, increment_h256(key_start), key_pointer);

            // Now we can write the key using the compression scheme
            self.write_compressed(address, key_pointer, key.as_bytes());
        }

        // Write the key normally using the compression scheme
        self.write_compressed(address, key_as_hash, value);
    }

    /// Internal function to write a compressed value to the database, according
    /// to the scheme described in update_account_storage_scilla
    fn write_compressed(&mut self, address: Address, mut key: H256, value: &[u8]) -> H256 {
        let value_fixed_width = u64_to_h256(value.len() as u64);

        // Key, Value for the length of the proceeding value in bytes
        self.update_account_storage(address, key, value_fixed_width);

        for chunk in value.chunks(32) {
            let mut value_fixed_width = [0u8; 32];
            value_fixed_width[..chunk.len()].copy_from_slice(chunk);
            let value = H256::from(value_fixed_width);
            key = increment_h256(key);
            self.update_account_storage(address, key, value);
        }
        key
    }

    /// Internal function to read a compressed value from the database, according
    /// to the scheme described in update_account_storage_scilla
    fn read_compressed(&self, address: Address, mut key: H256) -> (Vec<u8>, H256) {
        let value = self.get_account_storage(address, key);
        let value = h256_to_u64(value);
        let len = value.div_ceil(32);

        // If a single value is over 1MB, this indicates an issue where the value read isn't actually
        // a length
        if len > 1_000_000 {
            panic!("Length of value read from scilla storage is too large, this indicates an issue. Len: {:?}", len);
        }

        let mut result = vec![];

        for _i in 0..len {
            key = increment_h256(key);
            let value = self.get_account_storage(address, key);
            result.extend_from_slice(value.as_bytes());
        }

        // Remove trailing zeros if any (from padding)
        result.truncate(value as usize);

        (result, key)
    }

    fn reconstruct_kv_pairs_inner(&mut self, address: Address) -> Vec<(String, Vec<u8>)> {
        // to do this, we will traverse and collect the keys from the keys linked list
        // and then we can get them normally using the key lookup
        trace!("Reconstructing kv pairs for address: {:?}", address);
        let key_start = H256::from_slice(&Keccak256::digest("0".as_bytes()));

        let keys_number = self.get_account_storage(address, key_start);
        let keys_number = h256_to_u64(keys_number);
        let mut key_pointer = increment_h256(key_start);
        key_pointer = increment_h256(key_pointer); // Jump past first item which is the pointer to last

        let all_keys = match keys_number {
            0 => {
                warn!("NO keys found when requesting scilla contract state");
                vec![]
            }
            _ => {
                let mut ret = vec![];
                for _i in 0..keys_number {
                    let (reconstructed_key, last_point) =
                        self.read_compressed(address, key_pointer);
                    key_pointer = increment_h256(last_point);
                    let reconstructed_key = String::from_utf8(reconstructed_key).unwrap();

                    trace!("Reconstructed key: {:?}", reconstructed_key);
                    ret.push(reconstructed_key);
                }
                ret
            }
        };

        all_keys
            .iter()
            .map(|key| (key.clone(), self.get_account_storage_scilla(address, key)))
            .collect()
    }

    /// Get all of the data the contract sees as key value pairs. Used to satisfy the call
    /// GetSmartContractState
    pub fn reconstruct_kv_pairs(&mut self, address: Address) -> Vec<(String, Vec<u8>)> {
        self.reconstruct_kv_pairs_inner(address)
            .into_iter()
            .filter_map(|(key, value)| self.state_conversion(key, value))
            .collect()
    }

    // Unwrap a proto value
    fn state_conversion(&self, key: String, value: Vec<u8>) -> Option<(String, Vec<u8>)> {
        // We have also stored the init_data in the state, so we need to filter that out
        if key.starts_with("init_data") {
            return None;
        }

        // Custom temporary logic to detemine if this is an actual key
        // for the key string
        let number_of_x16 = key.chars().filter(|x| *x == 0x16 as char).count();

        if number_of_x16 != 2 {
            return None;
        }

        // return everything after the first x16
        let key: String = key.split(0x16 as char).collect();

        // Strip off the address thats prepended
        let key = key.split_at(40).1;

        // Don't return values which start with an underscore
        if key.starts_with('_') {
            return None;
        }

        Some((key.to_string(), value))
    }

    /// Get data from the cache as a key, value. In order to be able to write and read arbitrary
    /// length data to the database (which expects K,V pairs of H256, H256), we:
    /// 1. Hash the key to H256
    /// 2. put the length of the value in bytes at this location
    /// 3. put the data at H256 + 1, H256 + 2, etc.
    pub fn get_account_storage_scilla(&self, address: Address, key: &str) -> Vec<u8> {
        let key = H256::from_slice(&Keccak256::digest(key.as_bytes()));
        self.read_compressed(address, key).0
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

    pub fn get_balance(&self, address: Address) -> U256 {
        self.backend.basic(address).balance
    }

    pub fn get_account(&self, address: Address) -> Account {
        // The account is never cached by the backend collector, so we can just get it from the backend
        Account {
            nonce: self.backend.basic(address).nonce.as_u64(),
            code: self.backend.code(address),
            storage_root: None,
            is_scilla: true, // todo: this is not neccessarily correct, but it might not matter
        }
    }

    pub fn get_code(&self, address: Address) -> Vec<u8> {
        if let Some(Some((acct, _))) = self.account_storage_cached.get(&address) {
            return acct.code.clone();
        }

        self.backend.code(address)
    }

    // Get the deltas from all of the operations so far
    pub fn get_result(&self) -> EvmResult {
        let mut applys: Vec<Apply> = vec![];

        //for (address, item) in self.account_storage_cached.into_iter() {
        for (address, item) in self.account_storage_cached.iter() {
            match item {
                Some((acct, stor)) => {
                    applys.push(Apply::Modify {
                        address: *address,
                        balance: U256::zero(),
                        nonce: U256::zero(),
                        code: acct.code.clone(),
                        storage: stor
                            .iter()
                            .map(|(key, value)| Storage {
                                key: *key,
                                value: *value,
                            })
                            .collect(),
                        reset_storage: false,
                    });
                }
                None => {
                    applys.push(Apply::Delete { address: *address });
                }
            }
        }

        EvmResult {
            apply: applys,
            ..Default::default()
        }
    }

    pub fn add_event(&mut self, event: Value) {
        self.events.push(event);
    }
}

// 'Increment' a H256
fn increment_h256(hash: H256) -> H256 {
    // To easily increment, just re-hash the hash
    H256::from_slice(&Keccak256::digest(&hash[..]))
}

/// Note that when we perform this conversion, we set the unused bytes to 1s which is useful
/// for detecting whether a '0' is a read of a location with nothing written to it so far, or a read
/// of a location with a value of 0
fn u64_to_h256(value: u64) -> H256 {
    let mut hash = [255u8; 32];
    hash[24..32].copy_from_slice(&value.to_be_bytes()); // Big-endian
    hash.into()
}

fn h256_to_u64(hash: H256) -> u64 {
    let bytes = &hash[24..32]; // Extract the last 8 bytes
    u64::from_be_bytes(bytes.try_into().expect("Wrong length for u64 conversion!"))
}
