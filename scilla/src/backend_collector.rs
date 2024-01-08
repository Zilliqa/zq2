use primitive_types::{H160, H256, U256};
use std::collections::HashMap;
use evm::backend::{Backend};
use tracing::field::debug;
use evm_ds::protos::evm_proto::{EvmResult, Storage, Apply};
use tracing::*;
use sha3::{Digest, Keccak256};

pub type Address = H160;

#[derive(Debug)]
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

    pub fn update_account_storage(&mut self, address: Address, key: &str, value: &[u8]) {
        // Get or create a cached account with these details.

        debug!("Updating account storage: {:?}, {:?}, {:?},", address, key, value);

        // Hash key to H256
        let key = H256::from_slice(&Keccak256::digest(key.as_bytes()).to_vec());

        // Put the value in as H256 for now...
        let mut value_fixed_width = [0u8; 32];
        // copy the value into the fixed width array
        value_fixed_width[..value.len()].copy_from_slice(value);
        let value = H256::from(value_fixed_width);

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
