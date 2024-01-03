use primitive_types::{H160, H256, U256};
use std::collections::HashMap;
use evm::backend::{Backend};
use evm_ds::protos::evm_proto::{EvmResult, Storage, Apply};

pub type Address = H160;

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
