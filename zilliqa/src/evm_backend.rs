//! The evm backend is what the evm sees when it is executing. It is a wrapper around the state
//! and in this implementation, we also cache changes to the state so that we can return them
//! all as one set of changes at the end of the transaction execution.
//! apply_update will be called for each continuation, and at the end we generate the EvmResult via
//! get_result

use evm_ds::protos::evm::{Apply, EvmResult, Storage};
use std::collections::HashMap;

use evm_ds::evm::backend::{Backend, Basic};

use primitive_types::{H160, H256, U256};
use tracing::{error, trace};

use crate::{
    message::BlockHeader,
    state::{Account, Address, State},
    time::SystemTime,
};

pub struct EvmBackend<'a> {
    pub state: &'a State,
    pub gas_price: U256,
    pub origin: H160,
    pub chain_id: u64,
    pub current_block: BlockHeader,
    pub account_storage_cached: HashMap<Address, (Account, HashMap<H256, H256>)>,
}

impl<'a> EvmBackend<'a> {
    pub fn new(
        state: &'a State,
        gas_price: U256,
        origin: H160,
        chain_id: u64,
        current_block: BlockHeader,
    ) -> Self {
        Self {
            state,
            gas_price,
            origin,
            chain_id,
            current_block,
            account_storage_cached: HashMap::new(),
        }
    }

    pub fn apply_update(
        &mut self,
        _to_addr: Option<Address>,
        applys: Vec<evm_ds::protos::evm::Apply>,
    ) {
        for apply in applys {
            match apply {
                Apply::Delete { address: _ } => {
                    panic!("Delete not implemented");
                }
                Apply::Modify {
                    address,
                    balance: _,
                    nonce: _,
                    code,
                    storage,
                    reset_storage,
                } => {
                    let address = Address(address);

                    if reset_storage {
                        todo!("clear_account_storage");
                    }

                    // Get or create the element in the cache, the account will be
                    // reflected but the storage will not.
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        self.account_storage_cached.entry(address)
                    {
                        let account = self.state.get_account(address).unwrap_or_default();
                        e.insert((account, HashMap::new()));
                    }

                    let cache = self.account_storage_cached.get_mut(&address).unwrap();
                    let account_cached = &mut cache.0;
                    let storage_cached = &mut cache.1;

                    if !code.is_empty() {
                        account_cached.code = code.to_vec();
                    }

                    for item in storage {
                        storage_cached.insert(item.key, item.value);
                    }
                }
            }
            // todo: delete.
        }
    }

    // Get the deltas from all of the operations so far
    pub fn get_result(self) -> EvmResult {
        let mut applys: Vec<Apply> = vec![];

        for (addr, (acct, stor)) in self.account_storage_cached.into_iter() {
            applys.push(Apply::Modify {
                address: addr.0,
                balance: U256::zero(),
                nonce: U256::zero(),
                code: acct.code,
                storage: stor
                    .into_iter()
                    .map(|(key, value)| Storage { key, value })
                    .collect(),
                reset_storage: false, // todo: this.
            });
        }

        EvmResult {
            apply: applys,
            ..Default::default()
        }
    }
}

impl<'a> Backend for EvmBackend<'a> {
    fn gas_price(&self) -> U256 {
        self.gas_price
    }

    fn origin(&self) -> H160 {
        trace!("EVM request: origin: {:?}", self.origin);
        self.origin
    }

    fn block_hash(&self, _: U256) -> H256 {
        // TODO: Get the hash of one of the 256 most recent blocks.
        H256::zero()
    }

    fn block_number(&self) -> U256 {
        self.current_block.view.into()
    }

    fn block_coinbase(&self) -> H160 {
        // TODO: Return something here, probably the proposer of the current block.
        H160::zero()
    }

    fn block_timestamp(&self) -> U256 {
        self.current_block
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default()
            .into()
    }

    fn block_difficulty(&self) -> U256 {
        0.into()
    }

    fn block_gas_limit(&self) -> U256 {
        0.into()
    }

    fn block_base_fee_per_gas(&self) -> U256 {
        0.into()
    }

    fn chain_id(&self) -> U256 {
        self.chain_id.into()
    }

    fn exists(&self, address: H160) -> bool {
        trace!("EVM request: Checking whether account {:?} exists", address);
        // Ethereum charges extra gas for `CALL`s or `SELFDESTRUCT`s which create new accounts, to discourage the
        // creation of many addresses and the resulting increase in state size.
        self.state.has_account(Address(address))
    }

    fn basic(&self, address: H160) -> Basic {
        trace!("EVM request: Requesting basic info for {:?}", address);
        let nonce = self.state.must_get_account(Address(address)).nonce;
        // For these accounts, we hardcode the balance we return to the EVM engine as zero. Otherwise, we have an
        // infinite recursion because getting the native balance of any account requires this method to be called for
        // these two 'special' accounts.
        let is_special_account = address == Address::ZERO.0 || address == Address::NATIVE_TOKEN.0;
        Basic {
            balance: if is_special_account {
                0.into()
            } else {
                self.state.get_native_balance(Address(address)).unwrap()
            },
            nonce: nonce.into(),
        }
    }

    fn code(&self, address: H160) -> Vec<u8> {
        trace!("EVM request: Requesting code for {:?}", address);
        // Will this mean panic if you try to call address that doesn't exist?
        self.state.must_get_account(Address(address)).code
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        let res = self.state.must_get_account_storage(Address(address), index);

        trace!(
            "EVM request: Requesting storage for {:?} at {:?} and is: {:?}",
            address,
            index,
            res
        );
        res
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        trace!(
            "EVM request: Requesting original storage for {:?} at {:?}",
            address,
            index
        );
        Some(self.storage(address, index))
    }

    // todo: this.
    fn code_as_json(&self, _address: H160) -> Vec<u8> {
        error!("code_as_json not implemented");
        vec![]
    }

    fn init_data_as_json(&self, _address: H160) -> Vec<u8> {
        error!("init_data_as_json not implemented");
        vec![]
    }

    // todo: this.
    fn substate_as_json(&self, _address: H160, _vname: &str, _indices: &[String]) -> Vec<u8> {
        error!("substate_as_json not implemented");
        vec![]
    }
}
