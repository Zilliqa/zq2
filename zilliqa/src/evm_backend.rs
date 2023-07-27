//! Manages execution of transactions on state.

use std::collections::HashMap;
//use evm_ds::protos::Evm::Apply_Modify;
//use evm_ds::protos::*;
use evm_ds::protos::Evm::EvmResult;
use evm_ds::protos::Evm;
//use bytes::Bytes;

use evm_ds::{
    evm::backend::{Backend, Basic},
    evm_server_run::{encode_storage},
};

//use crate::protos::{Evm as EvmProto};
//use evm_ds::protos::EvmProto;

//use std::{
//    collections::HashSet,
//    sync::{Arc, Mutex},
//};
//
//use anyhow::Result;
//use ethabi::Token;
//use evm_ds::evm::{
//    backend::{Backend, Basic},
//    tracing::EventListener,
//};
//use evm_ds::evm_server_run::EvmCallArgs;
//use evm_ds::protos::Evm::{Continuation, EvmResult};
//use evm_ds::{
//    continuations::Continuations,
//    evm_server_run::{calculate_contract_address, run_evm_impl_direct},
//};
use primitive_types::{H160, H256, U256};
use tracing::{error, info, trace};
//
//use crate::state::SignedTransaction;
use crate::{
    contracts,
    message::BlockHeader,
    state::{Address, Account, Log, State},
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

    pub fn apply_update<'b>(
        &mut self,
        to_addr: Option<Address>,
        applys: impl Iterator<Item = &'b evm_ds::protos::Evm::Apply>,
    )  {
        for apply in applys {

            if apply.has_modify() {
                let modify = apply.get_modify();

                let address = Address(modify.get_address().into());
                let balance: U256 = modify.get_balance().into();
                let code = modify.code.clone();
                let _nonce: U256 = modify.get_nonce().into();
                let storage = modify.storage.clone().into_iter();
                let reset_storage = modify.reset_storage;

                println!("We are modifying: {:?} {:?}", address, balance);

                if !balance.is_zero() {
                    println!("XXXXXXXXXXXXXXXXYYYYYYYYYYYYYY balance was zero(!!!!)");
                }


                //if !code.is_empty() {
                //    account.code = code.to_vec();
                //}

                if reset_storage {
                    todo!("clear_account_storage");
                }

                // Get or create the element in the cache, the account will be
                // reflected but the storage will not.
                if !self.account_storage_cached.contains_key(&address) {
                    let account = self.state.get_account(address).unwrap_or_default();
                    //let mut storage = HashMap::new();
                    //map.insert();
                    self.account_storage_cached.insert(address, (account, HashMap::new()));
                }

                let mut cache = self.account_storage_cached.get_mut(&address).unwrap();
                let mut account_cached = &mut cache.0;
                let mut storage_cached = &mut cache.1;

                if !code.is_empty() {
                    println!("We are actually inserting code here");
                    account_cached.code = code.to_vec();
                }

                //self.save_account(address, account)?;
                //self.account_overrides.insert(address, account);

                for item in storage {
                    let index: H256 = H256::from_slice(item.get_key());
                    let value: H256 = H256::from_slice(item.get_value());

                    //let stor = self.I//storage_cached.get_mut(&address);
                    storage_cached.insert(index, value);
                }
            }
            // todo: delete.
        }

    }

    // Get the deltas from all of the operations so far
    pub fn get_result(&self) -> EvmResult {
        let mut ret = EvmResult::new();

        let applys = ret.mut_apply();

        for (addr, (acct, stor)) in self.account_storage_cached.into_iter() {

            println!("Looping: {:?} {:?} {:?}", addr, acct, stor);
            //apply.set_modify()
            let mut apply = evm_ds::protos::Evm::Apply::new();
            let mut modify = Evm::Apply_Modify::new();
            modify.set_address(addr.0.into());
            //modify.set_balance(acct.balance.into());
            modify.set_code(acct.code.into());

            //if (stor.empty()) {
            //    modify.set_reset_storage(reset_storage);
            //}


            let storage_proto = stor
                .into_iter()
                //.map(|(k, v)| (Bytes::copy_from_slice(k.as_bytes()), Bytes::copy_from_slice(v.as_bytes())))
                .map(|(k, v)| encode_storage(k, v, true).into())
                .collect();
            modify.set_storage(storage_proto);
            apply.set_modify(modify);

            applys.push(apply);
        }
        println!("We are returning update: {:?}", ret);
        ret
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

    //fn block_randomness(&self) -> Option<H256> { // Put note for PR
    //    None
    //}

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
