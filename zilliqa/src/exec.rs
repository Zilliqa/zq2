//! Manages execution of transactions on state.

use evm::backend::{Apply, Backend, Basic};
use primitive_types::{H160, H256, U256};

use crate::state::{Address, State};

pub struct CallContext<'a> {
    state: &'a State,
    gas_price: U256,
    origin: H160,
}

impl State {
    pub fn call_context(&self, gas_price: U256, origin: H160) -> CallContext<'_> {
        CallContext {
            state: self,
            gas_price,
            origin,
        }
    }

    pub fn apply(&mut self, applys: Vec<Apply<Vec<(H256, H256)>>>) {
        for apply in applys {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage,
                } => {
                    let account = self.get_account_mut(Address(address));

                    if let Some(code) = code {
                        account.code = code;
                    }

                    account.nonce = basic.nonce.as_u64();
                    // TODO: Handle changes in `basic.balance`.

                    if reset_storage {
                        account.storage.clear();
                    }

                    for (index, value) in storage {
                        if value.is_zero() {
                            account.storage.remove(&index);
                        } else {
                            account.storage.insert(index, value);
                        }
                    }
                }
                Apply::Delete { address } => {
                    let account = self.get_account_mut(Address(address));
                    *account = Default::default();
                }
            }
        }
    }
}

impl<'a> Backend for CallContext<'a> {
    fn gas_price(&self) -> U256 {
        self.gas_price
    }

    fn origin(&self) -> H160 {
        self.origin
    }

    fn block_hash(&self, _: U256) -> H256 {
        todo!()
    }

    fn block_number(&self) -> U256 {
        todo!()
    }

    fn block_coinbase(&self) -> H160 {
        todo!()
    }

    fn block_timestamp(&self) -> U256 {
        todo!()
    }

    fn block_difficulty(&self) -> U256 {
        todo!()
    }

    fn block_gas_limit(&self) -> U256 {
        todo!()
    }

    fn block_base_fee_per_gas(&self) -> U256 {
        todo!()
    }

    fn chain_id(&self) -> U256 {
        todo!()
    }

    fn exists(&self, _: H160) -> bool {
        todo!()
    }

    fn basic(&self, address: H160) -> Basic {
        let nonce = self.state.get_account(Address(address)).nonce;
        Basic {
            balance: U256::exp10(10),
            nonce: nonce.into(),
        }
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.state.get_account(Address(address)).code.to_owned()
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.state
            .get_account(Address(address))
            .storage
            .get(&index)
            .copied()
            .unwrap_or_default()
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }
}
