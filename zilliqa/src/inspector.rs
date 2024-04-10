use std::collections::HashSet;

use primitive_types::H160;
use revm::{
    inspectors::NoOpInspector,
    interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome},
    Database, EvmContext, Inspector,
};

/// Provides callbacks from the Scilla interpreter.
pub trait ScillaInspector {
    fn create(&mut self, creator: H160, contract_address: H160) {
        let _ = contract_address;
        let _ = creator;
    }
    fn transfer(&mut self, from: H160, to: H160, amount: u128) {
        let _ = amount;
        let _ = to;
        let _ = from;
    }
    fn call(&mut self, from: H160, to: H160) {
        let _ = to;
        let _ = from;
    }
}

impl<T: ScillaInspector> ScillaInspector for &mut T {
    fn create(&mut self, creator: H160, contract_address: H160) {
        (*self).create(creator, contract_address);
    }

    fn transfer(&mut self, from: H160, to: H160, amount: u128) {
        (*self).transfer(from, to, amount)
    }

    fn call(&mut self, from: H160, to: H160) {
        (*self).call(from, to)
    }
}

pub fn noop() -> NoOpInspector {
    NoOpInspector
}

impl ScillaInspector for NoOpInspector {}

#[derive(Debug, Default)]
pub struct TouchedAddressInspector {
    pub touched: HashSet<H160>,
}

impl<DB: Database> Inspector<DB> for TouchedAddressInspector {
    fn call(&mut self, _: &mut EvmContext<DB>, inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.touched
            .insert(H160(inputs.context.caller.into_array()));
        self.touched.insert(H160(inputs.contract.into_array()));
        None
    }

    fn create_end(
        &mut self,
        _: &mut EvmContext<DB>,
        inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        self.touched.insert(H160(inputs.caller.into_array()));
        if let Some(address) = outcome.address {
            self.touched.insert(H160(address.into_array()));
        }
        outcome
    }

    fn selfdestruct(
        &mut self,
        contract: revm::primitives::Address,
        target: revm::primitives::Address,
        _: ruint::aliases::U256,
    ) {
        self.touched.insert(H160(contract.into_array()));
        self.touched.insert(H160(target.into_array()));
    }
}

impl ScillaInspector for TouchedAddressInspector {
    fn create(&mut self, creator: H160, contract_address: H160) {
        self.touched.insert(creator);
        self.touched.insert(contract_address);
    }

    fn transfer(&mut self, from: H160, to: H160, _: u128) {
        self.touched.insert(from);
        self.touched.insert(to);
    }

    fn call(&mut self, from: H160, to: H160) {
        self.touched.insert(from);
        self.touched.insert(to);
    }
}
