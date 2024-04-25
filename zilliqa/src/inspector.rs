use std::collections::HashSet;

use primitive_types::H160;
use revm::{
    inspectors::NoOpInspector,
    interpreter::{CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome},
    primitives::CreateScheme,
    Database, EvmContext, Inspector,
};

use crate::api::types::ots::{Operation, OperationType, TraceEntry, TraceEntryType};

/// Provides callbacks from the Scilla interpreter.
pub trait ScillaInspector {
    fn create(&mut self, creator: H160, contract_address: H160, amount: u128) {
        let _ = contract_address;
        let _ = creator;
        let _ = amount;
    }
    fn transfer(&mut self, from: H160, to: H160, amount: u128) {
        let _ = amount;
        let _ = to;
        let _ = from;
    }
    fn call(&mut self, from: H160, to: H160, amount: u128) {
        let _ = to;
        let _ = from;
        let _ = amount;
    }
}

impl<T: ScillaInspector> ScillaInspector for &mut T {
    fn create(&mut self, creator: H160, contract_address: H160, amount: u128) {
        (*self).create(creator, contract_address, amount);
    }

    fn transfer(&mut self, from: H160, to: H160, amount: u128) {
        (*self).transfer(from, to, amount)
    }

    fn call(&mut self, from: H160, to: H160, amount: u128) {
        (*self).call(from, to, amount)
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
    fn create(&mut self, creator: H160, contract_address: H160, _: u128) {
        self.touched.insert(creator);
        self.touched.insert(contract_address);
    }

    fn transfer(&mut self, from: H160, to: H160, _: u128) {
        self.touched.insert(from);
        self.touched.insert(to);
    }

    fn call(&mut self, from: H160, to: H160, _: u128) {
        self.touched.insert(from);
        self.touched.insert(to);
    }
}

#[derive(Debug)]
pub struct CreatorInspector {
    contract: H160,
    creator: Option<H160>,
}

impl CreatorInspector {
    pub fn new(contract: H160) -> Self {
        CreatorInspector {
            contract,
            creator: None,
        }
    }

    pub fn creator(&self) -> Option<H160> {
        self.creator
    }
}

impl<DB: Database> Inspector<DB> for CreatorInspector {
    fn create_end(
        &mut self,
        _: &mut EvmContext<DB>,
        inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        if let Some(address) = outcome.address {
            if H160(address.into_array()) == self.contract {
                self.creator = Some(H160(inputs.caller.into_array()));
            }
        }
        outcome
    }
}

impl ScillaInspector for CreatorInspector {
    fn create(&mut self, creator: H160, contract_address: H160, _: u128) {
        if contract_address == self.contract {
            self.creator = Some(creator);
        }
    }
}

#[derive(Debug, Default)]
pub struct OtterscanTraceInspector {
    entries: Vec<TraceEntry>,
}

impl OtterscanTraceInspector {
    pub fn entries(self) -> Vec<TraceEntry> {
        self.entries
    }
}

impl<DB: Database> Inspector<DB> for OtterscanTraceInspector {
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        let (ty, value) = match inputs.context.scheme {
            CallScheme::Call => (TraceEntryType::Call, Some(inputs.transfer.value.to())),
            CallScheme::CallCode => (TraceEntryType::CallCode, None),
            CallScheme::DelegateCall => (TraceEntryType::DelegateCall, None),
            CallScheme::StaticCall => {
                (TraceEntryType::StaticCall, Some(inputs.transfer.value.to()))
            }
        };
        self.entries.push(TraceEntry {
            ty,
            depth: context.journaled_state.depth(),
            from: H160(inputs.context.caller.into_array()),
            to: H160(inputs.contract.into_array()),
            value,
            input: inputs.input.to_vec(),
        });

        None
    }

    fn create(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        let ty = match inputs.scheme {
            CreateScheme::Create => TraceEntryType::Create,
            CreateScheme::Create2 { .. } => TraceEntryType::Create2,
        };
        let nonce = context.journaled_state.account(inputs.caller).info.nonce;
        self.entries.push(TraceEntry {
            ty,
            depth: context.journaled_state.depth(),
            from: H160(inputs.caller.into_array()),
            to: H160(inputs.created_address(nonce).into_array()),
            value: Some(inputs.value.to()),
            input: inputs.init_code.to_vec(),
        });

        None
    }

    fn selfdestruct(
        &mut self,
        contract: revm::primitives::Address,
        target: revm::primitives::Address,
        value: ruint::aliases::U256,
    ) {
        let depth = self.entries.last().map(|t| t.depth).unwrap_or_default();
        self.entries.push(TraceEntry {
            ty: TraceEntryType::SelfDestruct,
            depth,
            from: H160(contract.into_array()),
            to: H160(target.into_array()),
            value: Some(value.to()),
            input: vec![],
        });
    }
}

impl ScillaInspector for OtterscanTraceInspector {
    fn call(&mut self, from: H160, to: H160, amount: u128) {
        self.entries.push(TraceEntry {
            ty: TraceEntryType::Call,
            depth: 0, // TODO: Track Scilla depth
            from,
            to,
            value: Some(amount),
            input: vec![],
        })
    }

    fn create(&mut self, creator: H160, contract_address: H160, amount: u128) {
        self.entries.push(TraceEntry {
            ty: TraceEntryType::Create,
            depth: 0,
            from: creator,
            to: contract_address,
            value: Some(amount),
            input: vec![],
        })
    }

    fn transfer(&mut self, from: H160, to: H160, amount: u128) {
        self.entries.push(TraceEntry {
            ty: TraceEntryType::Call,
            depth: 0,
            from,
            to,
            value: Some(amount),
            input: vec![],
        })
    }
}

/// Traces internal transfers within a transaction for Otterscan. Transfers at the top-level are deliberately filtered
/// out.
#[derive(Debug, Default)]
pub struct OtterscanOperationInspector {
    entries: Vec<Operation>,
}

impl OtterscanOperationInspector {
    pub fn entries(self) -> Vec<Operation> {
        self.entries
    }
}

impl<DB: Database> Inspector<DB> for OtterscanOperationInspector {
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        if context.journaled_state.depth() != 0 && !inputs.transfer.value.is_zero() {
            self.entries.push(Operation {
                ty: OperationType::Transfer,
                from: H160(inputs.context.caller.into_array()),
                to: H160(inputs.contract.into_array()),
                value: inputs.transfer.value.to(),
            });
        }

        None
    }

    fn create(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        if context.journaled_state.depth() != 0 {
            let ty = match inputs.scheme {
                CreateScheme::Create => OperationType::Create,
                CreateScheme::Create2 { .. } => OperationType::Create2,
            };
            let nonce = context.journaled_state.account(inputs.caller).info.nonce;
            self.entries.push(Operation {
                ty,
                from: H160(inputs.caller.into_array()),
                to: H160(inputs.created_address(nonce).into_array()),
                value: inputs.value.to(),
            });
        }

        None
    }

    fn selfdestruct(
        &mut self,
        contract: revm::primitives::Address,
        target: revm::primitives::Address,
        value: ruint::aliases::U256,
    ) {
        self.entries.push(Operation {
            ty: OperationType::SelfDestruct,
            from: H160(contract.into_array()),
            to: H160(target.into_array()),
            value: value.to(),
        });
    }
}

// TODO: Filter depth=0 Scilla calls once we can track the depth.
impl ScillaInspector for OtterscanOperationInspector {
    fn call(&mut self, from: H160, to: H160, amount: u128) {
        if amount != 0 {
            self.entries.push(Operation {
                ty: OperationType::Transfer,
                from,
                to,
                value: amount,
            });
        }
    }

    fn create(&mut self, creator: H160, contract_address: H160, amount: u128) {
        self.entries.push(Operation {
            ty: OperationType::Create,
            from: creator,
            to: contract_address,
            value: amount,
        });
    }

    fn transfer(&mut self, from: H160, to: H160, amount: u128) {
        if amount != 0 {
            self.entries.push(Operation {
                ty: OperationType::Transfer,
                from,
                to,
                value: amount,
            });
        }
    }
}
