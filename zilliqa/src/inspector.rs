use std::collections::HashSet;

use alloy::primitives::{Address, U256};
use revm::{
    Inspector,
    context_interface::{ContextTr, CreateScheme, JournalTr},
    interpreter::{CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome},
};
use revm_inspector::NoOpInspector;
use revm_inspectors::tracing::{
    FourByteInspector, MuxInspector, TracingInspector, js::JsInspector,
};

use crate::api::types::ots::{Operation, OperationType, TraceEntry, TraceEntryType};

/// Provides callbacks from the Scilla interpreter.
pub trait ScillaInspector {
    fn create(&mut self, creator: Address, contract_address: Address, amount: u128) {
        let _ = contract_address;
        let _ = creator;
        let _ = amount;
    }
    fn transfer(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        let _ = amount;
        let _ = to;
        let _ = from;
        let _ = depth;
    }
    fn call(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        let _ = to;
        let _ = from;
        let _ = amount;
        let _ = depth;
    }
}

impl<T: ScillaInspector> ScillaInspector for &mut T {
    fn create(&mut self, creator: Address, contract_address: Address, amount: u128) {
        (*self).create(creator, contract_address, amount);
    }

    fn transfer(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        (*self).transfer(from, to, amount, depth)
    }

    fn call(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        (*self).call(from, to, amount, depth)
    }
}

pub fn noop() -> NoOpInspector {
    NoOpInspector
}

impl ScillaInspector for NoOpInspector {}

impl ScillaInspector for FourByteInspector {}

impl ScillaInspector for MuxInspector {}

impl ScillaInspector for JsInspector {}

#[derive(Debug, Default)]
pub struct TouchedAddressInspector {
    pub touched: HashSet<Address>,
}

impl<CTX: ContextTr> Inspector<CTX> for TouchedAddressInspector {
    fn call(&mut self, _: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.touched.insert(inputs.caller);
        self.touched.insert(inputs.bytecode_address);
        self.touched.insert(inputs.target_address);
        None
    }

    fn create_end(&mut self, _: &mut CTX, inputs: &CreateInputs, outcome: &mut CreateOutcome) {
        self.touched.insert(inputs.caller);
        if let Some(address) = outcome.address {
            self.touched.insert(address);
        }
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, _: U256) {
        self.touched.insert(contract);
        self.touched.insert(target);
    }
}

impl ScillaInspector for TouchedAddressInspector {
    fn create(&mut self, creator: Address, contract_address: Address, _: u128) {
        self.touched.insert(creator);
        self.touched.insert(contract_address);
    }

    fn transfer(&mut self, from: Address, to: Address, _: u128, _: u64) {
        self.touched.insert(from);
        self.touched.insert(to);
    }

    fn call(&mut self, from: Address, to: Address, _: u128, _: u64) {
        self.touched.insert(from);
        self.touched.insert(to);
    }
}

#[derive(Debug)]
pub struct CreatorInspector {
    contract: Address,
    creator: Option<Address>,
}

impl CreatorInspector {
    pub fn new(contract: Address) -> Self {
        CreatorInspector {
            contract,
            creator: None,
        }
    }

    pub fn creator(&self) -> Option<Address> {
        self.creator
    }
}

impl<CTX> Inspector<CTX> for CreatorInspector {
    fn create_end(&mut self, _: &mut CTX, inputs: &CreateInputs, outcome: &mut CreateOutcome) {
        if let Some(address) = outcome.address
            && address == self.contract
        {
            self.creator = Some(inputs.caller);
        }
    }
}

impl ScillaInspector for CreatorInspector {
    fn create(&mut self, creator: Address, contract_address: Address, _: u128) {
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

impl<CTX: ContextTr> Inspector<CTX> for OtterscanTraceInspector {
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let ty = match inputs.scheme {
            CallScheme::Call => TraceEntryType::Call,
            CallScheme::CallCode => TraceEntryType::CallCode,
            CallScheme::DelegateCall => TraceEntryType::DelegateCall,
            CallScheme::StaticCall => TraceEntryType::StaticCall,
        };
        self.entries.push(TraceEntry {
            ty,
            depth: context.journal().depth().try_into().unwrap_or_default(),
            from: inputs.caller,
            to: inputs.target_address,
            value: inputs.transfer_value().map(|v| v.to()),
            input: inputs.input.bytes(context).to_vec(),
        });

        None
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        let ty = match inputs.scheme {
            CreateScheme::Create => TraceEntryType::Create,
            CreateScheme::Create2 { .. } => TraceEntryType::Create2,
            _ => TraceEntryType::Create,
        };
        let nonce = context
            .journal_mut()
            .load_account(inputs.caller)
            .unwrap()
            .info
            .nonce;
        self.entries.push(TraceEntry {
            ty,
            depth: context.journal().depth().try_into().unwrap_or_default(),
            from: inputs.caller,
            to: inputs.created_address(nonce),
            value: Some(inputs.value.to()),
            input: inputs.init_code.to_vec(),
        });

        None
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        let depth = self.entries.last().map(|t| t.depth).unwrap_or_default();
        self.entries.push(TraceEntry {
            ty: TraceEntryType::SelfDestruct,
            depth,
            from: contract,
            to: target,
            value: Some(value.to()),
            input: vec![],
        });
    }
}

impl ScillaInspector for OtterscanTraceInspector {
    fn create(&mut self, creator: Address, contract_address: Address, amount: u128) {
        self.entries.push(TraceEntry {
            ty: TraceEntryType::Create,
            depth: 0,
            from: creator,
            to: contract_address,
            value: Some(amount),
            input: vec![],
        })
    }

    fn transfer(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        self.entries.push(TraceEntry {
            ty: TraceEntryType::Call,
            depth,
            from,
            to,
            value: Some(amount),
            input: vec![],
        })
    }

    fn call(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        self.entries.push(TraceEntry {
            ty: TraceEntryType::Call,
            depth,
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

impl<CTX: ContextTr> Inspector<CTX> for OtterscanOperationInspector {
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if context.journal().depth() != 0 && inputs.transfers_value() {
            self.entries.push(Operation {
                ty: OperationType::Transfer,
                from: inputs.caller,
                to: inputs.target_address,
                value: inputs.call_value().to(),
            });
        }

        None
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        if context.journal().depth() != 0 {
            let ty = match inputs.scheme {
                CreateScheme::Create => OperationType::Create,
                CreateScheme::Create2 { .. } => OperationType::Create2,
                _ => OperationType::Create,
            };
            let nonce = context
                .journal_mut()
                .load_account(inputs.caller)
                .unwrap()
                .info
                .nonce;
            self.entries.push(Operation {
                ty,
                from: inputs.caller,
                to: inputs.created_address(nonce),
                value: inputs.value.to(),
            });
        }

        None
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        self.entries.push(Operation {
            ty: OperationType::SelfDestruct,
            from: contract,
            to: target,
            value: value.to(),
        });
    }
}

impl ScillaInspector for OtterscanOperationInspector {
    fn transfer(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        if depth != 0 && amount != 0 {
            self.entries.push(Operation {
                ty: OperationType::Transfer,
                from,
                to,
                value: amount,
            });
        }
    }

    fn call(&mut self, from: Address, to: Address, amount: u128, depth: u64) {
        if depth != 0 && amount != 0 {
            self.entries.push(Operation {
                ty: OperationType::Transfer,
                from,
                to,
                value: amount,
            });
        }
    }

    // Creates are always ignored because they are always at depth=0 for Scilla transactions.
}

impl ScillaInspector for TracingInspector {}
