use std::collections::HashSet;

use alloy::primitives::{Address, Log, U256};
use revm::{
    inspectors::NoOpInspector,
    interpreter::{
        CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, EOFCreateInputs,
        Interpreter,
    },
    primitives::CreateScheme,
    Database, EvmContext, Inspector,
};
use revm_inspectors::tracing::{
    js::JsInspector, FourByteInspector, MuxInspector, TracingInspector,
};

use crate::{
    api::types::ots::{Operation, OperationType, TraceEntry, TraceEntryType},
    exec::PendingState,
};

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

impl<DB: Database> Inspector<DB> for TouchedAddressInspector {
    fn call(&mut self, _: &mut EvmContext<DB>, inputs: &mut CallInputs) -> Option<CallOutcome> {
        self.touched.insert(inputs.caller);
        self.touched.insert(inputs.bytecode_address);
        self.touched.insert(inputs.target_address);
        None
    }

    fn create_end(
        &mut self,
        _: &mut EvmContext<DB>,
        inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        self.touched.insert(inputs.caller);
        if let Some(address) = outcome.address {
            self.touched.insert(address);
        }
        outcome
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

impl<DB: Database> Inspector<DB> for CreatorInspector {
    fn create_end(
        &mut self,
        _: &mut EvmContext<DB>,
        inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        if let Some(address) = outcome.address {
            if address == self.contract {
                self.creator = Some(inputs.caller);
            }
        }
        outcome
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

impl<DB: Database> Inspector<DB> for OtterscanTraceInspector {
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        let ty = match inputs.scheme {
            CallScheme::Call => TraceEntryType::Call,
            CallScheme::CallCode => TraceEntryType::CallCode,
            CallScheme::DelegateCall => TraceEntryType::DelegateCall,
            CallScheme::StaticCall => TraceEntryType::StaticCall,
            CallScheme::ExtCall => TraceEntryType::ExtCall,
            CallScheme::ExtStaticCall => TraceEntryType::ExtStaticCall,
            CallScheme::ExtDelegateCall => TraceEntryType::ExtDelegateCall,
        };
        self.entries.push(TraceEntry {
            ty,
            depth: context.journaled_state.depth(),
            from: inputs.caller,
            to: inputs.target_address,
            value: inputs.transfer_value().map(|v| v.to()),
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

impl<DB: Database> Inspector<DB> for OtterscanOperationInspector {
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        if context.journaled_state.depth() != 0 && inputs.transfers_value() {
            self.entries.push(Operation {
                ty: OperationType::Transfer,
                from: inputs.caller,
                to: inputs.target_address,
                value: inputs.call_value().to(),
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

impl<I: Inspector<PendingState> + ScillaInspector> ScillaInspector for ZQ2Inspector<'_, I> {}

pub struct ZQ2Inspector<'a, I: Inspector<PendingState> + ScillaInspector> {
    inner: &'a mut I,
}

impl<'a, I: Inspector<PendingState> + ScillaInspector> ZQ2Inspector<'a, I> {
    pub fn new(inner: &'a mut I) -> Self {
        Self { inner }
    }
}

impl<I: Inspector<PendingState> + ScillaInspector> Inspector<PendingState> for ZQ2Inspector<'_, I> {
    fn initialize_interp(
        &mut self,
        interp: &mut Interpreter,
        context: &mut EvmContext<PendingState>,
    ) {
        // if interp.contract.caller != Address::ZERO {
        //     println!("INIT GAS LEFT with interp: {}, address: {:p}", interp.gas.remaining(), &context.db);
        // }
        context.db.gas_left = interp.gas;
        self.inner.initialize_interp(interp, context);
    }
    fn step(&mut self, interp: &mut Interpreter, context: &mut EvmContext<PendingState>) {
        if interp.contract.caller != Address::ZERO {
            println!("STEP GAS LEFT with interp: {}", interp.gas.remaining());
        }
        context.db.gas_left = interp.gas;
        self.inner.step(interp, context);
    }

    fn step_end(&mut self, interp: &mut Interpreter, context: &mut EvmContext<PendingState>) {
        self.inner.step_end(interp, context);
    }

    fn log(&mut self, interp: &mut Interpreter, context: &mut EvmContext<PendingState>, log: &Log) {
        self.inner.log(interp, context, log);
    }
    fn call(
        &mut self,
        context: &mut EvmContext<PendingState>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        Inspector::call(&mut self.inner, context, inputs)
    }
    fn call_end(
        &mut self,
        context: &mut EvmContext<PendingState>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        self.inner.call_end(context, inputs, outcome)
    }

    fn create(
        &mut self,
        context: &mut EvmContext<PendingState>,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        Inspector::create(&mut self.inner, context, inputs)
    }

    fn create_end(
        &mut self,
        context: &mut EvmContext<PendingState>,
        inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        self.inner.create_end(context, inputs, outcome)
    }

    fn eofcreate(
        &mut self,
        context: &mut EvmContext<PendingState>,
        inputs: &mut EOFCreateInputs,
    ) -> Option<CreateOutcome> {
        self.inner.eofcreate(context, inputs)
    }

    fn eofcreate_end(
        &mut self,
        context: &mut EvmContext<PendingState>,
        inputs: &EOFCreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        self.inner.eofcreate_end(context, inputs, outcome)
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, value: U256) {
        self.inner.selfdestruct(contract, target, value);
    }
}
