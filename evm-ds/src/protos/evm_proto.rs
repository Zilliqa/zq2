use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Range,
    sync::{Arc, Mutex},
};

use derivative::Derivative;
use evm::{
    executor::stack::{MemoryStackAccount, MemoryStackSubstate},
    ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed, Memory, Stack, Transfer, Valids,
};
use primitive_types::{H160, H256, U256};

pub use crate::evm::executor::stack::Log;
use crate::{evm::CreateScheme, tracing_logging::LoggingEventListener};

// This file contains all of the structs used to communicate between evm-ds and the outside world

// Convenience function to print long vectors, truncating if they are massive
fn shortened_vec(val: &Vec<u8>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", vec_to_string_concat(val))
}

fn vec_to_string_concat<T: fmt::Debug + fmt::Display>(input: &Vec<T>) -> String {
    if input.len() > 64 {
        let start = &input[0..5];
        let end = &input[input.len() - 5..];
        let start_str = start
            .iter()
            .map(|x| format!("{:}", x))
            .collect::<Vec<_>>()
            .join(", ");
        let end_str = end
            .iter()
            .map(|x| format!("{:}", x))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{}, ..., {}]", start_str, end_str)
    } else {
        format!("{:?}", input)
    }
}

// The struct used to drive the evm-ds execution. An external caller will maintain the continuations
// and set the node_continuation (populating return values) if this is a continuation call
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct EvmCallArgs {
    pub address: H160,
    #[derivative(Debug(format_with = "shortened_vec"))]
    pub code: Vec<u8>,
    #[derivative(Debug(format_with = "shortened_vec"))]
    pub data: Vec<u8>,
    pub apparent_value: U256,
    pub gas_limit: u64,
    pub caller: H160,
    pub gas_scaling_factor: u64,
    pub scaling_factor: Option<u64>,
    pub estimate: bool,
    pub is_static: bool,
    pub evm_context: String,
    pub node_continuation: Option<ContinuationFb>, // Set if this is a continuation, contains the return info from the previous continuation
    pub continuations: Arc<Mutex<Continuations>>,  // All continuations
    pub enable_cps: bool,
    pub tx_trace_enabled: bool,
    pub tx_trace: Arc<Mutex<LoggingEventListener>>,
}

#[derive(Debug)]
pub struct Storage {
    pub key: H256,
    pub value: H256,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub enum Apply {
    Delete {
        address: H160,
    },
    Modify {
        address: H160,
        balance: U256,
        nonce: U256,
        #[derivative(Debug(format_with = "shortened_vec"))]
        code: Vec<u8>,
        storage: Vec<Storage>,
        reset_storage: bool,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Call,
    Create,
}

#[derive(Debug, Clone)]
pub struct Call {
    pub data: Vec<u8>,
    pub memory_offset: U256,
    pub offset_len: U256,
}

// Continuation feedback
#[derive(Debug, Clone)]
pub struct ContinuationFb {
    pub id: u64,
    pub feedback_type: Type,
    pub feedback_data: Option<FeedbackData>,
    pub logs: Vec<Log>,
    pub succeeded: bool,
}

impl ContinuationFb {
    pub fn new(id: u64) -> Self {
        ContinuationFb {
            id,
            feedback_type: Type::Call,
            feedback_data: None,
            logs: Vec::new(),
            succeeded: false,
        }
    }

    pub fn get_address(&self) -> H160 {
        match &self.feedback_data {
            Some(FeedbackData::Address(address)) => *address,
            _ => panic!("ContinuationFb does not contain an address"),
        }
    }

    pub fn get_calldata(&self) -> &Call {
        match &self.feedback_data {
            Some(FeedbackData::CallData(call)) => call,
            _ => panic!("ContinuationFb does not contain call data"),
        }
    }
}

// When a continuation finishes, the feedback data must be correctly set here
// so the creating continuation can use it
#[derive(Debug, Clone)]
pub enum FeedbackData {
    Address(H160),
    CallData(Call),
}

#[derive(Debug)]
pub struct Continuation {
    pub data: Vec<u8>,
    pub code: Vec<u8>,
    pub position: Result<usize, ExitReason>,
    pub return_range: Range<U256>,
    pub valids: Valids,
    pub memory: Memory,
    pub stack: Stack,
    pub logs: Vec<Log>,
    pub accounts: BTreeMap<H160, MemoryStackAccount>,
    pub storages: BTreeMap<(H160, H256), H256>,
    pub deletes: BTreeSet<H160>,
}

#[derive(Debug)]
pub struct Continuations {
    storage: HashMap<u64, Continuation>,
    next_continuation_id: u64,
}

impl Default for Continuations {
    fn default() -> Self {
        Self::new()
    }
}

impl Continuations {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
            next_continuation_id: 0,
        }
    }

    pub fn last_created(&self) -> u64 {
        self.next_continuation_id
    }

    pub fn create_continuation(
        &mut self,
        machine: &mut evm::Machine,
        substate: &MemoryStackSubstate,
    ) -> u64 {
        self.next_continuation_id += 1;
        let continuation = Continuation {
            data: machine.data(),
            code: machine.code(),
            position: machine.position().to_owned(),
            return_range: machine.return_range().clone(),
            valids: machine.valids().clone(),
            memory: machine.memory().clone(),
            stack: machine.stack().clone(),
            accounts: substate.accounts().clone(),
            logs: Vec::from(substate.logs()),
            storages: substate.storages().clone(),
            deletes: substate.deletes().clone(),
        };
        self.storage.insert(self.next_continuation_id, continuation);
        self.next_continuation_id
    }

    pub fn get_contination(&mut self, id: u64) -> Option<Continuation> {
        self.storage.remove(&id)
    }

    // Sometimes a contract will change the state of another contract
    // in this case, we need to find cached state of continuations that
    // has now been invalidated by this and update it
    pub fn update_states(&mut self, addr: H160, key: H256, value: H256, skip: bool) {
        if skip {
            return;
        }

        // Loop over continuations updating the address if it exists
        for (_, continuation) in self.storage.iter_mut() {
            if let Some(value_current) = continuation.storages.get_mut(&(addr, key)) {
                *value_current = value;
            }
        }
    }
}

// This type extends the evm ExitReason by adding the Trap enum
#[derive(Debug, PartialEq)]
pub enum ExitReasonCps {
    Succeed(ExitSucceed),
    Error(ExitError),
    Revert(ExitRevert),
    Fatal(ExitFatal),
    Trap(Trap),
}

impl Default for ExitReasonCps {
    fn default() -> Self {
        ExitReasonCps::Fatal(ExitFatal::Other(
            "Defaulted ExitReasonCps used".to_string().into(),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub enum Trap {
    Unknown,
    Call,
    Create,
}

// When a trap is created (break in program execution, continuation created), it sets this data
// so the next continuation can get set up correctly
#[derive(Debug)]
pub enum TrapData {
    Call(CallTrap),
    Create(CreateTrap),
}

#[derive(Debug)]
pub struct Context {
    pub destination: H160,
    pub caller: H160,
    pub apparent_value: U256,
}

#[derive(Debug)]
pub struct Legacy {
    pub caller: H160,
}

#[derive(Debug)]
pub struct Create2 {
    pub caller: H160,
    pub code_hash: H256,
    pub salt: H256,
    pub create2_address: H160,
}

#[derive(Debug)]
pub struct Fixed {
    pub address: H160,
}

#[derive(Debug)]
pub struct CallTrap {
    pub context: Context,
    pub transfer: Option<Transfer>,
    pub callee_address: H160,
    pub call_data: Vec<u8>,
    pub target_gas: u64,
    pub is_static: bool,
    pub is_precompile: bool,
    pub memory_offset: U256,
    pub offset_len: U256,
}

#[derive(Debug)]
pub struct CreateTrap {
    pub caller: H160,
    pub scheme: CreateScheme,
    pub value: U256,
    pub call_data: Vec<u8>,
    pub target_gas: u64,
}

// This is the main struct returned from the evm after program invocation.
// Either it has completed, and is a success or revert, or it is some type of
// trap.
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct EvmResult {
    pub exit_reason: ExitReasonCps,
    #[derivative(Debug(format_with = "shortened_vec"))]
    pub return_value: Vec<u8>,
    pub apply: Vec<Apply>,
    pub logs: Vec<Log>,
    pub tx_trace: Arc<Mutex<LoggingEventListener>>,
    pub remaining_gas: u64,
    pub continuation_id: u64,
    pub trap_data: Option<TrapData>,
}

impl EvmResult {
    pub fn has_trap(&self) -> bool {
        matches!(self.exit_reason, ExitReasonCps::Trap(_))
    }

    pub fn succeeded(&self) -> bool {
        matches!(self.exit_reason, ExitReasonCps::Succeed(_))
    }

    pub fn take_apply(&mut self) -> Vec<Apply> {
        let mut ret = Vec::new();
        std::mem::swap(&mut ret, &mut self.apply);
        ret
    }
}
