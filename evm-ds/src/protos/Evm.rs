pub use crate::evm::executor::stack::Log;
use crate::evm::CreateScheme;
use evm::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed, Transfer};
use primitive_types::{H160, H256, U256};

#[derive(Debug)]
pub struct EvmEvalExtras {
    pub chain_id: u32,
    pub block_timestamp: u64,
    pub block_gas_limit: u64,
    pub block_difficulty: u64,
    pub block_number: u64,
    pub gas_price: U256,
}

#[derive(Debug)]
pub struct Storage {
    pub key: H256,
    pub value: H256,
}

#[derive(Debug)]
pub enum Apply {
    Delete {
        address: H160,
    },
    Modify {
        address: H160,
        balance: U256,
        nonce: U256,
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

#[derive(Debug, Clone)]
pub struct Continuation {
    pub id: u64,
    pub feedback_type: Type,
    pub feedback_data: Option<FeedbackData>,
    pub logs: Vec<Log>,
    pub succeeded: bool,
}

impl Continuation {
    pub fn new(id: u64) -> Self {
        Continuation {
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
            _ => panic!("Continuation does not contain an address"),
        }
    }

    pub fn get_calldata(&self) -> &Call {
        match &self.feedback_data {
            Some(FeedbackData::CallData(call)) => call,
            _ => panic!("Continuation does not contain call data"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum FeedbackData {
    Address(H160),
    CallData(Call),
}

#[derive(Debug)]
pub struct EvmArgs {
    pub address: H160,
    pub origin: H160,
    pub code: Vec<u8>,
    pub data: Vec<u8>,
    pub apparent_value: U256,
    pub gas_limit: u64,
    pub extras: EvmEvalExtras,
    pub estimate: bool,
    pub context: String,
    pub continuation: Continuation,
    pub enable_cps: bool,
    pub tx_trace_enabled: bool,
    pub tx_trace: String,
    pub is_static_call: bool,
    pub caller: H160,
}

#[derive(Debug, PartialEq)]
pub enum ExitReasonCps {
    Succeed(ExitSucceed),
    Error(ExitError),
    Revert(ExitRevert),
    Fatal(ExitFatal),
    Trap(Trap), // todo: trap raname
                //ExitSucceedX,
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

#[derive(Debug, Default)]
pub struct EvmResult {
    pub exit_reason: ExitReasonCps,
    pub return_value: Vec<u8>,
    pub apply: Vec<Apply>,
    pub logs: Vec<Log>,
    pub tx_trace: String,
    pub remaining_gas: u64,
    pub continuation_id: u64,
    //pub trap_data: TrapData,
    pub trap_data: Option<TrapData>,
}

impl EvmResult {
    pub fn has_trap(&self) -> bool {
        match self.exit_reason {
            ExitReasonCps::Trap(_) => true,
            _ => false,
        }
    }

    pub fn succeeded(&self) -> bool {
        match self.exit_reason {
            ExitReasonCps::Succeed(_) => true,
            _ => false,
        }
    }

    pub fn take_apply(&mut self) -> Vec<Apply> {
        let mut ret = Vec::new();
        std::mem::swap(&mut ret, &mut self.apply);
        ret
    }
}
