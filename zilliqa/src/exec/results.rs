use std::collections::{BTreeMap, HashMap};

use alloy::primitives::Address;
use revm::context::result::{ExecutionResult, ResultAndState};
use serde::{Deserialize, Serialize};

use super::PendingAccount;
use crate::{
    crypto::Hash,
    scilla,
    transaction::{EvmGas, EvmLog, Log, ScillaLog, ZilAmount},
};

pub(crate) type ScillaResultAndState = (ScillaResult, HashMap<Address, PendingAccount>);

#[derive(Clone)]
pub enum TransactionApplyResult {
    Evm(ResultAndState),
    Scilla(ScillaResultAndState),
}

impl TransactionApplyResult {
    pub fn output(&self) -> Option<&[u8]> {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => {
                result.output().map(|b| b.as_ref())
            }
            TransactionApplyResult::Scilla(_) => None,
        }
    }

    pub fn success(&self) -> bool {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => result.is_success(),
            TransactionApplyResult::Scilla((ScillaResult { success, .. }, _)) => *success,
        }
    }

    pub fn contract_address(&self) -> Option<Address> {
        match self {
            TransactionApplyResult::Evm(
                ResultAndState {
                    result: ExecutionResult::Success { output, .. },
                    ..
                },
                ..,
            ) => output.address().copied(),
            TransactionApplyResult::Evm(_) => None,
            TransactionApplyResult::Scilla((
                ScillaResult {
                    contract_address, ..
                },
                _,
            )) => *contract_address,
        }
    }

    pub fn gas_used(&self) -> EvmGas {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => {
                EvmGas(result.tx_gas_used())
            }
            TransactionApplyResult::Scilla((ScillaResult { gas_used, .. }, _)) => *gas_used,
        }
    }

    pub fn accepted(&self) -> Option<bool> {
        match self {
            TransactionApplyResult::Evm(_) => None,
            TransactionApplyResult::Scilla((ScillaResult { accepted, .. }, _)) => *accepted,
        }
    }

    pub fn exceptions(&self) -> &[ScillaException] {
        match self {
            TransactionApplyResult::Evm(_) => &[],
            TransactionApplyResult::Scilla((ScillaResult { exceptions, .. }, _)) => exceptions,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        Vec<Log>,
        Vec<ScillaTransition>,
        BTreeMap<u64, Vec<ScillaError>>,
        Vec<ScillaException>,
    ) {
        match self {
            TransactionApplyResult::Evm(ResultAndState { result, .. }, ..) => (
                result
                    .into_logs()
                    .into_iter()
                    .map(|l| {
                        let (topics, data) = l.data.split();
                        Log::Evm(EvmLog {
                            address: l.address,
                            topics,
                            data: data.to_vec(),
                        })
                    })
                    .collect(),
                Vec::new(),
                BTreeMap::new(),
                Vec::new(),
            ),
            TransactionApplyResult::Scilla((
                ScillaResult {
                    logs,
                    transitions,
                    errors,
                    exceptions,
                    ..
                },
                _,
            )) => (
                logs.into_iter().map(Log::Scilla).collect(),
                transitions,
                errors,
                exceptions,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScillaTransition {
    pub from: Address,
    pub to: Address,
    pub depth: u64,
    pub amount: ZilAmount,
    pub tag: String,
    pub params: String,
}

impl ScillaTransition {
    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.from.0.as_slice())
            .with(self.to.0.as_slice())
            .with(self.depth.to_be_bytes())
            .with(self.amount.to_be_bytes())
            .with(self.tag.as_bytes())
            .with(self.params.as_bytes())
            .finalize()
    }
}

#[derive(Debug, Clone)]
pub struct ScillaResult {
    pub success: bool,
    pub contract_address: Option<Address>,
    pub logs: Vec<ScillaLog>,
    pub gas_used: EvmGas,
    pub transitions: Vec<ScillaTransition>,
    pub accepted: Option<bool>,
    pub errors: BTreeMap<u64, Vec<ScillaError>>,
    pub exceptions: Vec<ScillaException>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScillaError {
    CheckerFailed,
    RunnerFailed,
    BalanceTransferFailed,
    ExecuteCmdFailed,
    ExecuteCmdTimeout,
    NoGasRemainingFound,
    NoAcceptedFound,
    CallContractFailed,
    CreateContractFailed,
    JsonOutputCorrupted,
    ContractNotExist,
    StateCorrupted,
    LogEntryInstallFailed,
    MessageCorrupted,
    ReceiptIsNull,
    MaxEdgesReached,
    ChainCallDiffShard,
    PreparationFailed,
    NoOutput,
    OutputIllegal,
    MapDepthMissing,
    GasNotSufficient,
    InternalError,
    LibraryAsRecipient,
    VersionInconsistent,
    LibraryExtractionFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScillaException {
    pub line: u64,
    pub message: String,
}

impl ScillaException {
    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.line.to_be_bytes())
            .with(self.message.as_bytes())
            .finalize()
    }
}

impl From<u64> for ScillaError {
    fn from(val: u64) -> ScillaError {
        match val {
            0 => ScillaError::CheckerFailed,
            1 => ScillaError::RunnerFailed,
            2 => ScillaError::BalanceTransferFailed,
            3 => ScillaError::ExecuteCmdFailed,
            4 => ScillaError::ExecuteCmdTimeout,
            5 => ScillaError::NoGasRemainingFound,
            6 => ScillaError::NoAcceptedFound,
            7 => ScillaError::CallContractFailed,
            8 => ScillaError::CreateContractFailed,
            9 => ScillaError::JsonOutputCorrupted,
            10 => ScillaError::ContractNotExist,
            11 => ScillaError::StateCorrupted,
            12 => ScillaError::LogEntryInstallFailed,
            13 => ScillaError::MessageCorrupted,
            14 => ScillaError::ReceiptIsNull,
            15 => ScillaError::MaxEdgesReached,
            16 => ScillaError::ChainCallDiffShard,
            17 => ScillaError::PreparationFailed,
            18 => ScillaError::NoOutput,
            19 => ScillaError::OutputIllegal,
            20 => ScillaError::MapDepthMissing,
            21 => ScillaError::GasNotSufficient,
            22 => ScillaError::InternalError,
            23 => ScillaError::LibraryAsRecipient,
            24 => ScillaError::VersionInconsistent,
            25 => ScillaError::LibraryExtractionFailed,
            _ => unreachable!(),
        }
    }
}

impl From<scilla::Error> for ScillaException {
    fn from(e: scilla::Error) -> ScillaException {
        ScillaException {
            line: e.start_location.line,
            message: e.error_message,
        }
    }
}
