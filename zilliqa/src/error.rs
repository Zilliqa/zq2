use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use alloy::{
    primitives::Bytes, rpc::types::error::EthRpcErrorCode, sol_types::decode_revert_reason,
};
use jsonrpsee::types::ErrorObjectOwned;
use revm::primitives::{ExecutionResult, HaltReason, OutOfGasError};

use crate::api::to_hex::ToHex;

pub fn ensure_success(result: ExecutionResult) -> Result<Bytes, TransactionError> {
    match result {
        ExecutionResult::Success { output, .. } => Ok(output.into_data()),
        ExecutionResult::Revert { output, .. } => {
            Err(TransactionError::Revert(RevertError::new(output)))
        }
        ExecutionResult::Halt { reason, gas_used } => match reason {
            HaltReason::OutOfGas(err) => match err {
                OutOfGasError::Basic => Err(TransactionError::BasicOutOfGas(gas_used)),
                OutOfGasError::MemoryLimit | OutOfGasError::Memory => {
                    Err(TransactionError::MemoryOutOfGas(gas_used))
                }
                OutOfGasError::Precompile => Err(TransactionError::PrecompileOutOfGas(gas_used)),
                OutOfGasError::InvalidOperand => {
                    Err(TransactionError::InvalidOperandOutOfGas(gas_used))
                }
            },
            reason => Err(TransactionError::EvmHalt(reason)),
        },
    }
}

/// An error from an executed transaction.
///
/// Many of the error strings and codes are de-facto standardised by other Ethereum clients.
///
// Much of this is derived from reth:
// https://github.com/paradigmxyz/reth/blob/bf44c9724f68d4aabc9ff1e27d278f36328b8d8f/crates/rpc/rpc-eth-types/src/error/mod.rs#L303
// Licensed under the Apache and MIT licenses.
#[derive(thiserror::Error, Debug)]
pub enum TransactionError {
    #[error(transparent)]
    Revert(RevertError),
    #[error("out of gas: gas required exceeds allowance: {0}")]
    BasicOutOfGas(u64),
    #[error("out of gas: gas exhausted during memory expansion: {0}")]
    MemoryOutOfGas(u64),
    #[error("out of gas: gas exhausted during precompiled contract execution: {0}")]
    PrecompileOutOfGas(u64),
    #[error("out of gas: invalid operand to an opcode: {0}")]
    InvalidOperandOutOfGas(u64),
    #[error("EVM error: {0:?}")]
    EvmHalt(HaltReason),
}

impl TransactionError {
    pub fn error_code(&self) -> i32 {
        match self {
            TransactionError::Revert(_) => EthRpcErrorCode::ExecutionError.code(),
            _ => EthRpcErrorCode::TransactionRejected.code(),
        }
    }
}

impl From<TransactionError> for ErrorObjectOwned {
    fn from(error: TransactionError) -> Self {
        let data = if let TransactionError::Revert(RevertError(ref output)) = error {
            output.as_ref().map(|o| o.to_hex())
        } else {
            None
        };

        ErrorObjectOwned::owned(error.error_code(), error.to_string(), data)
    }
}

#[derive(Debug)]
pub struct RevertError(Option<Bytes>);

impl RevertError {
    pub fn new(output: Bytes) -> Self {
        RevertError((!output.is_empty()).then_some(output))
    }
}

impl Error for RevertError {}

impl Display for RevertError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("execution reverted")?;
        if let Some(reason) = self.0.as_ref().and_then(|b| decode_revert_reason(b)) {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}
