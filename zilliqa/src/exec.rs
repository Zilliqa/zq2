//! Manages execution of transactions on state.

use std::{
    collections::{BTreeMap, HashMap, hash_map::Entry},
    error::Error,
    fmt::{self, Display, Formatter},
    fs, mem,
    num::NonZeroU128,
    path::Path,
    sync::{Arc, MutexGuard},
};

use alloy::primitives::{Address, Bytes, U256, address, hex};
use anyhow::{Context, Result, anyhow};
use eth_trie::{EthTrie, Trie};
use ethabi::Token;
use itertools::Itertools;
use jsonrpsee::types::ErrorObjectOwned;
use libp2p::PeerId;
use parking_lot::RwLock;
use revm::{
    Database, DatabaseRef, Inspector,
    context::{
        BlockEnv, CfgEnv,
        result::{ExecutionResult, HaltReason, Output, ResultAndState},
    },
    context_interface::{
        DBErrorMarker, TransactionType, block::BlobExcessGasAndPrice, transaction::AccessList,
    },
    handler::EvmTr,
    primitives::{B256, KECCAK_EMPTY, eip4844::MIN_BLOB_GASPRICE, hardfork::SpecId},
    state::{AccountInfo, Bytecode, EvmState},
};
use revm_context::{ContextTr, TxEnv};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{debug, info, trace, warn};

use crate::{
    cfg::{Fork, ScillaExtLibsPath, ScillaExtLibsPathInScilla, ScillaExtLibsPathInZq2},
    constants, contracts,
    crypto::{Hash, NodePublicKey},
    error::ensure_success,
    evm::{SPEC_ID_CANCUN, SPEC_ID_SHANGHAI, ZQ2Evm, ZQ2EvmContext, new_zq2_evm_ctx},
    inspector::{self, ScillaInspector, TouchedAddressInspector},
    message::{Block, BlockHeader},
    precompiles::{PENALTY_ADDRESS, SCILLA_CALL_ADDRESS, ViewHistory},
    scilla::{self, ParamValue, Scilla, split_storage_key, storage_key},
    state::{Account, Code, ContractInit, ExternalLibrary, State, contract_addr},
    time::SystemTime,
    transaction::{
        EvmGas, EvmLog, Log, ScillaGas, ScillaLog, Transaction, TxZilliqa, VerifiedTransaction,
        ZilAmount, total_scilla_gas_price,
    },
    trie_storage::TrieStorage,
};

#[derive(Clone, Copy, PartialEq)]
pub enum ExecType {
    Call,
    Estimate,
    Transact,
}

#[derive(Clone, Copy)]
pub struct ExtraOpts {
    pub(crate) disable_eip3607: bool,
    pub(crate) exec_type: ExecType,
    pub(crate) tx_type: TransactionType,
}

type ScillaResultAndState = (ScillaResult, HashMap<Address, PendingAccount>);

/// Data returned after applying a [Transaction] to [State].
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
                EvmGas(result.gas_used())
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
    /// The address of the Scilla contract which initiated the transition.
    pub from: Address,
    /// The recipient of the transition.
    pub to: Address,
    /// The call depth of the transition.
    pub depth: u64,
    /// The value passed with the transition.
    pub amount: ZilAmount,
    /// The tag of the transition. If the recipient is a Scilla contract, this is the method that will be called.
    pub tag: String,
    /// Any parameters passed with the transition.
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
    /// Whether the transaction succeeded and the resulting state changes were persisted.
    pub success: bool,
    /// If the transaction was a contract creation, the address of the resulting contract.
    pub contract_address: Option<Address>,
    /// The logs emitted by the transaction execution.
    pub logs: Vec<ScillaLog>,
    /// The gas paid by the transaction (in EVM gas units)
    pub gas_used: EvmGas,
    /// Scilla transitions executed by the transaction execution.
    pub transitions: Vec<ScillaTransition>,
    /// If the transaction was a call to a Scilla contract, whether the called contract accepted the ZIL sent to it.
    pub accepted: Option<bool>,
    /// Errors from calls to Scilla contracts. Indexed by the call depth of erroring contract.
    pub errors: BTreeMap<u64, Vec<ScillaError>>,
    /// Exceptions from calls to Scilla contracts.
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

// We need to define a custom error type for our [Database], which implements [Error].
#[derive(Debug)]
pub struct DatabaseError(anyhow::Error);

impl DBErrorMarker for DatabaseError {}

impl From<anyhow::Error> for DatabaseError {
    fn from(err: anyhow::Error) -> Self {
        DatabaseError(err)
    }
}

impl Display for DatabaseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for DatabaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl Database for PendingState {
    type Error = DatabaseError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.pre_state.basic_ref(address, &self.fork)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.pre_state.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.pre_state.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.pre_state.block_hash_ref(number)
    }
}

impl DatabaseRef for PendingState {
    type Error = DatabaseError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.pre_state.basic_ref(address, &self.fork)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.pre_state.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.pre_state.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.pre_state.block_hash_ref(number)
    }
}

impl State {
    fn basic_ref(
        &self,
        address: Address,
        fork: &Fork,
    ) -> Result<Option<AccountInfo>, DatabaseError> {
        if !self.has_account(address)? {
            return Ok(None);
        }

        let account = self.get_account(address)?;
        let code_raw = if fork.prevent_zil_transfer_from_evm_to_scilla_contract {
            match account.code {
                Code::Evm(code) => code,
                Code::Scilla { code, .. } => code.as_bytes().to_vec(),
            }
        } else {
            account.code.evm_code().unwrap_or_default()
        };

        let code = Bytecode::new_raw(code_raw.into());
        let account_info = AccountInfo {
            balance: U256::from(account.balance),
            nonce: account.nonce,
            code_hash: code.hash_slow(),
            code: Some(code),
        };

        Ok(Some(account_info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, DatabaseError> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, DatabaseError> {
        let index = B256::new(index.to_be_bytes());

        let result = self.get_account_storage(address, index)?;

        Ok(U256::from_be_bytes(result.0))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, DatabaseError> {
        Ok(self
            .get_canonical_block_by_number(number)?
            .map(|block| B256::new(block.hash().0))
            .unwrap_or_default())
    }
}

/// The external context used by [Evm].
pub struct ExternalContext {
    pub touched_address_inspector: TouchedAddressInspector,
    pub fork: Fork,
    // This flag is only used for zq1 whitelisted contracts, and it's used to detect if the entire transaction should be marked as failed
    pub enforce_transaction_failure: bool,
    /// The caller of each call in the call-stack. This is needed because the `scilla_call` precompile needs to peek
    /// into the call-stack. This will always be non-empty and the first entry will be the transaction signer.
    pub callers: Vec<Address>,
    pub has_evm_failed: bool,
    pub has_called_scilla_precompile: bool,
    pub finalized_view: u64,
    pub view_history: Arc<RwLock<ViewHistory>>,
    pub spec_id: SpecId,
}

pub enum BaseFeeAndNonceCheck {
    /// Transaction gas price will be validated to be at least the block gas price.
    Validate,
    /// Transaction gas price will not be validated.
    Ignore,
}

impl State {
    /// Used primarily during genesis to set up contracts for chain functionality.
    /// If override_address address is set, forces contract deployment to that addess.
    pub(crate) fn force_deploy_contract_evm(
        &mut self,
        creation_bytecode: Vec<u8>,
        override_address: Option<Address>,
        amount: u128,
    ) -> Result<Address> {
        let current_block = BlockHeader::genesis(Hash::ZERO);
        let (ResultAndState { result, mut state }, ..) = self.apply_transaction_evm(
            Address::ZERO,
            None,
            0,
            None,
            self.block_gas_limit,
            amount,
            creation_bytecode,
            None,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            ExtraOpts {
                disable_eip3607: false,
                exec_type: ExecType::Transact,
                tx_type: TransactionType::Legacy,
            },
        )?;

        match result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(addr)),
                ..
            } => {
                let addr = if let Some(override_address) = override_address {
                    let override_address = Address::from(override_address.0);
                    let account = state
                        .remove(&addr)
                        .ok_or_else(|| anyhow!("deployment did not change the contract account"))?;
                    state.insert(override_address, account);
                    override_address
                } else {
                    addr
                };

                self.apply_delta_evm(&state, current_block.number)?;
                Ok(addr)
            }
            ExecutionResult::Success { .. } => Err(anyhow!("deployment did not create a contract")),
            ExecutionResult::Revert { .. } => Err(anyhow!("deployment reverted")),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("deployment halted: {reason:?}")),
        }
    }

    fn failed(
        mut result_and_state: ResultAndState,
    ) -> Result<(ResultAndState, HashMap<Address, PendingAccount>)> {
        result_and_state.state.clear();
        Ok((
            ResultAndState {
                result: ExecutionResult::Revert {
                    gas_used: result_and_state.result.gas_used(),
                    output: Bytes::default(),
                },
                state: result_and_state.state,
            },
            HashMap::new(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_transaction_evm<I: Inspector<ZQ2EvmContext> + ScillaInspector>(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u128,
        max_priority_fee_per_gas: Option<u128>,
        gas_limit: EvmGas,
        amount: u128,
        payload: Vec<u8>,
        nonce: Option<u64>,
        access_list: Option<AccessList>,
        current_block: BlockHeader,
        inspector: I,
        enable_inspector: bool,
        base_fee_and_nonce_check: BaseFeeAndNonceCheck,
        extra_opts: ExtraOpts,
    ) -> Result<(ResultAndState, HashMap<Address, PendingAccount>)> {
        let fork = self.forks.get(current_block.number);
        //let fork = self.forks.get(current_block.number).clone();
        // if the view number is lower than min view of the node's missed view history and
        // state-sync is going on, use the checkpoint's history instead of the node's history
        let (view_history, finalized_view) = if current_block.view
            < self.view_history.read().min_view
            && self.ckpt_view_history.is_some()
            && self.ckpt_finalized_view.is_some()
        {
            (
                self.ckpt_view_history.clone().unwrap(),
                self.ckpt_finalized_view.unwrap(),
            )
        } else {
            (self.view_history.clone(), self.finalized_view)
        };

        let (spec_id, blob_excess_gas_and_price) = {
            if fork.cancun_active {
                (
                    SPEC_ID_CANCUN,
                    Some(BlobExcessGasAndPrice::new(0, MIN_BLOB_GASPRICE)),
                )
            } else {
                (SPEC_ID_SHANGHAI, None)
            }
        };

        let external_context = ExternalContext {
            touched_address_inspector: TouchedAddressInspector::default(),
            fork: fork.clone(),
            enforce_transaction_failure: false,
            callers: vec![from_addr],
            has_evm_failed: false,
            has_called_scilla_precompile: false,
            finalized_view,
            view_history,
            spec_id,
        };

        let (tx_type, access_list, gas_priority_fee) = {
            let access_list = if fork.inject_access_list {
                access_list.unwrap_or_default()
            } else {
                AccessList::default()
            };

            let gas_priority_fee = if fork.use_max_gas_priority_fee {
                max_priority_fee_per_gas
            } else {
                None
            };

            // Decide tx_type:
            // - If we injected access list or are using priority fee, use the one from extra_opts
            //   (caller provided) so it can be EIP-2930/1559 accordingly.
            // - Otherwise, default to Legacy.
            let tx_type = if fork.inject_access_list || fork.use_max_gas_priority_fee {
                extra_opts.tx_type
            } else {
                TransactionType::Legacy
            };
            (tx_type, access_list, gas_priority_fee)
        };
        let pending_state = PendingState::new(self.clone(), fork.clone());

        let randao_mix_hash = current_block.mix_hash.unwrap_or(Hash::EMPTY);

        let evm_ctx = new_zq2_evm_ctx(pending_state, external_context)
            .with_cfg({
                let mut cfg = CfgEnv::new_with_spec(spec_id);
                cfg.disable_eip3607 = extra_opts.disable_eip3607;
                cfg.chain_id = self.chain_id.eth;
                cfg.disable_base_fee = match base_fee_and_nonce_check {
                    BaseFeeAndNonceCheck::Validate => false,
                    BaseFeeAndNonceCheck::Ignore => true,
                };
                cfg.disable_nonce_check = match base_fee_and_nonce_check {
                    BaseFeeAndNonceCheck::Validate => false,
                    BaseFeeAndNonceCheck::Ignore => true,
                };
                cfg
            })
            .with_block(BlockEnv {
                number: U256::from(current_block.number),
                timestamp: U256::from(
                    current_block
                        .timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                gas_limit: self.block_gas_limit.0,
                basefee: self.gas_price.try_into()?,
                difficulty: U256::from(1),
                prevrandao: Some(randao_mix_hash.0.into()),
                blob_excess_gas_and_price,
                beneficiary: Default::default(),
            });

        let mut evm = ZQ2Evm::new(evm_ctx, inspector);

        let tx = TxEnv {
            tx_type: tx_type.into(),
            caller: from_addr.0.into(),
            gas_limit: gas_limit.0,
            gas_price,
            kind: to_addr.into(),
            value: U256::from(amount),
            data: payload.clone().into(),
            nonce: nonce.unwrap_or_default(),
            chain_id: Some(self.chain_id.eth),
            access_list,
            gas_priority_fee,
            blob_hashes: vec![],
            max_fee_per_blob_gas: 0,
            authorization_list: Vec::default(),
        };

        let result_and_state = {
            if enable_inspector {
                evm.inspect(tx)?
            } else {
                evm.transact(tx)?
            }
        };

        let ResultAndState { result, state } = result_and_state;

        // Don't apply state delta to SCILLA CALL AND PENALTY precompiles as in previous versions of revm they were called by custom handler
        let state = state
            .into_iter()
            .filter(|(addr, _)| *addr != SCILLA_CALL_ADDRESS && *addr != PENALTY_ADDRESS)
            .collect();

        let result_and_state = ResultAndState { result, state };

        if enable_inspector {
            let touched_address = &evm.0.ctx.chain.touched_address_inspector.touched;
            let inspector = &mut evm.0.inspector;
            for touched_address in touched_address.iter() {
                ScillaInspector::call(inspector, *touched_address, *touched_address, 0, 0);
            }
        }
        let ctx_with_handler = evm.ctx();

        // If the scilla precompile failed for whitelisted zq1 contract we mark the entire transaction as failed
        if ctx_with_handler.chain.enforce_transaction_failure {
            return Self::failed(result_and_state);
        }

        // If any of EVM (calls, creates, ...) failed and there was a call to whitelisted scilla address with interop precompile
        // then report entire transaction as failed
        let evm_exec_failure_causes_scilla_precompile_to_fail = self
            .forks
            .get(current_block.number)
            .evm_exec_failure_causes_scilla_precompile_to_fail;
        {
            let ext_ctx = &ctx_with_handler.chain;
            if evm_exec_failure_causes_scilla_precompile_to_fail
                && ext_ctx.has_evm_failed
                && ext_ctx.has_called_scilla_precompile
                && extra_opts.exec_type == ExecType::Transact
            {
                return Self::failed(result_and_state);
            }
        }

        let finalized_state = ctx_with_handler.db_mut().finalize();

        Ok((result_and_state, finalized_state))
    }

    // The rules here are somewhat odd, and inherited from ZQ1
    //
    // - Initially, we deduct the minimum cost from the account. If this fails, abort and deduct nothing.
    // - At the end of the txn, work out how much more to charge, and try to charge it
    //    * If this succeeds, we charge and reflect the results of the txn.
    //    * If it doesn't, we charge nothing (?!) and the state doesn't reflect the results of the txn.
    // - Failed scilla transactions don't count towards the block gas limit.
    // - Failed scilla transactions don't increment the nonce.
    // - If the user has enough gas to pay the deposit, but not to complete the txn, we neither increment the
    //   nonce nor charge the deposit :-(
    //
    // gas_used in the return value is used only for accounting towards the block gas limit - we need
    // to deduct gas charged to the user ourselves. Since our txns don't count towards block gas,
    // gas_used is always 0.
    fn apply_transaction_scilla(
        &mut self,
        from_addr: Address,
        txn: TxZilliqa,
        current_block: BlockHeader,
        inspector: impl ScillaInspector,
    ) -> Result<ScillaResultAndState> {
        let fork = self.forks.get(current_block.number).clone();

        let mut state = PendingState::new(self.try_clone()?, fork.clone());

        // Issue 1509 - for Scilla transitions, follow the legacy ZQ1 behaviour of deducting a small amount
        // of gas for the invocation and the rest of the gas once the txn has run.

        let gas_price = txn.gas_price;

        let deposit_gas = txn.get_deposit_gas()?;
        let deposit = total_scilla_gas_price(deposit_gas, gas_price);
        trace!("scilla_txn: gas_price {gas_price} deposit_gas {deposit_gas} deposit {deposit}");

        let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
            deposit_gas.into()
        } else {
            EvmGas(0)
        };
        if let Some(result) = state.deduct_from_account(from_addr, deposit, gas_used)? {
            trace!("scilla_txn: Could not deduct deposit");
            return Ok((result, state.finalize()));
        }

        let (result, mut new_state) = if txn.to_addr.is_zero() {
            scilla_create(
                state,
                self.scilla(),
                from_addr,
                txn,
                current_block,
                inspector,
                &self.scilla_ext_libs_path,
                &fork,
            )
        } else {
            scilla_call(
                state,
                self.scilla(),
                from_addr,
                from_addr,
                txn.gas_limit,
                txn.to_addr,
                txn.amount,
                txn.data,
                inspector,
                &self.scilla_ext_libs_path,
                &fork,
                current_block.number,
            )
        }?;

        let actual_gas_charged =
            total_scilla_gas_price(ScillaGas::from(result.gas_used), gas_price);
        let from = new_state.load_account(from_addr)?;
        from.account.nonce += 1;
        from.mark_touch();

        // If txn is successful deduct extra fee and keep balance changes intact
        if !fork.scilla_failed_txn_correct_balance_deduction || result.success {
            let to_charge = actual_gas_charged.checked_sub(&deposit);
            trace!("scilla_txn: actual_gas_used {actual_gas_charged} to_charge = {to_charge:?}");
            if let Some(extra_charge) = to_charge {
                // Deduct the remaining gas.
                // If we fail, Zilliqa 1 deducts nothing at all, and neither do we.
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    result.gas_used
                } else {
                    EvmGas(0)
                };
                if let Some(result) =
                    new_state.deduct_from_account(from_addr, extra_charge, gas_used)?
                {
                    trace!("scilla_txn: cannot deduct remaining gas - txn failed");
                    let mut failed_state = PendingState::new(self.try_clone()?, fork.clone());
                    return Ok((result, failed_state.finalize()));
                }
            }
        } else {
            // If txn has failed - make sure only fee is deducted from sender account
            let original_acc = self.get_account(from_addr)?;
            from.account.balance = original_acc
                .balance
                .saturating_sub(actual_gas_charged.get());
        }
        trace!("scilla_txn completed successfully");
        Ok((result, new_state.finalize()))
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction<I: Inspector<ZQ2EvmContext> + ScillaInspector>(
        &mut self,
        txn: VerifiedTransaction,
        current_block: BlockHeader,
        inspector: I,
        enable_inspector: bool,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash;
        let from_addr = txn.signer;
        let txn = txn.tx.into_transaction();

        info!(?hash, from = ?from_addr, to = ?txn.to_addr(), ?txn, "executing txn");

        let blessed = BLESSED_TRANSACTIONS.iter().any(|elem| elem.hash == hash);

        if let Transaction::Zilliqa(txn) = txn {
            let (result, state) =
                self.apply_transaction_scilla(from_addr, txn, current_block, inspector)?;

            let update_state_only_if_transaction_succeeds = self
                .forks
                .get(current_block.number)
                .apply_state_changes_only_if_transaction_succeeds;

            if !update_state_only_if_transaction_succeeds || result.success {
                self.apply_delta_scilla(&state, current_block.number)?;
            } else {
                // If the transaction rejected, we must update the nonce and balance of the sender account.
                let from_account = state
                    .get(&from_addr)
                    .ok_or(anyhow!("from account not found"))?;

                let mut storage = self.get_account_trie(from_addr)?;

                let account = Account {
                    nonce: from_account.account.nonce,
                    balance: from_account.account.balance,
                    code: from_account.account.code.clone(),
                    storage_root: storage.root_hash()?,
                };

                self.save_account(from_addr, account)?;
            }

            Ok(TransactionApplyResult::Scilla((result, state)))
        } else {
            let (ResultAndState { result, state }, scilla_state) = self.apply_transaction_evm(
                from_addr,
                txn.to_addr(),
                txn.max_fee_per_gas(),
                txn.max_priority_fee_per_gas(),
                txn.gas_limit(),
                txn.amount(),
                txn.payload().to_vec(),
                txn.nonce(),
                txn.access_list(),
                current_block,
                inspector,
                enable_inspector,
                if blessed {
                    BaseFeeAndNonceCheck::Ignore
                } else {
                    BaseFeeAndNonceCheck::Validate
                },
                ExtraOpts {
                    disable_eip3607: false,
                    exec_type: ExecType::Transact,
                    tx_type: txn.revm_transaction_type(),
                },
            )?;

            self.apply_delta_evm(&state, current_block.number)?;
            let apply_scilla_delta_when_evm_succeeded = self
                .forks
                .get(current_block.number)
                .apply_scilla_delta_when_evm_succeeded;

            if apply_scilla_delta_when_evm_succeeded {
                if let ExecutionResult::Success { .. } = result {
                    self.apply_delta_scilla(&scilla_state, current_block.number)?;
                }
            } else {
                self.apply_delta_scilla(&scilla_state, current_block.number)?;
            }

            Ok(TransactionApplyResult::Evm(ResultAndState {
                result,
                state,
            }))
        }
    }

    /// Applies a state delta from a Scilla execution to the state.
    fn apply_delta_scilla(
        &mut self,
        state: &HashMap<Address, PendingAccount>,
        current_block_number: u64,
    ) -> Result<()> {
        let fork = self.forks.get(current_block_number);
        let only_mutated_accounts_update_state = fork.only_mutated_accounts_update_state;
        let scilla_delta_maps_are_applied_correctly = fork.scilla_delta_maps_are_applied_correctly;
        for (&address, account) in state {
            if only_mutated_accounts_update_state && !account.touched {
                continue;
            }

            // We shouldn't mutate accounts that were from EVM.
            assert!(!account.from_evm);

            let mut storage = self.get_account_trie(address)?;

            /// Recursively called internal function which assigns `value` at the correct key to `storage`.
            fn handle(
                scilla_delta_maps_are_applied_correctly: bool,
                storage: &mut EthTrie<TrieStorage>,
                var: &str,
                value: &StorageValue,
                indices: &mut Vec<Vec<u8>>,
            ) -> Result<()> {
                match value {
                    StorageValue::Map { map, complete } => {
                        // If this is a complete view of the map, delete any existing values first.
                        if *complete {
                            storage.remove_by_prefix(&storage_key(var, indices))?;
                        }

                        // We will iterate over each key-value pair in this map and make a recursive call to this
                        // function with the given value. Before each call, we need to make sure we update `indices`
                        // to include the key. To avoid changing the length of the `Vec` in each iteration, we first
                        // add a dummy index (`vec![]`) and update it before each call.
                        indices.push(vec![]);
                        for (k, v) in map {
                            indices.last_mut().unwrap().clone_from(k);
                            handle(
                                scilla_delta_maps_are_applied_correctly,
                                storage,
                                var,
                                v,
                                indices,
                            )?;
                        }
                        if scilla_delta_maps_are_applied_correctly {
                            indices.pop();
                        }
                    }
                    StorageValue::Value(Some(value)) => {
                        let key = storage_key(var, indices);
                        storage.insert(&key, value)?;
                    }
                    StorageValue::Value(None) => {
                        let key = storage_key(var, indices);
                        // A deletion may occur at any depth of the map. Therefore we remove all keys with the relevent
                        // prefix.
                        storage.remove_by_prefix(&key)?;
                    }
                }
                Ok(())
            }

            for (var, value) in &account.storage {
                handle(
                    scilla_delta_maps_are_applied_correctly,
                    &mut storage,
                    var,
                    value,
                    &mut vec![],
                )?;
            }

            let account = Account {
                nonce: account.account.nonce,
                balance: account.account.balance,
                code: account.account.code.clone(),
                storage_root: storage.root_hash()?,
            };

            self.save_account(address, account)?;
        }

        Ok(())
    }

    /// Applies a state delta from an EVM execution to the state.
    pub fn apply_delta_evm(
        &mut self,
        state: &revm::primitives::HashMap<Address, revm::state::Account>,
        current_block_number: u64,
    ) -> Result<()> {
        let only_mutated_accounts_update_state = self
            .forks
            .get(current_block_number)
            .only_mutated_accounts_update_state;
        for (&address, account) in state {
            if only_mutated_accounts_update_state && !account.is_touched() {
                continue;
            }

            let mut storage = self.get_account_trie(address)?;

            for (index, value) in account.changed_storage_slots() {
                let index = B256::new(index.to_be_bytes());
                let value = B256::new(value.present_value().to_be_bytes());
                trace!(?address, ?index, ?value, "update storage");

                storage.insert(
                    &Self::account_storage_key(address, index).0,
                    value.as_slice(),
                )?;
            }

            // `account.info.code` might be `None`, even though we always return `Some` for the account code in our
            // [DatabaseRef] implementation. However, this is only the case for empty code, so we handle this case
            // separately.
            let mut code = if account.info.code_hash == KECCAK_EMPTY {
                Code::Evm(vec![])
            } else {
                Code::Evm(
                    account
                        .info
                        .code
                        .as_ref()
                        .expect("code_by_hash is not used")
                        .original_bytes()
                        .to_vec(),
                )
            };

            let fork = self.forks.get(current_block_number).clone();
            if fork.scilla_fix_contract_code_removal_on_evm_tx {
                // if contract is Scilla then fetch Code to include in Account update
                let mut pending_state = PendingState::new(self.try_clone()?, fork);
                let zq2_account = pending_state.load_account(address)?;
                if zq2_account.account.code.is_scilla() {
                    code = zq2_account.account.code.clone()
                }
            }

            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.try_into()?,
                code,
                storage_root: storage.root_hash()?,
            };
            trace!(?address, ?account, "update account");
            self.save_account(address, account)?;
        }

        Ok(())
    }

    pub fn deposit_contract_version(&self, current_block: BlockHeader) -> Result<u128> {
        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            contracts::deposit::VERSION.encode_input(&[]).unwrap(),
            0,
            current_block,
        )?;
        contracts::deposit::VERSION.decode_output(&ensure_success(result)?)?[0]
            .clone()
            .into_uint()
            .map_or(Ok(0), |v| Ok(v.as_u128()))
    }

    pub fn leader(
        &self,
        view: u64,
        current_block: BlockHeader,
        fork: &Fork,
        caller: &str,
    ) -> Result<NodePublicKey> {
        // let current_block = BlockHeader {
        //     mix_hash: Some(Hash::ZERO),
        //     ..current_block
        // };
        let data = {
            if fork.randao_support {
                contracts::deposit::LEADER_AT_VIEW_WITH_RANDAO
                    .encode_input(&[Token::Uint(view.into())])?
                //contracts::deposit::LEADER_AT_VIEW.encode_input(&[Token::Uint(view.into())])?
            } else {
                contracts::deposit::LEADER_AT_VIEW.encode_input(&[Token::Uint(view.into())])?
            }
        };

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            current_block,
        )?;
        let leader = ensure_success(result)?;

        let pub_key = NodePublicKey::from_bytes(
            &contracts::deposit::LEADER_AT_VIEW.decode_output(&leader)?[0]
                .clone()
                .into_bytes()
                .unwrap(),
        );

        let pub_key_compare = pub_key.unwrap();

        let peer_id = self.get_peer_id(pub_key_compare.clone()).unwrap().unwrap();
        let stakers = self.get_stakers(current_block)?;
        let idx = stakers
            .iter()
            .find_position(|&pk| pk.as_bytes().eq(&pub_key_compare.as_bytes()))
            .unwrap()
            .0;

        info!(
            "Calling leader at view: {}, block_number: {}, stakers: {}, leader: {:?}, randao: {:?}, caller: {}. idx: {:?}",
            view, current_block.number, stakers.len(), peer_id, current_block.mix_hash, caller, idx
        );

        NodePublicKey::from_bytes(
            &contracts::deposit::LEADER_AT_VIEW.decode_output(&leader)?[0]
                .clone()
                .into_bytes()
                .unwrap(),
        )
    }

    pub fn get_stakers(&self, current_block: BlockHeader) -> Result<Vec<NodePublicKey>> {
        let data: Vec<u8> = contracts::deposit::GET_STAKERS.encode_input(&[])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            current_block,
        )?;
        let stakers = ensure_success(result)?;

        let stakers = contracts::deposit::GET_STAKERS
            .decode_output(&stakers)
            .unwrap()[0]
            .clone()
            .into_array()
            .unwrap();

        stakers
            .into_iter()
            .map(|k| NodePublicKey::from_bytes(&k.into_bytes().unwrap()))
            .collect()
    }

    pub fn committee(&self) -> Result<()> {
        let data = contracts::deposit::COMMITTEE.encode_input(&[])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            BlockHeader::default(),
        )?;
        let committee = ensure_success(result)?;
        let committee = contracts::deposit::COMMITTEE.decode_output(&committee)?;
        debug!("committee: {committee:?}");

        Ok(())
    }

    pub fn get_stake(
        &self,
        public_key: NodePublicKey,
        current_block: BlockHeader,
    ) -> Result<Option<NonZeroU128>> {
        let data =
            contracts::deposit::GET_STAKE.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            current_block,
        )?;
        let stake = ensure_success(result)?;

        let stake = NonZeroU128::new(U256::from_be_slice(&stake).to());

        Ok(stake)
    }

    pub fn get_reward_address(&self, public_key: NodePublicKey) -> Result<Option<Address>> {
        let data = contracts::deposit::GET_REWARD_ADDRESS
            .encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            // The current block is not accessed when the native balance is read, so we just pass in some
            // dummy values.
            BlockHeader::default(),
        )?;
        let return_value = ensure_success(result)?;

        let addr = contracts::deposit::GET_REWARD_ADDRESS.decode_output(&return_value)?[0]
            .clone()
            .into_address()
            .unwrap();
        let addr = Address::new(addr.0);

        Ok((!addr.is_zero()).then_some(addr))
    }

    pub fn get_peer_id(&self, public_key: NodePublicKey) -> Result<Option<PeerId>> {
        let data =
            contracts::deposit::GET_PEER_ID.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            // The current block is not accessed when the native balance is read, so we just pass in some
            // dummy values.
            BlockHeader::default(),
        )?;
        let return_value = ensure_success(result)?;

        let data = contracts::deposit::GET_PEER_ID.decode_output(&return_value)?[0]
            .clone()
            .into_bytes()
            .unwrap();

        Ok(Some(PeerId::from_bytes(&data)?))
    }

    /// Returns the maximum gas a caller could pay for a given transaction. This is clamped the minimum of:
    /// 1. The block gas limit.
    /// 2. The gas limit specified by the caller.
    /// 3. The caller's balance after paying for any funds sent by the transaction.
    ///
    /// Returns an error if the caller does not have funds to pay for the transaction.
    fn max_gas_for_caller(
        &self,
        caller: Address,
        tx_value: u128,
        gas_price: u128,
        requested_gas_limit: Option<EvmGas>,
    ) -> Result<EvmGas> {
        let mut gas = self.block_gas_limit;

        if let Some(requested_gas_limit) = requested_gas_limit {
            gas = gas.min(requested_gas_limit);
        }

        if gas_price != 0 {
            let balance = self.get_account(caller)?.balance;
            // Calculate how much the caller has left to pay for gas after the transaction value is subtracted.
            let balance = balance.checked_sub(tx_value).ok_or_else(|| {
                anyhow!("caller has insufficient funds - has: {balance}, needs: {tx_value}")
            })?;
            // Calculate the gas the caller could pay for at this gas price.
            let max_gas = EvmGas((balance / gas_price) as u64);
            gas = gas.min(max_gas);
        }

        Ok(gas)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        current_block: BlockHeader,
        gas: Option<EvmGas>,
        gas_price: Option<u128>,
        max_priority_fee_per_gas: Option<u128>,
        value: u128,
        access_list: Option<AccessList>,
        extra_opts: ExtraOpts,
    ) -> Result<u64> {
        let gas_price = gas_price.unwrap_or(self.gas_price);

        let mut max = self.max_gas_for_caller(from_addr, value, gas_price, gas)?.0;

        let upper_bound = max;

        // Check if estimation succeeds with the highest possible gas
        // We use the result as lower bound
        let mut min = self.estimate_gas_inner(
            from_addr,
            to_addr,
            data.clone(),
            current_block,
            EvmGas(upper_bound),
            gas_price,
            max_priority_fee_per_gas,
            value,
            access_list.clone(),
            extra_opts,
        )?;

        // Execute the while loop iff (max - min)/max < MINIMUM_PERCENT_RATIO [%]
        const MINIMUM_PERCENT_RATIO: u64 = 3;

        // result should be somewhere in (min, max]
        while min < max {
            let break_cond = (max - min) <= (max * MINIMUM_PERCENT_RATIO) / 100;
            if break_cond {
                break;
            }
            let mid = (min + max) / 2;

            let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
                from_addr,
                to_addr,
                gas_price,
                max_priority_fee_per_gas,
                EvmGas(mid),
                value,
                data.clone(),
                None,
                access_list.clone(),
                current_block,
                inspector::noop(),
                false,
                BaseFeeAndNonceCheck::Ignore,
                extra_opts,
            )?;

            match result {
                ExecutionResult::Success { .. } => max = mid,
                ExecutionResult::Revert { .. } => min = mid + 1,
                ExecutionResult::Halt { reason, .. } => match reason {
                    HaltReason::OutOfGas(_) | HaltReason::InvalidFEOpcode => min = mid + 1,
                    _ => return Err(anyhow!("halted due to: {reason:?}")),
                },
            }
        }
        debug!("Estimated gas: {}", max);
        Ok(max)
    }
    #[allow(clippy::too_many_arguments)]
    fn estimate_gas_inner(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        current_block: BlockHeader,
        gas: EvmGas,
        gas_price: u128,
        max_priority_fee_per_gas: Option<u128>,
        value: u128,
        access_list: Option<AccessList>,
        extra_opts: ExtraOpts,
    ) -> Result<u64> {
        let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            gas_price,
            max_priority_fee_per_gas,
            gas,
            value,
            data.clone(),
            None,
            access_list,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            extra_opts,
        )?;

        let gas_used = result.gas_used();
        // Return an error if the transaction did not succeed
        ensure_success(result).map_err(ErrorObjectOwned::from)?;
        Ok(gas_used)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_contract(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: u128,
        current_block: BlockHeader,
    ) -> Result<ExecutionResult> {
        let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            0,
            None,
            self.block_gas_limit,
            amount,
            data,
            None,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            ExtraOpts {
                disable_eip3607: true,
                exec_type: ExecType::Call,
                tx_type: TransactionType::Legacy,
            },
        )?;

        Ok(result)
    }

    /// Call contract and apply changes to state
    #[allow(clippy::too_many_arguments)]
    pub fn call_contract_apply(
        &mut self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: u128,
        current_block: BlockHeader,
    ) -> Result<ExecutionResult> {
        let (ResultAndState { result, state }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            0,
            None,
            self.block_gas_limit,
            amount,
            data,
            None,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeAndNonceCheck::Ignore,
            ExtraOpts {
                disable_eip3607: false,
                exec_type: ExecType::Transact,
                tx_type: TransactionType::Legacy,
            },
        )?;
        self.apply_delta_evm(&state, current_block.number)?;

        Ok(result)
    }
}

/// Gets the contract address if a contract creation [TxZilliqa] is sent by `sender` with `nonce`.
pub fn zil_contract_address(sender: Address, nonce: u64) -> Address {
    let mut hasher = Sha256::new();
    hasher.update(sender.into_array());
    hasher.update(nonce.to_be_bytes());
    let hashed = hasher.finalize();
    Address::from_slice(&hashed[12..])
}

/// The account state during the execution of a Scilla transaction. Changes to the original state are kept in memory.
#[derive(Debug, Clone)]
pub struct PendingState {
    pub pre_state: State,
    pub new_state: HashMap<Address, PendingAccount>,
    // Read-only copy of the current cached EVM state. Only `Some` when this Scilla call is made by the `scilla_call`
    // precompile.
    pub evm_state: Option<EvmState>,
    pub fork: Fork,
}

/// Private helper function for `PendingState::load_account`. The only difference is that the fields of `PendingState`
/// are passed explicitly. This means the borrow-checker can see the reference we return only borrows from the
/// `new_state` field and thus we can later use `pre_state` without an error.
fn load_account<'a>(
    pre_state: &State,
    new_state: &'a mut HashMap<Address, PendingAccount>,
    evm_state: &Option<EvmState>,
    address: Address,
) -> Result<&'a mut PendingAccount> {
    match (
        new_state.entry(address),
        evm_state
            .as_ref()
            .and_then(|evm_state| evm_state.get(&address)),
    ) {
        (Entry::Occupied(entry), _) => Ok(entry.into_mut()),
        (Entry::Vacant(vac), Some(account)) => {
            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.to(),
                code: Code::Evm(if account.info.code_hash == KECCAK_EMPTY {
                    vec![]
                } else {
                    account
                        .info
                        .code
                        .as_ref()
                        .ok_or_else(|| anyhow!("account should have code"))?
                        .original_bytes()
                        .to_vec()
                }),
                storage_root: B256::ZERO, // There's no need to set this, since Scilla cannot query EVM contracts' state.
            };
            let account = PendingAccount {
                account,
                storage: BTreeMap::new(),
                from_evm: true,
                touched: false,
            };
            Ok(vac.insert(account))
        }
        (Entry::Vacant(vac), None) => {
            let account = pre_state.get_account(address)?;
            Ok(vac.insert(account.into()))
        }
    }
}

impl PendingState {
    pub fn new(state: State, fork: Fork) -> Self {
        PendingState {
            pre_state: state,
            new_state: HashMap::new(),
            evm_state: None,
            fork,
        }
    }

    pub fn zil_chain_id(&self) -> u64 {
        self.pre_state.chain_id.zil()
    }

    pub fn get_canonical_block_by_number(&self, block_number: u64) -> Result<Option<Block>> {
        self.pre_state.get_canonical_block_by_number(block_number)
    }

    pub fn get_highest_canonical_block_number(&self) -> Result<Option<u64>> {
        self.pre_state.get_highest_canonical_block_number()
    }

    pub fn touch(&mut self, address: Address) {
        if let Some(account) = self.new_state.get_mut(&address) {
            account.mark_touch();
        }
    }

    pub fn load_account(&mut self, address: Address) -> Result<&mut PendingAccount> {
        load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
        )
    }

    pub fn load_var_info(&mut self, address: Address, variable: &str) -> Result<(&str, u8)> {
        let account = self.load_account(address)?;
        let Code::Scilla { types, .. } = &account.account.code else {
            return Err(anyhow!("not a scilla contract"));
        };
        let (ty, depth) = types
            .get(variable)
            .ok_or_else(|| anyhow!("missing type for variable: {variable}"))?;
        Ok((ty, *depth))
    }

    /// Set the value of a given variable at the given indices. This can be used for setting map values, unlike
    /// `load_storage`.
    pub fn set_storage(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
        value: StorageValue,
    ) -> Result<()> {
        let account = load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
        )?;

        let mut current = account
            .storage
            .entry(var_name.to_owned())
            .or_insert_with(StorageValue::incomplete_map);
        for key in indices {
            let current_map = match current {
                StorageValue::Map { map, .. } => map,
                StorageValue::Value(Some(_)) => {
                    return Err(anyhow!("expected a map"));
                }
                StorageValue::Value(None) => {
                    // This branch is unreachable because `update_state_value` in `ActiveCall` asserts that a deletion
                    // can only occur at the same depth as a variable.
                    unreachable!("deletes of whole maps are unsupported")
                }
            };
            let child = current_map
                .entry(key.clone())
                .or_insert_with(StorageValue::incomplete_map);
            current = child;
        }

        *current = value;

        Ok(())
    }

    pub fn load_storage(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
    ) -> Result<&mut Option<Bytes>> {
        let account = load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
        )?;

        fn get_cached<'a>(
            storage: &'a mut BTreeMap<String, StorageValue>,
            var_name: &str,
            indices: &[Vec<u8>],
        ) -> Result<(&'a mut StorageValue, bool)> {
            let mut cached = true;
            let mut current = storage.entry(var_name.to_owned()).or_insert_with(|| {
                cached = false;
                StorageValue::incomplete_map()
            });
            for key in indices {
                let current_map = match current {
                    StorageValue::Map { map, .. } => map,
                    StorageValue::Value(Some(_)) => {
                        return Err(anyhow!("expected a map"));
                    }
                    StorageValue::Value(None) => {
                        // This branch is unreachable because `update_state_value` in `ActiveCall` asserts that a deletion
                        // can only occur at the same depth as a variable.
                        unreachable!("deletes of whole maps are unsupported")
                    }
                };
                let child = current_map.entry(key.clone()).or_insert_with(|| {
                    cached = false;
                    StorageValue::incomplete_map()
                });
                current = child;
            }
            Ok((current, cached))
        }

        let (value, cached) = get_cached(&mut account.storage, var_name, indices)?;

        if !cached {
            let value_from_disk = self
                .pre_state
                .get_account_trie(address)?
                .get(&storage_key(var_name, indices))?;

            *value = StorageValue::Value(value_from_disk.map(|b| b.into()));
        }

        match value {
            StorageValue::Map { .. } => Err(anyhow!("expected bytes")),
            StorageValue::Value(value) => Ok(value),
        }
    }

    pub fn load_storage_by_prefix(
        &mut self,
        address: Address,
        var_name: &str,
        indices: &[Vec<u8>],
    ) -> Result<BTreeMap<Vec<u8>, StorageValue>> {
        let account = load_account(
            &self.pre_state,
            &mut self.new_state,
            &self.evm_state,
            address,
        )?;

        // Even if we have something cached for this prefix, we don't know if it is a full representation of the map.
        // It might have been the case that only a few subfields were cached. Therefore, we need to retrieve the full
        // map from disk and apply any cached (and potentially updated) values. In future, we should use the 'complete'
        // flag on maps to avoid needing to read from disk unconditionally.

        let values_from_disk: Vec<_> = self
            .pre_state
            .get_account_trie(address)?
            .iter_by_prefix(&storage_key(var_name, indices))?
            .collect();

        let mut map = StorageValue::complete_map();
        let cached = account.storage.get(var_name);

        // Un-flatten the values from disk into their true representation.
        for (k, v) in values_from_disk.into_iter().flatten() {
            let (disk_var_name, disk_indices) = split_storage_key(&k)?;
            if var_name != disk_var_name {
                // There is a hazard caused by the storage key format when a contract contains a variable which is a
                // prefix of another variable. For example, if a contract has a variable "foo" and another variable
                // "foobar", we call `.iter_by_prefix(storage_key("foo", [])) -> .iter_by_prefix("foo")` and mistakenly
                // obtain the values from both "foo" and "foobar". A more sensible format would have suffixed the
                // variable name with a `SEPARATOR` too, but it is awkward to change the format now. Instead, we filter
                // the results of the `iter_by_prefix` call here to exclude the 'extra' returned variables.
                trace!(var_name, disk_var_name, "scilla var name mismatch");
                continue;
            }
            assert!(disk_indices.starts_with(indices));

            let mut current_value = &mut map;
            let mut current_cached = cached;

            let disk_indices_len = disk_indices.len();

            for index in disk_indices {
                if let Some(c) = current_cached {
                    match c {
                        StorageValue::Map { map, .. } => {
                            current_cached = map.get(&index);
                        }
                        // This branch can be hit in two cases:
                        // * Firstly, we expect the final index to point to a value in the cache, rather than a map.
                        // * Secondly, if a portion of the map has been deleted, then the cache can contain a `None`
                        // value at a greater height than the depth of the map.
                        StorageValue::Value(_) => {}
                    }
                }

                let map = match current_value {
                    StorageValue::Map { map, .. } => map,
                    StorageValue::Value(_) => {
                        return Err(anyhow!("expected map"));
                    }
                };
                // Note that we insert 'complete' maps here, because we know we are going to add *ALL* values from
                // with this prefix.
                current_value = map.entry(index).or_insert_with(StorageValue::complete_map);
            }

            *current_value = if let Some(cached) = current_cached {
                cached.clone()
            } else if disk_indices_len == 0 && self.fork.scilla_empty_maps_are_encoded_correctly {
                // Map is empty and has no entries represented in the storage (disk indices are empty)
                StorageValue::complete_map()
            } else {
                StorageValue::Value(Some(v.into()))
            };
        }

        let map = match map {
            StorageValue::Map { map, .. } => map,
            StorageValue::Value(_) => {
                return Err(anyhow!("expected map"));
            }
        };

        Ok(map)
    }

    #[track_caller]
    pub fn deduct_from_account(
        &mut self,
        address: Address,
        amount: ZilAmount,
        gas_used: EvmGas,
    ) -> Result<Option<ScillaResult>> {
        let caller = std::panic::Location::caller();
        let account = self.load_account(address)?;
        account.mark_touch();
        trace!(
            "account balance = {0} sub {1}",
            account.account.balance,
            amount.get()
        );
        let Some(balance) = account.account.balance.checked_sub(amount.get()) else {
            info!("insufficient balance: {caller}");
            return Ok(Some(ScillaResult {
                success: false,
                contract_address: None,
                logs: vec![],
                gas_used,
                transitions: vec![],
                accepted: None,
                errors: [(0, vec![ScillaError::BalanceTransferFailed])]
                    .into_iter()
                    .collect(),
                exceptions: vec![],
            }));
        };
        account.account.balance = balance;
        Ok(None)
    }

    /// Return the changed state and resets the [PendingState] to its initial state in [PendingState::new].
    pub fn finalize(&mut self) -> HashMap<Address, PendingAccount> {
        mem::take(&mut self.new_state)
    }
}

#[derive(Clone, Debug)]
pub struct PendingAccount {
    pub account: Account,
    /// Cached values of updated or deleted storage. Note that deletions can happen at any level of a map.
    pub storage: BTreeMap<String, StorageValue>,
    pub from_evm: bool,
    pub touched: bool,
}

impl PendingAccount {
    pub fn mark_touch(&mut self) {
        self.touched = true;
    }
}

#[derive(Debug, Clone)]
pub enum StorageValue {
    Map {
        map: BTreeMap<Vec<u8>, StorageValue>,
        complete: bool,
    },
    /// A value can either be `Some(bytes)` to represent an updated value or `None` to represent a deleted value.
    Value(Option<Bytes>),
}

impl StorageValue {
    pub fn incomplete_map() -> StorageValue {
        StorageValue::Map {
            map: BTreeMap::new(),
            complete: false,
        }
    }

    pub fn complete_map() -> StorageValue {
        StorageValue::Map {
            map: BTreeMap::new(),
            complete: true,
        }
    }
}

impl From<Account> for PendingAccount {
    fn from(account: Account) -> PendingAccount {
        PendingAccount {
            account,
            storage: BTreeMap::new(),
            from_evm: false,
            touched: false,
        }
    }
}

pub fn store_external_libraries(
    state: &State,
    scilla_ext_libs_path: &ScillaExtLibsPath,
    ext_libraries: Vec<ExternalLibrary>,
) -> Result<(ScillaExtLibsPathInZq2, ScillaExtLibsPathInScilla)> {
    let (ext_libs_dir_in_zq2, ext_libs_dir_in_scilla) =
        scilla_ext_libs_path.generate_random_subdirs();

    let ext_libs_path = Path::new(&ext_libs_dir_in_zq2.0);
    std::fs::create_dir_all(ext_libs_path)?;

    for mut lib in ext_libraries {
        let account = state.get_account(lib.address)?;
        match &account.code {
            Code::Evm(_) => {
                return Err(anyhow!(
                    "Impossible to load an EVM contract as a Scilla library."
                ));
            }
            Code::Scilla {
                code, init_data, ..
            } => {
                let contract_init = ContractInit::new(init_data.clone());
                if !contract_init.is_library()? {
                    return Err(anyhow!(
                        "Impossible to load a non-library contract as a Scilla library."
                    ));
                }

                lib.name.retain(|c| c.is_alphanumeric() || c == '.');
                let file_path = ext_libs_path.join(&lib.name);

                fs::write(&file_path, code).with_context(|| {
                    format!("Failed to write the contract code to {:?}. library name: {}, library address: {}", file_path, lib.name, lib.address)
                })?;
            }
        }
    }
    Ok((ext_libs_dir_in_zq2, ext_libs_dir_in_scilla))
}

#[allow(clippy::too_many_arguments)]
fn scilla_create(
    mut state: PendingState,
    scilla: MutexGuard<'_, Scilla>,
    from_addr: Address,
    txn: TxZilliqa,
    current_block: BlockHeader,
    mut inspector: impl ScillaInspector,
    scilla_ext_libs_path: &ScillaExtLibsPath,
    fork: &Fork,
) -> Result<(ScillaResult, PendingState)> {
    if txn.data.is_empty() {
        return Err(anyhow!("contract creation without init data"));
    }

    let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
        txn.gas_limit.into()
    } else {
        EvmGas(0)
    };

    if let Some(result) = state.deduct_from_account(from_addr, txn.amount, gas_used)? {
        return Ok((result, state));
    }

    // The contract address is created with the account's current nonce. The transaction's nonce is one greater
    // than this.
    let contract_address = zil_contract_address(from_addr, txn.nonce - 1);

    let mut init_data: Vec<ParamValue> = serde_json::from_str(&txn.data)?;
    if !fork.scilla_json_preserve_order {
        for param_value in init_data.iter_mut() {
            param_value.value.sort_all_objects();
        }
    }

    init_data.extend([
        ParamValue {
            name: "_creation_block".to_string(),
            value: Value::String(current_block.number.to_string()),
            ty: "BNum".to_string(),
        },
        ParamValue {
            name: "_this_address".to_string(),
            value: Value::String(format!("{contract_address:#x}")),
            ty: "ByStr20".to_string(),
        },
    ]);

    let gas = txn.gas_limit;

    let Some(gas) = gas.checked_sub(constants::SCILLA_INVOKE_CHECKER) else {
        warn!("not enough gas to invoke scilla checker");
        let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
            txn.gas_limit.into()
        } else {
            (txn.gas_limit - gas).into()
        };
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used,
                transitions: vec![],
                accepted: Some(false),
                errors: [(0, vec![ScillaError::GasNotSufficient])]
                    .into_iter()
                    .collect(),
                exceptions: vec![],
            },
            state,
        ));
    };

    let contract_init = ContractInit::new(init_data.clone());

    // We need to store external libraries used in the current contract. Scilla checker needs to import them to check the contract.
    let (ext_libs_dir_in_zq2, ext_libs_dir_in_scilla) = store_external_libraries(
        &state.pre_state,
        scilla_ext_libs_path,
        contract_init.external_libraries()?,
    )?;

    let _cleanup_ext_libs_guard = scopeguard::guard((), |_| {
        // We need to ensure that in any case, the external libs directory will be removed.
        let _ = std::fs::remove_dir_all(ext_libs_dir_in_zq2.0);
    });

    let check_output =
        match scilla.check_contract(&txn.code, gas, &contract_init, &ext_libs_dir_in_scilla)? {
            Ok(o) => o,
            Err(e) => {
                warn!(?e, "transaction failed");
                let gas = gas.min(e.gas_remaining);
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: Some(contract_address),
                        logs: vec![],
                        gas_used: (txn.gas_limit - gas).into(),
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(0, vec![ScillaError::CreateContractFailed])]
                            .into_iter()
                            .collect(),
                        exceptions: e.errors.into_iter().map(Into::into).collect(),
                    },
                    state,
                ));
            }
        };

    debug!(?check_output);

    let gas = gas.min(check_output.gas_remaining);

    // If the contract is a library, contract info is empty.
    let contract_info = check_output.contract_info.unwrap_or_default();
    let types = contract_info
        .fields
        .into_iter()
        .map(|p| (p.name, (p.ty, p.depth as u8)))
        .collect();

    let transitions = contract_info.transitions;

    let account = state.load_account(contract_address)?;
    account.mark_touch();
    if fork.scilla_contract_creation_increments_account_balance {
        account.account.balance += txn.amount.get();
    } else {
        account.account.balance = txn.amount.get();
    }
    account.account.code = Code::Scilla {
        code: txn.code.clone(),
        init_data,
        types,
        transitions,
    };

    let Some(gas) = gas.checked_sub(constants::SCILLA_INVOKE_RUNNER) else {
        warn!("not enough gas to invoke scilla runner");
        let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
            txn.gas_limit.into()
        } else {
            (txn.gas_limit - gas).into()
        };
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used,
                transitions: vec![],
                accepted: Some(false),
                errors: [(0, vec![ScillaError::GasNotSufficient])]
                    .into_iter()
                    .collect(),
                exceptions: vec![],
            },
            state,
        ));
    };

    let (create_output, state) = scilla.create_contract(
        state,
        contract_address,
        &txn.code,
        gas,
        txn.amount,
        &contract_init,
        &ext_libs_dir_in_scilla,
        fork,
        current_block.number,
    )?;
    let create_output = match create_output {
        Ok(o) => o,
        Err(e) => {
            warn!(?e, "transaction failed");
            let gas = gas.min(e.gas_remaining);
            return Ok((
                ScillaResult {
                    success: false,
                    contract_address: Some(contract_address),
                    logs: vec![],
                    gas_used: (txn.gas_limit - gas).into(),
                    transitions: vec![],
                    accepted: Some(false),
                    errors: [(0, vec![ScillaError::CreateContractFailed])]
                        .into_iter()
                        .collect(),
                    exceptions: e.errors.into_iter().map(Into::into).collect(),
                },
                state,
            ));
        }
    };

    debug!(?create_output);

    let gas = gas.min(create_output.gas_remaining);

    inspector.create(from_addr, contract_address, txn.amount.get());

    Ok((
        ScillaResult {
            success: true,
            contract_address: Some(contract_address),
            logs: vec![],
            gas_used: (txn.gas_limit - gas).into(),
            transitions: vec![],
            accepted: None,
            errors: BTreeMap::new(),
            exceptions: vec![],
        },
        state,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn scilla_call(
    state: PendingState,
    scilla: MutexGuard<'_, Scilla>,
    from_addr: Address,
    sender: Address,
    gas_limit: ScillaGas,
    to_addr: Address,
    amount: ZilAmount,
    data: String,
    mut inspector: impl ScillaInspector,
    scilla_ext_libs_path: &ScillaExtLibsPath,
    fork: &Fork,
    current_block: u64,
) -> Result<(ScillaResult, PendingState)> {
    let mut gas = gas_limit;

    let message = if !data.is_empty() {
        let mut m: Value = serde_json::from_str(&data)?;
        m["_amount"] = amount.to_string().into();
        m["_sender"] = format!("{sender:#x}").into();
        m["_origin"] = format!("{from_addr:#x}").into();
        Some(m)
    } else {
        None
    };

    let mut call_stack = vec![(0, sender, to_addr, amount, message)];
    let mut logs = vec![];
    let mut transitions = vec![];
    let mut root_contract_accepted = false;

    let mut state = Some(state);

    while let Some((depth, sender, to_addr, amount, message)) = call_stack.pop() {
        let mut current_state = state.take().expect("missing state");

        let contract = current_state.load_account(to_addr)?;
        let code_and_data = match &contract.account.code {
            // Note that EOAs are represented by [Code::Evm] with no code.
            Code::Evm(code) if fork.scilla_messages_can_call_evm_contracts || code.is_empty() => {
                None
            }
            Code::Scilla {
                code, init_data, ..
            } => Some((code, init_data)),
            // Calls to EVM contracts should fail because `fork.scilla_messages_can_call_evm_contract == false`.
            Code::Evm(_) => {
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used: (gas_limit - gas).into(),
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(depth, vec![ScillaError::CallContractFailed])]
                            .into_iter()
                            .collect(),
                        exceptions: vec![ScillaException {
                            line: 0,
                            message: "Scilla call to EVM contract".to_owned(),
                        }],
                    },
                    current_state,
                ));
            }
        };

        if let Some((code, init_data)) = code_and_data {
            // The `to_addr` is a Scilla contract, so we are going to invoke the Scilla interpreter.

            let Some(g) = gas.checked_sub(constants::SCILLA_INVOKE_RUNNER) else {
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    gas_limit.into()
                } else {
                    (gas_limit - gas).into()
                };
                warn!("not enough gas to invoke scilla runner");
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used,
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(depth, vec![ScillaError::GasNotSufficient])]
                            .into_iter()
                            .collect(),
                        exceptions: vec![],
                    },
                    current_state,
                ));
            };
            gas = g;

            let code = code.clone();

            let contract_init = ContractInit::new(init_data.clone());

            let contract_balance = contract.account.balance;

            // We need to store external libraries used in the current contract. Scilla needs to import them to run the transition.
            let (ext_libs_dir_in_zq2, ext_libs_dir_in_scilla) = store_external_libraries(
                &current_state.pre_state,
                scilla_ext_libs_path,
                contract_init.external_libraries()?,
            )?;
            let _cleanup_ext_libs_guard = scopeguard::guard((), |_| {
                // We need to ensure that in any case, the external libs directory will be removed.
                let _ = std::fs::remove_dir_all(ext_libs_dir_in_zq2.0);
            });
            let (output, mut new_state) = scilla.invoke_contract(
                current_state,
                to_addr,
                &code,
                gas,
                ZilAmount::from_amount(contract_balance),
                &contract_init,
                message
                    .as_ref()
                    .ok_or_else(|| anyhow!("call to a Scilla contract without a message"))?,
                &ext_libs_dir_in_scilla,
                fork,
                current_block,
            )?;
            inspector.call(sender, to_addr, amount.get(), depth);

            let mut output = match output {
                Ok(o) => o,
                Err(e) => {
                    warn!(?e, "transaction failed");
                    let gas = gas.min(e.gas_remaining);
                    return Ok((
                        ScillaResult {
                            success: false,
                            contract_address: None,
                            logs: vec![],
                            gas_used: (gas_limit - gas).into(),
                            transitions: vec![],
                            accepted: Some(false),
                            errors: [(0, vec![ScillaError::CallContractFailed])]
                                .into_iter()
                                .collect(),
                            exceptions: e.errors.into_iter().map(Into::into).collect(),
                        },
                        new_state,
                    ));
                }
            };

            debug!(?output);

            gas = gas.min(output.gas_remaining);

            if output.accepted {
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    (gas_limit - gas).into()
                } else {
                    EvmGas(0)
                };

                if let Some(result) = new_state.deduct_from_account(sender, amount, gas_used)? {
                    return Ok((result, new_state));
                }

                let to = new_state.load_account(to_addr)?;
                to.mark_touch();
                to.account.balance += amount.get();

                if depth == 0 {
                    root_contract_accepted = true;
                }
            }

            transitions.reserve(output.messages.len());
            call_stack.reserve(output.messages.len());

            // Ensure the order is preserved and transitions are dispatched in the same order
            // as they were emitted from contract
            if fork.scilla_transition_proper_order {
                output.messages.reverse();
            }

            for message in output.messages {
                transitions.push(ScillaTransition {
                    from: to_addr,
                    to: message.recipient,
                    depth: depth + 1,
                    amount: message.amount,
                    tag: message.tag.clone(),
                    params: serde_json::to_string(&message.params)?,
                });

                let next_message = json!({
                    "_tag": message.tag,
                    "_amount": message.amount.to_string(),
                    "_sender": format!("{to_addr:#x}"),
                    "_origin": format!("{from_addr:#x}"),
                    "params": message.params,
                });
                call_stack.push((
                    depth + 1,
                    to_addr,
                    message.recipient,
                    message.amount,
                    Some(next_message),
                ));
            }

            logs.reserve(output.events.len());
            for event in output.events {
                let log = ScillaLog {
                    address: to_addr,
                    event_name: event.event_name,
                    params: event.params,
                };
                logs.push(log);
            }

            state = Some(new_state);
        } else {
            // The `to_addr` is an EOA.
            let Some(g) = gas.checked_sub(constants::SCILLA_TRANSFER) else {
                warn!("not enough gas to make transfer");
                let gas_used: EvmGas = if fork.scilla_failed_txn_correct_gas_fee_charged {
                    gas_limit.into()
                } else {
                    (gas_limit - gas).into()
                };
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used,
                        transitions: vec![],
                        accepted: Some(false),
                        errors: [(0, vec![ScillaError::GasNotSufficient])]
                            .into_iter()
                            .collect(),
                        exceptions: vec![],
                    },
                    current_state,
                ));
            };
            gas = g;

            let deduct_funds_from = match fork.scilla_deduct_funds_from_actual_sender {
                true => sender,
                false => from_addr,
            };

            let gas_left = if fork.scilla_failed_txn_correct_gas_fee_charged {
                gas.into()
            } else {
                EvmGas(0)
            };

            let gas_used = if fork.failed_zil_transfers_to_eoa_proper_fee_deduction {
                EvmGas::from(gas_limit) - gas_left
            } else {
                gas_left
            };

            if let Some(result) =
                current_state.deduct_from_account(deduct_funds_from, amount, gas_used)?
            {
                return Ok((result, current_state));
            }

            let to = current_state.load_account(to_addr)?;
            to.mark_touch();
            to.account.balance += amount.get();

            inspector.transfer(from_addr, to_addr, amount.get(), depth);

            state = Some(current_state);
        }
    }

    Ok((
        ScillaResult {
            success: true,
            contract_address: None,
            logs,
            gas_used: (gas_limit - gas).into(),
            transitions,
            accepted: Some(root_contract_accepted),
            errors: BTreeMap::new(),
            exceptions: vec![],
        },
        state.take().expect("missing state"),
    ))
}

pub struct BlessedTransaction {
    pub hash: Hash,
    pub payload: Bytes,
    pub sender: Address,
    pub gas_limit: u64,
}

/// Blessed transactions bypass minimum gas price rules. These transactions have value to the network even at a lower
/// gas price, so we accept them anyway.
// It i s valuable to accept these transactions despite the low gas price, because it means the contract is deployed at the same address as other EVM-compatible chains.
// This means that contracts deployed using this proxy will be deployed to the same address as on other chains.
pub const BLESSED_TRANSACTIONS: [BlessedTransaction; 2] = [
    // Hash of the deployment transaction for the deterministic deployment proxy from
    // https://github.com/Arachnid/deterministic-deployment-proxy
    BlessedTransaction {
        hash: Hash(hex!(
            "eddf9e61fb9d8f5111840daef55e5fde0041f5702856532cdbb5a02998033d26"
        )),
        payload: Bytes::from_static(&hex!(
            "0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222"
        )),
        gas_limit: 1_000_000,
        sender: address!("0x3fab184622dc19b6109349b94811493bf2a45362"),
    },
    // Hash of the deployment transaction for the Multicall3
    // https://github.com/mds1/multicall?tab=readme-ov-file#new-deployments
    BlessedTransaction {
        hash: Hash(hex!(
            "0x07471adfe8f4ec553c1199f495be97fc8be8e0626ae307281c22534460184ed1"
        )),
        payload: Bytes::from_static(&hex!(
            "0xf90f538085174876e800830f42408080b90f00608060405234801561001057600080fd5b50610ee0806100206000396000f3fe6080604052600436106100f35760003560e01c80634d2301cc1161008a578063a8b0574e11610059578063a8b0574e1461025a578063bce38bd714610275578063c3077fa914610288578063ee82ac5e1461029b57600080fd5b80634d2301cc146101ec57806372425d9d1461022157806382ad56cb1461023457806386d516e81461024757600080fd5b80633408e470116100c65780633408e47014610191578063399542e9146101a45780633e64a696146101c657806342cbb15c146101d957600080fd5b80630f28c97d146100f8578063174dea711461011a578063252dba421461013a57806327e86d6e1461015b575b600080fd5b34801561010457600080fd5b50425b6040519081526020015b60405180910390f35b61012d610128366004610a85565b6102ba565b6040516101119190610bbe565b61014d610148366004610a85565b6104ef565b604051610111929190610bd8565b34801561016757600080fd5b50437fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0140610107565b34801561019d57600080fd5b5046610107565b6101b76101b2366004610c60565b610690565b60405161011193929190610cba565b3480156101d257600080fd5b5048610107565b3480156101e557600080fd5b5043610107565b3480156101f857600080fd5b50610107610207366004610ce2565b73ffffffffffffffffffffffffffffffffffffffff163190565b34801561022d57600080fd5b5044610107565b61012d610242366004610a85565b6106ab565b34801561025357600080fd5b5045610107565b34801561026657600080fd5b50604051418152602001610111565b61012d610283366004610c60565b61085a565b6101b7610296366004610a85565b610a1a565b3480156102a757600080fd5b506101076102b6366004610d18565b4090565b60606000828067ffffffffffffffff8111156102d8576102d8610d31565b60405190808252806020026020018201604052801561031e57816020015b6040805180820190915260008152606060208201528152602001906001900390816102f65790505b5092503660005b8281101561047757600085828151811061034157610341610d60565b6020026020010151905087878381811061035d5761035d610d60565b905060200281019061036f9190610d8f565b6040810135958601959093506103886020850185610ce2565b73ffffffffffffffffffffffffffffffffffffffff16816103ac6060870187610dcd565b6040516103ba929190610e32565b60006040518083038185875af1925050503d80600081146103f7576040519150601f19603f3d011682016040523d82523d6000602084013e6103fc565b606091505b50602080850191909152901515808452908501351761046d577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260846000fd5b5050600101610325565b508234146104e6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601a60248201527f4d756c746963616c6c333a2076616c7565206d69736d6174636800000000000060448201526064015b60405180910390fd5b50505092915050565b436060828067ffffffffffffffff81111561050c5761050c610d31565b60405190808252806020026020018201604052801561053f57816020015b606081526020019060019003908161052a5790505b5091503660005b8281101561068657600087878381811061056257610562610d60565b90506020028101906105749190610e42565b92506105836020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166105a66020850185610dcd565b6040516105b4929190610e32565b6000604051808303816000865af19150503d80600081146105f1576040519150601f19603f3d011682016040523d82523d6000602084013e6105f6565b606091505b5086848151811061060957610609610d60565b602090810291909101015290508061067d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b50600101610546565b5050509250929050565b43804060606106a086868661085a565b905093509350939050565b6060818067ffffffffffffffff8111156106c7576106c7610d31565b60405190808252806020026020018201604052801561070d57816020015b6040805180820190915260008152606060208201528152602001906001900390816106e55790505b5091503660005b828110156104e657600084828151811061073057610730610d60565b6020026020010151905086868381811061074c5761074c610d60565b905060200281019061075e9190610e76565b925061076d6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff166107906040850185610dcd565b60405161079e929190610e32565b6000604051808303816000865af19150503d80600081146107db576040519150601f19603f3d011682016040523d82523d6000602084013e6107e0565b606091505b506020808401919091529015158083529084013517610851577f08c379a000000000000000000000000000000000000000000000000000000000600052602060045260176024527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060445260646000fd5b50600101610714565b6060818067ffffffffffffffff81111561087657610876610d31565b6040519080825280602002602001820160405280156108bc57816020015b6040805180820190915260008152606060208201528152602001906001900390816108945790505b5091503660005b82811015610a105760008482815181106108df576108df610d60565b602002602001015190508686838181106108fb576108fb610d60565b905060200281019061090d9190610e42565b925061091c6020840184610ce2565b73ffffffffffffffffffffffffffffffffffffffff1661093f6020850185610dcd565b60405161094d929190610e32565b6000604051808303816000865af19150503d806000811461098a576040519150601f19603f3d011682016040523d82523d6000602084013e61098f565b606091505b506020830152151581528715610a07578051610a07576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601760248201527f4d756c746963616c6c333a2063616c6c206661696c656400000000000000000060448201526064016104dd565b506001016108c3565b5050509392505050565b6000806060610a2b60018686610690565b919790965090945092505050565b60008083601f840112610a4b57600080fd5b50813567ffffffffffffffff811115610a6357600080fd5b6020830191508360208260051b8501011115610a7e57600080fd5b9250929050565b60008060208385031215610a9857600080fd5b823567ffffffffffffffff811115610aaf57600080fd5b610abb85828601610a39565b90969095509350505050565b6000815180845260005b81811015610aed57602081850181015186830182015201610ad1565b81811115610aff576000602083870101525b50601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0169290920160200192915050565b600082825180855260208086019550808260051b84010181860160005b84811015610bb1578583037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe001895281518051151584528401516040858501819052610b9d81860183610ac7565b9a86019a9450505090830190600101610b4f565b5090979650505050505050565b602081526000610bd16020830184610b32565b9392505050565b600060408201848352602060408185015281855180845260608601915060608160051b870101935082870160005b82811015610c52577fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0888703018452610c40868351610ac7565b95509284019290840190600101610c06565b509398975050505050505050565b600080600060408486031215610c7557600080fd5b83358015158114610c8557600080fd5b9250602084013567ffffffffffffffff811115610ca157600080fd5b610cad86828701610a39565b9497909650939450505050565b838152826020820152606060408201526000610cd96060830184610b32565b95945050505050565b600060208284031215610cf457600080fd5b813573ffffffffffffffffffffffffffffffffffffffff81168114610bd157600080fd5b600060208284031215610d2a57600080fd5b5035919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81833603018112610dc357600080fd5b9190910192915050565b60008083357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1843603018112610e0257600080fd5b83018035915067ffffffffffffffff821115610e1d57600080fd5b602001915036819003821315610a7e57600080fd5b8183823760009101908152919050565b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc1833603018112610dc357600080fd5b600082357fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa1833603018112610dc357600080fdfea2646970667358221220bb2b5c71a328032f97c676ae39a1ec2148d3e5d6f73d95e9b17910152d61f16264736f6c634300080c00331ca0edce47092c0f398cebf3ffc267f05c8e7076e3b89445e0fe50f6332273d4569ba01b0b9d000e19b24c5869b0fc3b22b0d6fa47cd63316875cbbd577d76e6fde086"
        )),
        gas_limit: 10_000_000,
        sender: address!("0x05f32B3cC3888453ff71B01135B34FF8e41263F2"),
    },
];
