//! Manages execution of transactions on state.

use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap},
    error::Error,
    fmt::{self, Display, Formatter},
    fs, mem,
    num::NonZeroU128,
    path::Path,
    sync::{Arc, MutexGuard},
};

use alloy::primitives::{hex, Address, Bytes, U256};
use anyhow::{anyhow, Context, Result};
use eth_trie::{EthTrie, Trie};
use ethabi::Token;
use jsonrpsee::types::ErrorObjectOwned;
use libp2p::PeerId;
use revm::{
    inspector_handle_register,
    primitives::{
        AccountInfo, BlockEnv, Bytecode, Env, ExecutionResult, HaltReason, HandlerCfg, Output,
        ResultAndState, SpecId, TxEnv, B256, KECCAK_EMPTY,
    },
    Database, DatabaseRef, Evm, GetInspector, Inspector,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, info, trace, warn};

use crate::{
    cfg::{Fork, ScillaExtLibsPath, ScillaExtLibsPathInScilla, ScillaExtLibsPathInZq2},
    constants, contracts,
    crypto::{Hash, NodePublicKey},
    db::TrieStorage,
    error::ensure_success,
    inspector::{self, ScillaInspector},
    message::{Block, BlockHeader},
    precompiles::{get_custom_precompiles, scilla_call_handle_register},
    scilla::{self, split_storage_key, storage_key, ParamValue, Scilla},
    state::{contract_addr, Account, Code, ContractInit, ExternalLibrary, State},
    time::SystemTime,
    transaction::{
        total_scilla_gas_price, EvmGas, EvmLog, Log, ScillaGas, ScillaLog, Transaction, TxZilliqa,
        VerifiedTransaction, ZilAmount,
    },
};

type ScillaResultAndState = (ScillaResult, HashMap<Address, PendingAccount>);

/// Data returned after applying a [Transaction] to [State].

#[derive(Clone)]
pub enum TransactionApplyResult {
    Evm(ResultAndState, Box<Env>),
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
            TransactionApplyResult::Evm(_, _) => None,
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
            TransactionApplyResult::Evm(_, _) => None,
            TransactionApplyResult::Scilla((ScillaResult { accepted, .. }, _)) => *accepted,
        }
    }

    pub fn exceptions(&self) -> &[ScillaException] {
        match self {
            TransactionApplyResult::Evm(_, _) => &[],
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
        (&self.pre_state).basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        (&self.pre_state).code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        (&self.pre_state).storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        (&self.pre_state).block_hash_ref(number)
    }
}

impl DatabaseRef for PendingState {
    type Error = DatabaseError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        (&self.pre_state).basic_ref(address)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        (&self.pre_state).code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        (&self.pre_state).storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        (&self.pre_state).block_hash_ref(number)
    }
}

impl Database for &State {
    type Error = DatabaseError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

impl DatabaseRef for &State {
    type Error = DatabaseError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if !self.has_account(address)? {
            return Ok(None);
        }

        let account = self.get_account(address)?;
        let code = Bytecode::new_raw(account.code.evm_code().unwrap_or_default().into());
        let account_info = AccountInfo {
            balance: U256::from(account.balance),
            nonce: account.nonce,
            code_hash: code.hash_slow(),
            code: Some(code),
        };

        Ok(Some(account_info))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let index = B256::new(index.to_be_bytes());

        let result = self.get_account_storage(address, index)?;

        Ok(U256::from_be_bytes(result.0))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(self
            .block_store
            .get_canonical_block_by_number(number)?
            .map(|block| B256::new(block.hash().0))
            .unwrap_or_default())
    }
}

/// The external context used by [Evm].
pub struct ExternalContext<'a, I> {
    pub inspector: I,
    pub fork: Fork,
    pub scilla_call_gas_exempt_addrs: &'a [Address],
    // This flag is only used for zq1 whitelisted contracts, and it's used to detect if the entire transaction should be marked as failed
    pub enforce_transaction_failure: bool,
    /// The caller of each call in the call-stack. This is needed because the `scilla_call` precompile needs to peek
    /// into the call-stack. This will always be non-empty and the first entry will be the transaction signer.
    pub callers: Vec<Address>,
}

impl<I: Inspector<PendingState>> GetInspector<PendingState> for ExternalContext<'_, I> {
    fn get_inspector(&mut self) -> &mut impl Inspector<PendingState> {
        &mut self.inspector
    }
}

// As per EIP-150
pub const MAX_EVM_GAS_LIMIT: EvmGas = EvmGas(5_500_000);

const SPEC_ID: SpecId = SpecId::SHANGHAI;

pub enum BaseFeeCheck {
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
        let (ResultAndState { result, mut state }, ..) = self.apply_transaction_evm(
            Address::ZERO,
            None,
            0,
            self.block_gas_limit,
            amount,
            creation_bytecode,
            None,
            BlockHeader::genesis(Hash::ZERO),
            inspector::noop(),
            false,
            BaseFeeCheck::Ignore,
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

                self.apply_delta_evm(&state)?;
                Ok(addr)
            }
            ExecutionResult::Success { .. } => Err(anyhow!("deployment did not create a contract")),
            ExecutionResult::Revert { .. } => Err(anyhow!("deployment reverted")),
            ExecutionResult::Halt { reason, .. } => Err(anyhow!("deployment halted: {reason:?}")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_transaction_evm<I: Inspector<PendingState> + ScillaInspector>(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        gas_price: u128,
        gas_limit: EvmGas,
        amount: u128,
        payload: Vec<u8>,
        nonce: Option<u64>,
        current_block: BlockHeader,
        inspector: I,
        enable_inspector: bool,
        base_fee_check: BaseFeeCheck,
    ) -> Result<(ResultAndState, HashMap<Address, PendingAccount>, Box<Env>)> {
        let mut padded_view_number = [0u8; 32];
        padded_view_number[24..].copy_from_slice(&current_block.view.to_be_bytes());

        let external_context = ExternalContext {
            inspector,
            fork: self.forks.get(current_block.number),
            scilla_call_gas_exempt_addrs: &self.scilla_call_gas_exempt_addrs,
            enforce_transaction_failure: false,
            callers: vec![from_addr],
        };
        let pending_state = PendingState::new(self.clone());
        let mut evm = Evm::builder()
            .with_db(pending_state)
            .with_block_env(BlockEnv {
                number: U256::from(current_block.number),
                coinbase: Address::ZERO,
                timestamp: U256::from(
                    current_block
                        .timestamp
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                gas_limit: U256::from(self.block_gas_limit.0),
                basefee: U256::from(self.gas_price),
                difficulty: U256::from(1),
                prevrandao: Some(Hash::builder().with(padded_view_number).finalize().into()),
                blob_excess_gas_and_price: None,
            })
            .with_external_context(external_context)
            .with_handler_cfg(HandlerCfg { spec_id: SPEC_ID })
            .append_handler_register(scilla_call_handle_register)
            .modify_cfg_env(|c| {
                c.chain_id = self.chain_id.eth;
                c.disable_base_fee = match base_fee_check {
                    BaseFeeCheck::Validate => false,
                    BaseFeeCheck::Ignore => true,
                };
            })
            .with_tx_env(TxEnv {
                caller: from_addr.0.into(),
                gas_limit: gas_limit.0,
                gas_price: U256::from(gas_price),
                transact_to: to_addr.into(),
                value: U256::from(amount),
                data: payload.clone().into(),
                nonce,
                chain_id: Some(self.chain_id.eth),
                access_list: vec![],
                gas_priority_fee: None,
                blob_hashes: vec![],
                max_fee_per_blob_gas: None,
                authorization_list: None,
            })
            .append_handler_register(|handler| {
                let precompiles = handler.pre_execution.load_precompiles();
                handler.pre_execution.load_precompiles = Arc::new(move || {
                    let mut precompiles = precompiles.clone();
                    precompiles.extend(get_custom_precompiles());
                    precompiles
                });
            });
        if enable_inspector {
            evm = evm.append_handler_register(inspector_handle_register);
        }
        let mut evm = evm.build();

        let mut result_and_state = evm.transact()?;
        let mut ctx_with_handler = evm.into_context_with_handler_cfg();

        // If the scilla precompile failed for whitelisted zq1 contract we mark the entire transaction as failed
        if ctx_with_handler
            .context
            .external
            .enforce_transaction_failure
        {
            result_and_state.state.clear();
            return Ok((
                ResultAndState {
                    result: ExecutionResult::Revert {
                        gas_used: result_and_state.result.gas_used(),
                        output: Bytes::default(),
                    },
                    state: result_and_state.state,
                },
                HashMap::new(),
                ctx_with_handler.context.evm.inner.env,
            ));
        }

        Ok((
            result_and_state,
            ctx_with_handler.context.evm.db.finalize(),
            ctx_with_handler.context.evm.inner.env,
        ))
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
        let mut state = PendingState::new(self.try_clone()?);

        // Issue 1509 - for Scilla transitions, follow the legacy ZQ1 behaviour of deducting a small amount
        // of gas for the invocation and the rest of the gas once the txn has run.

        // let gas_limit = txn.gas_limit;
        let gas_price = txn.gas_price;

        let deposit_gas = txn.get_deposit_gas()?;
        let deposit = total_scilla_gas_price(deposit_gas, gas_price);
        trace!("scilla_txn: gas_price {gas_price} deposit_gas {deposit_gas} deposit {deposit}");

        if let Some(result) = state.deduct_from_account(from_addr, deposit, EvmGas(0))? {
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
            )
        }?;

        let actual_gas_charged =
            total_scilla_gas_price(ScillaGas::from(result.gas_used), gas_price);
        let to_charge = actual_gas_charged.checked_sub(&deposit);
        trace!("scilla_txn: actual_gas_used {actual_gas_charged} to_charge = {to_charge:?}");
        if let Some(extra_charge) = to_charge {
            // Deduct the remaining gas.
            // If we fail, Zilliqa 1 deducts nothing at all, and neither do we.
            if let Some(result) =
                new_state.deduct_from_account(from_addr, extra_charge, EvmGas(0))?
            {
                trace!("scilla_txn: cannot deduct remaining gas - txn failed");
                let mut failed_state = PendingState::new(self.try_clone()?);
                return Ok((result, failed_state.finalize()));
            }
        }
        // If the txn doesn't fail, increment the nonce.
        let from = new_state.load_account(from_addr)?;
        from.account.nonce += 1;

        trace!("scilla_txn completed successfully");
        Ok((result, new_state.finalize()))
    }

    /// Apply a transaction to the account state.
    pub fn apply_transaction<I: Inspector<PendingState> + ScillaInspector>(
        &mut self,
        txn: VerifiedTransaction,
        current_block: BlockHeader,
        inspector: I,
        enable_inspector: bool,
    ) -> Result<TransactionApplyResult> {
        let hash = txn.hash;
        let from_addr = txn.signer;
        info!(?hash, ?txn, "executing txn");

        let blessed = BLESSED_TRANSACTIONS.contains(&hash);

        let txn = txn.tx.into_transaction();
        if let Transaction::Zilliqa(txn) = txn {
            let (result, state) =
                self.apply_transaction_scilla(from_addr, txn, current_block, inspector)?;

            self.apply_delta_scilla(&state)?;

            Ok(TransactionApplyResult::Scilla((result, state)))
        } else {
            let (ResultAndState { result, state }, scilla_state, env) = self
                .apply_transaction_evm(
                    from_addr,
                    txn.to_addr(),
                    txn.max_fee_per_gas(),
                    txn.gas_limit(),
                    txn.amount(),
                    txn.payload().to_vec(),
                    txn.nonce(),
                    current_block,
                    inspector,
                    enable_inspector,
                    if blessed {
                        BaseFeeCheck::Ignore
                    } else {
                        BaseFeeCheck::Validate
                    },
                )?;

            self.apply_delta_evm(&state)?;
            self.apply_delta_scilla(&scilla_state)?;

            Ok(TransactionApplyResult::Evm(
                ResultAndState { result, state },
                env,
            ))
        }
    }

    /// Applies a state delta from a Scilla execution to the state.
    fn apply_delta_scilla(&mut self, state: &HashMap<Address, PendingAccount>) -> Result<()> {
        for (&address, account) in state {
            let mut storage = self.get_account_trie(address)?;

            /// Recursively called internal function which assigns `value` at the correct key to `storage`.
            fn handle(
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
                        // function with the given value. Before each call, we need to make sure we update `inidices`
                        // to include the key. To avoid changing the length of the `Vec` in each iteration, we first
                        // add a dummy index (`vec![]`) and update it before each call.
                        indices.push(vec![]);
                        for (k, v) in map {
                            indices.last_mut().unwrap().clone_from(k);
                            handle(storage, var, v, indices)?;
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
                handle(&mut storage, var, value, &mut vec![])?;
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
        state: &revm::primitives::HashMap<Address, revm::primitives::Account>,
    ) -> Result<()> {
        for (&address, account) in state {
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
            let code = if account.info.code_hash == KECCAK_EMPTY {
                vec![]
            } else {
                account
                    .info
                    .code
                    .as_ref()
                    .expect("code_by_hash is not used")
                    .original_bytes()
                    .to_vec()
            };

            let account = Account {
                nonce: account.info.nonce,
                balance: account.info.balance.try_into()?,
                code: Code::Evm(code),
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

    pub fn leader(&self, view: u64, current_block: BlockHeader) -> Result<NodePublicKey> {
        let data = contracts::deposit::LEADER_AT_VIEW.encode_input(&[Token::Uint(view.into())])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            current_block,
        )?;
        let leader = ensure_success(result)?;

        NodePublicKey::from_bytes(
            &contracts::deposit::LEADER_AT_VIEW
                .decode_output(&leader)
                .unwrap()[0]
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
        info!("committee: {committee:?}");

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

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        current_block: BlockHeader,
        gas: Option<EvmGas>,
        gas_price: Option<u128>,
        value: u128,
    ) -> Result<u64> {
        let gas_price = gas_price.unwrap_or(self.gas_price);

        let mut max = gas.unwrap_or(MAX_EVM_GAS_LIMIT).0;
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
            value,
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
                EvmGas(mid),
                value,
                data.clone(),
                None,
                current_block,
                inspector::noop(),
                false,
                BaseFeeCheck::Validate,
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
        value: u128,
    ) -> Result<u64> {
        let (ResultAndState { result, .. }, ..) = self.apply_transaction_evm(
            from_addr,
            to_addr,
            gas_price,
            gas,
            value,
            data.clone(),
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeCheck::Validate,
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
            self.block_gas_limit,
            amount,
            data,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeCheck::Ignore,
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
            self.block_gas_limit,
            amount,
            data,
            None,
            current_block,
            inspector::noop(),
            false,
            BaseFeeCheck::Ignore,
        )?;
        self.apply_delta_evm(&state)?;

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
#[derive(Debug)]
pub struct PendingState {
    pub pre_state: State,
    pub new_state: HashMap<Address, PendingAccount>,
}

/// Private helper function for `PendingState::load_account`. The only difference is that the fields of `PendingState`
/// are passed explicitly. This means the borrow-checker can see the reference we return only borrows from the
/// `new_state` field and thus we can later use `pre_state` without an error.
fn load_account<'a>(
    pre_state: &State,
    new_state: &'a mut HashMap<Address, PendingAccount>,
    address: Address,
) -> Result<&'a mut PendingAccount> {
    match new_state.entry(address) {
        Entry::Occupied(entry) => Ok(entry.into_mut()),
        Entry::Vacant(vac) => {
            let account = pre_state.get_account(address)?;
            Ok(vac.insert(account.into()))
        }
    }
}

impl PendingState {
    pub fn new(state: State) -> Self {
        PendingState {
            pre_state: state,
            new_state: HashMap::new(),
        }
    }

    pub fn zil_chain_id(&self) -> u64 {
        self.pre_state.chain_id.zil()
    }

    pub fn get_canonical_block_by_number(&self, block_number: u64) -> Result<Option<Block>> {
        self.pre_state
            .block_store
            .get_canonical_block_by_number(block_number)
    }

    pub fn get_highest_canonical_block_number(&self) -> Result<Option<u64>> {
        self.pre_state
            .block_store
            .get_highest_canonical_block_number()
    }

    pub fn load_account(&mut self, address: Address) -> Result<&mut PendingAccount> {
        load_account(&self.pre_state, &mut self.new_state, address)
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
        let account = load_account(&self.pre_state, &mut self.new_state, address)?;

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
        let account = load_account(&self.pre_state, &mut self.new_state, address)?;

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
                .get(&storage_key(var_name, indices))?
                .map(Vec::<u8>::from);

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
        let account = load_account(&self.pre_state, &mut self.new_state, address)?;

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
        for (k, v) in values_from_disk {
            let (disk_var_name, disk_indices) = split_storage_key(&k)?;
            assert_eq!(var_name, disk_var_name);
            assert!(disk_indices.starts_with(indices));

            let mut current_value = &mut map;
            let mut current_cached = cached;

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

fn scilla_create(
    mut state: PendingState,
    scilla: MutexGuard<'_, Scilla>,
    from_addr: Address,
    txn: TxZilliqa,
    current_block: BlockHeader,
    mut inspector: impl ScillaInspector,
    scilla_ext_libs_path: &ScillaExtLibsPath,
) -> Result<(ScillaResult, PendingState)> {
    if txn.data.is_empty() {
        return Err(anyhow!("contract creation without init data"));
    }

    if let Some(result) = state.deduct_from_account(from_addr, txn.amount, EvmGas(0))? {
        return Ok((result, state));
    }

    // The contract address is created with the account's current nonce. The transaction's nonce is one greater
    // than this.
    let contract_address = zil_contract_address(from_addr, txn.nonce - 1);

    let mut init_data: Vec<ParamValue> = serde_json::from_str(&txn.data)?;

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
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
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

    info!(?check_output);

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
    account.account.balance = txn.amount.get();
    account.account.code = Code::Scilla {
        code: txn.code.clone(),
        init_data,
        types,
        transitions,
    };

    let Some(gas) = gas.checked_sub(constants::SCILLA_INVOKE_RUNNER) else {
        warn!("not enough gas to invoke scilla runner");
        return Ok((
            ScillaResult {
                success: false,
                contract_address: Some(contract_address),
                logs: vec![],
                gas_used: (txn.gas_limit - gas).into(),
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

    info!(?create_output);

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
            // EOAs are currently represented by [Code::Evm] with no code.
            Code::Evm(code) if code.is_empty() => None,
            Code::Scilla {
                code, init_data, ..
            } => Some((code, init_data)),
            // Calls to EVM contracts should fail.
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
                warn!("not enough gas to invoke scilla runner");
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used: (gas_limit - gas).into(),
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
            let init_data: Vec<_> = init_data
                .clone()
                .into_iter()
                .map(ParamValue::from)
                .collect();

            let contract_init = ContractInit::new(init_data);

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
            )?;
            inspector.call(sender, to_addr, amount.get(), depth);

            let output = match output {
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

            info!(?output);

            gas = gas.min(output.gas_remaining);

            if output.accepted {
                if let Some(result) = new_state.deduct_from_account(sender, amount, EvmGas(0))? {
                    return Ok((result, new_state));
                }

                let to = new_state.load_account(to_addr)?;
                to.account.balance += amount.get();

                if depth == 0 {
                    root_contract_accepted = true;
                }
            }

            transitions.reserve(output.messages.len());
            call_stack.reserve(output.messages.len());
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
                return Ok((
                    ScillaResult {
                        success: false,
                        contract_address: None,
                        logs: vec![],
                        gas_used: (gas_limit - gas).into(),
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

            if let Some(result) = current_state.deduct_from_account(from_addr, amount, EvmGas(0))? {
                return Ok((result, current_state));
            }

            let to = current_state.load_account(to_addr)?;
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

/// Blessed transactions bypass minimum gas price rules. These transactions have value to the network even at a lower
/// gas price, so we accept them anyway.
const BLESSED_TRANSACTIONS: [Hash; 1] = [
    // Hash of the deployment transaction for the deterministic deployment proxy from
    // https://github.com/Arachnid/deterministic-deployment-proxy. It is valuable to accept this transaction despite
    // the low gas price, because it means the contract is deployed at the same address as other EVM-compatible chains.
    // This means that contracts deployed using this proxy will be deployed to the same address as on other chains.
    Hash(hex!(
        "eddf9e61fb9d8f5111840daef55e5fde0041f5702856532cdbb5a02998033d26"
    )),
];
