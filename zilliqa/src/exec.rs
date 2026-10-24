mod blessed;
mod env;
mod estimate;
mod evm_calls;
mod pending_state;
mod post_exec_state;
mod results;
mod scilla_exec;

use alloy::primitives::{Address, U256};
use anyhow::{Result, anyhow};
use std::collections::HashMap;

use revm::{
    Inspector,
    context::{BlockEnv, CfgEnv, result::ResultAndState},
    context_interface::{
        TransactionType,
        either::Either,
        transaction::{AccessList, SignedAuthorization},
    },
};
use revm_context::TxEnv;
use tracing::info;

pub use blessed::{BLESSED_TRANSACTIONS, BlessedTransaction};
pub use env::{BaseFeeAndNonceCheck, ExecType, ExternalContext, ExtraOpts};
pub use pending_state::{DatabaseError, PendingAccount, PendingState, StorageValue};
pub(crate) use results::ScillaResultAndState;
pub use results::{
    ScillaError, ScillaException, ScillaResult, ScillaTransition, TransactionApplyResult,
};
pub use scilla_exec::{scilla_call, store_external_libraries, zil_contract_address};

use crate::{
    crypto::Hash,
    evm::{ZQ2Evm, ZQ2EvmContext, new_zq2_evm_ctx},
    inspector::{ScillaInspector, TouchedAddressInspector},
    message::BlockHeader,
    protocol,
    state::State,
    time::SystemTime,
    transaction::{EvmGas, Transaction, VerifiedTransaction},
};

impl State {
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
        authorization_list: Option<Vec<SignedAuthorization>>,
        current_block: BlockHeader,
        inspector: I,
        enable_inspector: bool,
        base_fee_and_nonce_check: BaseFeeAndNonceCheck,
        extra_opts: ExtraOpts,
    ) -> Result<(ResultAndState, HashMap<Address, PendingAccount>)> {
        let fork = self.forks.get(current_block.number);
        let (view_history, finalized_view) = if current_block.view
            < self.view_history.read().min_view
            && let Some(ckpt_view_history) = &self.ckpt_view_history
            && let Some(ckpt_finalized_view) = self.ckpt_finalized_view
        {
            (ckpt_view_history.clone(), ckpt_finalized_view)
        } else {
            (self.view_history.clone(), self.finalized_view)
        };

        let (spec_id, blob_excess_gas_and_price) = protocol::select_spec_and_blob_params(fork);

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

            let tx_type = if fork.inject_access_list || fork.use_max_gas_priority_fee {
                extra_opts.tx_type
            } else {
                TransactionType::Legacy
            };
            (tx_type, access_list, gas_priority_fee)
        };
        let pending_state = PendingState::new(self.clone(), fork.clone());

        let randao_mix_hash = if fork.randao_support {
            current_block.mix_hash.unwrap_or(current_block.hash)
        } else {
            let mut padded_view_number = [0u8; 32];
            padded_view_number[24..].copy_from_slice(&current_block.view.to_be_bytes());
            Hash::builder().with(padded_view_number).finalize()
        };

        let evm_ctx = new_zq2_evm_ctx(pending_state, external_context)
            .with_cfg({
                let mut cfg = CfgEnv::new_with_spec(spec_id);
                cfg.disable_eip3607 = extra_opts.disable_eip3607;
                cfg.chain_id = self.chain_id.eth;
                cfg.disable_base_fee = match base_fee_and_nonce_check {
                    BaseFeeAndNonceCheck::Validate => false,
                    BaseFeeAndNonceCheck::ValidateExceptBaseFee | BaseFeeAndNonceCheck::Ignore => {
                        true
                    }
                };
                cfg.disable_nonce_check = match base_fee_and_nonce_check {
                    BaseFeeAndNonceCheck::Validate
                    | BaseFeeAndNonceCheck::ValidateExceptBaseFee => false,
                    BaseFeeAndNonceCheck::Ignore => true,
                };
                cfg.disable_balance_check = match base_fee_and_nonce_check {
                    BaseFeeAndNonceCheck::Validate
                    | BaseFeeAndNonceCheck::ValidateExceptBaseFee => false,
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
                slot_num: 0,
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
            nonce: nonce.unwrap_or(u64::MAX),
            chain_id: Some(self.chain_id.eth),
            access_list,
            gas_priority_fee,
            blob_hashes: vec![],
            max_fee_per_blob_gas: 0,
            authorization_list: authorization_list
                .unwrap_or_default()
                .into_iter()
                .map(Either::Left)
                .collect(),
        };

        let result_and_state = {
            if enable_inspector {
                evm.inspect(tx)?
            } else {
                evm.transact(tx)?
            }
        };

        self.finalize_evm_outcome_legacy(
            &mut evm,
            result_and_state,
            fork,
            from_addr,
            to_addr,
            gas_price,
            max_priority_fee_per_gas,
            enable_inspector,
            extra_opts,
        )
    }

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
            let fork = self.forks.get(current_block.number).clone();

            if fork.zil_transfers_only_to_escrow {
                return self.apply_zil_transfer_to_escrow(
                    from_addr,
                    txn,
                    current_block,
                    inspector,
                    enable_inspector,
                );
            }

            if fork.disable_zilliqa_txn_execution {
                return Err(anyhow!(
                    "Zilliqa transaction execution is disabled at block {}",
                    current_block.number
                ));
            }
            let (result, state) =
                self.apply_transaction_scilla(from_addr, txn, current_block, inspector)?;

            self.commit_scilla_tx(&result, &state, from_addr, current_block.number)?;

            Ok(TransactionApplyResult::Scilla((result, state)))
        } else {
            let (ResultAndState { result, state }, scilla_state) = self.apply_transaction_evm(
                from_addr,
                txn.to_addr(),
                txn.max_fee_per_gas()?,
                txn.max_priority_fee_per_gas(),
                txn.gas_limit(),
                txn.amount()?,
                txn.payload().to_vec(),
                txn.nonce(),
                txn.access_list(),
                txn.authorization_list(),
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

            self.commit_evm_tx(&result, &state, &scilla_state, current_block.number)?;

            Ok(TransactionApplyResult::Evm(ResultAndState {
                result,
                state,
            }))
        }
    }
}
