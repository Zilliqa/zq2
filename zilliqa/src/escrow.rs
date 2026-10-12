use alloy::primitives::{Address, U256};
use anyhow::{Result, anyhow};
use ethabi::Token;
use revm::{
    Inspector,
    context::result::{ExecutionResult, ResultAndState, ResultGas},
};
use tracing::{debug, warn};

use crate::{
    cfg::{ConsensusConfig, Fork, ForkName},
    constants, contracts,
    error::ensure_success,
    escrow_raw_input::ENTRIES_PER_BLOCK,
    evm::ZQ2EvmContext,
    exec::{BaseFeeAndNonceCheck, ExecType, ExtraOpts, TransactionApplyResult},
    inspector::ScillaInspector,
    message::BlockHeader,
    state::{State, contract_addr},
    transaction::{EvmGas, Transaction, TxZilliqa},
};

impl State {
    /// Deploys each escrow contract exactly at the activation height of its fork
    /// (`deploy_escrow_contract_v1`, `deploy_escrow_mintable_contract_v1`). Never at any other
    /// block: deploying again would replace the proxy account outright, wiping its native
    /// balance and the lodged-deposit bookkeeping.
    pub fn escrow_deploy_and_upgrade(
        &mut self,
        _config: &ConsensusConfig,
        block_header: &BlockHeader,
    ) -> Result<()> {
        let height = Some(block_header.number);
        if self
            .forks
            .find_height_fork_first_activated(ForkName::DeployEscrowContractV1)
            == height
        {
            self.deploy_initial_escrow_contract()?;
        }
        if self
            .forks
            .find_height_fork_first_activated(ForkName::DeployEscrowMintableContractV1)
            == height
        {
            let admin = self.forks.escrow_mintable_admin_at(block_header.number);
            self.deploy_initial_escrow_mintable_contract(admin)?;
        }
        let deployed_earlier = self
            .forks
            .find_height_fork_first_activated(ForkName::DeployEscrowMintableContractV1)
            .is_some_and(|deploy_height| deploy_height < block_header.number);
        if deployed_earlier
            && let Some(admin) = self
                .forks
                .escrow_mintable_admin_change_at(block_header.number)
        {
            self.escrow_set_admin(admin, *block_header)?;
        }
        Ok(())
    }

    pub fn escrow_set_admin(&mut self, admin: Address, current_block: BlockHeader) -> Result<()> {
        let data = contracts::escrow_mintable_init::SET_ADMIN
            .encode_input(&[Token::Address(ethabi::Address::from(admin.into_array()))])?;
        let result = self.call_contract_apply(
            Address::ZERO,
            Some(contract_addr::ESCROW_MINTABLE_PROXY),
            data,
            0,
            current_block,
        )?;
        ensure_success(result)
            .map(|_| ())
            .map_err(|e| anyhow!("escrow setAdmin({admin}) failed: {e}"))
    }

    fn deploy_initial_escrow_mintable_contract(&mut self, admin: Address) -> Result<Address> {
        if admin.is_zero() {
            warn!("escrow_mintable_admin is unset; the mintable escrow pair whitelist is closed");
        }
        let escrow_impl = self.force_deploy_contract_evm(
            contracts::escrow_mintable_init::BYTECODE.to_vec(),
            None,
            0,
        )?;
        let eip1967_constructor_data =
            contracts::eip1967_proxy::CONSTRUCTOR.encode_input(
                contracts::eip1967_proxy::BYTECODE.to_vec(),
                &[
                    Token::Address(ethabi::Address::from(escrow_impl.into_array())),
                    Token::Bytes(contracts::escrow_mintable_init::INITIALIZE.encode_input(&[
                        Token::Address(ethabi::Address::from(admin.into_array())),
                    ])?),
                ],
            )?;
        let eip1967_addr = self.force_deploy_contract_evm(
            eip1967_constructor_data,
            Some(contract_addr::ESCROW_MINTABLE_PROXY),
            0,
        )?;
        debug!("Deployed mintable Escrow to {escrow_impl}@{eip1967_addr}",);
        Ok(escrow_impl)
    }

    pub fn escrow_lodge(
        &mut self,
        token: Address,
        entries: &[(Address, u128)],
        current_block: BlockHeader,
    ) -> Result<()> {
        for chunk in entries.chunks(ENTRIES_PER_BLOCK as usize) {
            self.escrow_lodge_call(token, chunk, current_block)?;
        }
        Ok(())
    }

    fn escrow_lodge_call(
        &mut self,
        token: Address,
        entries: &[(Address, u128)],
        current_block: BlockHeader,
    ) -> Result<()> {
        let (users, amounts): (Vec<Token>, Vec<Token>) = entries
            .iter()
            .map(|(user, amount)| {
                (
                    Token::Address(ethabi::Address::from(user.into_array())),
                    Token::Uint((*amount).into()),
                )
            })
            .unzip();
        let data = contracts::escrow_mintable_init::LODGE.encode_input(&[
            Token::Address(ethabi::Address::from(token.into_array())),
            Token::Array(users),
            Token::Array(amounts),
        ])?;
        let result = self.call_contract_apply(
            Address::ZERO,
            Some(contract_addr::ESCROW_MINTABLE_PROXY),
            data,
            0,
            current_block,
        )?;
        ensure_success(result).map(|_| ()).map_err(|e| {
            anyhow!(
                "escrow lodge of {} entries into {token} failed: {e}",
                entries.len()
            )
        })
    }

    fn deploy_initial_escrow_contract(&mut self) -> Result<Address> {
        let escrow_impl =
            self.force_deploy_contract_evm(contracts::escrow_init::BYTECODE.to_vec(), None, 0)?;
        let eip1967_constructor_data = contracts::eip1967_proxy::CONSTRUCTOR.encode_input(
            contracts::eip1967_proxy::BYTECODE.to_vec(),
            &[
                Token::Address(ethabi::Address::from(escrow_impl.into_array())),
                Token::Bytes(vec![]),
            ],
        )?;
        let eip1967_addr = self.force_deploy_contract_evm(
            eip1967_constructor_data,
            Some(contract_addr::ESCROW_PROXY),
            0,
        )?;
        debug!("Deployed Escrow to {escrow_impl}@{eip1967_addr}",);
        Ok(escrow_impl)
    }

    pub(crate) fn apply_zil_transfer_to_escrow<I: Inspector<ZQ2EvmContext> + ScillaInspector>(
        &mut self,
        from_addr: Address,
        txn: TxZilliqa,
        current_block: BlockHeader,
        inspector: I,
        enable_inspector: bool,
        fork: &Fork,
    ) -> Result<TransactionApplyResult> {
        let to_escrow = txn.to_addr == contract_addr::ESCROW_PROXY;
        let generic = Transaction::Zilliqa(txn);

        let payload = if to_escrow {
            contracts::escrow_init::LODGE.encode_input(&[])?
        } else {
            Vec::new()
        };

        let flat_fee_gas = EvmGas::from(constants::SCILLA_TRANSFER);
        let flat_fee = (flat_fee_gas.0 as u128)
            .checked_mul(generic.max_fee_per_gas()?)
            .ok_or_else(|| anyhow!("escrow deposit fee overflows"))?;
        let amount = generic.amount()?;

        // The sender must still have offered the standard transfer gas - never charge
        // beyond the limit they signed. Transaction validation already requires this;
        // this guards blocks built by a faulty proposer.
        if generic.gas_limit() < flat_fee_gas {
            return Err(anyhow!(
                "escrow deposit gas limit {} below the flat fee's {flat_fee_gas}",
                generic.gas_limit()
            ));
        }

        // With a zero gas price, revm's upfront balance check only covers `amount`; this
        // extends it to the fee actually charged, mirroring `LackOfFundForMaxFee`: the
        // transaction is dropped without executing. A sender sweeping their entire
        // balance minus the standard transfer fee passes exactly.
        let required = amount
            .checked_add(flat_fee)
            .ok_or_else(|| anyhow!("escrow deposit cost overflows"))?;
        let sender_balance = self.get_account(from_addr)?.balance;
        if sender_balance < required {
            return Err(anyhow!(
                "insufficient funds for escrow deposit: balance {sender_balance} < amount {amount} + fee {flat_fee}"
            ));
        }

        let (ResultAndState { result, mut state }, scilla_state) = self.apply_transaction_evm(
            from_addr,
            Some(contract_addr::ESCROW_PROXY),
            0,
            None,
            self.block_gas_limit,
            amount,
            payload,
            generic.nonce(),
            generic.access_list(),
            generic.authorization_list(),
            current_block,
            inspector,
            enable_inspector,
            BaseFeeAndNonceCheck::ValidateExceptBaseFee,
            ExtraOpts {
                disable_eip3607: false,
                exec_type: ExecType::Transact,
                tx_type: generic.revm_transaction_type(),
            },
        )?;

        let sender = state
            .get_mut(&from_addr)
            .ok_or_else(|| anyhow!("sender missing from escrow deposit state delta"))?;
        sender.info.balance = sender.info.balance.saturating_sub(U256::from(flat_fee));

        // Nothing downstream debits the sender from `gas_used`, but it must equal the
        // flat fee's gas: block assembly credits the zero account with
        // `gas_used * gas_price` (ZIP-9), so reporting the real usage would credit more
        // than the fee deducted above, minting the difference.
        let flat_fee_result_gas = ResultGas::default().with_total_gas_spent(flat_fee_gas.0);
        let result = match result {
            ExecutionResult::Success {
                reason,
                logs,
                output,
                ..
            } => ExecutionResult::Success {
                reason,
                gas: flat_fee_result_gas,
                logs,
                output,
            },
            ExecutionResult::Revert { logs, output, .. } => ExecutionResult::Revert {
                gas: flat_fee_result_gas,
                logs,
                output,
            },
            ExecutionResult::Halt { reason, logs, .. } => ExecutionResult::Halt {
                reason,
                gas: flat_fee_result_gas,
                logs,
            },
        };

        self.apply_delta_evm(&state, current_block.number)?;
        if fork.apply_scilla_delta_when_evm_succeeded {
            if let ExecutionResult::Success { .. } = result {
                self.apply_delta_scilla(&scilla_state, Some(&state), current_block.number)?;
            }
        } else {
            self.apply_delta_scilla(&scilla_state, Some(&state), current_block.number)?;
        }

        Ok(TransactionApplyResult::Evm(ResultAndState {
            result,
            state,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        cfg::{DbConfig, Fork, NodeConfig, genesis_fork_default},
        crypto::Hash,
        db::Db,
        inspector,
        schnorr::{self, SecretKey},
        transaction::{ScillaGas, SignedTransaction, TxZilliqa, VerifiedTransaction, ZilAmount},
    };

    /// A funded `State` on a fork where legacy Zilliqa transactions are only permitted to the
    /// escrow contract, plus the signer address a `zil_txn` built with `SIGNER_SEED` recovers to.
    const SIGNER_SEED: u8 = 0x42;

    fn state_with_escrow_fork() -> (State, Address) {
        let db = Arc::new(Db::new::<PathBuf>(None, 0, None, DbConfig::default()).unwrap());
        let mut config = NodeConfig::default();
        config.consensus.genesis_fork = Fork {
            zil_transfers_only_to_escrow: true,
            deploy_escrow_contract_v1: true,
            disable_zilliqa_txn_execution: false,
            ..genesis_fork_default()
        };
        let mut state = State::new(db.state_trie().unwrap(), &config, db).unwrap();
        state
            .escrow_deploy_and_upgrade(&config.consensus, &BlockHeader::genesis(Hash::ZERO))
            .unwrap();

        let secret_key = SecretKey::from_slice(&[SIGNER_SEED; 32]).unwrap();
        let signer = zil_signer_address(&secret_key);
        state
            .mutate_account(signer, |a| {
                a.balance = 10u128.pow(24);
                Ok(())
            })
            .unwrap();

        (state, signer)
    }

    fn zil_signer_address(secret_key: &SecretKey) -> Address {
        let public_key = secret_key.public_key();
        let hashed = Sha256::digest(public_key.to_encoded_point(true).as_bytes());
        Address::from_slice(&hashed[12..])
    }

    /// A `TxZilliqa` for `SIGNER_SEED`'s signer, wrapped and verified. `verify_bypass` skips the
    /// signature check, so the signature itself doesn't need to be genuine - only the public key,
    /// which is what the signer address is derived from.
    fn zil_txn(nonce: u64, to_addr: Address, amount: u128, gas_limit: u64) -> VerifiedTransaction {
        let secret_key = SecretKey::from_slice(&[SIGNER_SEED; 32]).unwrap();
        let public_key = secret_key.public_key();
        let tx = TxZilliqa {
            chain_id: 1,
            nonce,
            // High enough to clear NodeConfig::default()'s block gas price once converted from
            // ScillaGas via EVM_GAS_PER_SCILLA_GAS.
            gas_price: ZilAmount::from_raw(3_000_000_000),
            gas_limit: ScillaGas(gas_limit),
            to_addr,
            amount: ZilAmount::from_amount(amount),
            code: String::new(),
            data: String::new(),
        };
        let sig = schnorr::sign(b"unused under verify_bypass", &secret_key);
        SignedTransaction::Zilliqa {
            tx,
            key: public_key,
            sig,
        }
        .verify_bypass(Hash::ZERO)
        .unwrap()
    }

    #[test]
    fn zil_transfer_to_escrow_lodges_with_signer_as_origin_and_sender() {
        let (mut state, signer) = state_with_escrow_fork();
        let amount = 10u128.pow(18);
        let header = BlockHeader::genesis(Hash::ZERO);

        let result = state
            .apply_transaction(
                zil_txn(1, contract_addr::ESCROW_PROXY, amount, 1000),
                header,
                inspector::noop(),
                false,
            )
            .unwrap();

        assert!(
            result.success(),
            "lodge() call to the escrow contract should succeed, gas_used = {:?}",
            result.gas_used()
        );
        assert_eq!(
            state
                .get_account(contract_addr::ESCROW_PROXY)
                .unwrap()
                .balance,
            amount,
            "the deposited value must land on the escrow contract"
        );
        assert_eq!(
            state.get_account(signer).unwrap().nonce,
            1,
            "the signer's nonce must be consumed exactly once"
        );
    }

    #[test]
    fn zil_transfer_to_other_address_fails_and_still_charges_gas() {
        let (mut state, signer) = state_with_escrow_fork();
        let other = Address::repeat_byte(0xAB);
        let amount = 10u128.pow(18);
        let balance_before = state.get_account(signer).unwrap().balance;
        let header = BlockHeader::genesis(Hash::ZERO);

        let result = state
            .apply_transaction(
                zil_txn(1, other, amount, 1000),
                header,
                inspector::noop(),
                false,
            )
            .unwrap();

        assert!(
            !result.success(),
            "a legacy Zilliqa transaction not addressed to the escrow contract must fail"
        );
        assert_eq!(
            state.get_account(other).unwrap().balance,
            0,
            "value must not move to the disallowed destination"
        );
        let balance_after = state.get_account(signer).unwrap().balance;
        assert!(
            balance_after < balance_before,
            "gas must still be charged even though the transaction failed"
        );
        assert!(
            balance_after > balance_before - amount,
            "only gas should be deducted, not the transfer amount"
        );
        assert_eq!(
            state.get_account(signer).unwrap().nonce,
            1,
            "the signer's nonce must still be consumed on a rejected destination"
        );
    }
}
