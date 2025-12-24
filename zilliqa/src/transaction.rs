use std::{
    cmp::{Ordering, PartialOrd, max},
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    ops::{Add, AddAssign, Sub},
    str::FromStr,
};

use alloy::{
    consensus::{
        SignableTransaction, TxEip1559, TxEip2930, TxLegacy, transaction::RlpEcdsaEncodableTx,
    },
    primitives::{Address, B256, Signature, TxKind, U256, keccak256},
    rlp::{EMPTY_STRING_CODE, Encodable, Header},
    sol_types::SolValue,
};
use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};
use itertools::Itertools;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use revm::context_interface::{TransactionType, transaction::AccessList};
use revm_context::TxEnv;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{
    Digest, Keccak256,
    digest::generic_array::{
        GenericArray,
        sequence::Split,
        typenum::{U12, U20},
    },
};
use tracing::warn;

use crate::{
    constants::{
        EVM_MAX_INIT_CODE_SIZE, EVM_MAX_TX_INPUT_SIZE, EVM_MIN_GAS_UNITS, SCILLA_INVOKE_RUNNER,
        SCILLA_TRANSFER, ZIL_CONTRACT_CREATE_GAS, ZIL_CONTRACT_INVOKE_GAS, ZIL_MAX_CODE_SIZE,
        ZIL_NORMAL_TXN_GAS,
    },
    crypto::{self, Hash},
    exec::{BLESSED_TRANSACTIONS, ScillaError, ScillaException, ScillaTransition},
    schnorr,
    scilla::ParamValue,
    serde_util::vec_param_value,
    state::Account,
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};

/// Represents a validation result.
/// This could be Result<String>, except that we would then return
/// Result<Result<String>>, which would be confusing.
/// The argument is a human-readable error message which can be returned to the
/// user to indicate the problem with the transaction.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ValidationOutcome {
    Success,
    /// Transaction input size exceeds configured limit - (size, limit)
    TransactionInputSizeExceeded(usize, usize),
    /// Transaction initcode size exceeds configured limit - (size, limit)
    InitCodeSizeExceeded(usize, usize),
    /// Gas limit exceeds block gas limit - (gas_limit, block_gas_limit)
    BlockGasLimitExceeded(EvmGas, EvmGas),
    /// Insufficient gas for zil transaction - (given, required)
    InsufficientGasZil(ScillaGas, ScillaGas),
    /// Insufficient gas for EVM transaction
    InsufficientGasEvm(EvmGas, EvmGas),
    /// Chain id was incorrect - (received, expected)
    IncorrectChainId(u64, u64),
    /// Insufficient funds in account - (txn_cost, account_balance)
    InsufficientFunds(u128, u128),
    /// Nonce too low - arg is the nonce we were expecting - (nonce, expected_nonce)
    NonceTooLow(u64, u64),
    /// Unrecognised type - not invocation, creation or transfer
    UnknownTransactionType,
    /// Global transaction count exceeded
    GlobalTransactionCountExceeded,
    /// Transaction counter exceeded for a sender
    TransactionCountExceededForSender,
    /// Total nunber of sender slots exceeded
    TotalNumberOfSlotsExceeded,
    /// Gas price is too low
    GasPriceTooLow,
}

impl ValidationOutcome {
    // I did try this with a vector, but sadly this involves too much
    // trait magic to be convenient.
    pub fn and_then<T>(&self, test: T) -> Result<ValidationOutcome>
    where
        T: FnOnce() -> Result<ValidationOutcome>,
    {
        if self.is_ok() { test() } else { Ok(*self) }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn to_msg_string(&self) -> String {
        match self {
            Self::Success => "Txn accepted".to_string(),
            Self::TransactionInputSizeExceeded(size, limit) => {
                format!("Transaction input size ({size}) exceeds limit ({limit})")
            }
            Self::InitCodeSizeExceeded(size, limit) => {
                format!("Init code size ({size}) exceeds limit ({limit})")
            }
            Self::BlockGasLimitExceeded(gas, limit) => {
                format!("Txn gas limit ({gas}) exceeeds block gas limit ({limit})")
            }
            Self::InsufficientGasZil(gas, limit) => {
                format!("Insufficient Zilliqa txn gas supplied ({gas}) - required ({limit})")
            }
            Self::InsufficientGasEvm(gas, limit) => {
                format!("Insufficient EVM txn gas supplied ({gas}) - required ({limit})")
            }
            Self::IncorrectChainId(got, wanted) => {
                format!("Txn has chain id {got}, expected chain {wanted}")
            }
            Self::InsufficientFunds(txn_cost, bal) => {
                format!("Insufficient funds - txn cost {txn_cost} but account balance {bal}")
            }
            Self::NonceTooLow(txn_nonce, expected) => {
                format!("Txn nonce ({txn_nonce}) is too low for account ({expected})")
            }
            Self::UnknownTransactionType => {
                "Txn is not transfer, contract creation or contract invocation".to_string()
            }
            Self::GlobalTransactionCountExceeded => {
                "Global number of transactions stored in the mempool has been exceeded!".to_string()
            }
            Self::TransactionCountExceededForSender => {
                "Transactions count kept per user has been exceeded!".to_string()
            }
            Self::TotalNumberOfSlotsExceeded => {
                "Total number of slots for all senders has been exceeded".to_string()
            }
            Self::GasPriceTooLow => "Provided gas price is too low".to_string(),
        }
    }
}

/// A [Transaction] plus its signature. The underlying transaction can be obtained with
/// [`SignedTransaction::into_transaction()`]. The transaction's signer and hash can be obtained by converting this to a
/// [VerifiedTransaction] with [`SignedTransaction::verify()`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignedTransaction {
    Legacy {
        #[serde(with = "ser_rlp")]
        tx: TxLegacy,
        sig: Signature,
    },
    Eip2930 {
        #[serde(with = "ser_rlp")]
        tx: TxEip2930,
        sig: Signature,
    },
    Eip1559 {
        #[serde(with = "ser_rlp")]
        tx: TxEip1559,
        sig: Signature,
    },
    Zilliqa {
        tx: TxZilliqa,
        key: schnorr::PublicKey,
        sig: schnorr::Signature,
    },
    Intershard {
        tx: TxIntershard,
        // no signature as the transaction can only originate from a local (trusted) process
        // instead use raw from-address
        from: Address,
    },
}

// alloy's transaction types contain annotations (such as `skip_serializing_if`) which cause issues when
// (de)serializing with serde. Therefore, we serialize these transactions in their RLP form instead.
mod ser_rlp {
    use std::marker::PhantomData;

    use alloy::rlp::{Decodable, Encodable};
    use serde::{Deserializer, Serializer, de};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Encodable,
        S: Serializer,
    {
        let mut buf = Vec::with_capacity(value.length());
        value.encode(&mut buf);
        serializer.serialize_bytes(&buf)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: Decodable,
        D: Deserializer<'de>,
    {
        struct Visitor<T>(PhantomData<T>);

        impl<'de, T: Decodable> serde::de::Visitor<'de> for Visitor<T> {
            type Value = T;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a byte array")
            }

            fn visit_bytes<E>(self, mut v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                T::decode(&mut v).map_err(de::Error::custom)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // Limit the length we preallocate.
                let len = seq.size_hint().unwrap_or(0).min(4096);
                let mut bytes = Vec::with_capacity(len);

                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }

                T::decode(&mut bytes.as_slice()).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_bytes(Visitor(PhantomData))
    }
}

impl SignedTransaction {
    pub fn into_transaction(self) -> Transaction {
        match self {
            SignedTransaction::Legacy { tx, .. } => tx.into(),
            SignedTransaction::Eip2930 { tx, .. } => tx.into(),
            SignedTransaction::Eip1559 { tx, .. } => tx.into(),
            SignedTransaction::Zilliqa { tx, .. } => tx.into(),
            SignedTransaction::Intershard { tx, .. } => tx.into(),
        }
    }

    pub fn sig_r(&self) -> U256 {
        match self {
            SignedTransaction::Legacy { sig, .. } => sig.r(),
            SignedTransaction::Eip2930 { sig, .. } => sig.r(),
            SignedTransaction::Eip1559 { sig, .. } => sig.r(),
            SignedTransaction::Zilliqa { sig, .. } => {
                U256::from_be_bytes(sig.r().to_bytes().into())
            }
            SignedTransaction::Intershard { .. } => U256::ZERO,
        }
    }

    pub fn sig_s(&self) -> U256 {
        match self {
            SignedTransaction::Legacy { sig, .. } => sig.s(),
            SignedTransaction::Eip2930 { sig, .. } => sig.s(),
            SignedTransaction::Eip1559 { sig, .. } => sig.s(),
            SignedTransaction::Zilliqa { sig, .. } => {
                U256::from_be_bytes(sig.s().to_bytes().into())
            }
            SignedTransaction::Intershard { .. } => U256::ZERO,
        }
    }

    pub fn sig_v(&self) -> u64 {
        match self {
            SignedTransaction::Legacy { sig, .. } => sig.v() as u64,
            SignedTransaction::Eip2930 { sig, .. } => sig.v() as u64,
            SignedTransaction::Eip1559 { sig, .. } => sig.v() as u64,
            SignedTransaction::Zilliqa { .. } => 0,
            SignedTransaction::Intershard { .. } => 0,
        }
    }

    pub fn chain_id(&self) -> Option<u64> {
        match self {
            SignedTransaction::Legacy { tx, .. } => tx.chain_id,
            SignedTransaction::Eip2930 { tx, .. } => Some(tx.chain_id),
            SignedTransaction::Eip1559 { tx, .. } => Some(tx.chain_id),
            SignedTransaction::Zilliqa { tx, .. } => Some(tx.chain_id as u64),
            SignedTransaction::Intershard { tx, .. } => Some(tx.chain_id),
        }
    }

    pub fn nonce(&self) -> Option<u64> {
        match self {
            SignedTransaction::Legacy { tx, .. } => Some(tx.nonce),
            SignedTransaction::Eip2930 { tx, .. } => Some(tx.nonce),
            SignedTransaction::Eip1559 { tx, .. } => Some(tx.nonce),
            // Zilliqa nonces are 1-indexed rather than zero indexed.
            SignedTransaction::Zilliqa { tx, .. } => Some(tx.nonce - 1),
            SignedTransaction::Intershard { .. } => None,
        }
    }

    pub fn gas_price_per_evm_gas(&self) -> u128 {
        match self {
            SignedTransaction::Legacy { tx, .. } => tx.gas_price,
            SignedTransaction::Eip2930 { tx, .. } => tx.gas_price,
            // We ignore the priority fee and just use the maximum fee.
            SignedTransaction::Eip1559 { tx, .. } => tx.max_fee_per_gas,
            SignedTransaction::Zilliqa { tx, .. } => {
                tx.gas_price.get() / (EVM_GAS_PER_SCILLA_GAS as u128)
            }
            SignedTransaction::Intershard { tx, .. } => tx.gas_price,
        }
    }

    pub fn effective_gas_price(&self, base_fee: u128) -> u128 {
        match self {
            SignedTransaction::Eip1559 { tx, .. } => {
                // if the tip is greater than the max priority fee per gas, set it to the max
                // priority fee per gas + base fee
                let tip = tx.max_fee_per_gas.saturating_sub(base_fee);
                if tip > tx.max_priority_fee_per_gas {
                    tx.max_priority_fee_per_gas + base_fee
                } else {
                    // otherwise return the max fee per gas
                    tx.max_fee_per_gas
                }
            }
            _ => self.gas_price_per_evm_gas(),
        }
    }

    // ZilAmount / EvmGas
    // EvmGas / ScillaGas

    pub fn gas_price_per_scilla_gas(&self) -> ZilAmount {
        /// Convert a gas price in (10^-18) ZILs per [EvmGas] to [ZilAmount] ((10^-12) ZILs) per [ScillaGas].
        fn convert(price: u128) -> ZilAmount {
            // Units of `price`: u128 / EvmGas
            let price = ZilAmount::from_amount(price);
            // Units of `price`: ZilAmount / EvmGas
            // Units of `EVM_GAS_PER_SCILLA_GAS`: EvmGas / ScillaGas
            ZilAmount::from_raw(price.0 * (EVM_GAS_PER_SCILLA_GAS as u128))
            // Units of returned value: ZilAmount / ScillaGas
        }
        match self {
            SignedTransaction::Legacy { tx, .. } => convert(tx.gas_price),
            SignedTransaction::Eip2930 { tx, .. } => convert(tx.gas_price),
            // We ignore the priority fee and just use the maximum fee.
            SignedTransaction::Eip1559 { tx, .. } => convert(tx.max_fee_per_gas),
            SignedTransaction::Zilliqa { tx, .. } => tx.gas_price,
            SignedTransaction::Intershard { tx, .. } => convert(tx.gas_price),
        }
    }

    pub fn gas_limit(&self) -> EvmGas {
        match self {
            SignedTransaction::Legacy { tx, .. } => EvmGas(tx.gas_limit),
            SignedTransaction::Eip2930 { tx, .. } => EvmGas(tx.gas_limit),
            SignedTransaction::Eip1559 { tx, .. } => EvmGas(tx.gas_limit),
            SignedTransaction::Zilliqa { tx, .. } => tx.gas_limit.into(),
            SignedTransaction::Intershard { tx, .. } => tx.gas_limit,
        }
    }

    pub fn gas_limit_scilla(&self) -> ScillaGas {
        match self {
            SignedTransaction::Legacy { tx, .. } => EvmGas(tx.gas_limit).into(),
            SignedTransaction::Eip2930 { tx, .. } => EvmGas(tx.gas_limit).into(),
            SignedTransaction::Eip1559 { tx, .. } => EvmGas(tx.gas_limit).into(),
            SignedTransaction::Zilliqa { tx, .. } => tx.gas_limit,
            SignedTransaction::Intershard { tx, .. } => tx.gas_limit.into(),
        }
    }

    pub fn zil_amount(&self) -> ZilAmount {
        match self {
            SignedTransaction::Legacy { tx, .. } => ZilAmount::from_amount(tx.value.to()),
            SignedTransaction::Eip2930 { tx, .. } => ZilAmount::from_amount(tx.value.to()),
            SignedTransaction::Eip1559 { tx, .. } => ZilAmount::from_amount(tx.value.to()),
            SignedTransaction::Zilliqa { tx, .. } => tx.amount,
            SignedTransaction::Intershard { .. } => ZilAmount::from_raw(0),
        }
    }

    // We don't validate Zilliqa txns against their maximum cost, but against
    // the deposit size.
    pub(crate) fn maximum_validation_cost(&self) -> Result<u128> {
        match self {
            SignedTransaction::Legacy { tx, .. } => {
                Ok(tx.gas_limit as u128 * tx.gas_price + u128::try_from(tx.value)?)
            }
            SignedTransaction::Eip2930 { tx, .. } => {
                Ok(tx.gas_limit as u128 * tx.gas_price + u128::try_from(tx.value)?)
            }
            SignedTransaction::Eip1559 { tx, .. } => {
                Ok(tx.gas_limit as u128 * tx.max_fee_per_gas + u128::try_from(tx.value)?)
            }
            SignedTransaction::Zilliqa { tx, .. } => {
                // This is a copy of Transaction.h::GetTransactionType()
                // We validate against slightly different thresholds since we don't have the
                // mainnet constants to hand in Rust in zq2.
                Ok(total_scilla_gas_price(
                    if !tx.to_addr.is_zero() && !tx.data.is_empty() && tx.code.is_empty() {
                        // It's a contract call (erm, probably)
                        SCILLA_INVOKE_RUNNER
                    } else if !tx.code.is_empty() && tx.to_addr.is_zero() {
                        // create
                        SCILLA_INVOKE_RUNNER
                    } else {
                        // Validate as an EOA
                        SCILLA_TRANSFER
                    },
                    tx.gas_price,
                )
                .0)
            }
            SignedTransaction::Intershard { tx, .. } => Ok(tx.gas_price * tx.gas_limit.0 as u128),
        }
    }

    pub fn verify(self) -> Result<VerifiedTransaction> {
        self.verify_inner(false, Hash::ZERO)
    }

    pub fn verify_bypass(self, hash: Hash) -> Result<VerifiedTransaction> {
        self.verify_inner(true, hash)
    }

    fn verify_inner(self, force: bool, hash: Hash) -> Result<VerifiedTransaction> {
        let (tx, signer, hash) = match self {
            SignedTransaction::Legacy { tx, sig } => {
                let signed = tx.into_signed(sig);
                let signer = signed.recover_signer()?;
                let (tx, _, hash) = signed.into_parts();
                (SignedTransaction::Legacy { tx, sig }, signer, hash.into())
            }
            SignedTransaction::Eip2930 { tx, sig } => {
                let signed = tx.into_signed(sig);
                let signer = signed.recover_signer()?;
                let (tx, _, hash) = signed.into_parts();
                (SignedTransaction::Eip2930 { tx, sig }, signer, hash.into())
            }
            SignedTransaction::Eip1559 { tx, sig } => {
                let signed = tx.into_signed(sig);
                let signer = signed.recover_signer()?;
                let (tx, _, hash) = signed.into_parts();
                (SignedTransaction::Eip1559 { tx, sig }, signer, hash.into())
            }
            SignedTransaction::Zilliqa { tx, key, sig } => {
                let txn_data = encode_zilliqa_transaction(&tx, key);

                if !force {
                    schnorr::verify(&txn_data, key, sig)
                        .ok_or_else(|| anyhow!("invalid signature"))?;
                }

                let hashed = Sha256::digest(key.to_encoded_point(true).as_bytes());
                let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();
                let signer = Address::new(bytes.into());

                let tx = SignedTransaction::Zilliqa { tx, key, sig };
                let hash = if !force { tx.calculate_hash() } else { hash };
                (tx, signer, hash)
            }
            SignedTransaction::Intershard { tx, from } => {
                let tx = SignedTransaction::Intershard { tx, from };
                let hash = tx.calculate_hash();
                (tx, from, hash)
            }
        };

        let cbor_size = cbor4ii::serde::to_vec(Vec::with_capacity(4096), &tx)
            .map(|b| b.len())
            .unwrap_or_default();

        Ok(VerifiedTransaction {
            tx,
            signer,
            hash,
            cbor_size,
        })
    }

    /// Calculate the hash of this transaction. If you need to do this more than once, consider caching the result
    /// using [`Self::verify()`] and the `hash` field from [RecoveredTransaction].
    pub fn calculate_hash(&self) -> crypto::Hash {
        match self {
            SignedTransaction::Legacy { tx, sig } => tx.tx_hash(sig).into(),
            SignedTransaction::Eip2930 { tx, sig } => tx.tx_hash(sig).into(),
            SignedTransaction::Eip1559 { tx, sig } => tx.tx_hash(sig).into(),
            SignedTransaction::Zilliqa { tx, key, .. } => {
                let txn_data = encode_zilliqa_transaction(tx, *key);
                crypto::Hash(Sha256::digest(txn_data).into())
            }
            SignedTransaction::Intershard { tx, from } => {
                let mut buffer = BytesMut::with_capacity(1024);
                Header {
                    list: true,
                    payload_length: 7,
                }
                .encode(&mut buffer);
                tx.encode_fields(&mut buffer);
                from.encode(&mut buffer);
                crypto::Hash(Keccak256::digest(buffer).into())
            }
        }
    }

    pub fn validate(
        &self,
        account: &Account,
        block_gas_limit: EvmGas,
        min_gas_price: u128,
        eth_chain_id: u64,
    ) -> Result<ValidationOutcome> {
        let hash = self.calculate_hash();
        let blessed = BLESSED_TRANSACTIONS.iter().any(|elem| elem.hash == hash);
        if blessed {
            return Ok(ValidationOutcome::Success);
        }
        let result = ValidationOutcome::Success
            .and_then(|| self.validate_input_size())?
            .and_then(|| self.validate_gas_limit(block_gas_limit))?
            .and_then(|| self.validate_gas_price(min_gas_price))?
            .and_then(|| self.validate_chain_id(eth_chain_id))?
            .and_then(|| self.validate_sender_account(account))?;
        Ok(result)
    }

    fn validate_input_size(&self) -> Result<ValidationOutcome> {
        if let SignedTransaction::Zilliqa { tx, .. } = self {
            if tx.code.len() > ZIL_MAX_CODE_SIZE {
                warn!(
                    "Zil transaction input size: {} exceeds limit: {ZIL_MAX_CODE_SIZE}",
                    tx.code.len()
                );
                return Ok(ValidationOutcome::TransactionInputSizeExceeded(
                    tx.code.len(),
                    ZIL_MAX_CODE_SIZE,
                ));
            }
            return Ok(ValidationOutcome::Success);
        };

        let (input_size, tx_kind) = match self {
            SignedTransaction::Legacy { tx, .. } => (tx.input.len(), tx.to),
            SignedTransaction::Eip2930 { tx, .. } => (tx.input.len(), tx.to),
            SignedTransaction::Eip1559 { tx, .. } => (tx.input.len(), tx.to),
            _ => return Ok(ValidationOutcome::Success),
        };

        if input_size > EVM_MAX_TX_INPUT_SIZE {
            warn!(
                "Evm transaction input size: {input_size} exceeds limit: {EVM_MAX_TX_INPUT_SIZE}"
            );
            return Ok(ValidationOutcome::TransactionInputSizeExceeded(
                input_size,
                EVM_MAX_TX_INPUT_SIZE,
            ));
        }

        if tx_kind == TxKind::Create && input_size > EVM_MAX_INIT_CODE_SIZE {
            warn!(
                "Evm transaction initcode size: {input_size} exceeds limit: {EVM_MAX_INIT_CODE_SIZE}"
            );
            return Ok(ValidationOutcome::InitCodeSizeExceeded(
                input_size,
                EVM_MAX_INIT_CODE_SIZE,
            ));
        }

        Ok(ValidationOutcome::Success)
    }

    fn validate_gas_limit(&self, block_gas_limit: EvmGas) -> Result<ValidationOutcome> {
        if self.gas_limit() > block_gas_limit {
            warn!("Transaction gas limit exceeds block gas limit!");
            return Ok(ValidationOutcome::BlockGasLimitExceeded(
                self.gas_limit(),
                block_gas_limit,
            ));
        }

        // The following logic is taken from ZQ1
        if let SignedTransaction::Zilliqa { tx, .. } = self {
            let required_gas = tx.get_deposit_gas()?;
            if tx.gas_limit < required_gas {
                warn!(
                    "Insufficient gas give for zil transaction, given: {}, required: {required_gas}!",
                    tx.gas_limit
                );
                return Ok(ValidationOutcome::InsufficientGasZil(
                    tx.gas_limit,
                    required_gas,
                ));
            }
            return Ok(ValidationOutcome::Success);
        }

        let gas_limit = self.gas_limit();

        if gas_limit < EVM_MIN_GAS_UNITS {
            warn!(
                "Insufficient gas give for evm transaction, given: {gas_limit}, required: {EVM_MIN_GAS_UNITS}!"
            );
            return Ok(ValidationOutcome::InsufficientGasEvm(
                gas_limit,
                EVM_MIN_GAS_UNITS,
            ));
        }

        Ok(ValidationOutcome::Success)
    }

    fn validate_chain_id(&self, eth_chain_id: u64) -> Result<ValidationOutcome> {
        let node_chain_id = match &self {
            SignedTransaction::Zilliqa { .. } => eth_chain_id - 0x8000,
            _ => eth_chain_id,
        };

        if let Some(txn_chain_id) = self.chain_id()
            && node_chain_id != txn_chain_id
        {
            warn!(
                "Chain_id provided in transaction: {} is different than node chain_id: {}",
                txn_chain_id, node_chain_id
            );
            return Ok(ValidationOutcome::IncorrectChainId(
                txn_chain_id,
                node_chain_id,
            ));
        }
        Ok(ValidationOutcome::Success)
    }

    fn validate_gas_price(&self, min_gas_price: u128) -> Result<ValidationOutcome> {
        let gas_price = self.gas_price_per_evm_gas();
        if gas_price < min_gas_price {
            return Ok(ValidationOutcome::GasPriceTooLow);
        }
        Ok(ValidationOutcome::Success)
    }

    fn validate_sender_account(&self, account: &Account) -> Result<ValidationOutcome> {
        let txn_cost = self.maximum_validation_cost()?;
        if txn_cost > account.balance {
            warn!("Insufficient funds for acc: {:?}", account);
            return Ok(ValidationOutcome::InsufficientFunds(
                txn_cost,
                account.balance,
            ));
        }

        let Some(nonce) = self.nonce() else {
            return Ok(ValidationOutcome::Success);
        };
        if nonce < account.nonce {
            warn!(
                "Nonce is too low. Txn nonce is: {}, acc: {}",
                nonce, account.nonce
            );
            return Ok(ValidationOutcome::NonceTooLow(nonce, account.nonce));
        }
        Ok(ValidationOutcome::Success)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A [SignedTransaction] which has had the signature verified and the signer recovered. The transaction's hash is also
/// calculated and cached.
///
/// [Serialize] and [Deserialize] are deliberately not implemented for this type. [SignedTransaction]s should be sent
/// accross the network the signer should be verified and recovered independently.
pub struct VerifiedTransaction {
    pub tx: SignedTransaction,
    pub signer: Address,
    pub hash: crypto::Hash,
    pub cbor_size: usize,
}

impl VerifiedTransaction {
    #[inline]
    pub fn encoded_size(&self) -> usize {
        self.cbor_size
    }
}

/// The core information of a transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transaction {
    Legacy(TxLegacy),
    Eip2930(TxEip2930),
    Eip1559(TxEip1559),
    Zilliqa(TxZilliqa),
    Intershard(TxIntershard),
}

impl Transaction {
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Transaction::Legacy(TxLegacy { chain_id, .. }) => *chain_id,
            Transaction::Eip2930(TxEip2930 { chain_id, .. }) => Some(*chain_id),
            Transaction::Eip1559(TxEip1559 { chain_id, .. }) => Some(*chain_id),
            Transaction::Zilliqa(TxZilliqa { chain_id, .. }) => Some(*chain_id as u64 + 0x8000),
            Transaction::Intershard(TxIntershard { chain_id, .. }) => Some(*chain_id),
        }
    }

    pub fn nonce(&self) -> Option<u64> {
        match self {
            Transaction::Legacy(TxLegacy { nonce, .. }) => Some(*nonce),
            Transaction::Eip2930(TxEip2930 { nonce, .. }) => Some(*nonce),
            Transaction::Eip1559(TxEip1559 { nonce, .. }) => Some(*nonce),
            // Zilliqa nonces are 1-indexed rather than zero indexed.
            Transaction::Zilliqa(TxZilliqa { nonce, .. }) => Some(*nonce - 1),
            Transaction::Intershard(TxIntershard { .. }) => None,
        }
    }

    pub fn max_fee_per_gas(&self) -> u128 {
        match self {
            Transaction::Legacy(TxLegacy { gas_price, .. }) => *gas_price,
            Transaction::Eip2930(TxEip2930 { gas_price, .. }) => *gas_price,
            Transaction::Eip1559(TxEip1559 {
                max_fee_per_gas, ..
            }) => *max_fee_per_gas,
            Transaction::Zilliqa(t) => t.gas_price.get() / (EVM_GAS_PER_SCILLA_GAS as u128),
            Transaction::Intershard(TxIntershard { gas_price, .. }) => *gas_price,
        }
    }

    pub fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            Transaction::Eip1559(TxEip1559 {
                max_priority_fee_per_gas,
                ..
            }) => Some(*max_priority_fee_per_gas),
            _ => None,
        }
    }

    pub fn gas_limit(&self) -> EvmGas {
        match self {
            Transaction::Legacy(TxLegacy { gas_limit, .. }) => EvmGas(*gas_limit),
            Transaction::Eip2930(TxEip2930 { gas_limit, .. }) => EvmGas(*gas_limit),
            Transaction::Eip1559(TxEip1559 { gas_limit, .. }) => EvmGas(*gas_limit),
            Transaction::Zilliqa(TxZilliqa { gas_limit, .. }) => (*gas_limit).into(),
            Transaction::Intershard(TxIntershard { gas_limit, .. }) => *gas_limit,
        }
    }

    pub fn to_addr(&self) -> Option<Address> {
        match self {
            Transaction::Legacy(TxLegacy { to, .. }) => to.to().copied(),
            Transaction::Eip2930(TxEip2930 { to, .. }) => to.to().copied(),
            Transaction::Eip1559(TxEip1559 { to, .. }) => to.to().copied(),
            // Note: we map the zero address to 'None' here so it is consistent with eth txs (contract creation).
            Transaction::Zilliqa(TxZilliqa { to_addr, .. }) => {
                if !to_addr.is_zero() {
                    Some(*to_addr)
                } else {
                    None
                }
            }
            Transaction::Intershard(TxIntershard { to_addr, .. }) => *to_addr,
        }
    }

    pub fn amount(&self) -> u128 {
        match self {
            Transaction::Legacy(TxLegacy { value, .. }) => value.to(),
            Transaction::Eip2930(TxEip2930 { value, .. }) => value.to(),
            Transaction::Eip1559(TxEip1559 { value, .. }) => value.to(),
            Transaction::Zilliqa(t) => t.amount.get(),
            Transaction::Intershard(_) => 0,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Transaction::Legacy(TxLegacy { input, .. }) => input.as_ref(),
            Transaction::Eip2930(TxEip2930 { input, .. }) => input.as_ref(),
            Transaction::Eip1559(TxEip1559 { input, .. }) => input.as_ref(),
            // Zilliqa transactions can have both code and data set, but code takes precedence if it is non-empty.
            Transaction::Zilliqa(TxZilliqa { code, data, .. }) => {
                if !code.is_empty() {
                    code.as_bytes()
                } else {
                    data.as_bytes()
                }
            }
            Transaction::Intershard(TxIntershard { payload, .. }) => payload,
        }
    }

    pub fn access_list(&self) -> Option<AccessList> {
        match self {
            Transaction::Legacy(_) => None,
            Transaction::Eip2930(TxEip2930 { access_list, .. }) => Some(access_list.clone()),
            Transaction::Eip1559(TxEip1559 { access_list, .. }) => Some(access_list.clone()),
            Transaction::Zilliqa(_) => None,
            Transaction::Intershard(_) => None,
        }
    }

    pub fn transaction_type(&self) -> u64 {
        match self {
            Transaction::Legacy(_) => 0,
            Transaction::Eip2930(_) => 1,
            Transaction::Eip1559(_) => 2,
            // "ZIL" encoded in ASCII
            Transaction::Zilliqa(_) => 90_73_76,
            // "ZIL" + 1
            Transaction::Intershard(_) => 90_73_77,
        }
    }

    pub fn revm_transaction_type(&self) -> TransactionType {
        match self {
            Transaction::Legacy(_) => TransactionType::Legacy,
            Transaction::Eip2930(_) => TransactionType::Eip2930,
            Transaction::Eip1559(_) => TransactionType::Eip1559,
            Transaction::Zilliqa(_) => TransactionType::Custom,
            Transaction::Intershard(_) => TransactionType::Custom,
        }
    }
}

impl TryFrom<VerifiedTransaction> for TxEnv {
    type Error = anyhow::Error;

    fn try_from(txn: VerifiedTransaction) -> std::result::Result<TxEnv, anyhow::Error> {
        let signer = txn.signer;
        let inner = txn.tx.into_transaction();
        Ok(Self {
            tx_type: inner.revm_transaction_type().into(),
            caller: signer,
            gas_limit: inner.gas_limit().0,
            gas_price: inner.max_fee_per_gas(),
            kind: match inner.to_addr() {
                Some(addr) => TxKind::Call(addr),
                _ => TxKind::Create,
            },
            value: inner.amount().try_into()?,
            data: inner.payload().to_vec().into(),
            nonce: inner.nonce().unwrap_or_default(),
            chain_id: inner.chain_id(),
            access_list: inner.access_list().unwrap_or_default(),
            gas_priority_fee: inner.max_priority_fee_per_gas(),
            blob_hashes: vec![],
            max_fee_per_blob_gas: 0,
            authorization_list: vec![],
        })
    }
}

impl From<TxLegacy> for Transaction {
    fn from(tx: TxLegacy) -> Self {
        Transaction::Legacy(tx)
    }
}

impl From<TxEip2930> for Transaction {
    fn from(tx: TxEip2930) -> Self {
        Transaction::Eip2930(tx)
    }
}

impl From<TxEip1559> for Transaction {
    fn from(tx: TxEip1559) -> Self {
        Transaction::Eip1559(tx)
    }
}

impl From<TxZilliqa> for Transaction {
    fn from(tx: TxZilliqa) -> Self {
        Transaction::Zilliqa(tx)
    }
}

impl From<TxIntershard> for Transaction {
    fn from(tx: TxIntershard) -> Self {
        Transaction::Intershard(tx)
    }
}

/// Nonceless
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxIntershard {
    pub chain_id: u64,
    /// The bridge nonce alongside the source chain together guarantee hash uniqueness.
    pub bridge_nonce: u64,
    pub source_chain: u64,
    pub gas_price: u128,
    pub gas_limit: EvmGas,
    pub to_addr: Option<Address>,
    // Amount intentionally missing: cannot send native amount cross-shard
    pub payload: Vec<u8>,
}

impl TxIntershard {
    fn encode_fields(&self, out: &mut BytesMut) {
        self.chain_id.encode(out);
        self.source_chain.encode(out);
        self.bridge_nonce.encode(out);
        self.gas_price.encode(out);
        self.gas_limit.encode(out);
        encode_option_addr(&self.to_addr, out);
        self.payload.as_slice().encode(out);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxZilliqa {
    pub chain_id: u16,
    pub nonce: u64,
    pub gas_price: ZilAmount,
    pub gas_limit: ScillaGas,
    pub to_addr: Address,
    pub amount: ZilAmount,
    pub code: String,
    pub data: String,
}

impl TxZilliqa {
    pub fn get_deposit_gas(&self) -> Result<ScillaGas> {
        // Contract call
        if !self.to_addr.is_zero() && !self.data.is_empty() && self.code.is_empty() {
            Ok(ScillaGas(
                max(ZIL_CONTRACT_INVOKE_GAS, self.data.len()).try_into()?,
            ))
        }
        // Contract creation
        else if self.to_addr.is_zero() && !self.code.is_empty() {
            Ok(ScillaGas(
                max(ZIL_CONTRACT_CREATE_GAS, self.data.len() + self.code.len()).try_into()?,
            ))
        }
        // Transfer
        else if !self.to_addr.is_zero() && self.data.is_empty() && self.code.is_empty() {
            Ok(ScillaGas(ZIL_NORMAL_TXN_GAS.try_into()?))
        } else {
            warn!("transaction is none of: contract invocation, contract creation, transfer");
            Err(anyhow!("Unknown transaction type"))
        }
    }

    pub fn get_contract_address(&self, signer: &Address) -> Result<Address> {
        let mut hasher = Sha256::new();
        hasher.update(signer.as_slice());
        if self.nonce > 0 {
            hasher.update((self.nonce - 1).to_be_bytes());
        } else {
            return Err(anyhow!("Nonce must be greater than 0"));
        }
        let hashed = hasher.finalize();
        Ok(Address::from_slice(&hashed[12..]))
    }
}

/// A wrapper for ZIL amounts in the Zilliqa API. These are represented in units of (10^-12) ZILs, rather than (10^-18)
/// like in the rest of our code. The implementations of [Serialize], [Deserialize], [Display] and [FromStr] represent
/// the amount in units of (10^-12) ZILs, so this type can be used in the Zilliqa API layer.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ZilAmount(u128);

impl ZilAmount {
    pub const ZERO: ZilAmount = ZilAmount(0);

    /// Construct a [ZilAmount] from an amount in (10^-18) ZILs. The value will be truncated and rounded down.
    pub fn from_amount(amount: u128) -> ZilAmount {
        ZilAmount(amount / 10u128.pow(6))
    }

    // Construct a [ZilAmount] from an amount in (10^-12) ZILs.
    pub fn from_raw(amount: u128) -> ZilAmount {
        ZilAmount(amount)
    }

    /// Get the ZIL amount in units of (10^-18) ZILs.
    pub fn get(self) -> u128 {
        self.0.checked_mul(10u128.pow(6)).expect("amount overflow")
    }

    /// Return the memory representation of this amount as a big-endian byte array.
    pub fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    pub fn checked_sub(&self, v: &Self) -> Option<Self> {
        if v.0 < self.0 {
            Some(ZilAmount(self.0 - v.0))
        } else {
            None
        }
    }

    // In ZIL, rounded down to the nearest ZIL unit.
    pub fn to_zils(self) -> u128 {
        self.0 / 10u128.pow(12)
    }

    // In ZIL, as a string representation of the exact float amount
    pub fn to_float_string(self) -> String {
        let integer_part = self.0 / 10u128.pow(12);
        let fractional_part = self.0 % 10u128.pow(12);
        format!("{integer_part}.{fractional_part}")
    }
}

impl Add for ZilAmount {
    type Output = ZilAmount;

    fn add(self, rhs: Self) -> Self::Output {
        ZilAmount(self.0.checked_add(rhs.0).expect("amount overflow"))
    }
}

impl PartialOrd for ZilAmount {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl Display for ZilAmount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ZilAmount {
    type Err = <u128 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u128::from_str(s)?))
    }
}

/// Calculate the total price of a given `quantity` of [ScillaGas] at the specified `price`.
/// Note that the units of the `price` should really be ([ZilAmount] / [ScillaGas])
pub fn total_scilla_gas_price(quantity: ScillaGas, price: ZilAmount) -> ZilAmount {
    ZilAmount(
        (quantity.0 as u128)
            .checked_mul(price.0)
            .expect("amount overflow"),
    )
}

pub const EVM_GAS_PER_SCILLA_GAS: u64 = 420;

/// A quantity of Scilla gas. This is the currency used to pay for [TxZilliqa] transactions. When EVM gas is converted
/// to Scilla gas, the quantity is rounded down.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct ScillaGas(pub u64);

impl ScillaGas {
    pub fn checked_sub(self, rhs: ScillaGas) -> Option<ScillaGas> {
        Some(ScillaGas(self.0.checked_sub(rhs.0)?))
    }
}

impl Sub for ScillaGas {
    type Output = ScillaGas;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs).expect("scilla gas underflow")
    }
}

impl From<EvmGas> for ScillaGas {
    fn from(gas: EvmGas) -> Self {
        ScillaGas(gas.0 / EVM_GAS_PER_SCILLA_GAS)
    }
}

impl Display for ScillaGas {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ScillaGas {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u64::from_str(s)?))
    }
}

/// A quantity of EVM gas. This is the currency used to pay for EVM transactions.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct EvmGas(pub u64);

impl EvmGas {
    pub fn checked_sub(self, rhs: EvmGas) -> Option<EvmGas> {
        Some(EvmGas(self.0.checked_sub(rhs.0)?))
    }
}

impl Sub for EvmGas {
    type Output = EvmGas;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs).expect("evm gas underflow")
    }
}

impl Add for EvmGas {
    type Output = EvmGas;

    fn add(self, rhs: Self) -> Self::Output {
        EvmGas(self.0.checked_add(rhs.0).expect("evm gas overflow"))
    }
}

impl From<ScillaGas> for EvmGas {
    fn from(gas: ScillaGas) -> Self {
        EvmGas(gas.0 * EVM_GAS_PER_SCILLA_GAS)
    }
}

impl Display for EvmGas {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for EvmGas {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u64::from_str(s)?))
    }
}

impl AddAssign for EvmGas {
    fn add_assign(&mut self, rhs: Self) {
        self.0.add_assign(rhs.0)
    }
}

impl alloy::rlp::Decodable for EvmGas {
    fn decode(buf: &mut &[u8]) -> alloy::rlp::Result<Self> {
        Ok(EvmGas(<u64 as alloy::rlp::Decodable>::decode(buf)?))
    }
}

impl alloy::rlp::Encodable for EvmGas {
    fn encode(&self, out: &mut dyn BufMut) {
        self.0.encode(out);
    }

    fn length(&self) -> usize {
        self.0.length()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScillaLog {
    pub address: Address,
    #[serde(rename = "_eventname")]
    pub event_name: String,
    #[serde(with = "vec_param_value")]
    pub params: Vec<ParamValue>,
}

impl ScillaLog {
    pub fn into_evm(self) -> EvmLog {
        /// A version of [ScillaLog] which lets us serialise the `address` manually, so we can exclude the checksum, and doesn't encode the `params` values as strings.
        #[derive(Clone, Serialize, Debug)]
        pub struct ScillaLogRaw {
            address: String,
            #[serde(rename = "_eventname")]
            event_name: String,
            params: Vec<ParamValue>,
        }

        let address = self.address;
        let log = ScillaLogRaw {
            address: format!("{address:?}"),
            event_name: self.event_name,
            params: self.params,
        };

        // Unwrap is safe because [ScillaLogRaw::Serialize] is infallible.
        let data = serde_json::to_string(&log).unwrap().abi_encode();
        EvmLog {
            address,
            topics: vec![keccak256(
                format!("{}(string)", log.event_name).into_bytes(),
            )],
            data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Log {
    Evm(EvmLog),
    Scilla(ScillaLog),
}

impl Log {
    pub fn into_evm(self) -> Option<EvmLog> {
        match self {
            Log::Evm(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_evm(&self) -> Option<&EvmLog> {
        match self {
            Log::Evm(l) => Some(l),
            _ => None,
        }
    }

    pub fn into_scilla(self) -> Option<ScillaLog> {
        match self {
            Log::Scilla(l) => Some(l),
            _ => None,
        }
    }

    pub fn compute_hash(&self) -> Hash {
        match self {
            Log::Scilla(log) => Hash::builder()
                .with(log.event_name.as_bytes())
                .with(
                    log.params
                        .iter()
                        .map(|param| param.compute_hash())
                        .map(|hash| hash.as_bytes().to_vec())
                        .concat(),
                )
                .with(log.address.as_slice())
                .finalize(),
            Log::Evm(log) => Hash::builder()
                .with(log.address.as_slice())
                .with(&log.data)
                .with(log.topics.iter().map(|topic| topic.to_vec()).concat())
                .finalize(),
        }
    }
}

/// A transaction receipt stores data about the execution of a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub block_hash: crypto::Hash,
    pub index: u64,
    pub tx_hash: crypto::Hash,
    pub success: bool,
    pub gas_used: EvmGas,
    pub cumulative_gas_used: EvmGas,
    pub contract_address: Option<Address>,
    pub logs: Vec<Log>,
    pub transitions: Vec<ScillaTransition>,
    pub accepted: Option<bool>,
    pub errors: BTreeMap<u64, Vec<ScillaError>>,
    pub exceptions: Vec<ScillaException>,
}

impl TransactionReceipt {
    pub fn compute_hash(&self) -> Hash {
        let success = [u8::from(self.success); 1];
        let accepted = [u8::from(self.accepted.unwrap_or_default()); 1];
        Hash::builder()
            .with(self.index.to_be_bytes())
            .with(self.tx_hash.as_bytes())
            .with(success.as_slice())
            .with(self.gas_used.0.to_be_bytes())
            .with(self.cumulative_gas_used.0.to_be_bytes())
            .with(
                self.contract_address
                    .unwrap_or_default()
                    .to_vec()
                    .as_slice(),
            )
            .with(
                self.logs
                    .iter()
                    .map(|log| log.compute_hash().as_bytes().to_vec())
                    .concat(),
            )
            .with(
                self.transitions
                    .iter()
                    .map(|transition| transition.compute_hash().as_bytes().to_vec())
                    .concat(),
            )
            .with(accepted.as_slice())
            .with(
                self.exceptions
                    .iter()
                    .map(|exception| exception.compute_hash().as_bytes().to_vec())
                    .concat(),
            )
            .finalize()
    }
}

/// RLP-encode an `Option<Address>`.
/// `None` is represented as an empty string.
fn encode_option_addr(addr: &Option<Address>, out: &mut BytesMut) {
    match addr {
        Some(addr) => {
            addr.encode(out);
        }
        None => {
            out.put_u8(EMPTY_STRING_CODE);
        }
    }
}

fn encode_zilliqa_transaction(txn: &TxZilliqa, pub_key: schnorr::PublicKey) -> Vec<u8> {
    let oneof8 = (!txn.code.is_empty()).then_some(Code::Code(txn.code.clone().into_bytes()));
    let oneof9 = (!txn.data.is_empty()).then_some(Data::Data(txn.data.clone().into_bytes()));
    let proto = ProtoTransactionCoreInfo {
        version: (((txn.chain_id) as u32) << 16) | 0x0001,
        toaddr: txn.to_addr.as_slice().to_vec(),
        senderpubkey: Some(pub_key.to_sec1_bytes().into()),
        amount: Some((txn.amount).to_be_bytes().to_vec().into()),
        gasprice: Some((txn.gas_price).to_be_bytes().to_vec().into()),
        gaslimit: txn.gas_limit.0,
        oneof2: Some(Nonce::Nonce(txn.nonce)),
        oneof8,
        oneof9,
    };
    prost::Message::encode_to_vec(&proto)
}
