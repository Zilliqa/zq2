use std::{
    cmp::{max, Ordering, PartialOrd},
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    ops::{Add, AddAssign, Sub},
    str::FromStr,
};

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEip2930, TxLegacy},
    primitives::{keccak256, Address, Signature, TxKind, B256, U256},
    rlp::{Encodable, Header, EMPTY_STRING_CODE},
    sol_types::SolValue,
};
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use itertools::Itertools;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{
    digest::generic_array::{
        sequence::Split,
        typenum::{U12, U20},
        GenericArray,
    },
    Digest, Keccak256,
};
use tracing::warn;

use crate::{
    constants::{
        EVM_MAX_INIT_CODE_SIZE, EVM_MAX_TX_INPUT_SIZE, EVM_MIN_GAS_UNITS, ZIL_CONTRACT_CREATE_GAS,
        ZIL_CONTRACT_INVOKE_GAS, ZIL_MAX_CODE_SIZE, ZIL_NORMAL_TXN_GAS,
    },
    crypto,
    crypto::Hash,
    exec::{ScillaError, ScillaException, ScillaTransition},
    schnorr,
    state::Account,
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};

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
    use serde::{de, Deserializer, Serializer};

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
            SignedTransaction::Legacy { sig, .. } => sig.v().to_u64(),
            SignedTransaction::Eip2930 { sig, .. } => sig.v().to_u64(),
            SignedTransaction::Eip1559 { sig, .. } => sig.v().to_u64(),
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
            SignedTransaction::Legacy { tx, .. } => EvmGas(tx.gas_limit as u64),
            SignedTransaction::Eip2930 { tx, .. } => EvmGas(tx.gas_limit as u64),
            SignedTransaction::Eip1559 { tx, .. } => EvmGas(tx.gas_limit as u64),
            SignedTransaction::Zilliqa { tx, .. } => tx.gas_limit.into(),
            SignedTransaction::Intershard { tx, .. } => tx.gas_limit,
        }
    }

    pub fn gas_limit_scilla(&self) -> ScillaGas {
        match self {
            SignedTransaction::Legacy { tx, .. } => EvmGas(tx.gas_limit as u64).into(),
            SignedTransaction::Eip2930 { tx, .. } => EvmGas(tx.gas_limit as u64).into(),
            SignedTransaction::Eip1559 { tx, .. } => EvmGas(tx.gas_limit as u64).into(),
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

    fn maximum_cost(&self) -> Result<u128> {
        let gas_cost = self.gas_cost()?;
        match self {
            SignedTransaction::Legacy { tx, .. } => Ok(gas_cost + u128::try_from(tx.value)?),
            SignedTransaction::Eip2930 { tx, .. } => Ok(gas_cost + u128::try_from(tx.value)?),
            SignedTransaction::Eip1559 { tx, .. } => Ok(gas_cost + u128::try_from(tx.value)?),
            SignedTransaction::Zilliqa { .. } => Ok(gas_cost),
            SignedTransaction::Intershard { .. } => Ok(gas_cost),
        }
    }

    pub(crate) fn gas_cost(&self) -> Result<u128> {
        match self {
            SignedTransaction::Legacy { tx, .. } => Ok(tx.gas_limit * tx.gas_price),
            SignedTransaction::Eip2930 { tx, .. } => Ok(tx.gas_limit * tx.gas_price),
            SignedTransaction::Eip1559 { tx, .. } => Ok(tx.gas_limit * tx.max_fee_per_gas),
            SignedTransaction::Zilliqa { tx, .. } => {
                Ok(total_scilla_gas_price(tx.gas_limit, tx.gas_price).0)
            }
            SignedTransaction::Intershard { tx, .. } => Ok(tx.gas_price * tx.gas_limit.0 as u128),
        }
    }

    pub fn verify(self) -> Result<VerifiedTransaction> {
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

                schnorr::verify(&txn_data, key, sig).ok_or_else(|| anyhow!("invalid signature"))?;

                let hashed = Sha256::digest(key.to_encoded_point(true).as_bytes());
                let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();
                let signer = Address::new(bytes.into());

                let tx = SignedTransaction::Zilliqa { tx, key, sig };
                let hash = tx.calculate_hash();
                (tx, signer, hash)
            }
            SignedTransaction::Intershard { tx, from } => {
                let tx = SignedTransaction::Intershard { tx, from };
                let hash = tx.calculate_hash();
                (tx, from, hash)
            }
        };

        Ok(VerifiedTransaction { tx, signer, hash })
    }

    /// Calculate the hash of this transaction. If you need to do this more than once, consider caching the result
    /// using [`Self::verify()`] and the `hash` field from [RecoveredTransaction].
    pub fn calculate_hash(&self) -> crypto::Hash {
        match self {
            SignedTransaction::Legacy { tx, sig } => {
                let mut out = BytesMut::with_capacity(1024);
                tx.encode_with_signature_fields(sig, &mut out);
                (keccak256(out)).into()
            }
            SignedTransaction::Eip2930 { tx, sig } => {
                let mut out = BytesMut::with_capacity(1024);
                tx.encode_with_signature(sig, &mut out, false);
                (keccak256(out)).into()
            }
            SignedTransaction::Eip1559 { tx, sig } => {
                let mut out = BytesMut::with_capacity(1024);
                tx.encode_with_signature(sig, &mut out, false);
                (keccak256(out)).into()
            }
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
        eth_chain_id: u64,
    ) -> Result<bool> {
        self.validate_input_size()?;
        self.validate_gas_limit(block_gas_limit)?;
        self.validate_chain_id(eth_chain_id)?;
        self.validate_sender_account(account)
    }

    fn validate_input_size(&self) -> Result<bool> {
        if let SignedTransaction::Zilliqa { tx, .. } = self {
            if tx.code.len() > ZIL_MAX_CODE_SIZE {
                warn!(
                    "Zil transaction input size: {} exceeds limit: {ZIL_MAX_CODE_SIZE}",
                    tx.code.len()
                );
                return Ok(false);
            }
            return Ok(true);
        };

        let (input_size, tx_kind) = match self {
            SignedTransaction::Legacy { tx, .. } => (tx.input.len(), tx.to),
            SignedTransaction::Eip2930 { tx, .. } => (tx.input.len(), tx.to),
            SignedTransaction::Eip1559 { tx, .. } => (tx.input.len(), tx.to),
            _ => return Ok(true),
        };

        if input_size > EVM_MAX_TX_INPUT_SIZE {
            warn!(
                "Evm transaction input size: {input_size} exceeds limit: {EVM_MAX_TX_INPUT_SIZE}"
            );
            return Ok(false);
        }

        if tx_kind == TxKind::Create && input_size > EVM_MAX_INIT_CODE_SIZE {
            warn!("Evm transaction initcode size: {input_size} exceeds limit: {EVM_MAX_INIT_CODE_SIZE}");
            return Ok(false);
        }

        Ok(true)
    }

    fn validate_gas_limit(&self, block_gas_limit: EvmGas) -> Result<bool> {
        if self.gas_limit() > block_gas_limit {
            warn!("Transaction gas limit exceeds block gas limit!");
            return Ok(false);
        }

        // The following logic is taken from ZQ1
        if let SignedTransaction::Zilliqa { tx, .. } = self {
            let required_gas: ScillaGas = {
                // Contract call
                if !tx.to_addr.is_zero() && !tx.data.is_empty() && tx.code.is_empty() {
                    ScillaGas(max(ZIL_CONTRACT_INVOKE_GAS, tx.data.len()).try_into()?)
                }
                // Contract creation
                else if tx.to_addr.is_zero() && !tx.code.is_empty() {
                    ScillaGas(
                        max(ZIL_CONTRACT_CREATE_GAS, tx.data.len() + tx.code.len()).try_into()?,
                    )
                }
                // Transfer
                else if !tx.to_addr.is_zero() && tx.data.is_empty() && tx.code.is_empty() {
                    ScillaGas(ZIL_NORMAL_TXN_GAS.try_into()?)
                } else {
                    warn!("Given transaction is none of: contract invocation, contract creation, transfer");
                    return Ok(false);
                }
            };

            if tx.gas_limit < required_gas {
                warn!("Insufficient gas give for zil transaction, given: {}, required: {required_gas}!", tx.gas_limit);
                return Ok(false);
            }
            return Ok(true);
        }

        let gas_limit = self.gas_limit();

        if gas_limit < EVM_MIN_GAS_UNITS {
            warn!("Insufficient gas give for evm transaction, given: {gas_limit}, required: {EVM_MIN_GAS_UNITS}!");
            return Ok(false);
        }

        Ok(true)
    }

    fn validate_chain_id(&self, eth_chain_id: u64) -> Result<bool> {
        let node_chain_id = match &self {
            SignedTransaction::Zilliqa { .. } => eth_chain_id - 0x8000,
            _ => eth_chain_id,
        };

        if let Some(txn_chain_id) = self.chain_id() {
            if node_chain_id != txn_chain_id {
                warn!(
                    "Chain_id provided in transaction: {} is different than node chain_id: {}",
                    txn_chain_id, node_chain_id
                );
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate_sender_account(&self, account: &Account) -> Result<bool> {
        let txn_cost = self.maximum_cost()?;
        if txn_cost > account.balance {
            warn!("Insufficient funds!");
            return Ok(false);
        }

        let Some(nonce) = self.nonce() else {
            return Ok(true);
        };
        if nonce < account.nonce {
            warn!("Nonce is too low");
            return Ok(false);
        }
        Ok(true)
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
            Transaction::Zilliqa(TxZilliqa { chain_id, .. }) => Some(*chain_id as u64),
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

    pub fn gas_limit(&self) -> EvmGas {
        match self {
            Transaction::Legacy(TxLegacy { gas_limit, .. }) => EvmGas(*gas_limit as u64),
            Transaction::Eip2930(TxEip2930 { gas_limit, .. }) => EvmGas(*gas_limit as u64),
            Transaction::Eip1559(TxEip1559 { gas_limit, .. }) => EvmGas(*gas_limit as u64),
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

    pub fn access_list(&self) -> Option<Vec<(Address, Vec<B256>)>> {
        match self {
            Transaction::Legacy(_) => None,
            Transaction::Eip2930(TxEip2930 { access_list, .. }) => Some(
                access_list
                    .0
                    .iter()
                    .map(|i| (i.address, i.storage_keys.clone()))
                    .collect(),
            ),
            Transaction::Eip1559(TxEip1559 { access_list, .. }) => Some(
                access_list
                    .0
                    .iter()
                    .map(|i| (i.address, i.storage_keys.clone()))
                    .collect(),
            ),
            Transaction::Zilliqa(_) => None,
            Transaction::Intershard(_) => None,
        }
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
    pub params: Vec<ScillaParam>,
}

impl ScillaLog {
    pub fn into_evm(self) -> EvmLog {
        // Unwrap is safe because [ScillaLog::Serialize] is infallible.
        let data = serde_json::to_string(&self).unwrap().abi_encode();
        EvmLog {
            address: self.address,
            topics: vec![keccak256(
                format!("event {}(string)", self.event_name).into_bytes(),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScillaParam {
    #[serde(rename = "type")]
    pub ty: String,
    pub value: String,
    #[serde(rename = "vname")]
    pub name: String,
}

impl ScillaParam {
    pub fn compute_hash(&self) -> Hash {
        Hash::builder()
            .with(self.ty.as_bytes())
            .with(self.value.as_bytes())
            .with(self.name.as_bytes())
            .finalize()
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
