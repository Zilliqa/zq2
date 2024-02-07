use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use evm_ds::protos::evm_proto::Log;
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
};
use primitive_types::{H160, H256};
use prost::Message;
use rlp::RlpStream;
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

use crate::{
    crypto, schnorr,
    state::Address,
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};

/// A [Transaction] plus its signature. The underlying transaction can be obtained with
/// [`SignedTransaction::into_transaction()`]. The transaction's signer and hash can be obtained by converting this to a
/// [VerifiedTransaction] with [`SignedTransaction::verify()`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignedTransaction {
    Legacy {
        tx: TxLegacy,
        sig: EthSignature,
    },
    Eip2930 {
        tx: TxEip2930,
        sig: EthSignature,
    },
    Eip1559 {
        tx: TxEip1559,
        sig: EthSignature,
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

    pub fn sig_r(&self) -> [u8; 32] {
        match self {
            SignedTransaction::Legacy { sig, .. } => sig.r,
            SignedTransaction::Eip2930 { sig, .. } => sig.r,
            SignedTransaction::Eip1559 { sig, .. } => sig.r,
            SignedTransaction::Zilliqa { sig, .. } => sig.r().to_bytes().into(),
            SignedTransaction::Intershard { .. } => [0; 32],
        }
    }

    pub fn sig_s(&self) -> [u8; 32] {
        match self {
            SignedTransaction::Legacy { sig, .. } => sig.s,
            SignedTransaction::Eip2930 { sig, .. } => sig.s,
            SignedTransaction::Eip1559 { sig, .. } => sig.s,
            SignedTransaction::Zilliqa { sig, .. } => sig.s().to_bytes().into(),
            SignedTransaction::Intershard { .. } => [0; 32],
        }
    }

    pub fn sig_v(&self) -> u64 {
        match self {
            SignedTransaction::Legacy {
                sig,
                tx: TxLegacy {
                    chain_id: Some(c), ..
                },
            } => (sig.y_is_odd as u64) + c * 2 + 35,
            SignedTransaction::Legacy {
                sig,
                tx: TxLegacy { chain_id: None, .. },
            } => (sig.y_is_odd as u64) + 27,
            SignedTransaction::Eip2930 { sig, .. } => sig.y_is_odd as u64,
            SignedTransaction::Eip1559 { sig, .. } => sig.y_is_odd as u64,
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

    pub fn nonce(&self) -> u64 {
        match self {
            SignedTransaction::Legacy { tx, .. } => tx.nonce,
            SignedTransaction::Eip2930 { tx, .. } => tx.nonce,
            SignedTransaction::Eip1559 { tx, .. } => tx.nonce,
            // Zilliqa nonces are 1-indexed rather than zero indexed.
            SignedTransaction::Zilliqa { tx, .. } => tx.nonce - 1,
            SignedTransaction::Intershard { tx, .. } => tx.nonce,
        }
    }

    pub fn gas_price(&self) -> u128 {
        match self {
            SignedTransaction::Legacy { tx, .. } => tx.gas_price,
            SignedTransaction::Eip2930 { tx, .. } => tx.gas_price,
            // We ignore the priority fee and just use the maximum fee.
            SignedTransaction::Eip1559 { tx, .. } => tx.max_fee_per_gas,
            SignedTransaction::Zilliqa { tx, .. } => tx.gas_price,
            SignedTransaction::Intershard { tx, .. } => tx.gas_price,
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            SignedTransaction::Zilliqa { tx, .. } => tx.version,
            _ => 1,
        }
    }

    pub fn verify(self) -> Result<VerifiedTransaction> {
        let signer = match &self {
            SignedTransaction::Legacy { tx, sig } => {
                let recovery_id = RecoveryId::new(sig.y_is_odd, false);
                let signature = Signature::from_scalars(sig.r, sig.s)?;
                let key = VerifyingKey::recover_from_prehash(
                    &tx.signature_hash().0,
                    &signature,
                    recovery_id,
                )?;
                ecdsa_key_to_address(&key)
            }
            SignedTransaction::Eip2930 { tx, sig } => {
                let recovery_id = RecoveryId::new(sig.y_is_odd, false);
                let signature = Signature::from_scalars(sig.r, sig.s)?;
                let key = VerifyingKey::recover_from_prehash(
                    &tx.signature_hash().0,
                    &signature,
                    recovery_id,
                )?;
                ecdsa_key_to_address(&key)
            }
            SignedTransaction::Eip1559 { tx, sig } => {
                let recovery_id = RecoveryId::new(sig.y_is_odd, false);
                let signature = Signature::from_scalars(sig.r, sig.s)?;
                let key = VerifyingKey::recover_from_prehash(
                    &tx.signature_hash().0,
                    &signature,
                    recovery_id,
                )?;
                ecdsa_key_to_address(&key)
            }
            SignedTransaction::Zilliqa { tx, key, sig } => {
                let txn_data = encode_zilliqa_transaction(tx, *key);

                schnorr::verify(&txn_data, *key, *sig)
                    .ok_or_else(|| anyhow!("invalid signature"))?;

                let hashed = Sha256::digest(key.to_encoded_point(true).as_bytes());
                let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();
                H160(bytes.into())
            }
            SignedTransaction::Intershard { from, .. } => *from,
        };
        let hash = self.calculate_hash();

        Ok(VerifiedTransaction {
            tx: self,
            signer,
            hash,
        })
    }

    /// Calculate the hash of this transaction. If you need to do this more than once, consider caching the result
    /// using [`Self::verify()`] and the `hash` field from [RecoveredTransaction].
    pub fn calculate_hash(&self) -> crypto::Hash {
        match self {
            SignedTransaction::Legacy { tx, sig } => {
                let mut rlp = RlpStream::new_list(9);
                tx.encode_fields(&mut rlp);
                sig.encode_legacy(&mut rlp, tx.chain_id);
                crypto::Hash(Keccak256::digest(rlp.out()).into())
            }
            SignedTransaction::Eip2930 { tx, sig } => {
                let mut buffer = BytesMut::with_capacity(1024);
                buffer.put_u8(1);
                let mut rlp = RlpStream::new_list_with_buffer(buffer, 11);
                tx.encode_fields(&mut rlp);
                sig.encode(&mut rlp);
                crypto::Hash(Keccak256::digest(rlp.out()).into())
            }
            SignedTransaction::Eip1559 { tx, sig } => {
                let mut buffer = BytesMut::with_capacity(1024);
                buffer.put_u8(2);
                let mut rlp = RlpStream::new_list_with_buffer(buffer, 12);
                tx.encode_fields(&mut rlp);
                sig.encode(&mut rlp);
                crypto::Hash(Keccak256::digest(rlp.out()).into())
            }
            SignedTransaction::Zilliqa { tx, key, .. } => {
                let txn_data = encode_zilliqa_transaction(tx, *key);
                crypto::Hash(Sha256::digest(txn_data).into())
            }
            SignedTransaction::Intershard { tx, from } => {
                let mut rlp = RlpStream::new_list(7);
                tx.encode_fields(&mut rlp);
                rlp.append(from);
                crypto::Hash(Keccak256::digest(rlp.out()).into())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EthSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    // True if the parity of the y value of the signature is odd.
    pub y_is_odd: bool,
}

impl EthSignature {
    fn encode(&self, rlp: &mut RlpStream) {
        rlp.append(&self.y_is_odd)
            .append(&strip_leading_zeroes(self.r.as_slice()))
            .append(&strip_leading_zeroes(self.s.as_slice()));
    }

    fn encode_legacy(&self, rlp: &mut RlpStream, chain_id: Option<u64>) {
        // Encode the 'v' value of the signature, based the specification of EIP-155.
        let v = if let Some(chain_id) = chain_id {
            (self.y_is_odd as u64) + chain_id * 2 + 35
        } else {
            (self.y_is_odd as u64) + 27
        };
        rlp.append(&v)
            .append(&strip_leading_zeroes(self.r.as_slice()))
            .append(&strip_leading_zeroes(self.s.as_slice()));
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

    pub fn nonce(&self) -> u64 {
        match self {
            Transaction::Legacy(TxLegacy { nonce, .. }) => *nonce,
            Transaction::Eip2930(TxEip2930 { nonce, .. }) => *nonce,
            Transaction::Eip1559(TxEip1559 { nonce, .. }) => *nonce,
            // Zilliqa nonces are 1-indexed rather than zero indexed.
            Transaction::Zilliqa(TxZilliqa { nonce, .. }) => *nonce - 1,
            Transaction::Intershard(TxIntershard { nonce, .. }) => *nonce,
        }
    }

    pub fn max_fee_per_gas(&self) -> u128 {
        match self {
            Transaction::Legacy(TxLegacy { gas_price, .. }) => *gas_price,
            Transaction::Eip2930(TxEip2930 { gas_price, .. }) => *gas_price,
            Transaction::Eip1559(TxEip1559 {
                max_fee_per_gas, ..
            }) => *max_fee_per_gas,
            Transaction::Zilliqa(TxZilliqa { gas_price, .. }) => *gas_price,
            Transaction::Intershard(TxIntershard { gas_price, .. }) => *gas_price,
        }
    }

    pub fn gas_limit(&self) -> u64 {
        match self {
            Transaction::Legacy(TxLegacy { gas_limit, .. }) => *gas_limit,
            Transaction::Eip2930(TxEip2930 { gas_limit, .. }) => *gas_limit,
            Transaction::Eip1559(TxEip1559 { gas_limit, .. }) => *gas_limit,
            Transaction::Zilliqa(TxZilliqa { gas_limit, .. }) => *gas_limit,
            Transaction::Intershard(TxIntershard { gas_limit, .. }) => *gas_limit,
        }
    }

    pub fn to_addr(&self) -> Option<Address> {
        match self {
            Transaction::Legacy(TxLegacy { to_addr, .. }) => *to_addr,
            Transaction::Eip2930(TxEip2930 { to_addr, .. }) => *to_addr,
            Transaction::Eip1559(TxEip1559 { to_addr, .. }) => *to_addr,
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
            Transaction::Legacy(TxLegacy { amount, .. }) => *amount,
            Transaction::Eip2930(TxEip2930 { amount, .. }) => *amount,
            Transaction::Eip1559(TxEip1559 { amount, .. }) => *amount,
            // Zilliqa amounts are represented in units of (10^-12) ZILs, whereas our internal representation is in
            // units of (10^-18) ZILs. Account for this difference by multiplying the amount by (10^6).
            Transaction::Zilliqa(TxZilliqa { amount, .. }) => *amount * 10u128.pow(6),
            Transaction::Intershard(_) => 0,
        }
    }

    pub fn payload(&self) -> (&[u8], &[u8]) {
        match self {
            Transaction::Legacy(TxLegacy { payload, .. }) => (payload, <&[u8]>::default()),
            Transaction::Eip2930(TxEip2930 { payload, .. }) => (payload, <&[u8]>::default()),
            Transaction::Eip1559(TxEip1559 { payload, .. }) => (payload, <&[u8]>::default()),
            // Zilliqa transactions can have both code and data set, but code takes precedence if it is non-empty.
            Transaction::Zilliqa(TxZilliqa { code, data, .. }) => {
                match (!code.is_empty(), !data.is_empty()) {
                    (true, false) => (code.as_bytes(), <&[u8]>::default()),
                    (false, true) => (data.as_bytes(), <&[u8]>::default()),
                    (true, true) => (code.as_bytes(), data.as_bytes()),
                    (false, false) => (<&[u8]>::default(), <&[u8]>::default()),
                }
            }
            Transaction::Intershard(TxIntershard { payload, .. }) => (payload, <&[u8]>::default()),
        }
    }

    pub fn access_list(&self) -> Option<&[(Address, Vec<H256>)]> {
        match self {
            Transaction::Legacy(_) => None,
            Transaction::Eip2930(TxEip2930 { access_list, .. }) => Some(access_list),
            Transaction::Eip1559(TxEip1559 { access_list, .. }) => Some(access_list),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxLegacy {
    /// `None` for non-EIP-155 transactions without replay protection.
    pub chain_id: Option<u64>,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to_addr: Option<Address>,
    pub amount: u128,
    pub payload: Vec<u8>,
}

impl TxLegacy {
    /// Returns the "signature hash" of the transaction, over which the transaction's signature is calculated.
    fn signature_hash(&self) -> crypto::Hash {
        let mut rlp = RlpStream::new_list(if self.chain_id.is_some() { 9 } else { 6 });
        self.encode_fields(&mut rlp);
        if let Some(chain_id) = &self.chain_id {
            rlp.append(chain_id).append(&0u8).append(&0u8);
        }
        crypto::Hash(Keccak256::digest(rlp.out()).into())
    }

    fn encode_fields(&self, rlp: &mut RlpStream) {
        rlp.append(&self.nonce)
            .append(&self.gas_price)
            .append(&self.gas_limit)
            .append(&rlp_option_addr(&self.to_addr))
            .append(&self.amount)
            .append(&self.payload);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxIntershard {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to_addr: Option<Address>, // do not support cross-shard contract deployments (yet)
    // Amount intentionally missing: cannot send native amount cross-shard
    pub payload: Vec<u8>,
}

impl TxIntershard {
    fn encode_fields(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.gas_price)
            .append(&self.gas_limit)
            .append(&self.to_addr)
            .append(&self.payload);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxEip2930 {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to_addr: Option<Address>,
    pub amount: u128,
    pub payload: Vec<u8>,
    pub access_list: Vec<(Address, Vec<H256>)>,
}

impl TxEip2930 {
    /// Returns the "signature hash" of the transaction, over which the transaction's signature is calculated.
    fn signature_hash(&self) -> crypto::Hash {
        let mut buffer = BytesMut::with_capacity(1024);
        buffer.put_u8(1);
        let mut rlp = RlpStream::new_list_with_buffer(buffer, 8);
        self.encode_fields(&mut rlp);

        crypto::Hash(Keccak256::digest(rlp.out()).into())
    }

    fn encode_fields(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.gas_price)
            .append(&self.gas_limit)
            .append(&rlp_option_addr(&self.to_addr))
            .append(&self.amount)
            .append(&self.payload);
        encode_access_list(rlp, &self.access_list);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxEip1559 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to_addr: Option<Address>,
    pub amount: u128,
    pub payload: Vec<u8>,
    pub access_list: Vec<(Address, Vec<H256>)>,
}

impl TxEip1559 {
    /// Returns the "signature hash" of the transaction, over which the transaction's signature is calculated.
    fn signature_hash(&self) -> crypto::Hash {
        let mut buffer = BytesMut::with_capacity(1024);
        buffer.put_u8(2);
        let mut rlp = RlpStream::new_list_with_buffer(buffer, 9);
        self.encode_fields(&mut rlp);

        crypto::Hash(Keccak256::digest(rlp.out()).into())
    }

    fn encode_fields(&self, rlp: &mut RlpStream) {
        rlp.append(&self.chain_id)
            .append(&self.nonce)
            .append(&self.max_priority_fee_per_gas)
            .append(&self.max_fee_per_gas)
            .append(&self.gas_limit)
            .append(&rlp_option_addr(&self.to_addr))
            .append(&self.amount)
            .append(&self.payload);
        encode_access_list(rlp, &self.access_list);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxZilliqa {
    pub chain_id: u16,
    pub version: u32,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to_addr: Address,
    pub amount: u128,
    pub code: String,
    pub data: String,
}

/// A transaction receipt stores data about the execution of a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub block_hash: crypto::Hash,
    pub tx_hash: crypto::Hash,
    pub success: bool,
    pub gas_used: u64,
    pub contract_address: Option<Address>,
    pub logs: Vec<Log>,
    pub scilla_events: String,
}

fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
    // If `bytes` is all zeroes, default to `bytes.len() - 2`. This is because zeroes should be
    // encoded as `[0]`.
    let first_non_zero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 2);

    &bytes[first_non_zero..]
}

fn ecdsa_key_to_address(key: &VerifyingKey) -> Address {
    // Remove the first byte before hashing - The first byte specifies the encoding tag.
    let hashed = Keccak256::digest(&key.to_encoded_point(false).as_bytes()[1..]);
    let (_, bytes): (GenericArray<u8, U12>, GenericArray<u8, U20>) = hashed.split();
    H160(bytes.into())
}

/// Encode an `Option<H160>` ready to be added to an [RlpStream].
/// `None` is represented as an empty string.
fn rlp_option_addr(addr: &Option<H160>) -> &[u8] {
    addr.as_ref().map(|a| a.as_ref()).unwrap_or_default()
}

fn encode_access_list(rlp: &mut RlpStream, access_list: &[(Address, Vec<H256>)]) {
    rlp.begin_list(access_list.len());
    for (address, storage_keys) in access_list {
        rlp.begin_list(2);
        rlp.append(address);
        rlp.append_list(storage_keys);
    }
}

fn encode_zilliqa_transaction(txn: &TxZilliqa, pub_key: schnorr::PublicKey) -> Vec<u8> {
    let oneof8 = (!txn.code.is_empty()).then_some(Code::Code(txn.code.clone().into_bytes()));
    let oneof9 = (!txn.data.is_empty()).then_some(Data::Data(txn.data.clone().into_bytes()));
    let proto = ProtoTransactionCoreInfo {
        version: (((txn.chain_id) as u32) << 16) | 0x0001,
        toaddr: txn.to_addr.as_bytes().to_vec(),
        senderpubkey: Some(pub_key.to_sec1_bytes().into()),
        amount: Some((txn.amount).to_be_bytes().to_vec().into()),
        gasprice: Some((txn.gas_price).to_be_bytes().to_vec().into()),
        gaslimit: txn.gas_limit,
        oneof2: Some(Nonce::Nonce(txn.nonce)),
        oneof8,
        oneof9,
    };
    proto.encode_to_vec()
}
