//! A collection of cryptographic primitives used by Zilliqa.
//!
//! The exact implementations of these primitives is an implementation detail for this module only and dependents
//! should not care about the implementations. This gives us some confidence that we could replace the implementations
//! in the future if we wanted to.

use std::fmt::Display;

use alloy::primitives::{Address, B256};
use anyhow::{anyhow, Result};
use blsful::{
    inner_types::Group, vsss_rs::ShareIdentifier, AggregateSignature, Bls12381G2, Bls12381G2Impl, MultiPublicKey, MultiSignature, PublicKey, Signature
};
use itertools::Itertools;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature as EcdsaSignature, VerifyingKey};
use serde::{
    de::{self, Unexpected},
    Deserialize, Serialize,
};
use sha3::{Digest, Keccak256};

/// The signature type used internally in consensus, to e.g. sign block proposals.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodeSignature(Signature<Bls12381G2Impl>);

impl NodeSignature {
    pub fn identity() -> NodeSignature {
        // Default to Basic signatures - it's the normal signature.
        NodeSignature(Signature::<Bls12381G2Impl>::Basic(
            blsful::inner_types::G2Projective::identity(),
        ))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<NodeSignature> {
        // Default to Basic signatures - it's the normal signature.
        Ok(NodeSignature(Signature::<Bls12381G2Impl>::Basic(
            blsful::inner_types::G2Projective::from_compressed(bytes.try_into()?)
                .expect("blst_p2_uncompress() error"),
        )))
    }

    pub fn aggregate(signatures: &[NodeSignature]) -> Result<NodeSignature> {
        let signatures = signatures.iter().map(|s| s.0).collect_vec();

        // IETF standards say N >= 1
        // Handles single case where N == 1, as AggregateSignature::from_signatures() only handles N > 1.
        if signatures.len() < 2 {
            let g = blsful::inner_types::G2Projective::identity();
            return Ok(NodeSignature(match signatures[0] {
                Signature::Basic(s) => Signature::Basic(g + s),
                Signature::MessageAugmentation(s) => Signature::MessageAugmentation(g + s),
                Signature::ProofOfPossession(s) => Signature::ProofOfPossession(g + s),
            }));
        }

        let asig = AggregateSignature::<Bls12381G2Impl>::from_signatures(signatures)?;
        Ok(NodeSignature(match asig {
            AggregateSignature::Basic(s) => Signature::Basic(s),
            AggregateSignature::MessageAugmentation(s) => Signature::MessageAugmentation(s),
            AggregateSignature::ProofOfPossession(s) => Signature::ProofOfPossession(s),
        }))
    }

    // Verify that the aggregated signature is valid for the given public keys and message.
    // That is, each public key has signed the message, and the aggregated signature is the
    // aggregation of those signatures.
    pub fn verify_aggregate(
        signature: &NodeSignature,
        message: &[u8],
        public_keys: Vec<NodePublicKey>,
    ) -> Result<()> {
        let keys = public_keys.iter().map(|p| p.0).collect_vec();
        let mpk = MultiPublicKey::<Bls12381G2Impl>::from_public_keys(keys);
        let msig: MultiSignature<Bls12381G2Impl> = match signature.0 {
            Signature::Basic(s) => MultiSignature::Basic(s),
            Signature::MessageAugmentation(s) => MultiSignature::MessageAugmentation(s),
            Signature::ProofOfPossession(s) => MultiSignature::ProofOfPossession(s),
        };
        if msig.verify(mpk, message).is_err() {
            return Err(anyhow!("invalid QC aggregated signature!"));
        }
        Ok(())
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.as_raw_value().to_compressed().to_vec()
    }
}

pub fn verify_messages(
    signature: NodeSignature,
    messages: &[&[u8]],
    public_keys: &[NodePublicKey],
) -> Result<()> {
    let data: Vec<_> = public_keys
        .iter()
        .zip(messages.iter())
        .map(|(a, &b)| (a.0, b))
        .collect();
    let asig = match signature.0 {
        Signature::Basic(s) => AggregateSignature::Basic(s),
        Signature::MessageAugmentation(s) => AggregateSignature::MessageAugmentation(s),
        Signature::ProofOfPossession(s) => AggregateSignature::ProofOfPossession(s),
    };
    if asig.verify(data.as_slice()).is_err() {
        return Err(anyhow!("invalid signature"));
    }
    Ok(())
}

impl serde::Serialize for NodeSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodeSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        NodeSignature::from_bytes(&bytes)
            .map_err(|_| de::Error::invalid_value(Unexpected::Bytes(&bytes), &"a signature"))
    }
}

/// The set signatures that are accepted for signing and validating transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionSignature {
    Ecdsa(EcdsaSignature),
}

/// The public key type used internally in consensus, alongside `NodeSignature`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodePublicKey(PublicKey<Bls12381G2Impl>);

impl NodePublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<NodePublicKey> {
        Ok(NodePublicKey(PublicKey::<Bls12381G2Impl>::try_from(bytes)?))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0 .0.to_compressed().to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: NodeSignature) -> Result<()> {
        if signature.0.verify(&self.0, message).is_err() {
            return Err(anyhow!("invalid signature"));
        }
        Ok(())
    }
}

impl Display for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl serde::Serialize for NodePublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        hex::encode(self.as_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodePublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        let bytes = hex::decode(s).unwrap();
        NodePublicKey::from_bytes(&bytes)
            .map_err(|_| de::Error::invalid_value(Unexpected::Bytes(&bytes), &"a public key"))
    }
}

#[derive(Debug, Clone)]
pub struct NodePublicKeyRaw(Vec<u8>);

impl NodePublicKeyRaw {
    pub fn from_bytes(bytes: &[u8]) -> NodePublicKeyRaw {
        Self(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl From<NodePublicKey> for NodePublicKeyRaw {
    fn from(value: NodePublicKey) -> Self {
        Self::from_bytes(&value.as_bytes())
    }
}

impl TryFrom<NodePublicKeyRaw> for NodePublicKey {
    type Error = anyhow::Error;

    fn try_from(raw: NodePublicKeyRaw) -> std::result::Result<Self, Self::Error> {
        NodePublicKey::from_bytes(&raw.0)
    }
}

/// The set of public keys that are accepted for signing and validating transactions, each
/// corresponding to a variant of `TransactionSignature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionPublicKey {
    /// Ethereum-compatible ECDA signatures. The second element determines whether
    /// it is used for EIP155 compatible signatures (if false, assumes legacy ones).
    Ecdsa(VerifyingKey, bool),
}

impl TransactionPublicKey {
    pub fn verify(&self, message: &[u8], signature: TransactionSignature) -> Result<()> {
        let result = match (self, signature) {
            (TransactionPublicKey::Ecdsa(pubkey, _), TransactionSignature::Ecdsa(sig)) => {
                pubkey.verify_prehash(message, &sig).map_err(|e| anyhow!(e))
            }
            #[allow(unreachable_patterns)] // will be necessary with >1 signature types
            _ => Err(anyhow!("Mismatch between signature and public key type!")),
        };
        result.map_err(|_| anyhow!("Invalid signature"))
    }

    pub fn into_addr(&self) -> Address {
        let bytes = match self {
            Self::Ecdsa(key, _) => {
                // Remove the first byte before hashing - The first byte specifies the encoding tag.
                key.to_encoded_point(false).as_bytes()[1..].to_owned()
            }
        };
        Address::from_slice(&Keccak256::digest(bytes)[12..32])
    }
}
/// The secret key type used as the basis of all cryptography in the node.
/// Any of the `NodePublicKey` or `TransactionPublicKey`s, or a libp2p identity, can be derived
/// from this.
#[derive(Debug, Clone, Copy)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// Generates a random private key.
    pub fn new() -> Result<SecretKey> {
        let bls_temp = Bls12381G2::new_secret_key();
        Self::from_bytes(&bls_temp.to_be_bytes())
    }

    pub fn new_from_rng<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Result<SecretKey> {
        let bls_temp = Bls12381G2::random_secret_key(rng);
        Self::from_bytes(&bls_temp.to_be_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey> {
        let bytes: [u8; 32] = bytes.try_into()?;

        if bytes == [0; 32] {
            return Err(anyhow!("bytes are all zero"));
        }

        Ok(SecretKey { bytes })
    }

    pub fn from_hex(s: &str) -> Result<SecretKey> {
        let bytes_vec = hex::decode(s)?;
        Self::from_bytes(&bytes_vec)
    }

    pub fn as_bls(&self) -> blsful::SecretKey<Bls12381G2Impl> {
        blsful::SecretKey::<Bls12381G2Impl>::from_hash(self.bytes)
    }

    pub fn pop_prove(&self) -> blsful::ProofOfPossession<Bls12381G2Impl> {
        let sk = blsful::SecretKey::<Bls12381G2Impl>::from_hash(self.bytes);
        sk.proof_of_possession().expect("sk != 0")
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn sign(&self, message: &[u8]) -> NodeSignature {
        NodeSignature(
            self.as_bls()
                .sign(blsful::SignatureSchemes::Basic, message)
                .expect("sk != 0"),
        )
    }

    pub fn node_public_key(&self) -> NodePublicKey {
        NodePublicKey(self.as_bls().public_key())
    }

    pub fn to_libp2p_keypair(&self) -> libp2p::identity::Keypair {
        let keypair: libp2p::identity::ed25519::Keypair = libp2p::identity::ed25519::SecretKey::try_from_bytes(self.bytes)
            .expect("`SecretKey::from_bytes` returns an `Err` only when the length is not 32, we know the length is 32")
            .into();
        keypair.into()
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0; Hash::LEN]);
    pub const LEN: usize = 32;

    pub fn builder() -> HashBuilder {
        HashBuilder(Keccak256::new())
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        Ok(Hash(bytes.try_into()?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<B256> for Hash {
    fn from(value: B256) -> Self {
        Self(value.0)
    }
}

impl From<Hash> for B256 {
    fn from(value: Hash) -> Self {
        Self(value.0)
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(<[u8; 32]>::try_from(value)?))
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

pub struct HashBuilder(Keccak256);

impl HashBuilder {
    pub fn finalize(self) -> Hash {
        Hash(self.0.finalize().into())
    }

    pub fn with(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.0.update(bytes.as_ref());

        self
    }

    pub fn with_optional(self, bytes_optional: Option<impl AsRef<[u8]>>) -> Self {
        if let Some(bytes) = bytes_optional {
            self.with(bytes)
        } else {
            self
        }
    }

    pub fn with_iter<T: AsRef<[u8]>>(mut self, bytes_iter: impl Iterator<Item = T>) -> Self {
        bytes_iter.for_each(|bytes| self.0.update(bytes.as_ref()));

        self
    }
}
