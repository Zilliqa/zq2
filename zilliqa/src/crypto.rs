//! A collection of cryptographic primitives used by Zilliqa.
//!
//! The exact implementations of these primitives is an implementation detail for this module only and dependents
//! should not care about the implementations. This gives us some confidence that we could replace the implementations
//! in the future if we wanted to.

use k256::ecdsa::signature::Signer;
use std::fmt::Display;

use anyhow::{anyhow, Result};
use bls12_381::G2Affine;
use bls_signatures::Serialize as BlsSerialize;
use k256::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};
use rand_core;
use serde::{
    de::{self, Unexpected},
    Deserialize, Serialize,
};
use sha3::{Digest, Keccak256};

use crate::state::Address;

/// The signature type used internally in consensus, to e.g. sign block proposals.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodeSignature(bls_signatures::Signature);

impl NodeSignature {
    pub fn identity() -> NodeSignature {
        NodeSignature(G2Affine::identity().into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<NodeSignature> {
        Ok(NodeSignature(bls_signatures::Signature::from_bytes(bytes)?))
    }

    pub fn aggregate(signatures: &[NodeSignature]) -> Result<NodeSignature> {
        let signatures: Vec<_> = signatures.iter().map(|s| s.0).collect();
        Ok(NodeSignature(bls_signatures::aggregate(&signatures)?))
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.as_bytes()
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TransactionSignature {
    Ecdsa(EcdsaSignature),
}

/// The public key type used internally in consensus, alongside `NodeSignature`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodePublicKey(bls_signatures::PublicKey);

impl NodePublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<NodePublicKey> {
        Ok(NodePublicKey(bls_signatures::PublicKey::from_bytes(bytes)?))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: NodeSignature) -> Result<()> {
        if !self.0.verify(signature.0, message) {
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
        self.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodePublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        NodePublicKey::from_bytes(&bytes)
            .map_err(|_| de::Error::invalid_value(Unexpected::Bytes(&bytes), &"a public key"))
    }
}

/// The set of public keys that are accepted for signing and validating transactions, each
/// corresponding to a variant of `TransactionSignature`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TransactionPublicKey {
    Ecdsa(VerifyingKey),
}

impl TransactionPublicKey {
    pub fn verify(&self, message: &[u8], signature: TransactionSignature) -> Result<()> {
        let result = match (self, signature) {
            (TransactionPublicKey::Ecdsa(pubkey), TransactionSignature::Ecdsa(sig)) => {
                pubkey.verify(message, &sig).map_err(|e| anyhow!(e))
            }
            #[allow(unreachable_patterns)] // will be necessary with >1 signature types
            _ => Err(anyhow!("Mismatch between signature and public key type!")),
        };
        result.map_err(|_| anyhow!("Invalid signature"))
    }

    pub fn into_addr(&self) -> Address {
        let bytes = match self {
            Self::Ecdsa(key) => {
                // Remove the first byte before hashing - The first byte specifies the encoding tag.
                key.to_encoded_point(false).as_bytes()[1..].to_owned()
            }
        };
        Address::from_slice(&Keccak256::digest(bytes)[12..32])
    }
}

pub fn verify_messages(
    signature: NodeSignature,
    messages: &[&[u8]],
    public_keys: &[NodePublicKey],
) -> Result<()> {
    let public_keys: Vec<_> = public_keys.iter().map(|p| p.0).collect();
    if !bls_signatures::verify_messages(&signature.0, messages, &public_keys) {
        return Err(anyhow!("invalid signature"));
    }

    Ok(())
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
        let bls_temp = bls_signatures::PrivateKey::generate(&mut rand_core::OsRng);
        Self::from_bytes(&bls_temp.as_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey> {
        let bytes: [u8; 32] = bytes.try_into()?;
        // ensure the key is valid for all representations
        Self::try_cast_to_bls(&bytes)?;
        Self::try_cast_to_ecdsa(&bytes)?;
        Ok(Self { bytes })
    }

    pub fn from_hex(s: &str) -> Result<SecretKey> {
        let bytes_vec = hex::decode(s)?;
        Self::from_bytes(&bytes_vec)
    }

    fn try_cast_to_bls(bytes: &[u8; 32]) -> Result<bls_signatures::PrivateKey> {
        Ok(bls_signatures::PrivateKey::from_bytes(bytes)?)
    }

    /// Warning: panics if the bytes aren't a valid key for the cast.
    /// Should only be used on SecretKeys that have been validated using the
    /// `try_cast_...` method, e.g. during construction.
    fn cast_to_bls(&self) -> bls_signatures::PrivateKey {
        Self::try_cast_to_bls(&self.bytes)
            .expect("Validated private key failed to cast to BLS key type")
    }

    fn try_cast_to_ecdsa(bytes: &[u8; 32]) -> Result<k256::ecdsa::SigningKey> {
        Ok(k256::ecdsa::SigningKey::from_slice(bytes)?)
    }

    /// Warning: panics if the bytes aren't a valid key for the cast.
    /// Should only be used on SecretKeys that have been validated using the
    /// `try_cast_...` method, e.g. during construction.
    fn cast_to_ecdsa(&self) -> k256::ecdsa::SigningKey {
        Self::try_cast_to_ecdsa(&self.bytes)
            .expect("Validated private key failed to cast to ECDSA key type")
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.bytes.to_vec())
    }

    pub fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(self.bytes))
    }

    pub fn sign(&self, message: &[u8]) -> NodeSignature {
        NodeSignature(self.cast_to_bls().sign(message))
    }

    pub fn node_public_key(&self) -> NodePublicKey {
        NodePublicKey(self.cast_to_bls().public_key())
    }

    pub fn tx_ecdsa_public_key(&self) -> TransactionPublicKey {
        TransactionPublicKey::Ecdsa(k256::ecdsa::VerifyingKey::from(&self.cast_to_ecdsa()))
    }

    pub fn tx_sign_ecdsa(&self, message: &[u8]) -> TransactionSignature {
        TransactionSignature::Ecdsa(self.cast_to_ecdsa().sign(message))
    }

    pub fn to_libp2p_keypair(&self) -> libp2p::identity::Keypair {
        libp2p::identity::Keypair::Ed25519(
            libp2p::identity::ed25519::SecretKey::from_bytes(self.bytes)
                .expect("`SecretKey::from_bytes` returns an `Err` only when the length is not 32, we know the length is 32")
                .into(),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const ZERO: Hash = Hash([0; 32]);

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn compute(preimages: &[&[u8]]) -> Hash {
        let mut hasher = Keccak256::new();
        for preimage in preimages {
            hasher.update(preimage);
        }
        Self(hasher.finalize().into())
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
