//! A collection of cryptographic primitives used by Zilliqa.
//!
//! The exact implementations of these primitives is an implementation detail for this module only and dependents
//! should not care about the implementations. This gives us some confidence that we could replace the implementations
//! in the future if we wanted to.

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlsSignature(bls_signatures::Signature);

impl BlsSignature {
    pub fn identity() -> BlsSignature {
        BlsSignature(G2Affine::identity().into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BlsSignature> {
        Ok(BlsSignature(bls_signatures::Signature::from_bytes(bytes)?))
    }

    pub fn aggregate(signatures: &[BlsSignature]) -> Result<BlsSignature> {
        let signatures: Vec<_> = signatures.iter().map(|s| s.0).collect();
        Ok(BlsSignature(bls_signatures::aggregate(&signatures)?))
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.as_bytes()
    }
}

impl serde::Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        BlsSignature::from_bytes(&bytes)
            .map_err(|_| de::Error::invalid_value(Unexpected::Bytes(&bytes), &"a signature"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BlsOrEcdsaSignature {
    Bls(BlsSignature),
    Ecdsa(EcdsaSignature),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlsPublicKey(bls_signatures::PublicKey);

impl BlsPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<BlsPublicKey> {
        Ok(BlsPublicKey(bls_signatures::PublicKey::from_bytes(bytes)?))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: BlsSignature) -> Result<()> {
        if !self.0.verify(signature.0, message) {
            return Err(anyhow!("invalid signature"));
        }

        Ok(())
    }
}

impl Display for BlsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl serde::Serialize for BlsPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        BlsPublicKey::from_bytes(&bytes)
            .map_err(|_| de::Error::invalid_value(Unexpected::Bytes(&bytes), &"a public key"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BlsOrEcdsaPublicKey {
    Bls(BlsPublicKey),
    Ecdsa(VerifyingKey),
}

impl BlsOrEcdsaPublicKey {
    pub fn verify(&self, message: &[u8], signature: BlsOrEcdsaSignature) -> Result<()> {
        let result = match (self, signature) {
            (BlsOrEcdsaPublicKey::Bls(pubkey), BlsOrEcdsaSignature::Bls(sig)) => {
                pubkey.verify(message, sig)
            }
            (BlsOrEcdsaPublicKey::Ecdsa(pubkey), BlsOrEcdsaSignature::Ecdsa(sig)) => {
                pubkey.verify(message, &sig).map_err(|e| anyhow!(e))
            }
            _ => Err(anyhow!("Mismatch between signature and public key type!")),
        };
        result.map_err(|_| anyhow!("Invalid signature"))
    }
}

pub fn verify_messages(
    signature: BlsSignature,
    messages: &[&[u8]],
    public_keys: &[BlsPublicKey],
) -> Result<()> {
    let public_keys: Vec<_> = public_keys.iter().map(|p| p.0).collect();
    if !bls_signatures::verify_messages(&signature.0, messages, &public_keys) {
        return Err(anyhow!("invalid signature"));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct SecretKey(pub bls_signatures::PrivateKey);
impl SecretKey {
    pub fn new() -> Result<SecretKey> {
        Ok(SecretKey(bls_signatures::PrivateKey::generate(
            &mut rand_core::OsRng,
        )))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey> {
        Ok(SecretKey(bls_signatures::PrivateKey::from_bytes(bytes)?))
    }

    pub fn from_hex(s: &str) -> Result<SecretKey> {
        SecretKey::from_bytes(&hex::decode(s)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.0.as_bytes())
    }

    pub fn to_hex(&self) -> Result<String> {
        Ok(hex::encode(self.0.as_bytes()))
    }

    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        BlsSignature(self.0.sign(message))
    }

    pub fn bls_public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.public_key())
    }

    pub fn to_libp2p_keypair(self) -> libp2p::identity::Keypair {
        libp2p::identity::Keypair::Ed25519(
            libp2p::identity::ed25519::SecretKey::from_bytes(self.0.as_bytes())
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
