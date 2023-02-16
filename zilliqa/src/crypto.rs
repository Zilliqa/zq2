//! A collection of cryptographic primitives used by Zilliqa.
//!
//! The exact implementations of these primitives is an implementation detail for this module only and dependents
//! should not care about the implementations. This gives us some confidence that we could replace the implementations
//! in the future if we wanted to.

use std::fmt::Display;

use anyhow::{anyhow, Result};
use bls12_381::G2Affine;
use bls_signatures::Serialize;
use serde::{
    de::{self, Unexpected},
    Deserialize,
};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature(bls_signatures::Signature);

impl Signature {
    pub fn identity() -> Signature {
        Signature(G2Affine::identity().into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Signature> {
        Ok(Signature(bls_signatures::Signature::from_bytes(bytes)?))
    }

    pub fn aggregate(signatures: &[Signature]) -> Result<Signature> {
        let signatures: Vec<_> = signatures.iter().map(|s| s.0).collect();
        Ok(Signature(bls_signatures::aggregate(&signatures)?))
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.as_bytes()
    }
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Signature::from_bytes(&bytes)
            .map_err(|_| de::Error::invalid_value(Unexpected::Bytes(&bytes), &"a signature"))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PublicKey(bls_signatures::PublicKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey> {
        Ok(PublicKey(bls_signatures::PublicKey::from_bytes(bytes)?))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes()
    }

    pub fn from_hex(s: &str) -> Result<PublicKey> {
        PublicKey::from_bytes(&hex::decode(s)?)
    }

    pub fn verify(&self, message: &[u8], signature: Signature) -> Result<()> {
        if !self.0.verify(signature.0, message) {
            return Err(anyhow!("invalid signature"));
        }

        Ok(())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

pub fn verify_messages(
    signature: Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
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
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey> {
        Ok(SecretKey(bls_signatures::PrivateKey::from_bytes(bytes)?))
    }

    pub fn from_hex(s: &str) -> Result<SecretKey> {
        SecretKey::from_bytes(&hex::decode(s)?)
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    pub fn to_libp2p_keypair(self) -> Result<libp2p::identity::Keypair> {
        Ok(libp2p::identity::Keypair::Secp256k1(
            libp2p::identity::secp256k1::SecretKey::from_bytes(self.0.as_bytes())?.into(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash([u8; 32]);

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
