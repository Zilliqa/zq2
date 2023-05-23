use crate::state::Address;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use crate::crypto::{self, BlsOrEcdsaPublicKey, BlsOrEcdsaSignature};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommitment {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub from_addr: Address,
    pub to_addr: Address,
    pub amount: u128,
    pub payload: Vec<u8>,
}

impl SignedCommitment {
    pub fn hash(&self) -> crypto::Hash {
        crypto::Hash::compute(&[
            &self.nonce.to_be_bytes(),
            &self.gas_price.to_be_bytes(),
            &self.gas_limit.to_be_bytes(),
            &self.from_addr.as_bytes(),
            &self.to_addr.as_bytes(),
            &self.amount.to_be_bytes(),
            &self.payload,
        ])
    }
}

/// A signed transaction body, broadcast before execution and then persisted as part of a block after the transaction is executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    signed_commitment: SignedCommitment,
    pub signature: BlsOrEcdsaSignature,
    pub pubkey: BlsOrEcdsaPublicKey,
    pub contract_address: Option<Address>,
}

impl Transaction {
    pub fn hash(&self) -> crypto::Hash {
        self.signed_commitment.hash()
    }

    pub fn nonce(&self) -> u64 {
        self.signed_commitment.nonce
    }

    pub fn 

    pub fn verify(&self) -> Result<()> {
        self.pubkey.verify(self.hash().as_bytes(), self.signature)
    }
}
