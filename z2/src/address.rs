use anyhow::Result;
use crypto_bigint::generic_array::GenericArray;
use serde::Deserialize;
use zilliqa::crypto::{SecretKey, TransactionPublicKey};

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct EthereumAddress {
    pub private_key: String,
    pub bls_public_key: String,
    pub bls_pop_signature: String,
    pub peer_id: String,
    pub address: String,
}

impl EthereumAddress {
    pub fn from_private_key(private_key: &str) -> Result<Self> {
        let secret_key = SecretKey::from_hex(private_key)?;

        let key_bytes = secret_key.as_bytes();
        let ecdsa_key =
            k256::ecdsa::SigningKey::from_bytes(GenericArray::from_slice(&key_bytes)).unwrap();

        let tx_pubkey =
            TransactionPublicKey::Ecdsa(k256::ecdsa::VerifyingKey::from(&ecdsa_key), true);

        Ok(Self {
            private_key: private_key.to_owned(),
            bls_public_key: secret_key.node_public_key().to_string(),
            bls_pop_signature: secret_key.pop_prove().to_string(),
            peer_id: secret_key
                .to_libp2p_keypair()
                .public()
                .to_peer_id()
                .to_string(),
            address: tx_pubkey.into_addr().to_string(),
        })
    }
}
