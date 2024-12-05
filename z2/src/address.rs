use anyhow::Result;
use blsful::{Bls12381G2Impl, Signature};
use serde::Deserialize;
use serde_json::json;
use zilliqa::crypto::SecretKey;

#[derive(Deserialize)]
pub struct EthereumAddress {
    pub bls_public_key: String,
    pub peer_id: String,
    pub address: String,
}

impl EthereumAddress {
    // TODO consider refactor of this struct. init only evm addr and add build_pop
    pub fn from_private_key(private_key: &str) -> Result<Self> {
        let secret_key = SecretKey::from_hex(private_key)?;
        let evm_address = secret_key.to_evm_address();

        let output = json!({
            "bls_public_key": secret_key.node_public_key(),
            "peer_id": secret_key.to_libp2p_keypair().public().to_peer_id(),
            "address": evm_address,
        });

        Ok(serde_json::from_value(output)?)
    }

    pub fn bls_pop_signature(
        private_key: &str,
        chain_id: u64,
    ) -> Result<Signature<Bls12381G2Impl>> {
        let secret_key = SecretKey::from_hex(private_key)?;
        let evm_address = secret_key.to_evm_address();
        Ok(secret_key.pop_prove(chain_id, evm_address))
    }
}
