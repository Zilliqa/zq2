use anyhow::Result;
use serde::Deserialize;
use zilliqa::crypto::SecretKey;

#[derive(Deserialize)]
pub struct EthereumAddress {
    secret_key: SecretKey,
    pub bls_public_key: String,
    pub peer_id: String,
    pub address: String,
}

impl EthereumAddress {
    pub fn from_private_key(private_key: &str) -> Result<Self> {
        let secret_key = SecretKey::from_hex(private_key)?;

        Ok(EthereumAddress {
            secret_key,
            bls_public_key: secret_key.node_public_key().to_string(),
            peer_id: secret_key
                .to_libp2p_keypair()
                .public()
                .to_peer_id()
                .to_string(),
            address: secret_key.to_evm_address().to_string(),
        })
    }

    pub fn bls_pop_signature(&self, chain_id: u64) -> Result<Signature<Bls12381G2Impl>> {
        Ok(self
            .secret_key
            .pop_prove(chain_id, self.secret_key.to_evm_address()))
    }
}
