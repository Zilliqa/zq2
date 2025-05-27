use anyhow::Result;
use libp2p::PeerId;
use revm::primitives::Address;
use serde::Deserialize;
use zilliqa::crypto::{NodePublicKey, SecretKey};

#[derive(Clone, Copy, Deserialize)]
pub struct EthereumAddress {
    pub secret_key: SecretKey,
    pub bls_public_key: NodePublicKey,
    pub peer_id: PeerId,
    pub address: Address,
}

impl EthereumAddress {
    pub fn from_private_key(private_key: &str) -> Result<Self> {
        let secret_key = SecretKey::from_hex(private_key)?;

        Ok(EthereumAddress {
            secret_key,
            bls_public_key: secret_key.node_public_key(),
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            address: secret_key.to_evm_address(),
        })
    }
}
