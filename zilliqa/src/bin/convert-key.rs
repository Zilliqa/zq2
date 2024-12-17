use std::io;

use alloy::primitives::Address;
use anyhow::Result;
use crypto_bigint::generic_array::GenericArray;
use serde::Deserialize;
use serde_json::json;
use zilliqa::crypto::{SecretKey, TransactionPublicKey};

#[derive(Deserialize)]
struct Input {
    secret_key: String,
    chain_id: u64,
    address: Option<String>,
}

fn main() -> Result<()> {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    let input: Input = serde_json::from_str(&buffer)?;

    let secret_key = SecretKey::from_hex(&input.secret_key)?;

    let key_bytes = secret_key.as_bytes();
    let ecdsa_key =
        k256::ecdsa::SigningKey::from_bytes(GenericArray::from_slice(&key_bytes)).unwrap();

    let tx_pubkey = TransactionPublicKey::Ecdsa(k256::ecdsa::VerifyingKey::from(&ecdsa_key), true);

    // default to address derived from pub key
    let address = match input.address {
        None => tx_pubkey.into_addr(),
        Some(addr) => addr.parse::<Address>().unwrap(),
    };

    let output = json!({
        "bls_public_key": secret_key.node_public_key(),
        "peer_id": secret_key.to_libp2p_keypair().public().to_peer_id(),
        "tx_pubkey": tx_pubkey,
        "address": address,
        "deposit_auth_signature": hex::encode(secret_key.deposit_auth_signature(input.chain_id, address).as_raw_value().to_compressed()),
    });

    println!("{output}");

    Ok(())
}
