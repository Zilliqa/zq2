use std::io;

use anyhow::Result;
use crypto_bigint::generic_array::GenericArray;
use serde::Deserialize;
use serde_json::json;
use zilliqa::crypto::{SecretKey, TransactionPublicKey};

#[derive(Deserialize)]
struct Input {
    secret_key: String,
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

    let output = json!({
        "bls_public_key": secret_key.node_public_key(),
        "peer_id": secret_key.to_libp2p_keypair().public().to_peer_id(),
        "tx_pubkey": tx_pubkey,
        "address": tx_pubkey.into_addr(),
        "bls_pop_signature": secret_key.pop_prove(),
    });

    println!("{output}");

    Ok(())
}
