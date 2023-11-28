use std::io;

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use zilliqa::crypto::SecretKey;

#[derive(Deserialize)]
struct Input {
    secret_key: String,
}

fn main() -> Result<()> {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    let input: Input = serde_json::from_str(&buffer)?;

    let secret_key = SecretKey::from_hex(&input.secret_key)?;

    let output = json!({
        "public_key": secret_key.node_public_key(),
        "peer_id": secret_key.to_libp2p_keypair().public().to_peer_id(),
        "address": secret_key.tx_ecdsa_public_key().into_addr(),
    });

    println!("{output}");

    Ok(())
}
