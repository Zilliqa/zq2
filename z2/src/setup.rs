use eyre::{eyre, Result};
/// This module should eventually generate configuration files
/// For now, it just generates secret keys (which should be different each run, or we will become dependent on their values)
use zilliqa::crypto;

pub struct Setup {}

impl Setup {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }

    pub fn generate_secret_key_hex(&self) -> Result<String> {
        crypto::SecretKey::new()
            .map_err(|err| eyre!(Box::new(err)))?
            .to_hex()
            .map_err(|err| eyre!(Box::new(err)))
    }
}
