use std::str::FromStr;

use anyhow::Result;
use ethers::signers::Signer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub enum AccountKind {
    #[serde(rename = "zil")]
    Zil,
    #[serde(rename = "eth")]
    Eth,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub kind: AccountKind,
    pub private_key: String,
}

impl Account {
    pub fn get_privkey_hex(&self) -> Result<String> {
        // TODO : reformat
        Ok(self.private_key.to_string())
    }

    pub fn get_zq_privkey(&self) -> Result<zilliqa_rs::core::PrivateKey> {
        Ok(self.private_key.parse()?)
    }
    pub fn get_zq_pubkey(&self) -> Result<zilliqa_rs::core::PublicKey> {
        Ok(self.get_zq_privkey()?.public_key())
    }
    pub fn get_zq_address(&self) -> Result<zilliqa_rs::core::ZilAddress> {
        Ok(zilliqa_rs::core::ZilAddress::try_from(
            &self.get_zq_pubkey()?,
        )?)
    }
    pub fn get_zq_hex(&self) -> Result<String> {
        Ok(format!("{}", self.get_zq_address()?))
    }

    pub fn get_eth_wallet(&self) -> Result<ethers::signers::LocalWallet> {
        Ok(ethers::signers::LocalWallet::from_str(&self.private_key)?)
    }

    pub fn get_address_as_zil(&self) -> Result<zilliqa_rs::core::ZilAddress> {
        Ok(zilliqa_rs::core::ZilAddress::from_str(
            &self.get_address()?,
        )?)
    }

    pub fn get_address_as_eth(&self) -> Result<ethers::types::Address> {
        Ok(ethers::types::Address::from_str(&self.get_address()?)?)
    }

    pub fn get_address(&self) -> Result<String> {
        Ok(match self.kind {
            AccountKind::Zil => self.get_zq_address()?.to_string(),
            AccountKind::Eth => hex::encode(self.get_eth_address()?),
        })
    }

    pub fn get_eth_address(&self) -> Result<ethers::types::Address> {
        let wallet = self.get_eth_wallet()?;
        Ok(wallet.address())
    }
}
