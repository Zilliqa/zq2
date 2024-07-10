use anyhow::Result;
use ethers::signers::Signer;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::Read;
use zilliqa_rs::{
    providers::{Http, Provider},
    signers::LocalWallet,
};

use super::Account;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStep {
    CallReadOnlyMethods(CallReadOnlyMethods),
    SendTransactions(SendTransactions),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub blockchain: Blockchain,
    pub source_of_funds: Account,
    pub scenario: Vec<ScenarioStep>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputType {
    Json,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub r#type: OutputType,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallReadOnlyMethodsType {
    GetBalance,
    QueryContractSubState,
    EvmContractViewFunction,
    Mixed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallReadOnlyMethods {
    pub iterations: u32,
    pub r#type: CallReadOnlyMethodsType,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallTransactionsType {
    ZilTransfer,
    EthTransfer,
    EvmContractCall,
    ScillaContractCall,
    Mixed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactions {
    pub iterations: u32,
    pub attempts_to_confirm: u32,
    pub sleep_ms_before_next_try: u64,
    pub r#type: CallTransactionsType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Blockchain {
    pub rpc_url: String,
    pub chainid: u16,
    pub gas_price: u128,
    pub gas_limit: u64,
}
impl Config {
    pub fn load(path: &str) -> Result<Config> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut config: Config = serde_yaml::from_str(&contents)?;

        const PRIV_KEY_ENV_VAR: &str = "PRIV_KEY";
        let priv_key_placeholder = format!("${{{PRIV_KEY_ENV_VAR}}}");
        if config.source_of_funds.private_key == priv_key_placeholder {
            let private_key = env::var(PRIV_KEY_ENV_VAR)?;
            config.source_of_funds.private_key = private_key;
        }

        Ok(config)
    }

    pub fn get_provider(&self) -> Result<Provider<Http>> {
        Ok(
            Provider::<Http>::try_from(self.blockchain.rpc_url.as_ref())?
                .with_chain_id(self.blockchain.chainid),
        )
    }

    pub fn get_signer(&self) -> Result<LocalWallet> {
        // TODO: Consider funding account type
        Ok(self.source_of_funds.private_key.parse()?)
    }

    pub fn make_eth_provider(
        &self,
    ) -> Result<ethers::providers::Provider<ethers::providers::Http>> {
        Ok(
            ethers::providers::Provider::<ethers::providers::Http>::try_from(
                self.blockchain.rpc_url.as_str(),
            )?,
        )
    }

    pub fn eth_chainid(&self) -> u64 {
        u64::from(self.blockchain.chainid | 0x8000)
    }

    pub async fn get_eth_middleware(
        &self,
        from: &Account,
    ) -> Result<
        ethers::middleware::signer::SignerMiddleware<
            ethers::providers::Provider<ethers::providers::Http>,
            ethers::signers::LocalWallet,
        >,
    > {
        let provider = self.make_eth_provider()?;
        Ok(ethers::middleware::SignerMiddleware::new(
            provider,
            from.get_eth_wallet()?.with_chain_id(self.eth_chainid()),
        ))
    }
}
