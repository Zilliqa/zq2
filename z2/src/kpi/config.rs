use std::{env, fs::File, io::Read};

use alloy::{
    network::EthereumWallet,
    providers::{
        Identity, ProviderBuilder, RootProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
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
    pub output: Output,
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
    ScillaTransitionCall,
    Mixed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTransactions {
    pub iterations: usize,
    pub attempts_to_confirm: usize,
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

    // pub fn make_eth_provider(&self) -> Result<Wallet> {
    //     Ok(ProviderBuilder::new().connect_http(self.blockchain.rpc_url.parse().unwrap()))
    // }

    pub fn eth_chainid(&self) -> u64 {
        u64::from(self.blockchain.chainid | 0x8000)
    }

    pub async fn get_eth_middleware(
        &self,
        from: &Account,
    ) -> Result<
        FillProvider<
            JoinFill<
                JoinFill<
                    JoinFill<
                        Identity,
                        JoinFill<
                            GasFiller,
                            JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>,
                        >,
                    >,
                    WalletFiller<EthereumWallet>,
                >,
                ChainIdFiller,
            >,
            RootProvider,
        >,
    > {
        let key = SigningKey::from_slice(from.get_privkey_hex()?.as_bytes())?;
        let signer = PrivateKeySigner::from_signing_key(key);
        let wallet = EthereumWallet::new(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .with_chain_id(self.eth_chainid())
            .connect_hyper_http(self.blockchain.rpc_url.parse().unwrap());
        Ok(provider)
        // Ok(ethers::middleware::SignerMiddleware::new(
        //     provider,
        //     from.get_eth_wallet()?.with_chain_id(self.eth_chainid()),
        // ));
    }
}
