#![allow(unused_imports)]

use std::{
    cell::{RefCell, RefMut},
    fmt, fs,
    io::{Cursor, Write},
    iter,
    path::Path,
    str::FromStr,
    sync::RwLock,
};

use crate::perf_mod::async_transfer::AsyncTransferConfig;
use crate::perf_mod::conform::ConformConfig;
use anyhow::{anyhow, Context as _, Result};
use async_trait::async_trait;
use clap::ValueEnum;
use ethers::{middleware::Middleware as _, signers::Signer, types::U256};
use lazy_static::lazy_static;
use rand::{self, distributions::DistString as _, prelude::*};
use serde::{Deserialize, Serialize};
use tempfile;
use tokio::time::{sleep, Duration};
use url::Url;
use zilliqa_rs::{
    middlewares::Middleware,
    providers::{Http, Provider},
};

/// Stolen from z blockchain perf, partly so external contributors can also run it.
use crate::{perf_mod, utils};

#[derive(Serialize, Deserialize, Clone)]
pub struct SourceOfFunds {
    pub account: Account,
    pub gas: GasParams,
}

pub struct Perf {
    pub config: Config,
    pub source_of_funds: SourceOfFunds,
    pub provider: Provider<Http>,
    pub effective_url: String,
    pub effective_chainid: u32,
    pub step: usize,
}

pub struct PhaseResult {
    pub monitor: Vec<String>,
    pub feeder_nonce: u64,
    // Set this to true to keep going anyway - eg. because you are waiting for
    // a process to finish.
    pub keep_going_anyway: bool,
}

#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait PerfMod {
    async fn gen_phase(
        &mut self,
        phase: u32,
        rng: &mut StdRng,
        perf: &Perf,
        txns: &Vec<TransactionResult>,
        feeder_nonce: u64,
    ) -> Result<PhaseResult>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigSourceOfFunds {
    pub account: ConfigAccount,
    pub gas: GasParams,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub network_name: Option<String>,
    pub rpc_url: String,
    pub chainid: u32,
    pub seed: u64,
    pub attempts: u32,
    pub sleep_ms: u64,
    pub source_of_funds: Option<ConfigSourceOfFunds>,
    pub steps: Vec<ConfigSet>,
}

impl Config {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigSet {
    name: String,
    modules: Vec<ConfigModule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConfigModule {
    #[serde(rename = "async_transfer")]
    AsyncTransfer(perf_mod::async_transfer::AsyncTransferConfig),
    #[serde(rename = "conformance")]
    Conformance(perf_mod::conform::ConformConfig),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasParams {
    pub gas_price: u128,
    pub gas_limit: u64,
}

impl GasParams {
    pub fn gas_units(&self) -> u128 {
        self.gas_price * u128::from(self.gas_limit)
    }
}

#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub enum AccountKind {
    #[serde(rename = "zil")]
    Zil,
    #[serde(rename = "eth")]
    Eth,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigAccount {
    pub from_env: String,
    pub kind: AccountKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub privkey: String,
    pub kind: AccountKind,
}

impl std::convert::TryFrom<&ConfigAccount> for Account {
    type Error = anyhow::Error;

    fn try_from(ca: &ConfigAccount) -> Result<Account> {
        let val = std::env::var(&ca.from_env).context(format!(
            "Please define the environment variable {0} to contain a private key",
            &ca.from_env
        ))?;
        Ok(Account {
            privkey: val,
            kind: ca.kind,
        })
    }
}

impl Account {
    pub fn get_privkey_hex(&self) -> Result<String> {
        // TODO : reformat
        Ok(self.privkey.to_string())
    }

    pub fn get_zq_privkey(&self) -> Result<zilliqa_rs::core::PrivateKey> {
        Ok(self.privkey.parse()?)
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
        Ok(ethers::signers::LocalWallet::from_str(&self.privkey)?)
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

#[derive(Clone, Debug)]
pub struct Balance {
    pub nonce: u64,
    pub balance: u128,
}

impl Default for Balance {
    fn default() -> Self {
        Self::new()
    }
}

impl Balance {
    // The balance for a new account.
    pub fn new() -> Self {
        Balance {
            nonce: 0,
            balance: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TransactionResult {
    Pending,
    TimedOut,
    Success {
        hash: String,
        receipt: zilliqa_rs::core::types::TransactionReceipt,
    },
    Failure {
        hash: String,
        receipt: zilliqa_rs::core::types::TransactionReceipt,
    },
}

impl fmt::Display for TransactionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TransactionResult::Pending => "⏳",
                TransactionResult::TimedOut => "⏱️",
                TransactionResult::Success { .. } => "✅",
                TransactionResult::Failure { .. } => "❌",
            }
        )
    }
}

impl TransactionResult {
    pub fn assert_all_successful(txns: &[TransactionResult]) -> Result<()> {
        if txns
            .iter()
            .map(|x| matches!(x, TransactionResult::Success { .. }))
            .all(|y| y)
        {
            Ok(())
        } else {
            Err(anyhow!(
                "Not all txns were successful: {0}",
                txns.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            ))
        }
    }
}

pub struct ModuleRecord {
    module: Box<dyn PerfMod + Send>,
    // Results from the last phase.
    results: Vec<TransactionResult>,
    // Txns to monitor in the next phase.
    txns: Vec<String>,
    // Where in the overall monitoring vector do our txns start?
    offset: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Params {
    pub rpc_url: Option<String>,
    pub account: Option<Account>,
    pub eth_chain_id: Option<u32>,
    pub seed: Option<u64>,
}

impl Params {
    pub fn with_url(&self, url: &str) -> Self {
        Self {
            rpc_url: Some(url.to_string()),
            ..self.clone()
        }
    }

    pub fn with_seed(&self, seed: u64) -> Self {
        Self {
            seed: Some(seed),
            ..self.clone()
        }
    }
}

impl Perf {
    pub fn from_file(config_file: &str) -> Result<Self> {
        Perf::from_file_with_params(config_file, &Params::default())
    }

    pub fn from_file_with_params(config_file: &str, params: &Params) -> Result<Self> {
        let file_contents = fs::read_to_string(config_file)
            .context(format!("Cannot read configuration {config_file}"))?;
        let mut config_obj: Config = serde_yaml::from_str(&file_contents)?;
        let effective_url = if let Some(url) = &params.rpc_url {
            url.to_string()
        } else {
            config_obj.rpc_url.to_string()
        };
        let provider = Provider::<Http>::try_from(effective_url.as_str())?;
        let source_account = if let Some(v) = &params.account {
            v.clone()
        } else {
            config_obj
                .source_of_funds
                .as_ref()
                .map(|x| Account::try_from(&x.account))
                .ok_or(anyhow!("No source of funds provided."))??
        };
        if let Some(v) = &params.seed {
            config_obj.seed = *v;
        }
        let source_of_funds = SourceOfFunds {
            account: source_account,
            gas: config_obj
                .source_of_funds
                .as_ref()
                .ok_or(anyhow!("No source of funds provided"))?
                .gas
                .clone(),
        };
        let config_chain_id = config_obj.chainid;
        Ok(Perf {
            config: config_obj,
            provider,
            effective_url,
            effective_chainid: params.eth_chain_id.map_or(config_chain_id, |x| x & !0x8000),
            step: 0,
            source_of_funds,
        })
    }

    pub fn zil_chainid(&self) -> u32 {
        self.effective_chainid
    }

    pub fn eth_chainid(&self) -> u64 {
        u64::from(self.effective_chainid | 0x8000)
    }

    pub fn make_zil_provider(&self) -> Result<Provider<Http>> {
        Ok(Provider::<Http>::try_from(self.effective_url.as_str())?)
    }

    pub fn make_eth_provider(
        &self,
    ) -> Result<ethers::providers::Provider<ethers::providers::Http>> {
        Ok(
            ethers::providers::Provider::<ethers::providers::Http>::try_from(
                self.effective_url.as_str(),
            )?,
        )
    }

    pub fn make_rng(&self) -> Result<StdRng> {
        Ok(StdRng::seed_from_u64(self.config.seed))
    }

    pub async fn run(&self, rng: &mut StdRng) -> Result<()> {
        // Run the steps, one by one.
        for (index, step) in self.config.steps.iter().enumerate() {
            println!("🎄 running step {index}: {0} .. ", &step.name);
            self.step(rng, step).await?;
        }

        Ok(())
    }

    pub async fn step(&self, rng: &mut StdRng, step: &ConfigSet) -> Result<()> {
        let mut modules: Vec<ModuleRecord> = vec![];

        // Construct the modules.
        for this_module in step.modules.iter() {
            match this_module {
                ConfigModule::AsyncTransfer(async_transfer_config) => {
                    let this_mod = perf_mod::async_transfer::AsyncTransfer::new(
                        self,
                        rng,
                        &self.source_of_funds,
                        async_transfer_config,
                    )
                    .await?;
                    modules.push(ModuleRecord {
                        module: Box::new(this_mod),
                        results: vec![],
                        txns: vec![],
                        offset: 0,
                    });
                }
                ConfigModule::Conformance(conf_config) => {
                    let this_mod = perf_mod::conform::Conform::new(
                        self,
                        rng,
                        &self.source_of_funds,
                        conf_config,
                    )
                    .await?;
                    modules.push(ModuleRecord {
                        module: Box::new(this_mod),
                        results: vec![],
                        txns: vec![],
                        offset: 0,
                    });
                }
            }
        }
        let mut phase = 0;
        loop {
            // Construct the list of txns to monitor
            let mut monitor = vec![];
            let mut continue_anyway = false;
            let mut feeder_nonce = self.get_nonce(&self.source_of_funds.account).await?;
            for module in modules.iter_mut() {
                let result = module
                    .module
                    .gen_phase(phase, rng, self, &module.results, feeder_nonce)
                    .await?;
                feeder_nonce = result.feeder_nonce;
                module.txns = result.monitor;
                continue_anyway = continue_anyway || result.keep_going_anyway;
                module.offset = monitor.len();
                monitor.extend_from_slice(&module.txns);
            }
            // Now clear the old results
            for this_mod in modules.iter_mut() {
                this_mod.results = vec![];
            }
            // We're done if we have asked everyone and there is nothing to wait for anymore.
            if monitor.is_empty() {
                if continue_anyway {
                    // Sleep for a bit ..
                    //println!(
                    //    "> phase {phase} with {0} transactions - sleeping",
                    //    monitor.len()
                    //);
                    sleep(Duration::from_millis(self.config.sleep_ms)).await;
                } else {
                    break;
                }
            } else {
                println!(
                    "> phase {phase} with {0} transactions and {1} modules",
                    monitor.len(),
                    modules.len()
                );
                // OK. Now we have everything, wait for it ..
                let result = self.monitor(&monitor).await?;
                // Now slice it all up again.
                for this_mod in modules.iter_mut() {
                    // This is much more self-explanatory (to me, at least), than faffing
                    // with iterators.
                    #[allow(clippy::needless_range_loop)]
                    for val in this_mod.offset..this_mod.offset + this_mod.txns.len() {
                        this_mod.results.push(result[val].clone())
                    }
                }
            }
            phase += 1;
            // Go round again.
        }
        // If we got here, we're OK.

        Ok(())
    }

    pub async fn gen_account(&self, rng: &mut StdRng, acc_type: AccountKind) -> Result<Account> {
        const CHARSET: &[u8] = b"0123456789abcdef";
        // Horrid use of unwrap(), but hard to avoid here (and to be
        // fair, if this happens it is indeed a logic error in the
        // program - rrw 2023-11-28
        let get_one = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
        let privkey = iter::repeat_with(get_one).take(64).collect();
        println!("Invented privkey = {privkey}");
        Ok(Account {
            privkey,
            kind: acc_type,
        })
    }

    pub async fn gen_accounts(
        &self,
        rng: &mut StdRng,
        acc_type: AccountKind,
        nr: u32,
    ) -> Result<Vec<Account>> {
        let mut result = vec![];
        for _ in 0..nr {
            result.push(self.gen_account(rng, acc_type).await?)
        }
        Ok(result)
    }

    pub async fn get_zil_middleware(
        &self,
        from: &Account,
    ) -> Result<
        zilliqa_rs::middlewares::signer::SignerMiddleware<
            Provider<Http>,
            zilliqa_rs::signers::LocalWallet,
        >,
    > {
        let wallet = zilliqa_rs::signers::LocalWallet::from_str(&from.privkey)?;
        let provider = self.make_zil_provider()?;
        Ok(zilliqa_rs::middlewares::signer::SignerMiddleware::new(
            provider, wallet,
        ))
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

    pub async fn issue_transfer(
        &self,
        from: &Account,
        to: &Account,
        amt_zil: u128,
        nonce: Option<u64>,
        gas: &GasParams,
    ) -> Result<String> {
        match from.kind {
            AccountKind::Zil => {
                println!(
                    "💰 ZIL Transfer {0} -> {1} : {amt_zil} / {nonce:?} ",
                    from.get_zq_address()?,
                    to.get_address()?
                );
                let middleware = self.get_zil_middleware(from).await?;
                let mut txn = zilliqa_rs::transaction::builder::TransactionBuilder::default()
                    .chain_id(self.zil_chainid().try_into()?)
                    .gas_price(gas.gas_price)
                    .gas_limit(gas.gas_limit)
                    .pay(amt_zil, to.get_address_as_zil()?);
                txn = match nonce {
                    Some(val) => txn.nonce(val),
                    None => txn,
                };
                let txn_sent = middleware
                    .send_transaction_without_confirm::<zilliqa_rs::core::types::CreateTransactionResponse>(
                        txn.build(),
                    )
                    .await?;
                Ok(txn_sent.tran_id.to_string())
            }
            AccountKind::Eth => {
                let amt_eth = zil_to_eth(amt_zil);
                println!(
                    "💰 ETH Transfer {0:#032x} -> {1}: {amt_eth} / {nonce:?} ",
                    from.get_eth_address()?,
                    to.get_address()?
                );
                let mut txn =
                    ethers::types::TransactionRequest::pay(to.get_address_as_eth()?, amt_eth)
                        .chain_id(self.eth_chainid())
                        .gas_price(gas.gas_price);
                txn = match nonce {
                    Some(val) => txn.nonce(val),
                    None => txn,
                };
                println!("privkey {0}", from.privkey);
                let mware = self.get_eth_middleware(from).await?;
                println!("Got mware");
                let txn_sent = mware.send_transaction(txn, None).await?;
                println!("Sent txn");
                Ok(hex::encode(txn_sent.tx_hash()))
            }
        }
    }

    pub async fn transfer(
        &self,
        from: &Account,
        to: &Account,
        amt: u128,
        nonce: Option<u64>,
    ) -> Result<()> {
        let tran_id = self
            .issue_transfer(from, to, amt, nonce, &self.source_of_funds.gas)
            .await?;
        println!("Sent {tran_id:?}");
        let result = self.monitor_one(&tran_id).await?;
        println!("Result {result:?}");
        match result {
            TransactionResult::Success { .. } => Ok(()),
            TransactionResult::Pending | TransactionResult::TimedOut => Err(anyhow!("Timed out")),
            TransactionResult::Failure { .. } => {
                Err(anyhow!("Transaction failed (insufficient balance?)"))
            }
        }
    }

    pub async fn monitor_one(&self, txn: &str) -> Result<TransactionResult> {
        Ok(self.monitor(&[txn.to_string()]).await?[0].clone())
    }

    /// Monitor a transaction until it either completes or fails.
    pub async fn monitor(&self, txns: &[String]) -> Result<Vec<TransactionResult>> {
        println!(" --- 👓 --- ");
        for (idx, item) in txns.iter().enumerate() {
            println!("{idx:<02}   {0}", item)
        }

        let mut results: Vec<TransactionResult> = vec![TransactionResult::Pending; txns.len()];
        for attempt in 0..self.config.attempts {
            let any_pending = results
                .iter()
                .map(|x| matches!(x, TransactionResult::Pending))
                .any(|y| y);
            if !any_pending {
                return Ok(results);
            }

            for (txn_index, txn_hash) in txns.iter().enumerate() {
                // One day, there may be many of these.
                #[allow(clippy::single_match)]
                match results[txn_index] {
                    TransactionResult::Pending => {
                        let status = self
                            .provider
                            .get_transaction(&zilliqa_rs::core::TxHash::from_str(txn_hash)?)
                            .await;
                        match status {
                            Ok(val) => {
                                if val.receipt.success {
                                    results[txn_index] = TransactionResult::Success {
                                        hash: txn_hash.to_string(),
                                        receipt: val.receipt,
                                    };
                                } else {
                                    results[txn_index] = TransactionResult::Failure {
                                        hash: txn_hash.to_string(),
                                        receipt: val.receipt,
                                    }
                                }
                            }
                            Err(err) => {
                                if let Some(val) = Perf::get_server_error(&err) {
                                    if val
                                        != (zilliqa_rs::providers::RPCErrorCode::RpcDatabaseError
                                            as i32)
                                    {
                                        results[txn_index] = TransactionResult::TimedOut;
                                    }
                                }
                            }
                        }
                    }
                    _ => (),
                }
            }
            println!(
                ".. {2:<03} #{1} {0}",
                results
                    .iter()
                    .enumerate()
                    .map(|(x, y)| format!("{x:<02}:{0}", y))
                    .collect::<Vec<_>>()
                    .join(" "),
                results.len(),
                attempt
            );
            sleep(Duration::from_millis(self.config.sleep_ms)).await;
        }
        Ok(results)
    }

    pub fn get_server_error(err: &zilliqa_rs::Error) -> Option<i32> {
        #[allow(clippy::collapsible_match)]
        if let zilliqa_rs::Error::JsonRpcError(val2) = err {
            // This will probably expand later, and I'm not convinced collapsing
            // them will make life any clearer.
            #[allow(clippy::collapsible_match)]
            if let jsonrpsee::core::ClientError::Call(callerr) = val2 {
                return Some(callerr.code());
            }
        }
        None
    }

    pub async fn get_nonce(&self, account: &Account) -> Result<u64> {
        match account.kind {
            AccountKind::Zil => Ok(self.get_balance(&account.get_address()?).await?.nonce),
            AccountKind::Eth => {
                let provider = self.make_eth_provider()?;
                Ok(provider
                    .get_transaction_count(account.get_eth_address()?, None)
                    .await?
                    .as_u64())
            }
        }
    }

    pub async fn get_balance(&self, address: &str) -> Result<Balance> {
        match &self.provider.get_balance(address).await {
            Ok(bal) => Ok(Balance {
                nonce: bal.nonce,
                balance: bal.balance,
            }),
            Err(val) => match val {
                zilliqa_rs::Error::JsonRpcError(val2) => match val2 {
                    jsonrpsee::core::ClientError::Call(callerr) => {
                        if callerr.code() == -5 {
                            // Account didn't exist.
                            Ok(Balance::new())
                        } else {
                            Err(anyhow!("{callerr}"))
                        }
                    }
                    _ => Err(anyhow!("{val2}")),
                },
                _ => Err(anyhow!("{val}")),
            },
        }
    }
}

pub fn zil_to_eth(zil_amt: u128) -> u128 {
    zil_amt * 1000000
}
