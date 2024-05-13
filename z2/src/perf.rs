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

use anyhow::{anyhow, Context as _, Result};
use async_trait::async_trait;
use clap::ValueEnum;
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

pub struct Perf {
    pub config: Config,
    pub source_of_funds: Option<Account>,
    pub provider: Provider<Http>,
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
pub struct Config {
    pub network_name: Option<String>,
    pub rpc_url: String,
    pub chainid: u32,
    pub seed: u64,
    pub attempts: u32,
    pub sleep_ms: u64,
    pub gas: GasParams,
    pub source_of_funds: Option<ConfigAccount>,
    pub steps: Vec<ConfigSet>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigSet {
    name: String,
    modules: Vec<ConfigModule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConfigModule {
    #[serde(rename = "async_transfer")]
    AsyncTransfer(AsyncTransferConfig),
    #[serde(rename = "conformance")]
    Conformance(ConformConfig),
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
                TransactionResult::Pending => "p",
                TransactionResult::TimedOut => "T",
                TransactionResult::Success { .. } => "S",
                TransactionResult::Failure { .. } => "F",
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
    module: Box<dyn PerfMod>,
    // Results from the last phase.
    results: Vec<TransactionResult>,
    // Txns to monitor in the next phase.
    txns: Vec<String>,
    // Where in the overall monitoring vector do our txns start?
    offset: usize,
}

/// This test transfers a bulk amount from the source of funds to a
/// random account, then starts a thread which triggers a bunch of
/// asynchronous transfers from the source of funds. If
/// gap_min=gap_max=1, these are all sequential and we expect them to
/// succeed.  If gap_max > 1, we don't expect them to succeed, but we
/// do expect the chain to still be working at the end of it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AsyncTransferConfig {
    pub nr_transfers: u32,
    pub gap_min: u64,
    pub gap_max: u64,
    pub amount_min: u128,
    pub amount_max: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConformConfig {
    pub zilliqa_source: String,
    pub signer_count: u32,
    pub signer_amount: u128,
}

impl Perf {
    pub fn from_file(config_file: &str) -> Result<Self> {
        let config_path = Path::new(config_file);
        if !config_path.is_absolute() {
            return Err(anyhow!("z changes directory internally and {config_file} is not absolute - please pass an absolute path"));
        }
        let file_contents =
            fs::read_to_string(config_file).context("Cannot read configuration {config_file}")?;
        let config_obj: Config = serde_yaml::from_str(&file_contents)?;
        let provider = Provider::<Http>::try_from(config_obj.rpc_url.as_str())?;
        let source_of_funds = if let Some(val) = &config_obj.source_of_funds {
            Some(Account::try_from(val)?)
        } else {
            None
        };

        Ok(Perf {
            config: config_obj,
            provider,
            step: 0,
            source_of_funds,
        })
    }

    pub fn make_provider(&self) -> Result<Provider<Http>> {
        Ok(Provider::<Http>::try_from(self.config.rpc_url.as_str())?)
    }

    pub fn make_rng(&self) -> Result<StdRng> {
        Ok(StdRng::seed_from_u64(self.config.seed))
    }

    pub async fn run(&self, rng: &mut StdRng) -> Result<()> {
        // Run the steps, one by one.
        for i in 0..self.config.steps.len() {
            let step = &self.config.steps[i];
            println!("🎄 running step {i}: {0} .. ", &step.name);
            self.step(rng, step).await?;
        }
        Ok(())
    }

    pub async fn step(&self, rng: &mut StdRng, step: &ConfigSet) -> Result<()> {
        let mut modules: Vec<ModuleRecord> = Vec::new();

        // Construct the modules.
        for this_module in step.modules.iter() {
            match this_module {
                ConfigModule::AsyncTransfer(async_transfer) => {
                    if let Some(funds) = &self.source_of_funds {
                        let this_mod = perf_mod::async_transfer::AsyncTransfer::new(
                            self,
                            rng,
                            funds,
                            async_transfer,
                        )
                        .await?;
                        modules.push(ModuleRecord {
                            module: Box::new(this_mod),
                            results: Vec::new(),
                            txns: Vec::new(),
                            offset: 0,
                        });
                    } else {
                        return Err(anyhow!(
                            "Cannot instantiate the AsyncTransfer module without a source of funds"
                        ));
                    }
                }
                ConfigModule::Conformance(conf_config) => {
                    if let Some(funds) = &self.source_of_funds {
                        let this_mod =
                            perf_mod::conform::Conform::new(self, rng, funds, conf_config).await?;
                        modules.push(ModuleRecord {
                            module: Box::new(this_mod),
                            results: Vec::new(),
                            txns: Vec::new(),
                            offset: 0,
                        });
                    } else {
                        return Err(anyhow!(
                            "Cannot instantiate Conformance module without a source of funds"
                        ));
                    }
                }
            }
        }
        let mut phase = 0;
        loop {
            // Construct the list of txns to monitor
            let mut monitor = Vec::new();
            let mut continue_anyway = false;
            let mut feeder_nonce = if let Some(feeder) = &self.source_of_funds {
                self.get_balance(&feeder.get_zq_hex()?).await?.nonce
            } else {
                0
            };
            for this_mod in modules.iter_mut() {
                {
                    let result = this_mod
                        .module
                        .gen_phase(phase, rng, self, &this_mod.results, feeder_nonce)
                        .await?;
                    feeder_nonce = result.feeder_nonce;
                    this_mod.txns = result.monitor;
                    continue_anyway = continue_anyway || result.keep_going_anyway;
                }
                this_mod.offset = monitor.len();
                monitor.extend_from_slice(&this_mod.txns);
            }
            // Now clear the old results
            for this_mod in modules.iter_mut() {
                this_mod.results = Vec::new();
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
        let mut result = Vec::new();
        for _ in 0..nr {
            result.push(self.gen_account(rng, acc_type).await?)
        }
        Ok(result)
    }

    pub async fn get_middleware(
        &self,
        from: &Account,
    ) -> Result<
        zilliqa_rs::middlewares::signer::SignerMiddleware<
            Provider<Http>,
            zilliqa_rs::signers::LocalWallet,
        >,
    > {
        let wallet = zilliqa_rs::signers::LocalWallet::from_str(&from.privkey)?;
        let provider = self.make_provider()?;
        Ok(zilliqa_rs::middlewares::signer::SignerMiddleware::new(
            provider, wallet,
        ))
    }

    pub async fn issue_transfer(
        &self,
        from: &Account,
        to: &Account,
        amt: u128,
        nonce: Option<u64>,
    ) -> Result<String> {
        println!(
            "> Transfer {0} -> {1} : {amt} / {nonce:?} ",
            from.get_zq_address()?,
            to.get_zq_address()?
        );
        let middleware = self.get_middleware(from).await?;
        let mut txn = zilliqa_rs::transaction::builder::TransactionBuilder::default()
            .chain_id(self.config.chainid.try_into()?)
            .pay(amt, to.get_zq_address()?);
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

    pub async fn transfer(
        &self,
        from: &Account,
        to: &Account,
        amt: u128,
        nonce: Option<u64>,
    ) -> Result<()> {
        let tran_id = self.issue_transfer(from, to, amt, nonce).await?;
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
        let mut results: Vec<TransactionResult> = Vec::new();
        println!(" --- 👓 --- ");
        for (idx, item) in txns.iter().enumerate() {
            println!("{idx:<02}   {0}", item)
        }
        results.resize(txns.len(), TransactionResult::Pending);
        for attempt in 0..self.config.attempts {
            let any_pending = results
                .iter()
                .map(|x| matches!(x, TransactionResult::Pending))
                .any(|y| y);
            if !any_pending {
                return Ok(results);
            }
            for txn in 0..txns.len() {
                let txn_hash = &txns[txn];
                // One day, there may be many of these.
                #[allow(clippy::single_match)]
                match results[txn] {
                    TransactionResult::Pending => {
                        let status = self
                            .provider
                            .get_transaction(&zilliqa_rs::core::TxHash::from_str(txn_hash)?)
                            .await;
                        match status {
                            Ok(val) => {
                                if val.receipt.success {
                                    results[txn] = TransactionResult::Success {
                                        hash: txn_hash.to_string(),
                                        receipt: val.receipt,
                                    };
                                } else {
                                    results[txn] = TransactionResult::Failure {
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
                                        results[txn] = TransactionResult::TimedOut;
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
