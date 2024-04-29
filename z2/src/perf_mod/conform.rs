#![allow(unused_imports)]

use crate::perf::{AccountKind, PhaseResult, TransactionResult};
use crate::{perf, utils};
use anyhow::{anyhow, Context as _, Result};
use async_trait::async_trait;
use clap::ValueEnum;
use futures::task::Poll;
use lazy_static::lazy_static;
use rand;
use rand::distributions::DistString as _;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::{cell::RefCell, cell::RefMut, fs, iter, path::PathBuf};
use tempfile;
use tokio::time::{sleep, Duration};
use url::Url;
use zilliqa_rs::middlewares::Middleware;
use zilliqa_rs::providers::{Http, Provider};
use zutils::commands::{reap_on_termination, CommandBuilder};

pub enum MachineState {
    Feeding,
    BuildSigners,
    RunTests,
}

pub struct Conform {
    source_of_funds: perf::Account,
    config: perf::ConformConfig,
    feeder: perf::Account,
    test_source: String,
    current_command: Option<u32>,
    chain_name: String,
    state: MachineState,
}

impl Conform {
    pub async fn new(
        perf: &perf::Perf,
        rng: &mut StdRng,
        source_of_funds: &perf::Account,
        config: &perf::ConformConfig,
    ) -> Result<Self> {
        let mut test_path = PathBuf::from(&config.zilliqa_source);
        let network_name = perf.config.network_name.as_deref().unwrap_or("zq2");
        match network_name {
            "zq1" => {
                test_path.push("tests/EvmAcceptanceTests");
            }
            "zq2" => {
                test_path.push("evm_scilla_js_tests");
            }
            _ => return Err(anyhow!("Unsupported network name: {}", network_name)),
        }
        let test_source = zutils::utils::string_from_path(&test_path)?;
        if !test_path.is_dir() {
            return Err(anyhow!("{test_source} is not a directory"));
        }
        // Chain name is random

        let chain_name = zutils::security::generate_id(rng, 16)?;
        Ok(Self {
            source_of_funds: source_of_funds.clone(),
            config: config.clone(),
            feeder: perf.gen_account(rng, AccountKind::Zil).await?,
            test_source,
            current_command: None,
            chain_name,
            state: MachineState::Feeding,
        })
    }

    pub fn get_chain_env(&self, perf: &perf::Perf) -> Result<HashMap<String, String>> {
        let mut env: HashMap<String, String> = HashMap::new();

        env.insert("CHAIN_URL".to_string(), perf.config.rpc_url.to_string());
        env.insert(
            "CHAIN_WEBSOCKET".to_string(),
            perf.config.rpc_url.to_string(),
        );
        env.insert("CHAIN_NAME".to_string(), self.chain_name.to_string());
        env.insert("CHAIN_ID".to_string(), format!("{}", perf.config.chainid));

        Ok(env)
    }
}

#[async_trait]
impl perf::PerfMod for Conform {
    async fn gen_phase(
        &mut self,
        phase: u32,
        _rng: &mut StdRng,
        perf: &perf::Perf,
        _txns: &Vec<TransactionResult>,
        feeder_nonce: u64,
    ) -> Result<PhaseResult> {
        let mut result = Vec::new();
        match phase {
            0 => {
                // Feed the feeder
                // The +4, *2 here is because EvmAcceptanceTests seem to require it.
                let amount_required =
                    (u128::from(self.config.signer_count + 4) * (self.config.signer_amount) * 2)
                        + perf.config.gas.gas_units();
                println!("Funding with {amount_required}");
                result.push(
                    perf.issue_transfer(
                        &self.source_of_funds,
                        &self.feeder,
                        amount_required,
                        Some(feeder_nonce + 1),
                    )
                    .await?,
                );
                Ok(PhaseResult {
                    monitor: result,
                    feeder_nonce: feeder_nonce + 1,
                    keep_going_anyway: false,
                })
            }
            1 => {
                // OK. Now run a few things ..
                let mut npm_i = CommandBuilder::new();
                npm_i
                    .cwd(&self.test_source)
                    .cmd("npm", &["i"])
                    .run()
                    .await?;
                // Start the feeder.

                let feeder_account = self.feeder.get_privkey_hex()?;
                let count = format!("{}", self.config.signer_count);
                let amount = format!("{}", self.config.signer_amount / 1_000_000_000_000);

                self.current_command = Some(reap_on_termination(
                    CommandBuilder::new()
                        .cwd(&self.test_source)
                        .cmd(
                            "npx",
                            &[
                                "hardhat",
                                "init-signers",
                                "--from",
                                &feeder_account,
                                "--from-address-type",
                                "zil",
                                "--count",
                                &count,
                                "--balance",
                                &amount,
                                "--network",
                                "from_env",
                            ],
                        )
                        .env(&self.get_chain_env(perf)?)
                        .spawn_logged()
                        .await?,
                )?);
                self.state = MachineState::BuildSigners;
                Ok(PhaseResult {
                    monitor: Vec::new(),
                    feeder_nonce,
                    keep_going_anyway: true,
                })
            }
            _ => {
                // Has my process finished yet?
                if let Some(pid) = &self.current_command {
                    if zutils::process::is_running(pid)? {
                        // no. Wait..
                        return Ok(PhaseResult {
                            monitor: Vec::new(),
                            feeder_nonce,
                            keep_going_anyway: true,
                        });
                    }
                }

                match self.state {
                    MachineState::Feeding => {
                        return Err(anyhow!("Entered phase in invalid Feeding state"))
                    }
                    MachineState::BuildSigners => {
                        // W00t! Run the test
                        self.current_command = Some(reap_on_termination(
                            CommandBuilder::new()
                                .cwd(&self.test_source)
                                .cmd("npx", &["hardhat", "test", "--network", "from_env"])
                                .env(&self.get_chain_env(perf)?)
                                .spawn_logged()
                                .await?,
                        )?);
                        self.state = MachineState::RunTests;
                        Ok(PhaseResult {
                            monitor: Vec::new(),
                            feeder_nonce,
                            keep_going_anyway: true,
                        })
                    }
                    MachineState::RunTests => Ok(PhaseResult {
                        monitor: Vec::new(),
                        feeder_nonce,
                        keep_going_anyway: false,
                    }),
                }
            }
        }
    }
}
