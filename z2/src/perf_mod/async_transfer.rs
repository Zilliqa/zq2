use anyhow::{anyhow, Result};
use async_trait::async_trait;
use rand::{self, prelude::*};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    perf,
    perf::{AccountKind, PhaseResult, TransactionResult},
};

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
    pub kind: AccountKind,
    pub gas: perf::GasParams,
}

pub struct AsyncTransfer {
    source_of_funds: perf::SourceOfFunds,
    config: AsyncTransferConfig,
    feeder: perf::Account,
}

impl AsyncTransfer {
    pub async fn new(
        perf: &perf::Perf,
        rng: &mut StdRng,
        source_of_funds: &perf::SourceOfFunds,
        config: &crate::perf_mod::async_transfer::AsyncTransferConfig,
    ) -> Result<Self> {
        Ok(Self {
            source_of_funds: source_of_funds.clone(),
            config: config.clone(),
            feeder: perf.issuer()?.gen_account(rng, config.kind).await?,
        })
    }
}

#[async_trait]
impl perf::PerfMod for AsyncTransfer {
    async fn gen_phase(
        &mut self,
        phase: u64,
        rng: &mut StdRng,
        issuer: perf::Issuer,
        txns: &Vec<TransactionResult>,
        feeder_nonce: Arc<Mutex<Option<u64>>>,
    ) -> Result<PhaseResult> {
        let mut result = Vec::new();
        match phase {
            0 => {
                // Feed the feeder.
                let amount_required = (self.config.amount_max + self.config.gas.gas_units())
                    * u128::from(self.config.nr_transfers);
                println!("amount_required = {amount_required}");
                let new_feeder_nonce = perf::inc_nonce(&feeder_nonce).await;
                result.push(
                    issuer
                        .issue_transfer(
                            &self.source_of_funds.account,
                            &self.feeder,
                            amount_required,
                            Some(new_feeder_nonce),
                            &self.source_of_funds.gas,
                        )
                        .await?,
                );
                Ok(PhaseResult {
                    monitor: result,
                    end_now: false,
                })
            }
            1 => {
                perf::TransactionResult::assert_all_successful(txns)?;
                let mut nonce = issuer.get_nonce(&self.feeder).await?;
                let mut expect_success = true;
                let mut join_set = JoinSet::new();
                for _ in 0..self.config.nr_transfers {
                    let gap;
                    let amount;
                    {
                        gap = rng.gen_range(self.config.gap_min..self.config.gap_max + 1);
                        amount = rng.gen_range(self.config.amount_min..self.config.amount_max + 1);
                    }
                    if gap > 1 {
                        expect_success = false;
                    }
                    let local_issuer = issuer.duplicate()?;
                    let target = local_issuer.gen_account(rng, AccountKind::Zil).await?;
                    // Send the transfer and go back.
                    if gap > 0 {
                        if let Some(v) = nonce {
                            nonce = Some(v + gap)
                        } else {
                            nonce = Some(0)
                        }
                    } else {
                        // Gaps of zero don't set the flag, but don't succeed either, unless they are the
                        // first txn.
                    };
                    let local_feeder = self.feeder.clone();
                    let local_gas = self.config.gas.clone();
                    let expect_txn_to_succeed = expect_success && (gap == 1 || nonce.is_none());
                    let id = rng.next_u32();
                    join_set.spawn(async move {
                        println!(
                            "💻 {id:#08x} issue_transfer from {0:?} to {1:?} send nonce {nonce:?}",
                            local_feeder, target
                        );
                        let transfer = local_issuer
                            .issue_transfer(&local_feeder, &target, amount, nonce, &local_gas)
                            .await;
                        if let Ok(v) = transfer {
                            println!("💻 {id:#08x} issue_transfer - OK");
                            (true, expect_txn_to_succeed, Some(v))
                        } else {
                            println!("💻 {id:#08x} Transfer failed - {transfer:?}");
                            (false, expect_txn_to_succeed, None)
                        }
                    });
                }
                // Grab the accounts to send into.
                let joined = join_set.join_all().await;
                // Fail if any txn failed.
                let any_failures = joined.iter().fold(false, |acc, (f, _, _)| acc | !f);
                if any_failures {
                    Err(anyhow!("One or more transactions failed to send"))
                } else {
                    let monitor = joined
                        .iter()
                        .filter_map(
                            |(_, expect, result)| if *expect { result.clone() } else { None },
                        )
                        .collect();
                    Ok(PhaseResult {
                        monitor,
                        end_now: false,
                    })
                }
            }
            _ => {
                let val: Vec<String> = Vec::new();
                Ok(PhaseResult {
                    monitor: val,
                    end_now: true,
                })
            }
        }
    }
}
