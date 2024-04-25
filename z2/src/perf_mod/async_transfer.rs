use crate::perf;
use crate::perf::{AccountKind, PhaseResult, TransactionResult};
use anyhow::Result;
use async_trait::async_trait;
use rand;
use rand::prelude::*;

pub struct AsyncTransfer {
    source_of_funds: perf::Account,
    config: perf::AsyncTransferConfig,
    feeder: perf::Account,
}

impl AsyncTransfer {
    pub async fn new(
        perf: &perf::Perf,
        rng: &mut StdRng,
        source_of_funds: &perf::Account,
        config: &perf::AsyncTransferConfig,
    ) -> Result<Self> {
        Ok(Self {
            source_of_funds: source_of_funds.clone(),
            config: config.clone(),
            feeder: perf.gen_account(rng, AccountKind::Zil).await?,
        })
    }
}

#[async_trait]
impl perf::PerfMod for AsyncTransfer {
    async fn gen_phase(
        &mut self,
        phase: u32,
        rng: &mut StdRng,
        perf: &perf::Perf,
        txns: &Vec<TransactionResult>,
        feeder_nonce: u64,
    ) -> Result<PhaseResult> {
        let mut result = Vec::new();
        match phase {
            0 => {
                // Feed the feeder.
                let amount_required = (self.config.amount_max + perf.config.gas.gas_units())
                    * u128::from(self.config.nr_transfers);
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
                perf::TransactionResult::assert_all_successful(txns)?;
                let mut nonce = perf.get_balance(&self.feeder.get_zq_hex()?).await?.nonce;
                let mut expect_success = true;
                // Grab the accounts to send into.
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
                    let target = perf.gen_account(rng, AccountKind::Zil).await?;
                    // Send the transfer and go back.
                    nonce += gap;
                    let transfer = perf
                        .issue_transfer(&self.feeder, &target, amount, Some(nonce))
                        .await?;
                    // check gap == 1 here in case gap was 0 - a gap 0 txn doesn't succeed itself, but
                    // also doesn't stop other txns succeeding later (so we don't set !expect_success)
                    if gap == 1 && expect_success {
                        result.push(transfer)
                    }
                }
                Ok(PhaseResult {
                    monitor: result,
                    feeder_nonce,
                    keep_going_anyway: false,
                })
            }
            _ => {
                let val: Vec<String> = Vec::new();
                Ok(PhaseResult {
                    monitor: val,
                    feeder_nonce,
                    keep_going_anyway: false,
                })
            }
        }
    }
}
