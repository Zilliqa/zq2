use std::time::Instant;

use futures::future::join_all;
use zilliqa_rs::{
    core::{parse_zil, CreateTransactionResponse},
    middlewares::Middleware,
    signers::LocalWallet,
    transaction::TransactionBuilder,
};

use crate::kpi::{CallTransactionResult, KpiResult, ScenarioAgent};

pub struct ZilTransfer {
    pub iterations: usize,
    pub attempts_to_confirm: usize,
    pub sleep_ms_before_next_try: u64,
}

impl ScenarioAgent for ZilTransfer {
    async fn run(&self, config: &crate::kpi::Config) -> anyhow::Result<crate::kpi::KpiResult> {
        let wallet = config.get_signer()?;
        let receiver = LocalWallet::create_random()?;
        let tx = TransactionBuilder::default()
            .to_address(receiver.address.clone())
            .amount(parse_zil("2.0")?)
            .gas_price(config.blockchain.gas_price)
            .gas_limit(config.blockchain.gas_limit)
            .build();

        let attempts = self.attempts_to_confirm;
        let sleep_ms = self.sleep_ms_before_next_try;
        let num_transactions = self.iterations;
        let mut futures = Vec::new();
        let total_start = Instant::now();
        for _ in 0..num_transactions {
            let provider = config.get_provider()?.with_signer(wallet.clone());
            let tx = tx.clone();
            let future: tokio::task::JoinHandle<Result<(f64, bool, u64), zilliqa_rs::Error>> =
                tokio::spawn(async move {
                    let start = Instant::now();
                    let result = provider
                        .send_transaction_without_confirm::<CreateTransactionResponse>(tx)
                        .await?;

                    for _ in 0..attempts {
                        match provider.get_transaction(&result.tran_id).await {
                            Ok(r) => {
                                let total_gas_used = r.receipt.cumulative_gas.parse::<u64>()?;
                                return Ok((
                                    start.elapsed().as_secs_f64(),
                                    r.receipt.success,
                                    total_gas_used,
                                ));
                            }
                            Err(_e) => { /*println!("{e:?}"); */ }
                        }

                        tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
                    }

                    Ok((start.elapsed().as_secs_f64(), false, 0))
                });
            futures.push(future);
        }
        let results: Vec<_> = join_all(futures)
            .await
            .into_iter()
            .filter_map(Result::ok)
            .collect::<Result<_, _>>()?;
        let total_duration = total_start.elapsed().as_secs_f64();
        let latency = results.iter().map(|r| r.0).sum::<f64>() / num_transactions as f64;
        let success_rate = results.iter().filter(|r| r.1).count() as f32 / self.iterations as f32;
        let total_gas: u64 = results.iter().map(|r| r.2).sum();

        Ok(KpiResult::SendTransaction(CallTransactionResult {
            latency,
            success_rate,
            gas_throughput: total_gas as f64 / total_duration,
            throughput: self.iterations as f64 / total_duration,
        }))
    }
}
