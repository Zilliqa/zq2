use std::time::Instant;

use alloy::{
    hex, network::TransactionBuilder as _, primitives::U256, providers::Provider as _,
    rpc::types::TransactionRequest, signers::local::PrivateKeySigner,
};
use anyhow::Result;
use futures::future::join_all;

use crate::kpi::{CallTransactionResult, KpiResult, ScenarioAgent};

pub struct EthTransfer {
    pub iterations: usize,
    pub attempts_to_confirm: usize,
    pub sleep_ms_before_next_try: u64,
}

impl ScenarioAgent for EthTransfer {
    async fn run(&self, config: &crate::kpi::Config) -> Result<crate::kpi::KpiResult> {
        let wallet = PrivateKeySigner::random();

        let txn = TransactionRequest::default()
            .to(wallet.address())
            .value(U256::from(1))
            .with_chain_id(config.eth_chainid());
        let mware = config.get_eth_middleware(&config.source_of_funds).await?;
        let num_transactions = self.iterations;
        let mut futures = Vec::new();
        let attempts = self.attempts_to_confirm;
        let sleep_ms = self.sleep_ms_before_next_try;

        let total_start = Instant::now();
        for _ in 0..num_transactions {
            let provider = config.get_provider()?;
            let mware = mware.clone();
            let txn = txn.clone();
            let future: tokio::task::JoinHandle<Result<(f64, bool, u64)>> =
                tokio::spawn(async move {
                    let start = Instant::now();
                    let txn_sent = mware.send_transaction(txn).await?;
                    let txn_hash = hex::encode(txn_sent.tx_hash());

                    for _ in 0..attempts {
                        match zilliqa_rs::middlewares::Middleware::get_transaction(
                            &provider,
                            &txn_hash.parse()?,
                        )
                        .await
                        {
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
