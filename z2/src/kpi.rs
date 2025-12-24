use alloy::providers::{Provider as _, ProviderBuilder, WsConnect};
use anyhow::Result;
pub use config::Config;
use futures::StreamExt;
use serde::Serialize;
use tokio::sync::oneshot;

mod account;
pub mod config;
mod read;
mod txn;

use account::Account;
use tokio::task::JoinHandle;

#[derive(Debug, Serialize)]
enum KpiResult {
    CallReadOnlyMethods(CallReadOnlyMethodsResult),
    SendTransaction(CallTransactionResult),
    CallScillaTransitions(CallTransactionResult),
    BlockInfo(Vec<BlockInfo>),
}

#[derive(Debug, Serialize)]
struct CallTransactionResult {
    latency: f64,
    throughput: f64,
    success_rate: f32,
    gas_throughput: f64,
}

#[derive(Debug, Serialize)]
struct CallReadOnlyMethodsResult {
    latency: f64,
}

trait ScenarioAgent {
    async fn run(&self, config: &Config) -> Result<KpiResult>;
}

pub struct Kpi;

#[derive(Debug, Serialize)]
struct BlockInfo {
    timestamp_delta: u64,
    // num_transactions: usize,
    gas_used: u64,
}

fn spawn_block_info_collector(
    mut rx: Option<oneshot::Receiver<()>>,
) -> JoinHandle<Result<Vec<BlockInfo>>> {
    tokio::spawn(async move {
        let provider = ProviderBuilder::new()
            .connect_ws(WsConnect::new("ws://localhost:4201"))
            .await?;
        let mut stream = provider.subscribe_blocks().await?.into_stream();
        let mut previous_timestamp = None;
        let mut block_infos = Vec::new();

        loop {
            tokio::select! {
                block =  stream.next() => {
                    if let Some(block) = block {
                        let timestamp_delta = block.timestamp - previous_timestamp.unwrap_or(block.timestamp);
                        previous_timestamp = Some(block.timestamp);

                        // let num_transactions = block.transactions.len(); FIXME:
                        let gas_used = block.gas_used;

                        block_infos.push(BlockInfo {
                            timestamp_delta,
                            // num_transactions,
                            gas_used,
                        });
                    }
                }
                _ = rx.as_mut().unwrap() => {
                    break;
                }
            }
        }

        Ok(block_infos)
    })
}

impl Kpi {
    pub async fn run(config: &Config) {
        let mut results = vec![];

        let (tx, rx) = oneshot::channel();
        let task_handle = spawn_block_info_collector(Some(rx));

        for agent in config.scenario.iter() {
            let out = match agent {
                config::ScenarioStep::CallReadOnlyMethods(r) => r.run(config).await,
                config::ScenarioStep::SendTransactions(w) => w.run(config).await,
            }
            .unwrap();

            results.push(out);
        }

        let _ = tx.send(());

        let block_results = task_handle.await.unwrap().unwrap();
        results.push(KpiResult::BlockInfo(block_results));

        let output = serde_json::to_string_pretty(&results).unwrap();

        if config.output.path == "stdout" {
            println!("{output}")
        } else {
            std::fs::write(&config.output.path, output)
                .expect("Failed to write KPI result to file.");
        }
    }
}
