use anyhow::Result;
pub use config::Config;
use serde::Serialize;

mod account;
pub mod config;
mod read;
mod txn;

use account::Account;

#[derive(Debug, Serialize)]
pub enum KpiResult {
    CallReadOnlyMethods(CallReadOnlyMethodsResult),
    SendTransaction(CallTransactionResult),
}

#[derive(Debug, Serialize)]
pub struct CallTransactionResult {
    latency: f64,
    throughput: f64,
    success_rate: f32,
    gas_throughput: f64,
}

#[derive(Debug, Serialize)]
pub struct CallReadOnlyMethodsResult {
    latency: f64,
}

trait ScenarioAgent {
    async fn run(&self, config: &Config) -> Result<KpiResult>;
}

pub struct Kpi;

impl Kpi {
    pub async fn run(config: &Config) {
        let mut results = vec![];
        for agent in config.scenario.iter() {
            let out = match agent {
                config::ScenarioStep::CallReadOnlyMethods(r) => r.run(config).await,
                config::ScenarioStep::SendTransactions(w) => w.run(config).await,
            }
            .unwrap();

            results.push(out);
        }

        let output = serde_json::to_string_pretty(&results).unwrap();

        println!("{output}")
    }
}
