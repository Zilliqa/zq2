use anyhow::Result;
pub use config::Config;
use serde::Serialize;

pub mod config;
mod read_latency;
mod txn_latency;

#[derive(Debug, Serialize)]
pub enum KpiResult {
    ReadLatency(f64),
    TxnLatency(TxnLatencyResult),
}

#[derive(Debug, Serialize)]
pub struct TxnLatencyResult {
    latency: f64,
    throughput: f64,
    success_rate: f32,
    gas_throughput: f64,
}

trait KpiAgent {
    async fn run(&self, config: &Config) -> Result<KpiResult>;
}

pub struct Kpi;

impl Kpi {
    pub async fn run(config: &Config) {
        let mut results = vec![];
        for agent in config.key_performance_indicators.iter() {
            let out = match agent {
                config::KeyPerformanceIndicator::ReadLatency(r) => r.run(config).await,
                config::KeyPerformanceIndicator::TxnLatency(w) => w.run(config).await,
            }
            .unwrap();

            results.push(out);
        }

        let output = serde_json::to_string_pretty(&results).unwrap();

        println!("{output}")
    }
}
