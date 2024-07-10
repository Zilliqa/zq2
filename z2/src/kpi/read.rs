use std::time::Instant;

use anyhow::Result;
use zilliqa_rs::{middlewares::Middleware, signers::LocalWallet};

use super::{
    config::{CallReadOnlyMethods, Config},
    CallReadOnlyMethodsResult, KpiResult, ScenarioAgent,
};

impl ScenarioAgent for CallReadOnlyMethods {
    async fn run(&self, config: &Config) -> Result<KpiResult> {
        match self.r#type {
            super::config::CallReadOnlyMethodsType::GetBalance => {
                let provider = config.get_provider()?;
                let mut total_latency = 0.0;
                let num_requests = self.iterations;
                for _ in 0..num_requests {
                    let wallet = LocalWallet::create_random()?;
                    let start = Instant::now();
                    let _ = provider.get_balance(&wallet.address).await?;
                    let duration = start.elapsed();
                    total_latency += duration.as_secs_f64();
                }

                let average_latency = total_latency / num_requests as f64;
                Ok(KpiResult::CallReadOnlyMethods(CallReadOnlyMethodsResult {
                    latency: average_latency,
                }))
            }
            super::config::CallReadOnlyMethodsType::QueryContractSubState => todo!(),
            super::config::CallReadOnlyMethodsType::EvmContractViewFunction => todo!(),
            super::config::CallReadOnlyMethodsType::Mixed => todo!(),
        }
    }
}
