use anyhow::Result;

mod eth_transfer;
mod zil_transfer;

use super::{
    config::{self, Config, SendTransactions},
    KpiResult, ScenarioAgent,
};

impl ScenarioAgent for SendTransactions {
    async fn run(&self, config: &Config) -> Result<KpiResult> {
        match self.r#type {
            config::CallTransactionsType::ZilTransfer => {
                let zil_transfer = zil_transfer::ZilTransfer {
                    iterations: self.iterations,
                    attempts_to_confirm: self.attempts_to_confirm,
                    sleep_ms_before_next_try: self.sleep_ms_before_next_try,
                };
                zil_transfer.run(config).await
            }
            config::CallTransactionsType::EthTransfer => {
                let eth_transfer = eth_transfer::EthTransfer {
                    iterations: self.iterations,
                    attempts_to_confirm: self.attempts_to_confirm,
                    sleep_ms_before_next_try: self.sleep_ms_before_next_try,
                };
                eth_transfer.run(config).await
            }
            config::CallTransactionsType::EvmContractCall => todo!(),
            config::CallTransactionsType::ScillaContractCall => todo!(),
            config::CallTransactionsType::Mixed => todo!(),
        }
    }
}
