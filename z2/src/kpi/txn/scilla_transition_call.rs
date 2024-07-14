use anyhow::Result;
use futures::future::join_all;
use serde_json::json;
use tokio::time::Instant;
use zilliqa_rs::{
    contract::{Init, ScillaVariable},
    core::{
        parse_zil, CreateTransactionRequest, CreateTransactionResponse, DeployContractResponse,
        ZilAddress,
    },
    middlewares::Middleware,
    transaction::TransactionBuilder,
};

use crate::kpi::{CallTransactionResult, Config, KpiResult, ScenarioAgent};

pub struct ScillaTransitionCall {
    pub iterations: usize,
    pub attempts_to_confirm: usize,
    pub sleep_ms_before_next_try: u64,
}

impl ScillaTransitionCall {
    async fn deploy_contract(
        config: &Config,
        filename: &str,
        init: Init,
    ) -> Result<DeployContractResponse> {
        let provider = config.get_provider()?.with_signer(config.get_signer()?);
        let contract_code = std::fs::read_to_string(filename)?;
        let tx = TransactionBuilder::default()
            .to_address(ZilAddress::nil())
            .amount(0_u128)
            .code(contract_code)
            .data(serde_json::to_string(&init)?)
            .gas_price(parse_zil("0.002")?)
            .gas_limit(10000u64)
            .build();

        Ok(provider.send_transaction_without_confirm(tx).await?)
    }

    fn make_call_transition_txn(
        contract_address: &ZilAddress,
        transition_name: &str,
        args: Option<Vec<ScillaVariable>>,
    ) -> Result<CreateTransactionRequest> {
        Ok(TransactionBuilder::default()
            .gas_price_if_none(parse_zil("0.002")?)
            .gas_limit_if_none(10000u64)
            .to_address(contract_address.clone())
            .data(
                serde_json::to_string(&json!({
                    "_tag": transition_name.to_string(),
                    "params": args.clone().unwrap_or_default(),
                }))
                .unwrap(),
            )
            .build())
    }
}

impl ScenarioAgent for ScillaTransitionCall {
    async fn run(&self, config: &Config) -> anyhow::Result<crate::kpi::KpiResult> {
        let init = Init(vec![ScillaVariable::new_from_str(
            "_scilla_version",
            "Uint32",
            "0",
        )]);

        let response = Self::deploy_contract(
            config,
            "evm_scilla_js_tests/contracts/scilla/SetGet.scilla",
            init,
        )
        .await?;

        let wallet = config.get_signer()?;
        let tx = Self::make_call_transition_txn(&response.contract_address, "get_string", None)?;
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
        Ok(KpiResult::CallScillaTransitions(CallTransactionResult {
            latency,
            success_rate,
            gas_throughput: total_gas as f64 / total_duration,
            throughput: self.iterations as f64 / total_duration,
        }))
    }
}
