use zilliqa_rs::{
    contract::{Init, ScillaVariable},
    core::{parse_zil, DeployContractResponse, ZilAddress},
    middlewares::Middleware,
    transaction::TransactionBuilder,
};

use crate::kpi::{Config, ScenarioAgent};
use anyhow::Result;

pub struct ScillaTransitionCall;

impl ScillaTransitionCall {
    pub async fn deploy_contract(
        config: &Config,
        filename: &str,
        init: Init,
    ) -> Result<DeployContractResponse> {
        let provider = config.get_provider()?.with_signer(config.get_signer()?);
        let contract_code = std::fs::read_to_string(filename)?;
        println!("{contract_code}");
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
}

impl ScenarioAgent for ScillaTransitionCall {
    async fn run(&self, config: &Config) -> anyhow::Result<crate::kpi::KpiResult> {
        let init = Init(vec![ScillaVariable::new_from_str(
            "_scilla_version",
            "Uint32",
            "0",
        )]);

        let _result = Self::deploy_contract(
            config,
            "evm_scilla_js_tests/contracts/scilla/SetGet.scilla",
            init,
        )
        .await?;

        todo!();
    }
}
