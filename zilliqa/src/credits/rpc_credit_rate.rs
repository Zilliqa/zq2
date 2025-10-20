use std::collections::HashMap;

use dashmap::DashMap;

const DEFAULT_CREDIT: u64 = 500; // arbitrarily chosen

#[derive(Debug, Clone)]
pub struct RpcCreditRate {
    credits: DashMap<String, u64>,
    default: u64,
}

impl RpcCreditRate {
    pub fn new(credit_list: HashMap<String, u64>) -> Self {
        // get the default credit rate, if unspecified
        //
        // [credit_rates]
        // default = 500
        let default = credit_list
            .get("default")
            .copied()
            .unwrap_or(DEFAULT_CREDIT);

        let credits = DashMap::with_capacity(credit_list.len());
        for (key, value) in credit_list.into_iter() {
            credits.insert(key, value);
        }

        // Zero fee for health checks
        credits.insert(String::from("health_check"), 0);

        Self { credits, default }
    }

    #[inline]
    pub fn get_credit(&self, method: &str) -> u64 {
        self.credits.get(method).map(|v| *v).unwrap_or(self.default)
    }
}
