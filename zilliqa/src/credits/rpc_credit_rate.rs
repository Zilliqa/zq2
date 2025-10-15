use dashmap::DashMap;
use std::collections::HashMap;

const DEFAULT_CREDIT: u64 = 500; // arbitrarily chosen

#[derive(Debug, Clone)]
pub struct RpcCreditRate {
    credits: DashMap<String, u64>,
}

impl RpcCreditRate {
    pub fn new(credit_list: HashMap<String, u64>) -> Self {
        let credits = DashMap::with_capacity(credit_list.len());
        for (key, value) in credit_list.into_iter() {
            credits.insert(key, value);
        }
        // Zero fee for health check
        credits.insert(String::from("health_check"), 0);
        Self { credits }
    }

    #[inline]
    pub fn get_credit(&self, method: &str) -> u64 {
        self.credits
            .get(method)
            .map(|v| *v)
            .unwrap_or(DEFAULT_CREDIT)
    }
}
