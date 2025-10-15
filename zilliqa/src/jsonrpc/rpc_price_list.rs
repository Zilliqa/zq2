use dashmap::DashMap;
use std::collections::HashMap;

static DEFAULT_CREDIT: u64 = 500;

#[derive(Debug, Clone)]
pub struct RpcPriceList {
    credits: DashMap<String, u64>,
}

// Pricing should be derived based on the typical/average timing of the RPC calls.
// The conversion rate should be around 1ms:1credit such that a 5ms call costs 5 credits.

impl RpcPriceList {
    pub fn new(credit_list: HashMap<String, u64>) -> Self {
        let credits = DashMap::with_capacity(credit_list.len());
        for (key, value) in credit_list.into_iter() {
            credits.insert(key, value);
        }
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
