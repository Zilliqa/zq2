use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use super::eth::GetLogsParams;
use crate::{crypto::Hash, time::SystemTime};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Filter {
    pub created_at: SystemTime,
    pub last_poll: SystemTime,
    pub kind: FilterKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FilterKind {
    Block(BlockFilter),
    PendingTx(PendingTxFilter),
    Log(LogFilter),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockFilter {
    pub last_block: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PendingTxFilter {
    pub seen_txs: HashSet<Hash>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogFilter {
    pub criteria: GetLogsParams,
    pub seen_logs: HashSet<super::eth::Log>,
}

impl Filter {
    pub fn new(kind: FilterKind) -> Self {
        let now = SystemTime::now();
        Self {
            created_at: now,
            last_poll: now,
            kind,
        }
    }

    pub fn touch(&mut self) {
        self.last_poll = SystemTime::now();
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        SystemTime::now()
            .duration_since(self.last_poll)
            .unwrap_or_default()
            > timeout
    }
}

#[derive(Clone, Debug, Deserialize, Default, Serialize)]
pub struct Filters {
    filters: HashMap<u128, Filter>,
}

impl Filters {
    pub fn new() -> Self {
        Self {
            filters: HashMap::new(),
        }
    }

    pub fn insert(&mut self, kind: FilterKind) -> u128 {
        let id = rand::random::<u128>();

        self.filters.insert(id, Filter::new(kind));
        id
    }

    pub fn get(&self, id: &u128) -> Option<&Filter> {
        self.filters.get(id)
    }

    pub fn get_mut(&mut self, id: &u128) -> Option<&mut Filter> {
        self.filters.get_mut(id)
    }

    pub fn touch(&mut self, id: &u128) {
        if let Some(filter) = self.filters.get_mut(id) {
            filter.touch();
        }
    }

    pub fn remove(&mut self, id: &u128) -> Option<Filter> {
        self.filters.remove(id)
    }

    pub fn cleanup(&mut self) {
        self.filters.retain(|_, filter| {
            SystemTime::now()
                .duration_since(filter.last_poll)
                .unwrap_or_default()
                > Duration::from_secs(300)
        });
    }
}
