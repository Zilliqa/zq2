use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::eth::GetLogsParams;
use crate::{crypto::Hash, message::BlockHeader, time::SystemTime};

#[derive(Debug)]
pub struct Filter {
    pub created_at: SystemTime,
    pub last_poll: SystemTime,
    pub kind: FilterKind,
}

#[derive(Debug)]
pub enum FilterKind {
    Block(BlockFilter),
    PendingTx(PendingTxFilter),
    Log(LogFilter),
}

#[derive(Debug)]
pub struct BlockFilter {
    pub block_receiver: tokio::sync::broadcast::Receiver<BlockHeader>,
}

impl BlockFilter {
    pub fn consume_headers(&mut self) -> anyhow::Result<Vec<BlockHeader>> {
        let mut headers = Vec::new();

        // Try to receive all currently available messages
        loop {
            match self.block_receiver.try_recv() {
                Ok(header) => {
                    // Successfully got a header, add it to our vec
                    headers.push(header);
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                    // No more messages available, we're done
                    break;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
                    // We've lagged behind, some messages were missed
                    return Err(anyhow!(
                        "Filter was not polled in time, {} BlockHeaders missed",
                        skipped
                    ));
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    // Channel is closed
                    return Err(anyhow!("Filter has been deleted"));
                }
            }
        }

        Ok(headers)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PendingTxFilter {
    pub seen_txs: HashSet<Hash>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogFilter {
    pub criteria: GetLogsParams,
    pub last_block_number: Option<u64>,
    pub last_log_index: Option<u64>,
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

#[derive(Debug, Default)]
pub struct Filters {
    filters: HashMap<u128, Filter>,
    actions_since_cleanup: usize,
}

impl Filters {
    pub fn new() -> Self {
        Self {
            filters: HashMap::new(),
            actions_since_cleanup: 0,
        }
    }

    pub fn add_filter(&mut self, kind: FilterKind) -> u128 {
        self.cleanup_forced();
        let id = rand::random::<u128>();
        self.filters.insert(id, Filter::new(kind));
        id
    }

    pub fn remove_filter(&mut self, id: u128) -> bool {
        let result = self.filters.remove(&id).is_some();
        self.cleanup();
        result
    }

    pub fn get_mut(&mut self, id: &u128) -> Option<&mut Filter> {
        self.touch(id);
        self.cleanup();
        self.filters.get_mut(id)
    }

    pub fn touch(&mut self, id: &u128) {
        if let Some(filter) = self.filters.get_mut(id) {
            filter.touch();
        }
        self.cleanup();
    }

    pub fn cleanup(&mut self) {
        self.actions_since_cleanup += 1;
        if self.actions_since_cleanup > 100 {
            self.cleanup_forced();
            self.actions_since_cleanup = 0;
        }
    }

    pub fn cleanup_forced(&mut self) {
        self.filters.retain(|_, filter| {
            SystemTime::now()
                .duration_since(filter.last_poll)
                .unwrap_or_default()
                > Duration::from_secs(300)
        });
    }
}
