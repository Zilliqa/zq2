use std::{collections::HashMap, time::Duration};

use anyhow::anyhow;
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};

use crate::{message::BlockHeader, time::SystemTime, transaction::VerifiedTransaction};

#[derive(Debug)]
pub struct Filter {
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
    pub fn poll(&mut self) -> anyhow::Result<Vec<BlockHeader>> {
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
                        "Filter was not polled in time, {skipped} blocks missed",
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

#[derive(Debug)]
pub struct PendingTxFilter {
    pub pending_txn_receiver: tokio::sync::broadcast::Receiver<VerifiedTransaction>,
}

impl PendingTxFilter {
    pub fn poll(&mut self) -> anyhow::Result<Vec<VerifiedTransaction>> {
        let mut txns = Vec::new();

        // Try to receive all currently available messages
        loop {
            match self.pending_txn_receiver.try_recv() {
                Ok(txn) => {
                    // Successfully got a header, add it to our vec
                    txns.push(txn);
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                    // No more messages available, we're done
                    break;
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
                    // We've lagged behind, some messages were missed
                    return Err(anyhow!(
                        "Filter was not polled in time, {skipped} transactions missed",
                    ));
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    // Channel is closed
                    return Err(anyhow!("Filter has been deleted"));
                }
            }
        }

        Ok(txns)
    }
}

#[derive(Debug)]
pub struct LogFilter {
    pub criteria: Box<alloy::rpc::types::Filter>,
    pub last_block_number: Option<u64>,
}

impl Filter {
    pub fn new(kind: FilterKind) -> Self {
        Self {
            last_poll: SystemTime::now(),
            kind,
        }
    }

    pub fn touch(&mut self) {
        self.last_poll = SystemTime::now();
    }
}

#[derive(Debug, Default)]
pub struct Filters {
    filters: Mutex<HashMap<u128, Filter>>,
}

impl Filters {
    pub fn new() -> Self {
        Self {
            filters: Mutex::new(HashMap::new()),
        }
    }

    pub fn add(&self, kind: FilterKind) -> u128 {
        let mut filters = self.filters.lock();

        // Clean expired filters
        filters.retain(|_, filter| {
            SystemTime::now()
                .duration_since(filter.last_poll)
                .unwrap_or_default()
                > Duration::from_secs(5 * 60)
        });

        let id = rand::random::<u128>();
        filters.insert(id, Filter::new(kind));
        id
    }

    pub fn remove(&self, id: u128) -> bool {
        self.filters.lock().remove(&id).is_some()
    }

    pub fn get(&self, id: u128) -> Option<MappedMutexGuard<'_, Filter>> {
        let filters = self.filters.lock();
        if !filters.contains_key(&id) {
            return None;
        }
        let mut filter = MutexGuard::map(filters, |fs| fs.get_mut(&id).unwrap());
        filter.touch();
        Some(filter)
    }
}
