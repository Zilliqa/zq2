use std::sync::Arc;

use parking_lot::RwLock;
use tracing::warn;

use crate::{
    crypto::Hash,
    db::{BlockFilter, Db},
    message::Block,
    pool::TransactionPool,
    transaction::{TransactionReceipt, VerifiedTransaction},
};

pub fn get_block_by_hash(db: Arc<Db>, key: &Hash) -> anyhow::Result<Option<Block>> {
    db.get_block(key.into())
}

pub fn get_block_by_number(db: Arc<Db>, number: u64) -> anyhow::Result<Option<Block>> {
    db.get_block(BlockFilter::Height(number))
}

pub fn _head_block(db: Arc<Db>) -> Block {
    let highest_block_number = db.get_highest_canonical_block_number().unwrap().unwrap();
    db.get_block(BlockFilter::Height(highest_block_number))
        .unwrap()
        .unwrap()
}

pub fn get_canonical_block_by_number(db: Arc<Db>, number: u64) -> anyhow::Result<Option<Block>> {
    db.get_block(BlockFilter::Height(number))
}

pub fn get_finalized_block(db: Arc<Db>) -> anyhow::Result<Option<Block>> {
    let Some(view) = db.get_finalized_view()? else {
        return get_canonical_block_by_number(db.clone(), 0);
    };
    let Some(block) = db.get_block(BlockFilter::View(view))? else {
        return get_canonical_block_by_number(db.clone(), 0);
    };
    Ok(Some(block))
}

pub fn get_finalized_height(db: Arc<Db>) -> anyhow::Result<u64> {
    Ok(db.get_finalized_view()?.unwrap_or_else(|| {
        warn!("no finalised view found in table. Defaulting to 0");
        0
    }))
}

pub fn get_finalized_block_number(db: Arc<Db>) -> anyhow::Result<u64> {
    match get_finalized_block(db)? {
        Some(block) => Ok(block.number()),
        None => Ok(0),
    }
}

pub fn get_highest_canonical_block_number(db: Arc<Db>) -> u64 {
    db.get_highest_canonical_block_number().unwrap().unwrap()
}

pub fn get_num_transactions(db: Arc<Db>) -> anyhow::Result<usize> {
    let count = db.get_total_transaction_count()?;
    Ok(count)
}

// Queries txn by hash from db (and optionally from pool on a fallback)
pub fn get_transaction_by_hash(
    db: Arc<Db>,
    transaction_pool: Option<Arc<RwLock<TransactionPool>>>,
    hash: Hash,
) -> anyhow::Result<Option<VerifiedTransaction>> {
    Ok(match db.get_transaction(&hash)? {
        Some(tx) => Some(tx),
        None => {
            if let Some(transaction_pool) = transaction_pool {
                transaction_pool.read().get_transaction(&hash).cloned()
            } else {
                None
            }
        }
    })
}
pub fn get_transaction_receipt(
    db: Arc<Db>,
    hash: Hash,
) -> anyhow::Result<Option<TransactionReceipt>> {
    let Some(block_hash) = db.get_block_hash_reverse_index(&hash)? else {
        return Ok(None);
    };
    let block_receipts = db.get_transaction_receipts_in_block(&block_hash)?;
    Ok(block_receipts
        .into_iter()
        .find(|receipt| receipt.tx_hash == hash))
}

pub fn get_transaction_receipts_in_block(
    db: Arc<Db>,
    block_hash: Hash,
) -> anyhow::Result<Vec<TransactionReceipt>> {
    db.get_transaction_receipts_in_block(&block_hash)
}
