use std::sync::Arc;

use anyhow::Result;
use lru_mem::LruCache;
use parking_lot::RwLock;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocksdb::WriteBatchWithTransaction;
use rusqlite::OptionalExtension;

use crate::{cfg::Forks, crypto::Hash};

/// Special storage keys
const ROCKSDB_MIGRATE_AT: &str = "migrate_at";
const ROCKSDB_CUTOVER_AT: &str = "cutover_at";

/// An implementor of [eth_trie::DB] which uses a [rocksdb::DB]/[rusqlite::Connection] to persist data.
#[derive(Debug, Clone)]
pub struct TrieStorage {
    pool: Arc<Pool<SqliteConnectionManager>>,
    cache: Arc<RwLock<LruCache<Vec<u8>, Vec<u8>>>>,
    kvdb: Arc<rocksdb::DB>,
}

impl TrieStorage {
    pub fn new(
        pool: Arc<Pool<SqliteConnectionManager>>,
        cache: Arc<RwLock<LruCache<Vec<u8>, Vec<u8>>>>,
        kvdb: Arc<rocksdb::DB>,
    ) -> Self {
        Self { pool, cache, kvdb }
    }

    pub fn write_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        anyhow::ensure!(keys.len() == values.len(), "Keys != Values");

        let mut batch = WriteBatchWithTransaction::<false>::default();
        let mut cache = self.cache.write();
        for (key, value) in keys.into_iter().zip(values.into_iter()) {
            batch.put(key.as_slice(), value.as_slice());
            cache.insert(key, value).ok(); // write-thru policy; silent errors
        }
        Ok(self.kvdb.write(batch)?)
    }

    pub fn init_state_trie(&self, _forks: Forks) -> Result<()> {
        let rdb = self.kvdb.clone();
        if rdb.get(ROCKSDB_CUTOVER_AT)?.is_none() {
            let n = self
                .pool
                .get()?
                .query_one(
                    "SELECT MAX(height) FROM blocks WHERE is_canonical = 1",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap_or_default();
            rdb.put(ROCKSDB_CUTOVER_AT, n.to_be_bytes())?;
        };
        Ok(())
    }

    #[inline]
    pub fn get_migrate_at(&self) -> Result<u64> {
        Ok(self
            .kvdb
            .get(ROCKSDB_MIGRATE_AT)?
            .map(|v| u64::from_be_bytes(v.try_into().expect("must be 8-bytes")))
            .unwrap_or(u64::MAX)) // default to no state-sync
    }

    #[inline]
    pub fn get_cutover_at(&self) -> Result<u64> {
        Ok(self
            .kvdb
            .get(ROCKSDB_CUTOVER_AT)?
            .map(|v| u64::from_be_bytes(v.try_into().expect("must be 8-bytes")))
            .unwrap_or_default())
    }

    #[inline]
    pub fn get_root_hash(&self, height: u64) -> Result<Hash> {
        Ok(self.pool.get()?.query_one(
            "SELECT state_root_hash FROM blocks WHERE is_canonical = TRUE AND height = ?1",
            [height],
            |row| row.get::<_, Hash>(0),
        )?)
    }

    #[inline]
    pub fn set_migrate_at(&self, height: u64) -> Result<()> {
        self.kvdb.put(ROCKSDB_MIGRATE_AT, height.to_be_bytes())?;
        Ok(())
    }

    #[inline]
    pub fn state_exists(&self, hash: &Hash) -> Result<bool> {
        let exists = self
            .pool
            .get()?
            .query_row("SELECT 1 FROM state_trie WHERE key = ?1", [hash], |row| {
                row.get::<_, i32>(0)
            })
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn finish_migration(&self) -> Result<()> {
        self.kvdb.put(ROCKSDB_MIGRATE_AT, u64::MAX.to_be_bytes())?;
        Ok(())
    }
}

impl eth_trie::DB for TrieStorage {
    type Error = eth_trie::TrieError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        // L1 - in-memory cache
        // does not mark the entry as MRU, but allows concurrent cache reads;
        if let Some(cached) = self.cache.read().peek(key) {
            return Ok(Some(cached.to_vec()));
        }

        // L2 - rocksdb
        if let Some(value) = self
            .kvdb
            .get(key)
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?
        {
            self.cache.write().insert(key.to_vec(), value.clone()).ok(); // silent errors
            return Ok(Some(value));
        }

        // L3 - sqlite migration
        let value: Option<Vec<u8>> = self
            .pool
            .get()
            .unwrap()
            .prepare_cached("SELECT value FROM state_trie WHERE key = ?1")
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?
            .query_row([key], |row| row.get(0))
            .optional()
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?;

        if let Some(value) = value {
            self.kvdb
                .put(key, value.as_slice())
                .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?;
            self.cache.write().insert(key.to_vec(), value.clone()).ok(); // silent errors
            return Ok(Some(value));
        }

        Ok(None)
    }

    #[inline]
    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.write_batch(vec![key.to_vec()], vec![value])
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))
    }

    #[inline]
    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        self.write_batch(keys, values)
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))
    }

    fn flush(&self) -> Result<(), Self::Error> {
        self.kvdb
            .flush()
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))
    }

    fn remove(&self, _key: &[u8]) -> Result<(), Self::Error> {
        // we keep old state to function as an archive node, therefore no-op
        Ok(())
    }

    fn remove_batch(&self, _: &[Vec<u8>]) -> Result<(), Self::Error> {
        // we keep old state to function as an archive node, therefore no-op
        Ok(())
    }
}
