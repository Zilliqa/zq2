use std::sync::Arc;

use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocksdb::WriteBatch;
use rusqlite::OptionalExtension;

use crate::{cfg::Forks, crypto::Hash};

// Percentiles: P50: 414.93 P75: 497.53 P99: 576.82 P99.9: 579.79 P99.99: 12678.76
pub const BLOCK_SIZE: usize = 1 << 12;

/// Special storage keys
const ROCKSDB_MIGRATE_AT: &str = "migrate_at";
const ROCKSDB_CUTOVER_AT: &str = "cutover_at";

/// An implementor of [eth_trie::DB] which uses a [rocksdb::DB]/[rusqlite::Connection] to persist data.
#[derive(Debug, Clone)]
pub struct TrieStorage {
    pool: Arc<Pool<SqliteConnectionManager>>,
    kvdb: Arc<rocksdb::DB>,
    height_tag: [u8; 8], // reverse height tag, big-endian u64
}

impl TrieStorage {
    pub fn new(
        pool: Arc<Pool<SqliteConnectionManager>>,
        kvdb: Arc<rocksdb::DB>,
        final_height: Option<u64>,
    ) -> Self {
        Self {
            pool,
            kvdb,
            height_tag: u64::MAX
                .saturating_sub(final_height.unwrap_or(u64::MIN))
                .to_be_bytes(),
        }
    }

    pub fn write_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        anyhow::ensure!(keys.len() == values.len(), "Keys != Values");

        let mut batch = WriteBatch::default();
        for (mut key, value) in keys.into_iter().zip(values.into_iter()) {
            // timestamp-suffix keys; lexicographically sorted
            key.extend_from_slice(&self.height_tag); // suffix big-endian height tags
            batch.put(key.as_slice(), value.as_slice());
        }
        Ok(self.kvdb.write(batch)?)
    }

    pub fn init_state_trie(&self, _forks: Forks) -> Result<()> {
        let rdb = self.kvdb.clone();
        if rdb.get(ROCKSDB_CUTOVER_AT)?.is_none() {
            let n = self
                .pool
                .get()?
                // highest block seen, regardless of canonicality
                .query_one("SELECT MAX(height) FROM blocks", [], |row| {
                    row.get::<_, u64>(0)
                })
                .unwrap_or_default()
                // slightly above highest block seen.
                .saturating_add(2);
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
    pub fn get_root_hash(&self, height: u64) -> Result<Option<Hash>> {
        Ok(self
            .pool
            .get()?
            .query_one(
                "SELECT state_root_hash FROM blocks WHERE is_canonical = TRUE AND height = ?1",
                [height],
                |row| row.get::<_, Hash>(0),
            )
            .optional()?)
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

    // This function retrieves the 'latest' key, at all times.
    // Legacy keys do not have a timestamp-suffix and are iterated first due to lexicographical sorting used by rocksdb.
    // We peek the next key to determine if the legacy key is the latest, or if a later timestamp-suffix key is present.
    fn get_latest_value(&self, key_prefix: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut iter = self.kvdb.prefix_iterator(key_prefix);
        // early return if prefix is not found
        let Some(prefix) = iter.next() else {
            return Ok(None);
        };
        let (key, value) = prefix?;
        if !key.starts_with(key_prefix) {
            return Ok(None);
        }

        if key.len() == 40 {
            // timestamp-suffix key, return the latest value
            Ok(Some(value.to_vec()))
        } else if key.len() == 32 {
            // legacy key - check to see if timestamp-suffix key is present
            if let Some(peek) = iter.next() {
                let peek = peek?;
                if peek.0.starts_with(key_prefix) {
                    return Ok(Some(peek.1.to_vec()));
                }
            }
            Ok(Some(value.to_vec())) // fall-thru value
        } else {
            unimplemented!("unsupported key");
        }
    }
}

impl eth_trie::DB for TrieStorage {
    type Error = eth_trie::TrieError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        // L1 - rocksdb
        if let Some(value) = self
            .get_latest_value(key)
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?
        {
            return Ok(Some(value));
        }

        // L2 - sqlite migration
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
            // lazy migration
            self.write_batch(vec![key.to_vec()], vec![value.clone()])
                .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?;
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
