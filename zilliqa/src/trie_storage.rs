use std::sync::Arc;

use anyhow::Result;
use eth_trie::{EthTrie, MemoryDB, Trie};
use lru_mem::LruCache;
use parking_lot::RwLock;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocksdb::WriteBatchWithTransaction;
use rusqlite::OptionalExtension;

use crate::crypto::Hash;
use crate::state::Account;

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

    pub fn init_state_trie(&self) -> Result<()> {
        let rdb = self.kvdb.clone();
        let started_at = match rdb.get(crate::constants::ROCKSDB_STARTED_AT)? {
            Some(b) => u64::from_be_bytes(b.try_into().expect("must be 8-bytes")),
            None => {
                let n = self
                    .pool
                    .get()?
                    .query_one(
                        "SELECT MAX(height) FROM blocks WHERE is_canonical = 1",
                        [],
                        |row| row.get::<_, u64>(0),
                    )
                    .unwrap_or_default();
                rdb.put(crate::constants::ROCKSDB_STARTED_AT, n.to_be_bytes())?;
                n
            }
        };
        if rdb.get(crate::constants::ROCKSDB_MIGRATE_AT)?.is_none() {
            rdb.put(
                crate::constants::ROCKSDB_MIGRATE_AT,
                started_at.to_be_bytes(),
            )?;
        }
        Ok(())
    }

    #[inline]
    fn get_migrate_at(&self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.kvdb
                .get(crate::constants::ROCKSDB_MIGRATE_AT)?
                .map(|v| v.try_into().expect("must be 8-bytes"))
                .expect("inserted at constructor"),
        ))
    }

    #[inline]
    fn get_root_hash(&self, height: u64) -> Result<Hash> {
        Ok(self
            .pool
            .get()?
            .prepare_cached(
                "SELECT state_root_hash FROM blocks WHERE is_canonical = TRUE AND height = ?1",
            )?
            .query_one([height], |row| row.get::<_, Hash>(0))?)
    }

    /// Actively migrate state_trie from sqlite to rocksdb.
    /// By iterating over every node in the trie, flushing the data to disk.
    pub fn migrate_state_trie(&self) -> Result<()> {
        let migrate_at = self.get_migrate_at()?;
        if migrate_at == 0 {
            // extremely unlikely that the state_root for block_0 == block_N;
            // so, if height = 0 it means that we're done.
            // TODO: drop the sqlite state_trie table in a subsequent release.
            return Ok(());
        }
        let root_hash = self.get_root_hash(migrate_at)?;

        let trie_store = Arc::new(Self {
            pool: self.pool.clone(),
            cache: self.cache.clone(),
            kvdb: self.kvdb.clone(),
        });

        let mut count = 0;
        // skip if state trie already exists
        let state_trie = EthTrie::new(trie_store.clone()).at_root(root_hash.into());
        let mut state_mem = EthTrie::new(Arc::new(MemoryDB::new(true)));
        for (k, v) in state_trie.iter().flatten() {
            state_mem.insert(k.as_slice(), v.as_slice())?;
            count += 1;

            // for each account, load its corresponding storage trie
            let account_state = Account::try_from(v.as_slice())?.storage_root;

            // skip if storage trie already exists
            if trie_store
                .kvdb
                .get_pinned(account_state.0.as_slice())?
                .is_none()
            {
                let account_trie = EthTrie::new(trie_store.clone()).at_root(account_state.0.into());
                let mut account_mem = EthTrie::new(Arc::new(MemoryDB::new(true)));
                account_trie.iter().flatten().for_each(|(k, v)| {
                    account_mem.insert(k.as_slice(), v.as_slice()).ok();
                    count += 1;
                });
                assert_eq!(account_state, account_mem.root_hash()?);
                // flush account storage to disk
                let (keys, values): (Vec<_>, Vec<_>) =
                    account_mem.db.storage.write().drain().unzip();
                trie_store.write_batch(keys, values)?;
            }
        }
        // flush new state_trie nodes to disk
        assert_eq!(root_hash.0, state_mem.root_hash()?.0);
        let (keys, values) = state_mem.db.storage.write().drain().unzip();
        trie_store.write_batch(keys, values)?;
        tracing::debug!(%count, block=%migrate_at, %root_hash, "Migrated");

        // save next migrate_at, fast-reversing past the same states
        // do this only after successfully migrating the previous migrate_at
        for n in (0..migrate_at).rev() {
            let next_root_hash = self.get_root_hash(n)?;
            if next_root_hash != root_hash {
                self.kvdb
                    .put(crate::constants::ROCKSDB_MIGRATE_AT, n.to_be_bytes())?;
                break;
            } else if n == 0 {
                // migration complete
                tracing::info!("State migration complete");
                self.kvdb
                    .put(crate::constants::ROCKSDB_MIGRATE_AT, n.to_be_bytes())?;
            }
        }
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
            // lazy migration skipped during manual migration
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
