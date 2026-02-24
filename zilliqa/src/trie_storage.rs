use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::Result;
use eth_trie::{DB, EthTrie, Trie as _};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use revm::primitives::B256;
use rocksdb::WriteBatch;
use rusqlite::OptionalExtension;

use crate::{cfg::Forks, crypto::Hash, state::Account};

/// Special storage keys
const ROCKSDB_MIGRATE_AT: &str = "migrate_at";
const ROCKSDB_CUTOVER_AT: &str = "cutover_at";
pub const ROCKSDB_TAGGING_AT: &str = "tagging_at";
pub const LEGACY_KEY_LEN: usize = 32;
pub const TAGGED_KEY_LEN: usize = 40;

/// An implementor of [eth_trie::DB] which uses a [rocksdb::DB]/[rusqlite::Connection] to persist data.
#[derive(Debug, Clone)]
pub struct TrieStorage {
    pool: Arc<Pool<SqliteConnectionManager>>,
    kvdb: Arc<rocksdb::DB>,
    cache: Arc<RwLock<LruCache<Vec<u8>, Vec<u8>>>>,
    // the tag_* values are stored in the reverse height order i.e. u64::MAX is genesis.
    rev_ceil: Arc<AtomicU64>, // used to tag every write to the state database; reverse-ordered.
    rev_floor: Arc<AtomicU64>, // used to mark the compaction boundary; reverse-ordered.
    pub tag_view: Arc<Mutex<u64>>, // used to lock the snapshot process; forward-ordered.
    state_prune: bool,
}

impl TrieStorage {
    pub fn new(
        pool: Arc<Pool<SqliteConnectionManager>>,
        kvdb: Arc<rocksdb::DB>,
        cache: Arc<RwLock<LruCache<Vec<u8>, Vec<u8>>>>,
        rev_ceil: Arc<AtomicU64>,
        rev_floor: Arc<AtomicU64>,
        tag_view: Arc<Mutex<u64>>,
        state_prune: bool,
    ) -> Self {
        Self {
            pool,
            kvdb,
            cache,
            rev_ceil,
            rev_floor,
            tag_view,
            state_prune,
        }
    }

    /// Truncate the state_trie table
    pub fn drop_sql_state_trie(&self) -> Result<()> {
        let sql = self.pool.get().unwrap();
        sql.execute("DROP TABLE IF EXISTS state_trie", [])?; // Use DROP TABLE faster
        Ok(())
    }

    /// This snapshot promotes the *active* keys to the tag
    ///
    /// This works on duplicating the underlying db-level keys, not the trie-level keys.
    /// e.g. 500 trie-level random keys takes ~150 db-level keys.
    //
    // Previously, no deletion of keys was allowed in the state database. So, it is safe to repurpose clear_trie_from_db() to
    // snapshot-to-promote the trie, rather than delete it.
    pub fn snapshot(trie_storage: Arc<TrieStorage>, state_root_hash: B256) -> Result<()> {
        let mut state_trie = EthTrie::new(trie_storage.clone()).at_root(state_root_hash);
        for akv in state_trie.iter() {
            let (_key, serialised_account) = akv?;
            let account_root = Account::try_from(serialised_account.as_slice())?.storage_root;
            let mut account_trie = EthTrie::new(trie_storage.clone()).at_root(account_root);
            // repurpose clear_trie_from_db() to promote the trie; root_hash() forces a commit.
            let _ = account_trie.root_hash()?;
            account_trie.clear_trie_from_db()?;
        }
        // repurpose clear_trie_from_db() to promote the trie; root_hash() forces a commit.
        let _ = state_trie.root_hash()?;
        state_trie.clear_trie_from_db()?;
        // force flush to disk
        trie_storage.flush()?;
        Ok(())
    }

    /// Set the tag floor to the given view, returning previous tag
    ///
    /// This ensures that: floor != ceil && new_floor 'increments' old_floor.
    pub fn set_tag_floor(&self, view: u64) -> Result<u64> {
        let new_tag = u64::MAX.saturating_sub(view); // reverse-ordered
        let tag_floor = self.rev_floor.load(Ordering::Relaxed);
        anyhow::ensure!(new_tag <= tag_floor, "{new_tag} <= {tag_floor}");
        let tag_ceil = self.rev_ceil.load(Ordering::Relaxed);
        anyhow::ensure!(new_tag > tag_ceil, "{new_tag} > {tag_ceil}");
        self.rev_floor.store(new_tag, Ordering::Relaxed);
        Ok(u64::MAX.saturating_sub(tag_floor))
    }

    /// Set the tag to the given view, returning the previous tag
    ///
    /// This ensures that: floor != ceil && new_ceil 'increments' old_ceil.
    pub fn set_tag_ceil(&self, view: u64) -> Result<u64> {
        let new_tag = u64::MAX.saturating_sub(view); // reverse-ordered
        let tag_ceil = self.rev_ceil.load(Ordering::Relaxed);
        anyhow::ensure!(new_tag <= tag_ceil, "{new_tag} <= {tag_ceil}");
        let tag_floor = self.rev_floor.load(Ordering::Relaxed);
        anyhow::ensure!(new_tag < tag_floor, "{new_tag} < {tag_floor}");
        self.kvdb.put(ROCKSDB_TAGGING_AT, new_tag.to_be_bytes())?;
        self.rev_ceil.store(new_tag, Ordering::Relaxed);
        Ok(u64::MAX.saturating_sub(tag_ceil))
    }

    /// Writes a batch of key-value pairs to the database.
    ///
    /// Since the tagging is only performed here, only Trie keys are tagged, leaving other keys untagged.
    /// The other keys stored in this database are e.g. internal settings.
    //
    // This is the tagging scheme used. Each tag is a U64 in big-endian format.
    // |user-key + tag|seqno|type|
    // |<-----internal key------>|
    fn write_batch(
        &self,
        keys: Vec<Vec<u8>>,
        values: Vec<Vec<u8>>,
        tag: [u8; 8],
        is_migration: bool,
    ) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        anyhow::ensure!(keys.len() == values.len(), "Keys != Values");

        let mut batch = WriteBatch::default();
        let mut cache = self.cache.write();
        for (key_prefix, value) in keys.into_iter().zip(values.into_iter()) {
            // tag keys; lexicographically sorted
            let mut tag_key = key_prefix.clone();
            tag_key.extend_from_slice(tag.as_slice()); // suffix big-endian tags
            batch.put(tag_key.as_slice(), value.as_slice());

            // If migration, bypass cache, and delete the old key
            if !is_migration {
                cache.put(key_prefix, value);
            } else {
                batch.delete(key_prefix.as_slice());
            }
        }
        Ok(self.kvdb.write(batch)?)
    }

    /// This function retrieves the 'latest' value, at all times.
    ///
    /// Legacy keys do not have a tag and are ordered first due to lexicographical sorting used by rocksdb.
    /// We peek the next key to determine if the legacy key is the latest, or if a later tag key is present.
    //
    // This is the tagging scheme used. Each tag is a U64 in big-endian format.
    // |user-key + tag|seqno|type|
    // |<-----internal key------>|
    fn get_tag_value(&self, key_prefix: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut iter = self.kvdb.prefix_iterator(key_prefix);
        // early return if user-key/prefix is not found
        let Some((key, value)) = iter.next().transpose()? else {
            return Ok(None);
        };
        if !key.starts_with(key_prefix) {
            return Ok(None);
        }

        // Given that the trie keys are *all* Keccak256 keys, the legacy keys are exactly 32-bytes (256-bits) long,
        // while the new tag keys are exactly 40-bytes (320-bits) long. We do not expect any other trie-key lengths.
        match key.len() {
            TAGGED_KEY_LEN => {
                // latest tag key, naturally the most recent due to lexicographical order.
                Ok(Some(value.to_vec()))
            }
            LEGACY_KEY_LEN => {
                // legacy key - peek to see if a later tag key is present
                if let Some((k, v)) = iter.next().transpose()?
                    && k.starts_with(key_prefix)
                {
                    // Lazily delete the legacy key, if state_prune is false.
                    if !self.state_prune {
                        self.kvdb.delete(key)?;
                    }
                    return Ok(Some(v.to_vec())); // tag key has newer value
                }
                // Migration fall-thru.
                // If state_prune is true, migration will naturally happen during promotion.
                // Lazily migrate the key, if state_prune is false.
                if !self.state_prune {
                    self.write_batch(
                        vec![key.to_vec()],
                        vec![value.to_vec()],
                        self.rev_ceil.load(Ordering::Relaxed).to_be_bytes(),
                        true,
                    )?;
                }
                Ok(Some(value.to_vec())) // fall-thru value; return legacy value
            }
            _ => unimplemented!("unsupported trie key length: {} bytes", key.len()),
        }
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
            .map(|v| u64::from_be_bytes(v.try_into().expect("8-bytes")))
            .unwrap_or(u64::MAX)) // default to no state-sync
    }

    #[inline]
    pub fn get_cutover_at(&self) -> Result<u64> {
        Ok(self
            .kvdb
            .get(ROCKSDB_CUTOVER_AT)?
            .map(|v| u64::from_be_bytes(v.try_into().expect("8-bytes")))
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

    #[cfg(test)]
    // test artifacts
    fn inc_tag(&self, new_height: u64) -> Result<()> {
        let new_tag = u64::MAX.saturating_sub(new_height);
        self.rev_ceil
            .store(new_tag, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl eth_trie::DB for TrieStorage {
    type Error = eth_trie::TrieError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        // L1 - pseudo-lru
        if let Some(value) = self.cache.read().peek(key) {
            return Ok(Some(value.clone()));
        }

        // L2 - rocksdb
        if let Some(value) = self
            .get_tag_value(key)
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?
        {
            self.cache.write().put(key.to_vec(), value.clone());
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
            // lazy migration
            self.write_batch(
                vec![key.to_vec()],
                vec![value.clone()],
                self.rev_ceil.load(Ordering::Relaxed).to_be_bytes(),
                false,
            )
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?;
            return Ok(Some(value));
        }

        Ok(None)
    }

    #[inline]
    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.write_batch(
            vec![key.to_vec()],
            vec![value],
            self.rev_ceil
                .load(std::sync::atomic::Ordering::Relaxed)
                .to_be_bytes(),
            false,
        )
        .map_err(|e| eth_trie::TrieError::DB(e.to_string()))
    }

    #[inline]
    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        self.write_batch(
            keys,
            values,
            self.rev_ceil
                .load(std::sync::atomic::Ordering::Relaxed)
                .to_be_bytes(),
            false,
        )
        .map_err(|e| eth_trie::TrieError::DB(e.to_string()))
    }

    #[inline]
    fn flush(&self) -> Result<(), Self::Error> {
        self.kvdb
            .flush()
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))
    }

    // Since clear_trie_from_db() iterates over all db-level keys in the trie; this will end up
    // promoting the trie at the db-level, without iterating the trie-level keys.
    // ** only called from clear_trie_from_db() **
    fn remove(&self, promote_key: &[u8]) -> Result<(), Self::Error> {
        if let Some(value) = self
            .get_tag_value(promote_key)
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?
        {
            self.write_batch(
                vec![promote_key.to_vec()],
                vec![value],
                self.rev_ceil.load(Ordering::Relaxed).to_be_bytes(), // keeps 2 snapshots on-disk
                false,
            )
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))
        } else {
            Err(eth_trie::TrieError::DB("clear trie not found".to_string()))
        }
    }

    fn remove_batch(&self, _: &[Vec<u8>]) -> Result<(), Self::Error> {
        // TODO: Possibly remove intermediate keys.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use eth_trie::DB;
    use tempfile::tempdir;

    use super::*;
    use crate::crypto::SecretKey;

    #[allow(clippy::type_complexity)]
    fn setup() -> (
        Arc<Pool<SqliteConnectionManager>>,
        Arc<rocksdb::DB>,
        Arc<RwLock<LruCache<Vec<u8>, Vec<u8>>>>,
        Arc<TrieStorage>,
    ) {
        let sql = Arc::new(
            Pool::builder()
                .build(SqliteConnectionManager::memory())
                .unwrap(),
        );
        let rdb = Arc::new(rocksdb::DB::open_default(tempdir().unwrap().keep()).unwrap());
        let tag = Arc::new(AtomicU64::new(u64::MAX));
        let lock = Arc::new(Mutex::new(u64::MIN));
        let cache = Arc::new(RwLock::new(LruCache::unbounded()));
        let trie_storage = TrieStorage::new(
            sql.clone(),
            rdb.clone(),
            cache.clone(),
            tag.clone(),
            tag.clone(),
            lock.clone(),
            false,
        );
        let trie_storage = Arc::new(trie_storage);
        (sql, rdb, cache, trie_storage)
    }

    #[test]
    fn snapshot_doubles_the_nodes() {
        let (_, rdb, _, trie_storage) = setup();

        let mut pmt = EthTrie::new(trie_storage.clone());
        pmt.root_hash().unwrap(); // create one 'empty' record
        assert_eq!(rdb.iterator(rocksdb::IteratorMode::Start).count(), 1);

        // create 10 random accounts
        let account = Account::default();
        let value = bincode::serde::encode_to_vec(account, bincode::config::legacy()).unwrap();
        for _ in 0..100 {
            let key = SecretKey::new().unwrap().as_bytes();
            pmt.insert(key.as_slice(), value.as_slice()).unwrap();
        }

        // write-to-disk; and count nodes
        trie_storage.inc_tag(u64::MIN).unwrap();
        let root_hash = pmt.root_hash().unwrap(); // write to disk
        let old_count = rdb.iterator(rocksdb::IteratorMode::Start).count();
        assert!(old_count > 1);

        // snapshot-to-promote nodes; and count nodes
        trie_storage.inc_tag(u64::MAX).unwrap();
        TrieStorage::snapshot(trie_storage.clone(), root_hash).unwrap();
        let new_count = rdb.iterator(rocksdb::IteratorMode::Start).count();
        assert_eq!(new_count, old_count * 2);
    }

    #[test]
    // lazy migration from sqlite to rocksdb, works.
    fn lazy_migration_from_sqlite() {
        let (sql, rdb, _, trie_storage) = setup();

        let key_prefix = alloy::consensus::EMPTY_ROOT_HASH.0;
        let conn = sql.get().unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS state_trie (key BLOB NOT NULL PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;", []).unwrap();

        // read missing key
        let value = trie_storage.get(key_prefix.as_slice()).unwrap();
        assert_eq!(value, None);

        // migrate key - from sql
        conn.execute(
            "INSERT INTO state_trie (key, value) VALUES (?1, ?2)",
            [key_prefix.as_slice(), b"sql_value".to_vec().as_slice()],
        )
        .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"sql_value".to_vec());

        // count all keys
        let iter = rdb.prefix_iterator(key_prefix.as_slice());
        assert_eq!(iter.count(), 1);
    }

    #[test]
    // height-tag read/write works
    fn key_tagging_works() {
        let (_, rdb, cache, trie_storage) = setup();

        let key_prefix = alloy::consensus::EMPTY_ROOT_HASH.0;

        // write/read hi value, cached
        trie_storage.inc_tag(u64::MAX).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"max_value".to_vec())
            .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap();
        assert_eq!(value.unwrap(), b"max_value".to_vec());

        // write/read lo value, cached
        trie_storage.inc_tag(u64::MIN).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"min_value".to_vec())
            .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap();
        assert_eq!(value.unwrap(), b"min_value".to_vec());

        // read highest value, bypassing cache.
        cache.write().clear();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap();
        assert_eq!(value.unwrap(), b"max_value".to_vec());

        // count all keys
        let iter = rdb.prefix_iterator(key_prefix.as_slice());
        assert_eq!(iter.count(), 2);
    }

    #[test]
    // peek ahead works
    fn peek_ahead_and_migration() {
        let (_, rdb, cache, trie_storage) = setup();

        let key_prefix = alloy::consensus::EMPTY_ROOT_HASH.0;
        rdb.put(key_prefix.as_slice(), b"rdb_value").unwrap();

        // read legacy value
        let value = trie_storage.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"rdb_value".to_vec());

        // peak ahead tests
        trie_storage.inc_tag(u64::MIN).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"min_value".to_vec())
            .unwrap();
        cache.write().clear();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"min_value".to_vec());

        // peak ahead ordering
        trie_storage.inc_tag(u64::MAX).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"max_value".to_vec())
            .unwrap();
        cache.write().clear();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"max_value".to_vec());

        // count all keys
        let iter = rdb.prefix_iterator(key_prefix.as_slice());
        // The migration should have deleted the legacy key; and migrated everything to new keys.
        assert_eq!(iter.count(), 2);
    }

    #[test]
    // writes to disk only happens on commit
    fn write_on_commit_only() {
        let (_, rdb, cache, trie_storage) = setup();

        let key_prefix = alloy::consensus::EMPTY_ROOT_HASH.0;
        let mut pmt = EthTrie::new(trie_storage.clone());

        trie_storage.inc_tag(u64::MIN).unwrap();
        pmt.insert(key_prefix.as_slice(), b"one_value").unwrap();
        pmt.insert(key_prefix.as_slice(), b"two_value").unwrap();
        pmt.insert(key_prefix.as_slice(), b"tri_value").unwrap();
        cache.write().clear();
        let value = pmt.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"tri_value".to_vec());
        pmt.root_hash().unwrap(); // write to disk

        trie_storage.inc_tag(1).unwrap();
        pmt.insert(key_prefix.as_slice(), b"for_value").unwrap();
        trie_storage.inc_tag(2).unwrap();
        pmt.insert(key_prefix.as_slice(), b"fiv_value").unwrap();
        cache.write().clear();
        let value = pmt.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"fiv_value".to_vec());
        pmt.root_hash().unwrap(); // write to disk

        let iter = rdb.iterator(rocksdb::IteratorMode::Start);
        assert_eq!(iter.count(), 2);
    }
}
