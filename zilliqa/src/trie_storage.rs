use std::sync::Arc;

use anyhow::Result;
use eth_trie::{EthTrie, Trie};
use parking_lot::RwLock;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocksdb::WriteBatch;
use rusqlite::OptionalExtension;

use crate::{cfg::Forks, crypto::Hash, state::Account};

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
    tag: Arc<RwLock<[u8; 8]>>, // reverse tag, big-endian u64
}

impl TrieStorage {
    pub fn new(
        pool: Arc<Pool<SqliteConnectionManager>>,
        kvdb: Arc<rocksdb::DB>,
        tag: Arc<RwLock<[u8; 8]>>,
    ) -> Self {
        Self { pool, kvdb, tag }
    }

    // This snapshot promotes the *active* keys to the latest tag
    //
    // By taking a snapshot of the trie storage, we ensure that the active keys are promoted to the latest tag.
    // This allows any older keys to be deprecated and eventually removed from storage during compaction.
    // However, this also means that the storage will grow in size as the active keys are duplicated.
    // So, it is crucial that compaction is triggered regularly to maintain a reasonable storage size.
    pub fn snapshot(&self, state_root_hash: Hash) -> Result<()> {
        let trie_storage = Arc::new(self.clone());

        let num_workers = crate::tokio_worker_count().max(2) / 2; // use N/2 threads
        let (work_tx, work_rx) = crossbeam::channel::bounded::<(Vec<u8>, Vec<u8>)>(num_workers * 2); // 2 x Threads
        tracing::info!("Snapshot with {num_workers} workers");
        // This code looks similar to checkpoint.rs::save_ckpt() as a checkpoint is effectively a snapshot of the trie storage.
        crossbeam::thread::scope(|s| {
            let mut workers = Vec::with_capacity(num_workers);
            for _ in 0..num_workers {
                let work_rx = work_rx.clone();
                let trie_storage = trie_storage.clone();
                let worker = s.spawn(move |_s| -> Result<u64> {
                    let mut count = u64::MIN;
                    while let Ok((key, serialised_account)) = work_rx.recv() {
                        // with some minimal capacity to reduce unnecessary duplication
                        let mut keys = Vec::with_capacity(128);
                        let mut values = Vec::with_capacity(128);

                        // iterate over the entire account trie
                        let account_root =
                            Account::try_from(serialised_account.as_slice())?.storage_root;
                        let mut account_trie =
                            EthTrie::new(trie_storage.clone()).at_root(account_root);
                        for skv in account_trie.iter() {
                            let (storage_key, storage_val) = skv?;
                            keys.push(storage_key);
                            values.push(storage_val);
                        }

                        // write the account key-value itself
                        keys.push(key);
                        values.push(serialised_account);

                        // promote the entire set of keys/values
                        self.write_batch(keys, values)?;
                        account_trie.root_hash()?; // promote account root
                        count += 1;
                    }
                    Ok(count)
                });
                workers.push(worker);
            }

            // iterate over the entire state trie
            let trie_storage = trie_storage.clone();
            let producer = s.spawn(move |_s| -> Result<u64> {
                let mut state_trie =
                    EthTrie::new(trie_storage.clone()).at_root(state_root_hash.into());
                let mut count = u64::MIN;
                for akv in state_trie.iter() {
                    let (key, serialised_account) = akv?;
                    work_tx.send((key.to_vec(), serialised_account.to_vec()))?;
                    count += 1;
                }
                drop(work_tx); // Close the work channel so Workers exit when done
                state_trie.root_hash()?; // promote state root
                Ok(count)
            });

            let producer_count = producer.join().expect("producer panicked").unwrap();
            let mut consumer_count = u64::MIN;
            for worker in workers {
                let worker_count = worker.join().expect("worker panicked").unwrap();
                consumer_count += worker_count;
            }
            assert_eq!(
                producer_count, consumer_count,
                "Missing snapshot {producer_count} != {consumer_count}"
            );
        })
        .expect("Failed snapshot");
        Ok(())
    }

    // Called at startup, and writes the initial cutover value once, if it is missing.
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

    // Writes a batch of key-value pairs to the database.
    //
    // This is the tagging scheme used. Each tag is a U64 in big-endian format.
    // |user-key + tag|seqno|type|
    // |<-----internal key------>|
    //
    // Since the tagging is only performed here, only Trie keys are tagged.
    // The only other keys stored in this database are internal configuration.
    fn write_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        anyhow::ensure!(keys.len() == values.len(), "Keys != Values");

        let mut batch = WriteBatch::default();
        let tag = self.tag.read();
        for (mut key, value) in keys.into_iter().zip(values.into_iter()) {
            // tag keys; lexicographically sorted
            key.extend_from_slice(tag.as_slice()); // suffix big-endian tags
            batch.put(key.as_slice(), value.as_slice());
        }
        Ok(self.kvdb.write(batch)?)
    }

    // This function retrieves the 'latest' value, at all times.
    //
    // Legacy keys do not have a tag and are ordered first due to lexicographical sorting used by rocksdb.
    // We peek the next key to determine if the legacy key is the latest, or if a later tag key is present.
    //
    // This is the tagging scheme used. Each tag is a U64 in big-endian format.
    // |user-key + tag|seqno|type|
    // |<-----internal key------>|
    fn get_latest(&self, key_prefix: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut iter = self.kvdb.prefix_iterator(key_prefix);
        // early return if user-key/prefix is not found
        let Some(prefix) = iter.next() else {
            return Ok(None);
        };
        let (key, value) = prefix?;
        if !key.starts_with(key_prefix) {
            return Ok(None);
        }

        // Given that the trie keys are *all* Keccak256 keys, the legacy keys are exactly 32-bytes (256-bits) long,
        // while the new tag keys are exactly 40-bytes (320-bits) long. We do not expect any other key lengths.
        if key.len() == 40 {
            // latest tag key, return the latest value
            Ok(Some(value.to_vec()))
        } else if key.len() == 32 {
            // legacy key - peek to see if a later tag key is present
            if let Some(peek) = iter.next() {
                let peek = peek?;
                if peek.0.starts_with(key_prefix) {
                    return Ok(Some(peek.1.to_vec())); // tag key has newer value
                }
            }
            // We do not perform lazy migration here to avoid write amplification.
            Ok(Some(value.to_vec())) // fall-thru value; return legacy value
        } else {
            unimplemented!("unsupported trie key length {} bytes", key.len());
        }
    }

    #[cfg(test)]
    // We set the height tag to the reverse height, due to the lexicographical order used by rocksdb.
    // This ensures that the higher/later keys always get hit first, improving performance.
    fn inc_tag(&self, new_height: u64) -> Result<()> {
        let mut tag = self.tag.write();
        let new_tag = u64::MAX.saturating_sub(new_height).to_be_bytes();
        *tag = new_tag;
        Ok(())
    }
}

impl eth_trie::DB for TrieStorage {
    type Error = eth_trie::TrieError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        // L1 - rocksdb
        if let Some(value) = self
            .get_latest(key)
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

#[cfg(test)]
mod tests {
    use eth_trie::DB;
    use tempfile::tempdir;

    use super::*;

    #[test]
    // basic read/write
    fn read_write() {
        let sql = Arc::new(
            Pool::builder()
                .build(SqliteConnectionManager::memory())
                .unwrap(),
        );
        let rdb = Arc::new(rocksdb::DB::open_default(tempdir().unwrap()).unwrap());
        let tag = Arc::new(RwLock::new(u64::MAX.to_be_bytes()));
        let trie_storage = TrieStorage::new(sql.clone(), rdb.clone(), tag);

        let key_prefix = alloy::consensus::EMPTY_ROOT_HASH.0;

        // normal key read/write, w/o height-tags
        assert_eq!(trie_storage.get_migrate_at().unwrap(), u64::MAX); // default

        trie_storage.inc_tag(u64::MAX).unwrap(); // ignored
        trie_storage.set_migrate_at(u64::MIN).unwrap();
        assert_eq!(trie_storage.get_migrate_at().unwrap(), u64::MIN); // new value

        trie_storage.inc_tag(u64::MIN).unwrap(); // ignored
        trie_storage.set_migrate_at(u64::MAX).unwrap();
        assert_eq!(trie_storage.get_migrate_at().unwrap(), u64::MAX); // prev value

        // count all keys
        let iter = rdb.prefix_iterator(key_prefix.as_slice());
        assert_eq!(iter.count(), 1);
    }

    #[test]
    // lazy migration from sqlite to rocksdb, works.
    fn lazy_migration() {
        let sql = Arc::new(
            Pool::builder()
                .build(SqliteConnectionManager::memory())
                .unwrap(),
        );
        let rdb = Arc::new(rocksdb::DB::open_default(tempdir().unwrap()).unwrap());
        let tag = Arc::new(RwLock::new(u64::MAX.to_be_bytes()));
        let trie_storage = TrieStorage::new(sql.clone(), rdb.clone(), tag);

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
    fn tagging() {
        let sql = Arc::new(
            Pool::builder()
                .build(SqliteConnectionManager::memory())
                .unwrap(),
        );
        let rdb = Arc::new(rocksdb::DB::open_default(tempdir().unwrap()).unwrap());
        let tag = Arc::new(RwLock::new(u64::MAX.to_be_bytes()));
        let trie_storage = TrieStorage::new(sql.clone(), rdb.clone(), tag);

        let key_prefix = alloy::consensus::EMPTY_ROOT_HASH.0;

        // write/read lo value
        trie_storage.inc_tag(u64::MIN).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"min_value".to_vec())
            .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap();
        assert_eq!(value.unwrap(), b"min_value".to_vec());

        // write/read hi value
        trie_storage.inc_tag(u64::MAX).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"max_value".to_vec())
            .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap();
        assert_eq!(value.unwrap(), b"max_value".to_vec());

        // test
        trie_storage.inc_tag(u64::MIN).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"min_value".to_vec())
            .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap();
        assert_eq!(value.unwrap(), b"max_value".to_vec());

        // count all keys
        let iter = rdb.prefix_iterator(key_prefix.as_slice());
        assert_eq!(iter.count(), 2);
    }

    #[test]
    // peek ahead works
    fn peek_ahead() {
        let sql = Arc::new(
            Pool::builder()
                .build(SqliteConnectionManager::memory())
                .unwrap(),
        );
        let rdb = Arc::new(rocksdb::DB::open_default(tempdir().unwrap()).unwrap());
        let tag = Arc::new(RwLock::new(u64::MAX.to_be_bytes()));
        let trie_storage = TrieStorage::new(sql.clone(), rdb.clone(), tag);

        let key_prefix = alloy::consensus::EMPTY_ROOT_HASH.0;
        rdb.put(key_prefix.as_slice(), b"rdb_value".to_vec())
            .unwrap();

        // read legacy value
        let value = trie_storage.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"rdb_value".to_vec());

        // peak ahead tests
        trie_storage.inc_tag(u64::MIN).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"min_value".to_vec())
            .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"min_value".to_vec());

        // peak ahead ordering
        trie_storage.inc_tag(u64::MAX).unwrap();
        trie_storage
            .insert(key_prefix.as_slice(), b"max_value".to_vec())
            .unwrap();
        let value = trie_storage.get(key_prefix.as_slice()).unwrap().unwrap();
        assert_eq!(value, b"max_value".to_vec());

        // count all keys
        let iter = rdb.prefix_iterator(key_prefix.as_slice());
        assert_eq!(iter.count(), 3);
    }
}
