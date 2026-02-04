use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::primitives::Address;
use anyhow::{Context, Result, anyhow};
#[allow(unused_imports)]
use eth_trie::{DB, EthTrie, MemoryDB, Trie};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use revm::primitives::B256;
use rocksdb::{
    BlockBasedOptions, Cache, CompactionDecision, DBWithThreadMode, Options, SingleThreaded,
};
use rusqlite::{
    Connection, OptionalExtension, Row, ToSql, named_params,
    types::{FromSql, FromSqlError, ToSqlOutput},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    cfg::DbConfig,
    crypto::{BlsSignature, Hash},
    exec::{ScillaError, ScillaException, ScillaTransition},
    message::{AggregateQc, Block, BlockHeader, QuorumCertificate},
    precompiles::ViewHistory,
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, TransactionReceipt, VerifiedTransaction},
    trie_storage::{ROCKSDB_TAGGING_AT, TrieStorage},
};

const MAX_KEYS_IN_SINGLE_QUERY: usize = 32765;

macro_rules! sqlify_with_bincode {
    ($type: ty) => {
        impl ToSql for $type {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                let data = bincode::serde::encode_to_vec(self, bincode::config::legacy())
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                Ok(ToSqlOutput::from(data))
            }
        }
        impl FromSql for $type {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                let blob = value.as_blob()?;
                Ok(
                    bincode::serde::decode_from_slice(blob, bincode::config::legacy())
                        .map_err(|e| FromSqlError::Other(Box::new(e)))?
                        .0,
                )
            }
        }
    };
}

/// Creates a thin wrapper for a type with proper From traits. To ease implementing To/FromSql on
/// foreign types.
macro_rules! make_wrapper {
    ($old: ty, $new: ident) => {
        paste::paste! {
            #[derive(Serialize, Deserialize)]
            struct $new($old);

            impl From<$old> for $new {
                fn from(value: $old) -> Self {
                    Self(value)
                }
            }

            impl From<$new> for $old {
                fn from(value: $new) -> Self {
                    value.0
                }
            }
        }
    };
}

sqlify_with_bincode!(AggregateQc);
sqlify_with_bincode!(QuorumCertificate);
sqlify_with_bincode!(BlsSignature);
sqlify_with_bincode!(SignedTransaction);

make_wrapper!(Vec<ScillaException>, VecScillaExceptionSqlable);
sqlify_with_bincode!(VecScillaExceptionSqlable);
make_wrapper!(BTreeMap<u64, Vec<ScillaError>>, MapScillaErrorSqlable);
sqlify_with_bincode!(MapScillaErrorSqlable);

make_wrapper!(Vec<Log>, VecLogSqlable);
sqlify_with_bincode!(VecLogSqlable);

make_wrapper!(Vec<ScillaTransition>, VecScillaTransitionSqlable);
sqlify_with_bincode!(VecScillaTransitionSqlable);

make_wrapper!(SystemTime, SystemTimeSqlable);
impl ToSql for SystemTimeSqlable {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        use std::mem::size_of;

        let since_epoch = self.0.duration_since(SystemTime::UNIX_EPOCH).unwrap();

        let mut buf = [0u8; size_of::<u64>() + size_of::<u32>()];

        buf[..size_of::<u64>()].copy_from_slice(&since_epoch.as_secs().to_be_bytes()[..]);
        buf[size_of::<u64>()..].copy_from_slice(&since_epoch.subsec_nanos().to_be_bytes()[..]);

        Ok(ToSqlOutput::from(buf.to_vec()))
    }
}
impl FromSql for SystemTimeSqlable {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        use std::mem::size_of;

        let blob = value.as_blob()?;

        if blob.len() != size_of::<u64>() + size_of::<u32>() {
            return Err(FromSqlError::InvalidBlobSize {
                expected_size: size_of::<u64>() + size_of::<u32>(),
                blob_size: blob.len(),
            });
        }

        let mut secs_buf = [0u8; size_of::<u64>()];
        let mut subsec_nanos_buf = [0u8; size_of::<u32>()];

        secs_buf.copy_from_slice(&blob[..size_of::<u64>()]);
        subsec_nanos_buf.copy_from_slice(&blob[size_of::<u64>()..]);

        let secs = u64::from_be_bytes(secs_buf);
        let subsec_nanos = u32::from_be_bytes(subsec_nanos_buf);

        Ok(SystemTimeSqlable(
            SystemTime::UNIX_EPOCH + Duration::new(secs, subsec_nanos),
        ))
    }
}

make_wrapper!(Address, AddressSqlable);
impl ToSql for AddressSqlable {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.as_slice()))
    }
}
impl FromSql for AddressSqlable {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(AddressSqlable(Address::from(<[u8; 20]>::column_result(
            value,
        )?)))
    }
}

impl ToSql for Hash {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.to_vec()))
    }
}
impl FromSql for Hash {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(Hash(<[u8; 32]>::column_result(value)?))
    }
}

impl ToSql for EvmGas {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for EvmGas {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(Self(u64::column_result(value)?))
    }
}

pub enum BlockFilter {
    Hash(Hash),
    View(u64),
    Height(u64),
    MaxHeight,
    MaxCanonicalByHeight,
    Finalized,
    HighQC,
}

impl From<Hash> for BlockFilter {
    fn from(hash: Hash) -> Self {
        BlockFilter::Hash(hash)
    }
}

impl From<&Hash> for BlockFilter {
    fn from(hash: &Hash) -> Self {
        BlockFilter::Hash(*hash)
    }
}

impl From<u64> for BlockFilter {
    fn from(height: u64) -> Self {
        BlockFilter::Height(height)
    }
}

impl From<alloy::eips::BlockNumberOrTag> for BlockFilter {
    fn from(x: alloy::eips::BlockNumberOrTag) -> Self {
        match x {
            alloy::eips::BlockNumberOrTag::Latest => BlockFilter::MaxCanonicalByHeight,
            alloy::eips::BlockNumberOrTag::Finalized => BlockFilter::Finalized,
            alloy::eips::BlockNumberOrTag::Safe => BlockFilter::HighQC,
            alloy::eips::BlockNumberOrTag::Earliest => BlockFilter::Height(0),
            alloy::eips::BlockNumberOrTag::Pending => {
                panic!("Pending block cannot be retrieved from db by definition")
            }
            alloy::eips::BlockNumberOrTag::Number(x) => BlockFilter::Height(x),
        }
    }
}

#[derive(Clone)]
pub struct BlockAndReceipts {
    pub block: Block,
    pub receipts: Vec<TransactionReceipt>,
}

#[derive(Clone)]
pub struct BlockAndReceiptsAndTransactions {
    pub block: Block,
    pub receipts: Vec<TransactionReceipt>,
    pub transactions: Vec<VerifiedTransaction>,
}

const LARGE_OFFSET: u64 = 1_000_000_000_000;

/// Version string that is written to disk along with the persisted database. This should be bumped whenever we make a
/// backwards incompatible change to our database format. This should be done rarely, since it forces all node
/// operators to re-sync.
const CURRENT_DB_VERSION: &str = "1";

#[derive(Debug)]
pub struct Db {
    pool: Arc<Pool<SqliteConnectionManager>>,
    kvdb: Arc<rocksdb::DB>,
    cache: Arc<RwLock<LruCache<Vec<u8>, Vec<u8>>>>,
    path: Option<Box<Path>>,
    /// The block height at which ZQ2 blocks begin.
    /// This value should be required only for proto networks to distinguise between ZQ1 and ZQ2 blocks.
    executable_blocks_height: Option<u64>,
    /// Clone of DbConfig
    pub config: DbConfig,
    /// State Pruning
    tag_ceil: Arc<AtomicU64>, // always set to the finalised view height; set by Db::set_finalised_view()
    tag_floor: Arc<AtomicU64>, // resets to u64::MAX at startup; gets set during prune.; set by Db::snapshot()
    pub tag_lock: Arc<Mutex<u64>>, // used to lock the snapshot process
}

impl Db {
    pub fn new<P>(
        data_dir: Option<P>,
        shard_id: u64,
        executable_blocks_height: Option<u64>,
        config: DbConfig,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let (manager, path) = match data_dir {
            Some(path) => {
                let path = path.as_ref().join(shard_id.to_string());
                fs::create_dir_all(&path).context(format!("Unable to create {path:?}"))?;

                let mut version_file = OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .read(true)
                    .write(true)
                    .open(path.join("version"))?;
                let mut version = String::new();
                version_file.read_to_string(&mut version)?;

                if !version.is_empty() && version != CURRENT_DB_VERSION {
                    return Err(anyhow!(
                        "data is incompatible with this version - please delete the data and re-sync"
                    ));
                }

                version_file.seek(SeekFrom::Start(0))?;
                version_file.write_all(CURRENT_DB_VERSION.as_bytes())?;

                let db_path = path.join("db.sqlite3");
                let cfg = config.clone();
                (
                    SqliteConnectionManager::file(db_path)
                        .with_init(move |conn| Self::init_connection(conn, cfg.clone())),
                    Some(path.into_boxed_path()),
                )
            }
            None => (SqliteConnectionManager::memory(), None),
        };

        // Build connection pool
        let num_workers = crate::available_threads().max(4) as u32;
        let builder = Pool::builder().min_idle(Some(1)).max_size(num_workers * 2); // more than enough connections
        debug!("SQLite {builder:?}");

        let pool = builder.build(manager)?;
        let connection = pool.get()?;
        Self::ensure_schema(&connection)?;

        let tag_floor = Arc::new(AtomicU64::new(u64::MAX)); // default to no compaction
        // Should be safe in single-threaded mode
        // https://docs.rs/rocksdb/latest/rocksdb/type.DB.html#limited-performance-implication-for-single-threaded-mode
        let rdb_path = path.as_ref().map_or_else(
            || tempfile::tempdir().unwrap().path().join("state.rocksdb"),
            |p| p.join("state.rocksdb"),
        );
        let rdb_opts = Self::init_rocksdb(config.clone(), tag_floor.clone());
        let rdb = DBWithThreadMode::<SingleThreaded>::open(&rdb_opts, rdb_path)?;

        tracing::info!(
            "State database: {} ({})",
            rdb.path().display(),
            rdb.latest_sequence_number()
        );

        // Percentiles: P50: 414.93 P75: 497.53 P99: 576.82 P99.9: 579.79 P99.99: 12678.76
        let cache =
            LruCache::new(NonZeroUsize::new(config.rocksdb_state_cache_size / 500).unwrap());

        // *** Must use the latest tag for keys. ***
        let last_tag = rdb.get(ROCKSDB_TAGGING_AT)?.map_or(u64::MAX, |v| {
            u64::from_be_bytes(v.try_into().expect("8-bytes"))
        });
        let tag_ceil = Arc::new(AtomicU64::new(last_tag)); // stores the reverse view
        let tag_lock = Arc::new(Mutex::new(u64::MAX.saturating_sub(last_tag))); // stores the equivalent view

        Ok(Db {
            pool: Arc::new(pool),
            kvdb: Arc::new(rdb),
            cache: Arc::new(RwLock::new(cache)),
            path,
            executable_blocks_height,
            config,
            tag_ceil,
            tag_floor,
            tag_lock,
        })
    }

    fn ensure_schema(connection: &Connection) -> Result<()> {
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocks (
                block_hash BLOB NOT NULL PRIMARY KEY,
                view INTEGER NOT NULL UNIQUE,
                height INTEGER NOT NULL,
                signature BLOB NOT NULL,
                state_root_hash BLOB NOT NULL,
                transactions_root_hash BLOB NOT NULL,
                receipts_root_hash BLOB NOT NULL,
                timestamp BLOB NOT NULL,
                gas_used INTEGER NOT NULL,
                gas_limit INTEGER NOT NULL,
                qc BLOB NOT NULL,
                agg BLOB,
                is_canonical BOOLEAN NOT NULL) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash BLOB NOT NULL PRIMARY KEY,
                data BLOB NOT NULL) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS receipts (
                tx_hash BLOB NOT NULL PRIMARY KEY REFERENCES transactions (tx_hash) ON DELETE CASCADE,
                block_hash BLOB NOT NULL REFERENCES blocks (block_hash), -- the touched_address_index needs to be updated for all the txs in the block, so delete txs first - thus no cascade here
                tx_index INTEGER NOT NULL,
                success INTEGER NOT NULL,
                gas_used INTEGER NOT NULL,
                cumulative_gas_used INTEGER NOT NULL,
                contract_address BLOB,
                logs BLOB,
                transitions BLOB,
                accepted INTEGER,
                errors BLOB,
                exceptions BLOB);
            CREATE INDEX IF NOT EXISTS block_hash_index ON receipts (block_hash);
            CREATE TABLE IF NOT EXISTS touched_address_index (
                address BLOB,
                tx_hash BLOB REFERENCES transactions (tx_hash) ON DELETE CASCADE,
                PRIMARY KEY (address, tx_hash)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS tip_info (
                finalized_view INTEGER,
                view INTEGER,
                high_qc BLOB,
                high_qc_updated_at BLOB,
                _single_row INTEGER DEFAULT 0 NOT NULL UNIQUE CHECK (_single_row = 0)); -- max 1 row
            CREATE TABLE IF NOT EXISTS state_trie (key BLOB NOT NULL PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
            ",
        )?;
        connection.execute_batch("
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL PRIMARY KEY) WITHOUT ROWID;
        ")?;
        // No version entries implies we are on version 0.
        let version = connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get::<_, Option<u32>>(0)
            })?
            .unwrap_or_default();

        if version < 1 {
            connection.execute_batch(
                "
                BEGIN;
                INSERT INTO schema_version VALUES (1);
                ALTER TABLE tip_info ADD COLUMN voted_in_view BOOLEAN NOT NULL DEFAULT FALSE;
                COMMIT;
            ",
            )?;
        }

        if version < 2 {
            connection.execute_batch(
                "
                BEGIN;
                INSERT INTO schema_version VALUES (2);
                CREATE TABLE new_receipts (
                    tx_hash BLOB NOT NULL REFERENCES transactions (tx_hash),
                    block_hash BLOB NOT NULL REFERENCES blocks (block_hash),
                    tx_index INTEGER NOT NULL,
                    success INTEGER NOT NULL,
                    gas_used INTEGER NOT NULL,
                    cumulative_gas_used INTEGER NOT NULL,
                    contract_address BLOB,
                    logs BLOB,
                    transitions BLOB,
                    accepted INTEGER,
                    errors BLOB,
                    exceptions BLOB,
                    PRIMARY KEY (block_hash, tx_hash)
                );
                INSERT INTO new_receipts SELECT * FROM receipts;
                DROP TABLE receipts;
                ALTER TABLE new_receipts RENAME TO receipts;
                CREATE INDEX block_hash_index ON receipts (block_hash);
                COMMIT;
            ",
            )?;
        }

        if version < 3 {
            connection.execute_batch(
                "
                BEGIN;
                INSERT INTO schema_version VALUES (3);
                CREATE INDEX idx_receipts_tx_hash ON receipts (tx_hash);
                COMMIT;
            ",
            )?;
        }

        if version < 4 {
            connection.execute_batch(
                "
                BEGIN;
                INSERT INTO schema_version VALUES (4);
                CREATE TABLE IF NOT EXISTS aux_table (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
                COMMIT;
            ",
            )?;
        }

        if version < 5 {
            connection.execute_batch(
                "
                BEGIN;

                INSERT INTO schema_version VALUES (5);

                CREATE TABLE IF NOT EXISTS view_history (view INTEGER NOT NULL PRIMARY KEY, leader BLOB) WITHOUT ROWID;

                CREATE INDEX IF NOT EXISTS idx_view_history_leader ON view_history(leader);

                INSERT INTO view_history (view, leader) VALUES (1000000000000, NULL);

                COMMIT;
            ",
            )?;
        }

        if version < 6 {
            connection.execute_batch(
                "
                BEGIN;

                INSERT INTO schema_version VALUES (6);

                CREATE TABLE IF NOT EXISTS ckpt_view_history (view INTEGER NOT NULL PRIMARY KEY, leader BLOB) WITHOUT ROWID;

                CREATE INDEX IF NOT EXISTS idx_ckpt_view_history_leader ON ckpt_view_history(leader);

                INSERT INTO ckpt_view_history (view, leader) VALUES (1000000000000, NULL);

                COMMIT;
            ",
            )?;
        }

        Ok(())
    }

    pub fn read_ckpt_view_history(&self) -> Result<Vec<(u64, Vec<u8>)>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached(
                "SELECT view, leader FROM ckpt_view_history WHERE leader NOT NULL ORDER BY view",
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn reset_ckpt_view_history(&self) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("DELETE FROM ckpt_view_history WHERE leader NOT NULL")?
            .execute([])?;
        self.pool
            .get()?
            .prepare_cached(
                format!("UPDATE ckpt_view_history SET view = {LARGE_OFFSET} WHERE leader IS NULL")
                    .as_str(),
            )?
            //.execute(rusqlite::params![view, leader])?;
            .execute([])?;
        Ok(())
    }

    pub fn extend_ckpt_view_history(&self, view: u64, leader: Vec<u8>) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("INSERT INTO ckpt_view_history (view, leader) VALUES (?1, ?2)")?
            //.execute(rusqlite::params![view, leader])?;
            .execute((view, leader))?;
        Ok(())
    }

    pub fn get_min_view_of_ckpt_view_history(&self) -> Result<u64> {
        let min_view: u64 = self
            .pool
            .get()?
            .prepare_cached("SELECT view FROM ckpt_view_history WHERE leader IS NULL LIMIT 1")?
            .query_row([], |row| row.get(0))
            .unwrap_or_default();
        // to prevent primary key collision with missed views stored in the table
        Ok(min_view - LARGE_OFFSET)
    }

    pub fn set_min_view_of_ckpt_view_history(&self, min_view: u64) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("UPDATE ckpt_view_history SET view = ?1 WHERE leader IS NULL")?
            // to prevent primary key collision with missed views stored in the table
            .execute([min_view + LARGE_OFFSET])?;
        Ok(())
    }

    pub fn read_recent_view_history(&self, view: u64) -> Result<Vec<(u64, Vec<u8>)>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached(
                "SELECT view, leader FROM view_history WHERE view > ?1 AND leader NOT NULL ORDER BY view",
            )?
            .query_map([view], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn prune_view_history(&self, view: u64) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("DELETE FROM view_history WHERE view < ?1 AND leader NOT NULL")?
            .execute([view])?;
        Ok(())
    }

    pub fn get_first_last_from_view_history(&self) -> Result<(u64, u64)> {
        let min = self
            .pool
            .get()?
            .prepare_cached("SELECT MIN(view) FROM view_history WHERE leader NOT NULL")?
            .query_row([], |row| row.get(0))
            .unwrap_or_default();
        let max = self
            .pool
            .get()?
            .prepare_cached("SELECT MAX(view) FROM view_history WHERE leader NOT NULL")?
            .query_row([], |row| row.get(0))
            .unwrap_or_default();
        Ok((min, max))
    }

    pub fn get_min_view_of_view_history(&self) -> Result<u64> {
        let min_view: u64 = self
            .pool
            .get()?
            .prepare_cached("SELECT view FROM view_history WHERE leader IS NULL LIMIT 1")?
            .query_row([], |row| row.get(0))
            .unwrap_or_default();
        // to prevent primary key collision with missed views stored in the table
        Ok(min_view - LARGE_OFFSET)
    }

    pub fn set_min_view_of_view_history(&self, min_view: u64) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("UPDATE view_history SET view = ?1 WHERE leader IS NULL")?
            // to prevent primary key collision with missed views stored in the table
            .execute([min_view + LARGE_OFFSET])?;
        Ok(())
    }

    pub fn extend_view_history(&self, view: u64, leader: Vec<u8>) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("INSERT INTO view_history (view, leader) VALUES (?1, ?2)")?
            //.execute(rusqlite::params![view, leader])?;
            .execute((view, leader))?;
        Ok(())
    }

    fn init_rocksdb(config: DbConfig, tag_floor: Arc<AtomicU64>) -> rocksdb::Options {
        // RocksDB configuration
        let mut block_opts = BlockBasedOptions::default();
        // reduce disk and memory usage - https://github.com/facebook/rocksdb/wiki/RocksDB-Bloom-Filter#ribbon-filter
        block_opts.set_ribbon_filter(10.0);
        block_opts.set_optimize_filters_for_memory(true); // reduce memory wastage with JeMalloc
        // Mitigate OOM
        block_opts.set_cache_index_and_filter_blocks(config.rocksdb_cache_index_filters);
        // Improve cache utilisation
        block_opts.set_pin_top_level_index_and_filter(true);
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        block_opts.set_index_type(rocksdb::BlockBasedIndexType::TwoLevelIndexSearch);
        block_opts.set_partition_filters(true);
        block_opts.set_block_size(config.rocksdb_block_size);
        block_opts.set_metadata_block_size(config.rocksdb_block_size);

        let cache =
            Cache::new_hyper_clock_cache(config.rocksdb_cache_size, config.rocksdb_block_size);
        block_opts.set_block_cache(&cache);

        let mut rdb_opts = Options::default();
        rdb_opts.create_if_missing(true);
        rdb_opts.set_block_based_table_factory(&block_opts);
        rdb_opts.set_periodic_compaction_seconds(config.rocksdb_compaction_period);
        // Mitigate OOM - prevent opening too many files at a time
        rdb_opts.set_max_open_files(config.rocksdb_max_open_files);
        // Reduce reads
        rdb_opts.set_level_compaction_dynamic_level_bytes(true);
        rdb_opts.set_target_file_size_base(config.rocksdb_target_file_size);
        rdb_opts.set_max_bytes_for_level_base(config.rocksdb_target_file_size << 2);
        // Reduce storage
        rdb_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        rdb_opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
        rdb_opts.set_bottommost_zstd_max_train_bytes(0, true);

        // Keys are only removed if they are older than the floor value, which is set during snapshot.
        // After pruning, old and legacy keys are eventually removed when the background compaction runs.
        let floor = tag_floor.clone();
        rdb_opts.set_compaction_filter(
            "StatePruneFilter",
            move |_lvl, key, _value| -> CompactionDecision {
                match key.len() {
                    // 40-bytes: remove tagged key, if the key is 'older' than the floor
                    40 if u64::from_be_bytes(key[32..40].try_into().unwrap())
                        > floor.load(Ordering::Relaxed) =>
                    {
                        CompactionDecision::Remove
                    }
                    // 32-bytes: remove legacy key, if snapshot already taken
                    32 if floor.load(Ordering::Relaxed) != u64::MAX => CompactionDecision::Remove,
                    // default to keep, all other keys
                    _ => CompactionDecision::Keep,
                }
            },
        );

        rdb_opts
    }

    // SQLite performance tweaks
    fn init_connection(
        connection: &mut Connection,
        config: DbConfig,
    ) -> Result<(), rusqlite::Error> {
        // large page_size is more compact/efficient, 64K is hard-coded maximum
        connection.pragma_update(None, "page_size", 1 << 15)?;
        // reduced non-critical fsync() calls, reducing disk I/O
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        // store temporary tables/indices in-memory, reducing disk I/O
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        // improved read/write multi-threaded locking
        connection.pragma_update(None, "journal_mode", "WAL")?;
        // journal size of 32MB - empirical value
        connection.pragma_update(None, "journal_size_limit", 1 << 25)?;
        // page cache 32MB/connection default
        connection.pragma_update(None, "cache_size", config.conn_cache_size)?;
        // page cache 1000 auto checkpoint default
        connection.pragma_update(None, "wal_autocheckpoint", config.auto_checkpoint)?;
        // larger prepared cache, due to many prepared statements
        connection.set_prepared_statement_cache_capacity(1 << 8); // default is 16, which is small
        // enable QPSG - https://github.com/Zilliqa/zq2/issues/2870
        if !connection.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG,
            true,
        )? {
            warn!("*** QPSG disabled - queries may be slow ***");
        }
        // Add tracing - logs SQL statements
        connection.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_PROFILE,
            Some(|profile_event| {
                if let rusqlite::trace::TraceEvent::Profile(statement, duration) = profile_event {
                    let statement_txt = statement.expanded_sql();
                    let query_duration = duration.as_millis();
                    const DURATION_TIME_THRESHOLD_MS: u128 = 1000;
                    if query_duration > DURATION_TIME_THRESHOLD_MS {
                        warn!(statement_txt, "sql execution took > {}", query_duration);
                    }
                }
            }),
        );
        Ok(())
    }

    pub fn get_value_from_aux_table(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT value FROM aux_table WHERE key = ?1")?
            .query_row([key], |row| row.get(0))
            .optional()?)
    }

    pub fn insert_value_to_aux_table(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("INSERT OR REPLACE INTO aux_table (key, value) VALUES (?1, ?2)")?
            .execute(rusqlite::params![key, value])?;
        Ok(())
    }

    pub fn get_checkpoint_dir(&self) -> Result<Option<Box<Path>>> {
        let Some(base_path) = &self.path else {
            // If we don't have on-disk persistency, disable checkpoints too
            warn!(
                "Attempting to create checkpoint, but no persistence directory has been configured"
            );
            return Ok(None);
        };
        Ok(Some(base_path.join("checkpoints").into_boxed_path()))
    }

    /// Returns the lowest and highest block numbers of stored blocks
    pub fn available_range(&self) -> Result<RangeInclusive<u64>> {
        let db = self.pool.get()?;
        // Doing it together is slow
        // sqlite> EXPLAIN QUERY PLAN SELECT MIN(height), MAX(height) FROM blocks;
        // QUERY PLAN
        // `--SCAN blocks USING COVERING INDEX idx_blocks_height
        let min = db
            .prepare_cached("SELECT MIN(height) FROM blocks")?
            .query_row([], |row| row.get::<_, u64>(0))
            .optional()?
            .unwrap_or_default();
        let max = db
            .prepare_cached("SELECT MAX(height) FROM blocks")?
            .query_row([], |row| row.get::<_, u64>(0))
            .optional()?
            .unwrap_or_default();
        Ok(min..=max)
    }
    /// Fetch checkpoint data from file and initialise db state
    /// Return checkpointed block and transactions which must be executed after this function
    /// Return None if checkpoint already loaded
    #[allow(clippy::type_complexity)]
    pub fn load_trusted_checkpoint(
        &self,
        path: PathBuf,
        hash: &Hash,
        our_shard_id: u64,
    ) -> Result<Option<(Block, Vec<SignedTransaction>, Block, ViewHistory)>> {
        let trie_storage = Arc::new(self.state_trie()?);
        let state_trie = EthTrie::new(trie_storage.clone());

        // If no state trie exists and no blocks are known, then we are in a fresh database.
        // We can safely load the checkpoint.
        if state_trie.iter().next().is_none()
            && self.get_highest_canonical_block_number()?.is_none()
        {
            tracing::info!(%hash, "Restoring checkpoint");
            let (block, transactions, parent, view_history) = crate::checkpoint::load_ckpt(
                path.as_path(),
                trie_storage.clone(),
                our_shard_id,
                hash,
            )?
            .expect("does not return None");

            let parent_ref: &Block = &parent; // for moving into the closure
            self.with_sqlite_tx(move |tx| {
                self.insert_block_with_db_tx(tx, parent_ref)?;
                self.set_finalized_view_with_db_tx(tx, parent_ref.view())?;
                self.set_high_qc_with_db_tx(tx, block.header.qc)?;
                self.set_view_with_db_tx(tx, parent_ref.view() + 1, false)?;
                Ok(())
            })?;

            return Ok(Some((block, transactions, parent, view_history)));
        }

        let (block, transactions, parent) = crate::checkpoint::load_ckpt_blocks(path.as_path())?;

        // Populated database; check if the parent block exists in the DB.
        let Some(ckpt_parent) = self.get_transactionless_block(parent.hash().into())? else {
            return Err(anyhow!("Invalid checkpoint attempt"));
        };
        anyhow::ensure!(
            ckpt_parent.parent_hash() == parent.parent_hash(),
            "Critical checkpoint error"
        );

        let view_history = crate::checkpoint::load_ckpt_history(path.as_path())?;

        // Since it exists, this must either be a state-sync/state-migration
        // If this is not desired, remove the config setting.
        tracing::info!(%hash, "Syncing checkpoint");
        crate::checkpoint::load_ckpt_state(
            path.as_path(),
            trie_storage.clone(),
            &ckpt_parent.state_root_hash(),
        )?;

        Ok(Some((block, transactions, parent, view_history)))
    }

    pub fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage::new(
            self.pool.clone(),
            self.kvdb.clone(),
            self.cache.clone(),
            self.tag_ceil.clone(),
            self.tag_floor.clone(),
            self.tag_lock.clone(),
        ))
    }

    pub fn with_sqlite_tx(&self, operations: impl FnOnce(&Connection) -> Result<()>) -> Result<()> {
        let mut sqlite_tx = self.pool.get()?;
        let sqlite_tx = sqlite_tx.transaction()?;
        operations(&sqlite_tx)?;
        Ok(sqlite_tx.commit()?)
    }

    pub fn get_block_hash_by_view(&self, view: u64) -> Result<Option<Hash>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT block_hash FROM blocks WHERE view = ?1")?
            .query_row([view], |row| row.get(0))
            .optional()?)
    }

    pub fn set_finalized_view_with_db_tx(&self, sqlite_tx: &Connection, view: u64) -> Result<()> {
        sqlite_tx
            .prepare_cached("INSERT INTO tip_info (finalized_view) VALUES (?1) ON CONFLICT DO UPDATE SET finalized_view = ?1")?
            .execute([view])?;
        Ok(())
    }

    pub fn set_finalized_view(&self, view: u64) -> Result<()> {
        let db = self.pool.get()?;
        self.set_finalized_view_with_db_tx(&db, view)
    }

    pub fn get_finalized_view(&self) -> Result<Option<u64>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT finalized_view FROM tip_info")?
            .query_row((), |row| row.get(0))
            .optional()
            .unwrap_or(None))
    }

    /// Write view to table if view is larger than current. Return true if write was successful
    pub fn set_view_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        view: u64,
        voted: bool,
    ) -> Result<bool> {
        let res = sqlite_tx
            .prepare_cached("INSERT INTO tip_info (view, voted_in_view) VALUES (?1, ?2) ON CONFLICT(_single_row) DO UPDATE SET view = ?1, voted_in_view = ?2 WHERE tip_info.view IS NULL OR tip_info.view < ?1",)?
            .execute((view, voted))?;
        Ok(res != 0)
    }

    pub fn set_view(&self, view: u64, voted: bool) -> Result<bool> {
        let db = self.pool.get()?;
        self.set_view_with_db_tx(&db, view, voted)
    }

    pub fn get_view(&self) -> Result<Option<u64>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT view FROM tip_info")?
            .query_row((), |row| row.get(0))
            .optional()
            .unwrap_or(None))
    }

    pub fn get_voted_in_view(&self) -> Result<bool> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT voted_in_view FROM tip_info")?
            .query_row((), |row| row.get(0))?)
    }

    pub fn get_highest_canonical_block_number(&self) -> Result<Option<u64>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT MAX(height) FROM blocks WHERE is_canonical = 1")?
            .query_row((), |row| {
                row.get(0).map_err(|e| {
                    // workaround where MAX(height) returns NULL if there are no blocks, instead of a NoRows error
                    if let rusqlite::Error::InvalidColumnType(_, _, typ) = e
                        && typ == rusqlite::types::Type::Null
                    {
                        return rusqlite::Error::QueryReturnedNoRows;
                    }
                    e
                })
            })
            .optional()?)
    }

    pub fn get_lowest_block_view_number(&self) -> Result<Option<u64>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT MIN(view) FROM blocks")?
            .query_row((), |row| {
                row.get(0).map_err(|e| {
                    // workaround where MIN(view) returns NULL if there are no blocks, instead of a NoRows error
                    if let rusqlite::Error::InvalidColumnType(_, _, typ) = e
                        && typ == rusqlite::types::Type::Null
                    {
                        return rusqlite::Error::QueryReturnedNoRows;
                    }
                    e
                })
            })
            .optional()?)
    }

    pub fn set_high_qc_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        high_qc: QuorumCertificate,
    ) -> Result<()> {
        sqlite_tx.prepare_cached("INSERT INTO tip_info (high_qc, high_qc_updated_at) VALUES (:high_qc, :timestamp) ON CONFLICT DO UPDATE SET high_qc = :high_qc, high_qc_updated_at = :timestamp",)?
        .execute(
            named_params! {
                ":high_qc": high_qc,
                ":timestamp": SystemTimeSqlable(SystemTime::now())
            })?;
        Ok(())
    }

    pub fn set_high_qc(&self, high_qc: QuorumCertificate) -> Result<()> {
        let db = self.pool.get()?;
        self.set_high_qc_with_db_tx(&db, high_qc)
    }

    pub fn get_high_qc(&self) -> Result<Option<QuorumCertificate>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT high_qc FROM tip_info")?
            .query_row((), |row| row.get(0))
            .optional()?
            .flatten())
    }

    pub fn get_high_qc_updated_at(&self) -> Result<Option<SystemTime>> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT high_qc_updated_at FROM tip_info")?
            .query_row((), |row| row.get::<_, SystemTimeSqlable>(0))
            .optional()
            .unwrap_or(None)
            .map(Into::<SystemTime>::into))
    }

    pub fn add_touched_address_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        address: Address,
        txn_hash: Hash,
    ) -> Result<()> {
        sqlite_tx
            .prepare_cached(
                "INSERT OR IGNORE INTO touched_address_index (address, tx_hash) VALUES (?1, ?2)",
            )?
            .execute((AddressSqlable(address), txn_hash))?;
        Ok(())
    }

    pub fn add_touched_address(&self, address: Address, txn_hash: Hash) -> Result<()> {
        let db = self.pool.get()?;
        self.add_touched_address_with_db_tx(&db, address, txn_hash)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        let conn = self.pool.get()?;

        // 1) tx hashes that touched the address
        let tx_hashes: Vec<Hash> = conn
            .prepare_cached("SELECT tx_hash FROM touched_address_index WHERE address = ?1")?
            .query_map([AddressSqlable(address)], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        if tx_hashes.is_empty() {
            return Ok(Vec::new());
        }

        // 2) receipts for those tx hashes (tx_hash -> (block_hash, tx_index))
        let mut tx_meta: HashMap<Hash, (Hash, u64)> = HashMap::with_capacity(tx_hashes.len());
        let mut block_hashes: HashSet<Hash> = HashSet::new();

        {
            for chunk in tx_hashes.chunks(MAX_KEYS_IN_SINGLE_QUERY) {
                let placeholders = std::iter::repeat_n("?", chunk.len())
                    .collect::<Vec<_>>()
                    .join(",");

                let sql = format!(
                    r#"
                    SELECT tx_hash, block_hash, tx_index
                        FROM receipts
                        WHERE tx_hash IN ({placeholders})
                    "#
                );

                // dynamic SQL -> use prepare (not prepare_cached)
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                    let tx_hash: Hash = row.get(0)?;
                    let block_hash: Hash = row.get(1)?;
                    let idx: u64 = row.get(2)?;
                    Ok((tx_hash, block_hash, idx))
                })?;

                for row in rows {
                    let (tx_hash, block_hash, idx) = row?;
                    tx_meta.insert(tx_hash, (block_hash, idx));
                    block_hashes.insert(block_hash);
                }
            }
        }

        let mut block_height: HashMap<Hash, u64> = HashMap::with_capacity(block_hashes.len());
        {
            let block_hashes_vec = block_hashes.into_iter().collect::<Vec<_>>();
            for chunk in block_hashes_vec.chunks(MAX_KEYS_IN_SINGLE_QUERY) {
                let placeholders = std::iter::repeat_n("?", chunk.len())
                    .collect::<Vec<_>>()
                    .join(",");

                let sql = format!(
                    r#"
                    SELECT block_hash, height
                        FROM blocks
                        WHERE block_hash IN ({placeholders})
                    "#
                );

                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                    let block_hash: Hash = row.get(0)?;
                    let height: u64 = row.get(1)?;
                    Ok((block_hash, height))
                })?;

                for row in rows {
                    let (block_hash, height) = row?;
                    block_height.insert(block_hash, height);
                }
            }
        }

        // 4) sort tx hashes by (block_height, tx_index)
        let mut out: Vec<Hash> = tx_hashes
            .into_iter()
            .filter(|tx| tx_meta.contains_key(tx))
            .collect();

        out.sort_unstable_by(|a, b| {
            let (bha, ia) = tx_meta.get(a).expect("Missing transaction hash!");
            let (bhb, ib) = tx_meta.get(b).expect("Missing transaction hash!");
            let ha = *block_height.get(bha).unwrap_or(&u64::MAX);
            let hb = *block_height.get(bhb).unwrap_or(&u64::MAX);
            (ha, ia).cmp(&(hb, ib))
        });

        Ok(out)
    }

    pub fn get_transaction(&self, txn_hash: &Hash) -> Result<Option<VerifiedTransaction>> {
        Ok(
            match self
                .pool
                .get()?
                .prepare_cached("SELECT data FROM transactions WHERE tx_hash = ?1")?
                .query_row([txn_hash], |row| row.get(0))
                .optional()?
                .map(|x: SignedTransaction| x.verify_bypass(*txn_hash))
            {
                Some(x) => Some(x?),
                None => None,
            },
        )
    }

    pub fn get_transactions(&self, txn_hashes: &[Hash]) -> Result<Vec<VerifiedTransaction>> {
        let mut transactions = Vec::with_capacity(txn_hashes.len());
        let conn = self.pool.get()?;

        for chunk in txn_hashes.chunks(MAX_KEYS_IN_SINGLE_QUERY) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");

            let sql = format!(
                r#"
                SELECT data, tx_hash
                    FROM transactions
                    WHERE tx_hash IN ({placeholders})
                "#
            );

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                let txn: SignedTransaction = row.get(0)?;
                let h: Hash = row.get(1)?;
                Ok((h, txn))
            })?;

            for row in rows {
                let (hash, signed_tx) = row?;
                transactions.push(signed_tx.verify_bypass(hash)?);
            }
        }
        Ok(transactions)
    }

    pub fn contains_transaction(&self, hash: &Hash) -> Result<bool> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT 1 FROM transactions WHERE tx_hash = ?1")?
            .query_row([hash], |row| row.get::<_, i64>(0))
            .optional()?
            .is_some())
    }

    pub fn insert_transaction_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        hash: &Hash,
        tx: &VerifiedTransaction,
    ) -> Result<()> {
        sqlite_tx
            .prepare_cached("INSERT OR IGNORE INTO transactions (tx_hash, data) VALUES (?1, ?2)")?
            .execute((hash, tx.tx.clone()))?;
        Ok(())
    }

    /// Insert a transaction whose hash was precalculated, to save a call to calculate_hash() if it
    /// is already known
    pub fn insert_transaction(&self, hash: &Hash, tx: &VerifiedTransaction) -> Result<()> {
        let db = self.pool.get()?;
        self.insert_transaction_with_db_tx(&db, hash, tx)
    }

    pub fn get_block_hash_reverse_index(&self, tx_hash: &Hash) -> Result<Option<Hash>> {
        Ok(self.pool.get()?
            .prepare_cached("SELECT r.block_hash FROM receipts r INNER JOIN blocks b ON r.block_hash = b.block_hash WHERE r.tx_hash = ?1 AND b.is_canonical = TRUE")?
            .query_row([tx_hash], |row| row.get(0))
            .optional()?)
    }

    pub fn insert_block_with_db_tx(&self, sqlite_tx: &Connection, block: &Block) -> Result<()> {
        self.insert_block_with_hash_with_db_tx(sqlite_tx, block.hash(), block)
    }

    pub fn insert_block_with_hash_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        hash: Hash,
        block: &Block,
    ) -> Result<()> {
        sqlite_tx.prepare_cached("INSERT INTO blocks
        (block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg, is_canonical)
    VALUES (:block_hash, :view, :height, :qc, :signature, :state_root_hash, :transactions_root_hash, :receipts_root_hash, :timestamp, :gas_used, :gas_limit, :agg, TRUE)",)?.execute(
            named_params! {
                ":block_hash": hash,
                ":view": block.header.view,
                ":height": block.header.number,
                ":qc": block.header.qc,
                ":signature": block.header.signature,
                ":state_root_hash": block.header.state_root_hash,
                ":transactions_root_hash": block.header.transactions_root_hash,
                ":receipts_root_hash": block.header.receipts_root_hash,
                ":timestamp": SystemTimeSqlable(block.header.timestamp),
                ":gas_used": block.header.gas_used,
                ":gas_limit": block.header.gas_limit,
                ":agg": block.agg,
            })?;
        Ok(())
    }

    pub fn mark_block_as_canonical(&self, hash: Hash) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("UPDATE blocks SET is_canonical = TRUE WHERE block_hash = ?1")?
            .execute([hash])?;
        Ok(())
    }

    pub fn mark_block_as_non_canonical(&self, hash: Hash) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("UPDATE blocks SET is_canonical = FALSE WHERE block_hash = ?1")?
            .execute([hash])?;
        Ok(())
    }

    pub fn insert_block(&self, block: &Block) -> Result<()> {
        let db = self.pool.get()?;
        self.insert_block_with_db_tx(&db, block)
    }

    pub fn remove_block(&self, block: &Block) -> Result<()> {
        self.pool
            .get()?
            .prepare_cached("DELETE FROM blocks WHERE block_hash = ?1")?
            .execute([block.header.hash])?;
        Ok(())
    }

    /// Triggers a DB vacuum
    pub fn vacuum(&self) -> Result<()> {
        // TODO: Implement vacuuming logic, after state is pruned. Otherwise, the space recovered is not much.
        // let db = self.pool.get()?;
        // db.execute("VACUUM", [])?;
        Ok(())
    }

    /// Delete the block and its related transactions and receipts
    pub fn prune_block(&self, block: &Block, is_canonical: bool) -> Result<()> {
        let hash = block.hash();
        self.with_sqlite_tx(|db| {
            // get a list of transactions
            let txns = db
                .prepare_cached("SELECT tx_hash FROM receipts WHERE block_hash = ?1")?
                .query_map([hash], |row| row.get(0))?
                .collect::<Result<Vec<Hash>, _>>()?;

            // Delete child row, before deleting parents
            // https://github.com/Zilliqa/zq2/issues/2216#issuecomment-2812501876
            db.prepare_cached("DELETE FROM receipts WHERE block_hash = ?1")?
                .execute([hash])?;

            // Delete the block after all references are deleted
            db.prepare_cached("DELETE FROM blocks WHERE block_hash = ?1")?
                .execute([hash])?;

            // Delete all other references to this list of txns
            if is_canonical {
                for tx in txns {
                    // Deletes all other references to this txn; txn can only exist in one canonical block.
                    db.prepare_cached("DELETE FROM receipts WHERE tx_hash = ?1")?
                        .execute([tx])?;
                    // Delete the txn itself after all references are deleted
                    db.prepare_cached("DELETE FROM transactions WHERE tx_hash = ?1")?
                        .execute([tx])?;
                }
            }
            Ok(())
        })
    }

    pub fn get_blocks_by_height(&self, height: u64) -> Result<Vec<Block>> {
        let rows = self.pool.get()?
            .prepare_cached("SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks WHERE height = ?1")?
            .query_map([height], |row| Ok(Block {
                header: BlockHeader {
                    hash: row.get(0)?,
                    view: row.get(1)?,
                    number: row.get(2)?,
                    qc: row.get(3)?,
                    signature: row.get(4)?,
                    state_root_hash: row.get(5)?,
                    transactions_root_hash: row.get(6)?,
                    receipts_root_hash: row.get(7)?,
                    timestamp: row.get::<_, SystemTimeSqlable>(8)?.into(),
                    gas_used: row.get(9)?,
                    gas_limit: row.get(10)?,
                },
                agg: row.get(11)?,
                transactions: vec![],
            })
        )?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_blocks_by_height_range(&self, range: RangeInclusive<u64>) -> Result<Vec<Block>> {
        let (from, to) = (*range.start(), *range.end());
        if from > to {
            return Ok(Vec::new());
        }

        let conn = self.pool.get()?;
        let mut stmt = conn.prepare_cached(
            "SELECT
                block_hash, view, height, qc, signature,
                state_root_hash, transactions_root_hash, receipts_root_hash,
                timestamp, gas_used, gas_limit, agg
             FROM blocks
             WHERE height BETWEEN ?1 AND ?2
             ORDER BY height ASC",
        )?;

        let rows = stmt
            .query_map([from, to], |row| {
                Ok(Block {
                    header: BlockHeader {
                        hash: row.get(0)?,
                        view: row.get(1)?,
                        number: row.get(2)?,
                        qc: row.get(3)?,
                        signature: row.get(4)?,
                        state_root_hash: row.get(5)?,
                        transactions_root_hash: row.get(6)?,
                        receipts_root_hash: row.get(7)?,
                        timestamp: row.get::<_, SystemTimeSqlable>(8)?.into(),
                        gas_used: row.get(9)?,
                        gas_limit: row.get(10)?,
                    },
                    agg: row.get(11)?,
                    transactions: vec![],
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn get_transactionless_block(&self, filter: BlockFilter) -> Result<Option<Block>> {
        fn make_block(row: &Row) -> rusqlite::Result<Block> {
            Ok(Block {
                header: BlockHeader {
                    hash: row.get(0)?,
                    view: row.get(1)?,
                    number: row.get(2)?,
                    qc: row.get(3)?,
                    signature: row.get(4)?,
                    state_root_hash: row.get(5)?,
                    transactions_root_hash: row.get(6)?,
                    receipts_root_hash: row.get(7)?,
                    timestamp: row.get::<_, SystemTimeSqlable>(8)?.into(),
                    gas_used: row.get(9)?,
                    gas_limit: row.get(10)?,
                },
                agg: row.get(11)?,
                transactions: vec![],
            })
        }
        // Remember to add to `query_planner_stability_guarantee()` test below
        Ok(match filter {
            BlockFilter::Hash(hash) => {
                self.pool.get()?.prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE block_hash = ?1"
                ),)?.query_row([hash], make_block).optional()?
            }
            BlockFilter::View(view) => {
                self.pool.get()?.prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE view = ?1"
                ),)?.query_row([view], make_block).optional()?
            }
            BlockFilter::Height(height) => {
                self.pool.get()?.prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE height = ?1 AND is_canonical = TRUE"
                ),)?.query_row([height], make_block).optional()?
            }
            // Compound SQL queries below, due to - https://github.com/Zilliqa/zq2/issues/2629
            BlockFilter::MaxCanonicalByHeight => {
                self.pool.get()?.prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE is_canonical = true AND height = (SELECT MAX(height) FROM blocks WHERE is_canonical = TRUE)"
                ),)?.query_row([], make_block).optional()?
            }
            BlockFilter::MaxHeight => {
                self.pool.get()?.prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE height = (SELECT MAX(height) FROM blocks) LIMIT 1"
                ),)?.query_row([], make_block).optional()?
            }
            BlockFilter::Finalized => {
                if let Some(result) = self.pool.get()?.prepare_cached(concat!(
                    "SELECT block_hash, blocks.view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "INNER JOIN tip_info ON blocks.view = tip_info.finalized_view"
                ),)?.query_row([], make_block).optional()? {
                    Some(result)
                }else{
                    self.get_transactionless_block(BlockFilter::Height(0))?
                }
            },
            BlockFilter::HighQC => {
                if let Some(high_qc) = self.get_high_qc()?{
                    self.pool.get()?.prepare_cached(concat!(
                        "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                        "WHERE block_hash = ?1"
                    ),)?.query_row([high_qc.block_hash], make_block).optional()?
                }else {
                    self.get_transactionless_block(BlockFilter::Height(0))?
                }
            },
        })
    }

    pub fn get_block(&self, filter: BlockFilter) -> Result<Option<Block>> {
        let Some(mut block) = self.get_transactionless_block(filter)? else {
            return Ok(None);
        };
        if self.executable_blocks_height.is_some()
            && block.header.number < self.executable_blocks_height.unwrap()
        {
            debug!("fetched ZQ1 block so setting state root hash to zeros");
            block.header.state_root_hash = Hash::ZERO;
        }
        let transaction_hashes = self
            .pool
            .get()?
            .prepare_cached(
                "SELECT tx_hash FROM receipts WHERE block_hash = ?1 ORDER BY tx_index ASC",
            )?
            .query_map([block.header.hash], |row| row.get(0))?
            .collect::<Result<Vec<Hash>, _>>()?;
        block.transactions = transaction_hashes;
        Ok(Some(block))
    }

    pub fn get_block_and_receipts(&self, filter: BlockFilter) -> Result<Option<BlockAndReceipts>> {
        let Some(mut block) = self.get_transactionless_block(filter)? else {
            return Ok(None);
        };
        if self.executable_blocks_height.is_some()
            && block.header.number < self.executable_blocks_height.unwrap()
        {
            debug!("fetched ZQ1 block so setting state root hash to zeros");
            block.header.state_root_hash = Hash::ZERO;
        }

        let receipts = self.pool.get()?.prepare_cached("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1 ORDER BY tx_index ASC")?.query_map([block.header.hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?;

        let transaction_hashes = receipts.iter().map(|x| x.tx_hash).collect();
        block.transactions = transaction_hashes;

        Ok(Some(BlockAndReceipts { block, receipts }))
    }

    pub fn get_block_and_receipts_and_transactions(
        &self,
        filter: BlockFilter,
    ) -> Result<Option<BlockAndReceiptsAndTransactions>> {
        let Some(mut block) = self.get_transactionless_block(filter)? else {
            return Ok(None);
        };
        if self.executable_blocks_height.is_some()
            && block.header.number < self.executable_blocks_height.unwrap()
        {
            debug!("fetched ZQ1 block so setting state root hash to zeros");
            block.header.state_root_hash = Hash::ZERO;
        }

        // retrieve the receipts, in-order
        let receipts = self.get_transaction_receipts_in_block(&block.header.hash)?;
        let receipt_hashes = receipts.iter().map(|r| r.tx_hash).collect::<Vec<Hash>>();

        // retrieve the set of transactions, out-of-order
        let mut tx_by_hash: HashMap<Hash, SignedTransaction> =
            HashMap::with_capacity(receipt_hashes.len());
        let placeholders = std::iter::repeat_n("?", receipt_hashes.len())
            .collect::<Vec<_>>()
            .join(",");
        self.pool
            .get()?
            .prepare(&format!(
                r#"SELECT data, tx_hash FROM transactions WHERE tx_hash IN ({placeholders})"#
            ))?
            .query_map(rusqlite::params_from_iter(receipt_hashes.iter()), |row| {
                let txn: SignedTransaction = row.get(0)?;
                let hash: Hash = row.get(1)?;
                Ok((txn, hash))
            })?
            .flatten()
            .for_each(|(txn, hash)| {
                tx_by_hash.insert(hash, txn.clone());
            });

        // construct the set of transactions, in-order
        let transactions: Vec<VerifiedTransaction> = receipts
            .iter()
            .map(|r| {
                let txn = tx_by_hash.remove(&r.tx_hash).ok_or_else(|| {
                    anyhow::anyhow!("missing transaction for receipt hash {:?}", r.tx_hash)
                })?;
                txn.verify_bypass(r.tx_hash)
            })
            .collect::<Result<_, _>>()?;

        block.transactions = receipt_hashes;

        assert_eq!(receipts.len(), transactions.len());

        Ok(Some(BlockAndReceiptsAndTransactions {
            block,
            receipts,
            transactions,
        }))
    }

    pub fn contains_block(&self, block_hash: &Hash) -> Result<bool> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT 1 FROM blocks WHERE block_hash = ?1")?
            .query_row([block_hash], |row| row.get::<_, i64>(0))
            .optional()?
            .is_some())
    }

    pub fn contains_canonical_block(&self, block_hash: &Hash) -> Result<bool> {
        Ok(self
            .pool
            .get()?
            .prepare_cached("SELECT 1 FROM blocks WHERE is_canonical = TRUE AND block_hash = ?1")?
            .query_row([block_hash], |row| row.get::<_, i64>(0))
            .optional()?
            .is_some())
    }

    fn make_receipt(row: &Row) -> rusqlite::Result<TransactionReceipt> {
        Ok(TransactionReceipt {
            tx_hash: row.get(0)?,
            block_hash: row.get(1)?,
            index: row.get(2)?,
            success: row.get(3)?,
            gas_used: row.get(4)?,
            cumulative_gas_used: row.get(5)?,
            contract_address: row.get::<_, Option<AddressSqlable>>(6)?.map(|a| a.into()),
            logs: row.get::<_, VecLogSqlable>(7)?.into(),
            transitions: row.get::<_, VecScillaTransitionSqlable>(8)?.into(),
            accepted: row.get(9)?,
            errors: row.get::<_, MapScillaErrorSqlable>(10)?.into(),
            exceptions: row.get::<_, VecScillaExceptionSqlable>(11)?.into(),
        })
    }

    pub fn insert_transaction_receipt_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        receipt: TransactionReceipt,
    ) -> Result<()> {
        sqlite_tx.prepare_cached("INSERT OR IGNORE INTO receipts
                (tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions)
            VALUES (:tx_hash, :block_hash, :tx_index, :success, :gas_used, :cumulative_gas_used, :contract_address, :logs, :transitions, :accepted, :errors, :exceptions)",)?.execute(
            named_params! {
                ":tx_hash": receipt.tx_hash,
                ":block_hash": receipt.block_hash,
                ":tx_index": receipt.index,
                ":success": receipt.success,
                ":gas_used": receipt.gas_used,
                ":cumulative_gas_used": receipt.cumulative_gas_used,
                ":contract_address": receipt.contract_address.map(AddressSqlable),
                ":logs": VecLogSqlable(receipt.logs),
                ":transitions": VecScillaTransitionSqlable(receipt.transitions),
                ":accepted": receipt.accepted,
                ":errors": MapScillaErrorSqlable(receipt.errors),
                ":exceptions": VecScillaExceptionSqlable(receipt.exceptions),
            })?;

        Ok(())
    }

    pub fn insert_transaction_receipt(&self, receipt: TransactionReceipt) -> Result<()> {
        let db = self.pool.get()?;
        self.insert_transaction_receipt_with_db_tx(&db, receipt)
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: &Hash,
    ) -> Result<Vec<TransactionReceipt>> {
        Ok(self.pool.get()?.prepare_cached("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1 ORDER BY tx_index")?.query_map([block_hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_transaction_receipts_in_blocks(
        &self,
        mut blocks: Vec<Block>,
    ) -> Result<Vec<(Block, Vec<TransactionReceipt>)>> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }
        let hashes = blocks.iter().map(|b| b.header.hash).collect::<Vec<Hash>>();

        let mut by_hash: HashMap<Hash, Vec<TransactionReceipt>> =
            HashMap::with_capacity(hashes.len());

        let conn = self.pool.get()?;
        for chunk in hashes.chunks(MAX_KEYS_IN_SINGLE_QUERY) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");

            let sql = format!(
                r#"
                SELECT
                tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used,
                contract_address, logs, transitions, accepted, errors, exceptions
                FROM receipts
                WHERE block_hash IN ({placeholders})
            "#
            );

            // dynamic placeholders -> prepare(), not prepare_cached()
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                Self::make_receipt(row)
            })?;

            for row in rows {
                let r = row?;
                by_hash.entry(r.block_hash).or_default().push(r);
            }
        }

        // Sort the input blocks by height
        blocks.sort_by_key(|b| b.header.number);

        // Assemble output in height order
        let mut blocks_with_hashes = Vec::with_capacity(blocks.len());
        for block in blocks {
            let mut receipts = by_hash.remove(&block.header.hash).unwrap_or_default();
            receipts.sort_unstable_by_key(|r| r.index);
            blocks_with_hashes.push((block, receipts));
        }
        Ok(blocks_with_hashes)
    }

    pub fn get_total_transaction_count(&self) -> Result<usize> {
        Ok(0)
    }
}

/// Promote the state trie.
///
/// Promotes the tag of each node to the given view. This process may take a while to complete.
/// The `tag_lock` ensures that only one snapshot is in progress at a time.
/// The previous state trie will be eventually pruned during compaction.
pub fn promote_trie(storage: TrieStorage, root_hash: B256, block_number: u64) -> Result<()> {
    let trie = Arc::new(storage);
    let tag_lock = trie.tag_lock.lock();
    tracing::info!(%root_hash, block_number, "Promote: start");
    TrieStorage::promote(trie.clone(), root_hash)?;
    tracing::info!(%root_hash, block_number, "Promote: done");
    let old_floor = trie.set_tag_floor(*tag_lock)?;
    if old_floor != 0 {
        trie.drop_sql_state_trie()?; // delete SQL database
    }
    Ok(()) // not fatal, it can be retried later.
}

pub fn get_checkpoint_filename<P: AsRef<Path> + Debug>(
    output_dir: P,
    block: &Block,
) -> Result<PathBuf> {
    Ok(output_dir.as_ref().join(block.number().to_string()))
}

/// Build checkpoint and write to disk.
/// A description of the data written can be found in docs/checkpoints
pub fn checkpoint_block_with_state<P: AsRef<Path> + Debug>(
    block: &Block,
    transactions: &Vec<SignedTransaction>,
    parent: &Block,
    state_trie_storage: TrieStorage,
    shard_id: u64,
    view_history: ViewHistory,
    output_dir: P,
) -> Result<()> {
    fs::create_dir_all(&output_dir)?;
    let trie_storage = Arc::new(state_trie_storage);
    let path = get_checkpoint_filename(output_dir, block)?;
    crate::checkpoint::save_ckpt(
        path.with_extension("part").as_path(),
        trie_storage,
        block,
        transactions,
        parent,
        shard_id,
        view_history,
    )?;

    // rename file when done
    Ok(fs::rename(
        path.with_extension("part").as_path(),
        path.as_path(),
    )?)
}

#[cfg(test)]
mod tests {
    use alloy::consensus::EMPTY_ROOT_HASH;
    use rand::{
        Rng, SeedableRng,
        distributions::{Distribution, Uniform},
    };
    use rand_chacha::ChaCha8Rng;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        crypto::SecretKey,
        state::{Account, State},
    };

    #[test]
    fn query_planner_stability_guarantee() {
        let base_path = tempdir().unwrap();
        let base_path = base_path.path();
        let db = Db::new(Some(base_path), 0, None, DbConfig::default()).unwrap();

        let sql = db.pool.get().unwrap();

        // Check that EXPLAIN works
        // sqlite> EXPLAIN QUERY PLAN SELECT min(height), max(height) FROM blocks;
        //         3|0|0|SCAN blocks USING COVERING INDEX idx_blocks_height
        let qp = sql
            .query_row_and_then(
                "EXPLAIN QUERY PLAN SELECT min(height), max(height) FROM blocks;",
                [],
                |r| r.get::<_, String>(3),
            )
            .unwrap();
        assert_eq!(
            qp,
            "SCAN blocks USING COVERING INDEX idx_blocks_height".to_string()
        );

        // List of queries to check - it doesn't have to be verbatim, just use the same set of indices i.e. validating assumptions
        let queries = vec![
            "SELECT MIN(height) FROM blocks",
            "SELECT MAX(height) FROM blocks",
            "SELECT block_hash FROM blocks WHERE view = ?1",
            "SELECT MAX(height) FROM blocks WHERE is_canonical = 1",
            "SELECT tx_hash FROM touched_address_index JOIN receipts USING (tx_hash) JOIN blocks USING (block_hash) WHERE address = ?1 ORDER BY blocks.height, receipts.tx_index",
            "SELECT data FROM transactions WHERE tx_hash = ?1",
            "SELECT r.block_hash FROM receipts r INNER JOIN blocks b ON r.block_hash = b.block_hash WHERE r.tx_hash = ?1 AND b.is_canonical = TRUE",
            "SELECT tx_hash FROM receipts WHERE block_hash = ?1",
            "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks WHERE height = ?1",
            "SELECT 1 FROM blocks WHERE is_canonical = TRUE AND block_hash = ?1",
            "SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE tx_hash = ?1",
            "SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1 ORDER BY tx_index",
            "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks WHERE is_canonical = true AND height = (SELECT MAX(height) FROM blocks WHERE is_canonical = TRUE)",
            "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks WHERE height = (SELECT MAX(height) FROM blocks) LIMIT 1",
            "SELECT data, transactions.tx_hash FROM transactions INNER JOIN receipts ON transactions.tx_hash = receipts.tx_hash WHERE receipts.block_hash = ?1 ORDER BY receipts.tx_index ASC",
            "SELECT state_root_hash FROM blocks WHERE is_canonical = TRUE AND height = ?1",
            "SELECT view FROM view_history WHERE leader IS NULL LIMIT 1",
            "UPDATE view_history SET view = ?1 WHERE leader IS NULL",
            "SELECT view FROM ckpt_view_history WHERE leader IS NULL LIMIT 1",
            "UPDATE ckpt_view_history SET view = ?1 WHERE leader IS NULL",
            // TODO: Add more queries
        ];

        for query in queries {
            let explain = format!("EXPLAIN QUERY PLAN {query};");
            let plans = sql
                .prepare(&explain)
                .unwrap()
                .raw_query()
                .mapped(|r| r.get::<_, String>(3))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(!plans.is_empty(), "{explain}");
            for plan in plans {
                assert!(!plan.is_empty(), "{explain}");
                // Check for any SCANs
                if plan.starts_with("SCAN") {
                    panic!("SQL regression {query} => {plan}");
                }
            }
        }
    }

    #[test]
    fn checkpoint_export_import() {
        let base_path = tempdir().unwrap();
        let base_path = base_path.path();
        let db = Db::new(Some(base_path), 0, None, DbConfig::default()).unwrap();

        // Seed db with data
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let distribution = Uniform::new(1, 50);
        let mut root_trie = EthTrie::new(Arc::new(db.state_trie().unwrap()));
        for _ in 0..100 {
            let account_address: [u8; 20] = rng.r#gen();
            let mut account_trie = EthTrie::new(Arc::new(db.state_trie().unwrap()));
            let mut key = Vec::<u8>::with_capacity(50);
            let mut value = Vec::<u8>::with_capacity(50);
            for _ in 0..distribution.sample(&mut rng) {
                for _ in 0..distribution.sample(&mut rng) {
                    key.push(rng.r#gen());
                }
                for _ in 0..distribution.sample(&mut rng) {
                    value.push(rng.r#gen());
                }
                account_trie.insert(&key, &value).unwrap();
            }
            let account = Account {
                storage_root: account_trie.root_hash().unwrap(),
                ..Default::default()
            };
            root_trie
                .insert(
                    &State::account_key(account_address.into()).0,
                    &bincode::serde::encode_to_vec(&account, bincode::config::legacy()).unwrap(),
                )
                .unwrap();
        }

        let state_hash = root_trie.root_hash().unwrap();
        let checkpoint_parent = Block::genesis(state_hash.into());
        // bit of a hack to generate a successor block
        let mut qc2 = QuorumCertificate::genesis();
        qc2.block_hash = checkpoint_parent.hash();
        qc2.view = 1;
        let checkpoint_block = Block::from_qc(
            SecretKey::new().unwrap(),
            1,
            1,
            qc2,
            None,
            state_hash.into(),
            EMPTY_ROOT_HASH.into(),
            EMPTY_ROOT_HASH.into(),
            vec![],
            SystemTime::now(),
            EvmGas(0),
            EvmGas(0),
        );

        let view_history: ViewHistory = ViewHistory::default();

        let checkpoint_path = db.get_checkpoint_dir().unwrap().unwrap();

        const SHARD_ID: u64 = 5000;

        let checkpoint_transactions = vec![];
        checkpoint_block_with_state(
            &checkpoint_block,
            &checkpoint_transactions,
            &checkpoint_parent,
            db.state_trie().unwrap(),
            SHARD_ID,
            view_history,
            &checkpoint_path,
        )
        .unwrap();

        // now load the checkpoint
        let (block, transactions, parent, view_history) = db
            .load_trusted_checkpoint(
                checkpoint_path.join(checkpoint_block.number().to_string()),
                &checkpoint_block.hash(),
                SHARD_ID,
            )
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint_block, block);
        assert_eq!(checkpoint_transactions, transactions);
        assert_eq!(checkpoint_parent, parent);
        if let Some((view, _)) = view_history.missed_views.front() {
            assert!(*view >= view_history.min_view);
        } else {
            assert_eq!(0, view_history.min_view);
        }

        // load the checkpoint again, to ensure idempotency
        let (block, transactions, parent, view_history) = db
            .load_trusted_checkpoint(
                checkpoint_path.join(checkpoint_block.number().to_string()),
                &checkpoint_block.hash(),
                SHARD_ID,
            )
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint_block, block);
        assert_eq!(checkpoint_transactions, transactions);
        assert_eq!(checkpoint_parent, parent);
        if let Some((view, _)) = view_history.missed_views.front() {
            assert!(*view >= view_history.min_view);
        } else {
            assert_eq!(0, view_history.min_view);
        }

        // Always return Some, even if checkpointed block already executed
        db.insert_block(&checkpoint_block).unwrap();
        let result = db
            .load_trusted_checkpoint(
                checkpoint_path.join(checkpoint_block.number().to_string()),
                &checkpoint_block.hash(),
                SHARD_ID,
            )
            .unwrap();
        assert!(result.is_some());
    }
}
