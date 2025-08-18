use std::{
    collections::BTreeMap,
    fmt::Debug,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::primitives::Address;
use anyhow::{Context, Result, anyhow};
#[allow(unused_imports)]
use eth_trie::{DB, EthTrie, MemoryDB, Trie};
// use lru_mem::LruCache;
use lz4::{Decoder, EncoderBuilder};
use rocksdb::{DBWithThreadMode, SingleThreaded, WriteBatchWithTransaction};
use rusqlite::{
    Connection, OptionalExtension, Row, ToSql, named_params,
    types::{FromSql, FromSqlError, ToSqlOutput},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    crypto::{BlsSignature, Hash},
    exec::{ScillaError, ScillaException, ScillaTransition},
    message::{AggregateQc, Block, BlockHeader, QuorumCertificate},
    state::Account,
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, TransactionReceipt, VerifiedTransaction},
};

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
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
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

/// Version string that is written to disk along with the persisted database. This should be bumped whenever we make a
/// backwards incompatible change to our database format. This should be done rarely, since it forces all node
/// operators to re-sync.
const CURRENT_DB_VERSION: &str = "1";

#[derive(Debug)]
pub struct Db {
    db: Arc<Mutex<Connection>>,
    rdb: Arc<rocksdb::DB>,
    // state_cache: Arc<Mutex<LruCache<Vec<u8>, Vec<u8>>>>,
    path: Option<Box<Path>>,
    /// The block height at which ZQ2 blocks begin.
    /// This value should be required only for proto networks to distinguise between ZQ1 and ZQ2 blocks.
    executable_blocks_height: Option<u64>,
}

impl Db {
    pub fn new<P>(
        data_dir: Option<P>,
        shard_id: u64,
        _state_cache_size: usize,
        executable_blocks_height: Option<u64>,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let (connection, path) = match data_dir {
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
                (
                    Connection::open(&db_path)
                        .context(format!("Cannot access sqlite db {0:?}", &db_path))?,
                    Some(path.into_boxed_path()),
                )
            }
            None => (Connection::open_in_memory()?, None),
        };

        // SQLite performance tweaks

        // large page_size is more compact/efficient
        connection.pragma_update(None, "page_size", 1 << 15)?;
        let page_size: i32 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;

        // reduced non-critical fsync() calls
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        let synchronous: i8 = connection.pragma_query_value(None, "synchronous", |r| r.get(0))?;

        // store temporary tables/indices in-memory
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        let temp_store: i8 = connection.pragma_query_value(None, "temp_store", |r| r.get(0))?;

        // general read/write performance improvement
        let journal_mode: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;

        // retain journal size of 32MB - based on observations
        let journal_size_limit: i32 =
            connection
                .pragma_update_and_check(None, "journal_size_limit", 1 << 25, |r| r.get(0))?;

        // cache 1-days data (256MB) in-memory
        connection.pragma_update(None, "cache_size", (1 << 28) / page_size)?;
        let cache_size: i32 = connection.pragma_query_value(None, "cache_size", |r| r.get(0))?;

        // increase size of prepared cache
        connection.set_prepared_statement_cache_capacity(128); // default is 16, which is small

        // enable QPSG - https://github.com/Zilliqa/zq2/issues/2870
        if !connection.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG,
            true,
        )? {
            tracing::warn!("QPSG disabled");
        }

        tracing::info!(
            ?journal_mode,
            ?journal_size_limit,
            ?synchronous,
            ?temp_store,
            ?page_size,
            ?cache_size,
            "PRAGMA"
        );

        // Add tracing - logs SQL statements
        connection.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_PROFILE,
            Some(|profile_event| {
                if let rusqlite::trace::TraceEvent::Profile(statement, duration) = profile_event {
                    let statement_txt = statement.expanded_sql();
                    let duration_secs = duration.as_secs();
                    // tracing::trace!(duration_secs, statement_txt, "sql executed");
                    if duration_secs > 5 {
                        tracing::warn!(duration_secs, statement_txt, "sql execution took > 5s");
                    }
                }
            }),
        );

        Self::ensure_schema(&connection)?;

        // RocksDB
        let rdb_path = if let Some(s) = path.clone() {
            s.join("state.db")
        } else {
            tempfile::tempdir().unwrap().path().join("state.db")
        };
        let rdb = DBWithThreadMode::<SingleThreaded>::open_default(rdb_path)?;

        tracing::info!("State database: {}", rdb.path().display());
        Ok(Db {
            db: Arc::new(Mutex::new(connection)),
            // state_cache: Arc::new(Mutex::new(LruCache::new(state_cache_size))),
            rdb: Arc::new(rdb),
            path,
            executable_blocks_height,
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

        Ok(())
    }

    pub fn get_value_from_aux_table(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT value FROM aux_table WHERE key = ?1")?
            .query_row([key], |row| row.get(0))
            .optional()?)
    }

    pub fn insert_value_to_aux_table(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.db
            .lock()
            .unwrap()
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
        let db = self.db.lock().unwrap();
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
    pub fn load_trusted_checkpoint<P: AsRef<Path>>(
        &self,
        path: P,
        hash: &Hash,
        our_shard_id: u64,
    ) -> Result<Option<(Block, Vec<SignedTransaction>, Block)>> {
        tracing::info!(%hash, "Checkpoint");
        // Decompress the file for processing
        let input_file = File::open(path.as_ref())?;
        let buf_reader: BufReader<File> = BufReader::with_capacity(128 * 1024 * 1024, input_file);
        let mut reader = Decoder::new(buf_reader)?;
        let Some((block, transactions, parent)) =
            crate::checkpoint::get_checkpoint_block(&mut reader, hash, our_shard_id)?
        else {
            return Err(anyhow!("Invalid checkpoint file"));
        };

        let trie_storage = Arc::new(self.state_trie()?);
        let state_trie = EthTrie::new(trie_storage.clone());

        // INITIAL CHECKPOINT LOAD
        // If no state trie exists and no blocks are known, then we are in a fresh database.
        // We can safely load the checkpoint.
        if state_trie.iter().next().is_none()
            && self.get_highest_canonical_block_number()?.is_none()
        {
            tracing::info!(state = %parent.state_root_hash(), "Restoring checkpoint");
            crate::checkpoint::load_state_trie(&mut reader, trie_storage, &parent)?;

            let parent_ref: &Block = &parent; // for moving into the closure
            self.with_sqlite_tx(move |tx| {
                self.insert_block_with_db_tx(tx, parent_ref)?;
                self.set_finalized_view_with_db_tx(tx, parent_ref.view())?;
                self.set_high_qc_with_db_tx(tx, block.header.qc)?;
                self.set_view_with_db_tx(tx, parent_ref.view() + 1, false)?;
                Ok(())
            })?;

            return Ok(Some((block, transactions, parent)));
        }

        // OTHER SANITY CHECKS
        // Check if the parent block is sane
        let Some(ckpt_parent) = self.get_block(parent.hash().into())? else {
            return Err(anyhow!("Invalid checkpoint attempt"));
        };
        if ckpt_parent.parent_hash() != parent.parent_hash() {
            return Err(anyhow!("Critical checkpoint error"));
        };
        if trie_storage
            .get(ckpt_parent.state_root_hash().as_bytes())?
            .is_none()
        {
            // If the corresponding state is missing, load it from the checkpoint
            tracing::info!(state = %ckpt_parent.state_root_hash(), "Syncing checkpoint");
            crate::checkpoint::load_state_trie(&mut reader, trie_storage, &ckpt_parent)?;
        }
        Ok(Some((block, transactions, ckpt_parent)))
    }

    pub fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage {
            db: self.db.clone(),
            // _cache: self.state_cache.clone(),
            rdb: self.rdb.clone(),
        })
    }

    pub fn with_sqlite_tx(&self, operations: impl FnOnce(&Connection) -> Result<()>) -> Result<()> {
        let mut sqlite_tx = self.db.lock().unwrap();
        let sqlite_tx = sqlite_tx.transaction()?;
        operations(&sqlite_tx)?;
        Ok(sqlite_tx.commit()?)
    }

    pub fn get_block_hash_by_view(&self, view: u64) -> Result<Option<Hash>> {
        Ok(self
            .db
            .lock()
            .unwrap()
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
        self.set_finalized_view_with_db_tx(&self.db.lock().unwrap(), view)
    }

    pub fn get_finalized_view(&self) -> Result<Option<u64>> {
        Ok(self
            .db
            .lock()
            .unwrap()
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
        self.set_view_with_db_tx(&self.db.lock().unwrap(), view, voted)
    }

    pub fn get_view(&self) -> Result<Option<u64>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT view FROM tip_info")?
            .query_row((), |row| row.get(0))
            .optional()
            .unwrap_or(None))
    }

    pub fn get_voted_in_view(&self) -> Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT voted_in_view FROM tip_info")?
            .query_row((), |row| row.get(0))?)
    }

    pub fn get_highest_canonical_block_number(&self) -> Result<Option<u64>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT MAX(height) FROM blocks WHERE is_canonical = 1")?
            .query_row((), |row| {
                row.get(0).map_err(|e| {
                    // workaround where MAX(height) returns NULL if there are no blocks, instead of a NoRows error
                    if let rusqlite::Error::InvalidColumnType(_, _, typ) = e {
                        if typ == rusqlite::types::Type::Null {
                            return rusqlite::Error::QueryReturnedNoRows;
                        }
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
        self.set_high_qc_with_db_tx(&self.db.lock().unwrap(), high_qc)
    }

    pub fn get_high_qc(&self) -> Result<Option<QuorumCertificate>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT high_qc FROM tip_info")?
            .query_row((), |row| row.get(0))
            .optional()?
            .flatten())
    }

    pub fn get_high_qc_updated_at(&self) -> Result<Option<SystemTime>> {
        Ok(self
            .db
            .lock()
            .unwrap()
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
        self.add_touched_address_with_db_tx(&self.db.lock().unwrap(), address, txn_hash)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        // TODO: this is only ever used in one API, so keep an eye on performance - in case e.g.
        // the index table might need to be denormalised to simplify this lookup
        Ok(self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT tx_hash FROM touched_address_index JOIN receipts USING (tx_hash) JOIN blocks USING (block_hash) WHERE address = ?1 ORDER BY blocks.height, receipts.tx_index")?
            .query_map([AddressSqlable(address)], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_transaction(&self, txn_hash: &Hash) -> Result<Option<VerifiedTransaction>> {
        Ok(
            match self
                .db
                .lock()
                .unwrap()
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

    pub fn contains_transaction(&self, hash: &Hash) -> Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
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
        self.insert_transaction_with_db_tx(&self.db.lock().unwrap(), hash, tx)
    }

    pub fn get_block_hash_reverse_index(&self, tx_hash: &Hash) -> Result<Option<Hash>> {
        Ok(self
            .db
            .lock()
            .unwrap()
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
        self.db
            .lock()
            .unwrap()
            .prepare_cached("UPDATE blocks SET is_canonical = TRUE WHERE block_hash = ?1")?
            .execute([hash])?;
        Ok(())
    }

    pub fn mark_block_as_non_canonical(&self, hash: Hash) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .prepare_cached("UPDATE blocks SET is_canonical = FALSE WHERE block_hash = ?1")?
            .execute([hash])?;
        Ok(())
    }

    pub fn insert_block(&self, block: &Block) -> Result<()> {
        self.insert_block_with_db_tx(&self.db.lock().unwrap(), block)
    }

    pub fn remove_block(&self, block: &Block) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .prepare_cached("DELETE FROM blocks WHERE block_hash = ?1")?
            .execute([block.header.hash])?;
        Ok(())
    }

    /// Triggers a DB vacuum
    pub fn vacuum(&self) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("VACUUM", [])?;
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
        let rows = self
            .db
            .lock()
            .unwrap()
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
                self.db.lock().unwrap().prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE block_hash = ?1"
                ),)?.query_row([hash], make_block).optional()?
            }
            BlockFilter::View(view) => {
                self.db.lock().unwrap().prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE view = ?1"
                ),)?.query_row([view], make_block).optional()?
            }
            BlockFilter::Height(height) => {
                self.db.lock().unwrap().prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE height = ?1 AND is_canonical = TRUE"
                ),)?.query_row([height], make_block).optional()?
            }
            // Compound SQL queries below, due to - https://github.com/Zilliqa/zq2/issues/2629
            BlockFilter::MaxCanonicalByHeight => {
                self.db.lock().unwrap().prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE is_canonical = true AND height = (SELECT MAX(height) FROM blocks WHERE is_canonical = TRUE)"
                ),)?.query_row([], make_block).optional()?
            }
            BlockFilter::MaxHeight => {
                self.db.lock().unwrap().prepare_cached(concat!(
                    "SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks ",
                    "WHERE height = (SELECT MAX(height) FROM blocks) LIMIT 1"
                ),)?.query_row([], make_block).optional()?
            }
            BlockFilter::Finalized => {
                if let Some(result) = self.db.lock().unwrap().prepare_cached(concat!(
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
                    self.db.lock().unwrap().prepare_cached(concat!(
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
            .db
            .lock()
            .unwrap()
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

        let receipts = self.db.lock().unwrap().prepare_cached("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1 ORDER BY tx_index ASC")?.query_map([block.header.hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?;

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

        let receipts = self.db.lock().unwrap().prepare_cached("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1 ORDER BY tx_index ASC")?.query_map([block.header.hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?;

        let transactions: Vec<VerifiedTransaction> = self
            .db
            .lock()
            .unwrap()
            .prepare_cached(
                "SELECT data, transactions.tx_hash FROM transactions INNER JOIN receipts ON transactions.tx_hash = receipts.tx_hash WHERE receipts.block_hash = ?1 ORDER BY receipts.tx_index ASC",
            )?
            .query_map([block.header.hash], |row| {
                let txn: SignedTransaction = row.get(0)?;
                let hash: Hash = row.get(1)?;
                Ok((txn, hash))
            })?
            .map(|x| {
                let (txn, hash) = x.unwrap();
                txn.verify_bypass(hash)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let transaction_hashes = receipts.iter().map(|x| x.tx_hash).collect();
        block.transactions = transaction_hashes;

        assert_eq!(receipts.len(), transactions.len());

        Ok(Some(BlockAndReceiptsAndTransactions {
            block,
            receipts,
            transactions,
        }))
    }

    pub fn contains_block(&self, block_hash: &Hash) -> Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT 1 FROM blocks WHERE block_hash = ?1")?
            .query_row([block_hash], |row| row.get::<_, i64>(0))
            .optional()?
            .is_some())
    }

    pub fn contains_canonical_block(&self, block_hash: &Hash) -> Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
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
        self.insert_transaction_receipt_with_db_tx(&self.db.lock().unwrap(), receipt)
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: &Hash,
    ) -> Result<Vec<TransactionReceipt>> {
        Ok(self.db.lock().unwrap().prepare_cached("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1 ORDER BY tx_index")?.query_map([block_hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_total_transaction_count(&self) -> Result<usize> {
        Ok(0)
    }
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
    output_dir: P,
) -> Result<()> {
    const VERSION: u32 = 3;

    fs::create_dir_all(&output_dir)?;

    let state_trie_storage = Arc::new(state_trie_storage);
    // quick sanity check
    if block.parent_hash() != parent.hash() {
        return Err(anyhow!(
            "Parent block parameter must match the checkpoint block's parent hash"
        ));
    }

    // Note: we ignore any existing file
    let output_filename = get_checkpoint_filename(output_dir, block)?;
    let temp_filename = output_filename.with_extension("part");
    let outfile_temp = File::create_new(&temp_filename)?;
    let mut writer = BufWriter::with_capacity(128 * 1024 * 1024, outfile_temp); // 128 MiB chunks

    // write the header:
    writer.write_all(&crate::checkpoint::CHECKPOINT_HEADER_BYTES)?; // file identifier
    writer.write_all(&VERSION.to_be_bytes())?; // 4 BE bytes for version
    writer.write_all(&shard_id.to_be_bytes())?; // 8 BE bytes for shard ID
    writer.write_all(b"\n")?;

    // write the block...
    let block_ser = &bincode::serde::encode_to_vec(block, bincode::config::legacy())?;
    writer.write_all(&u64::try_from(block_ser.len())?.to_be_bytes())?;
    writer.write_all(block_ser)?;

    // write transactions
    let transactions_ser = &bincode::serde::encode_to_vec(transactions, bincode::config::legacy())?;
    writer.write_all(&u64::try_from(transactions_ser.len())?.to_be_bytes())?;
    writer.write_all(transactions_ser)?;

    // and its parent, to keep the qc tracked
    let parent_ser = &bincode::serde::encode_to_vec(parent, bincode::config::legacy())?;
    writer.write_all(&u64::try_from(parent_ser.len())?.to_be_bytes())?;
    writer.write_all(parent_ser)?;

    // then write state for each account
    let accounts =
        EthTrie::new(state_trie_storage.clone()).at_root(parent.state_root_hash().into());
    let account_storage = EthTrie::new(state_trie_storage);
    let mut account_key_buf = [0u8; 32]; // save a few allocations, since account keys are fixed length

    for (key, serialised_account) in accounts.iter() {
        // export the account itself
        account_key_buf.copy_from_slice(&key);
        writer.write_all(&account_key_buf)?;

        writer.write_all(&u64::try_from(serialised_account.len())?.to_be_bytes())?;
        writer.write_all(&serialised_account)?;

        // now write the entire account storage map
        let account_storage = account_storage.at_root(
            bincode::serde::decode_from_slice::<Account, _>(
                &serialised_account,
                bincode::config::legacy(),
            )?
            .0
            .storage_root,
        );
        let mut account_storage_buf = vec![];
        for (storage_key, storage_val) in account_storage.iter() {
            account_storage_buf.extend_from_slice(&u64::try_from(storage_key.len())?.to_be_bytes());
            account_storage_buf.extend_from_slice(&storage_key);

            account_storage_buf.extend_from_slice(&u64::try_from(storage_val.len())?.to_be_bytes());
            account_storage_buf.extend_from_slice(&storage_val);
        }
        writer.write_all(&u64::try_from(account_storage_buf.len())?.to_be_bytes())?;
        writer.write_all(&account_storage_buf)?;
    }
    writer.flush()?;

    // lz4 compress and write to output
    compress_file(&temp_filename, &output_filename)?;

    fs::remove_file(temp_filename)?;

    Ok(())
}

/// Read temp file, compress usign lz4, write into output file
fn compress_file<P: AsRef<Path> + Debug>(input_file_path: P, output_file_path: P) -> Result<()> {
    let mut reader = BufReader::new(File::open(input_file_path)?);

    let mut encoder = EncoderBuilder::new().build(File::create(output_file_path)?)?;
    let mut buffer = [0u8; 1024 * 64]; // read 64KB chunks at a time
    loop {
        let bytes_read = reader.read(&mut buffer)?; // Read a chunk of decompressed data
        if bytes_read == 0 {
            break; // End of file
        }
        encoder.write_all(&buffer[..bytes_read])?;
    }
    encoder.finish().1?;

    Ok(())
}

/// An implementor of [eth_trie::DB] which uses a [Connection] to persist data.
#[derive(Debug, Clone)]
pub struct TrieStorage {
    db: Arc<Mutex<Connection>>,
    // _cache: Arc<Mutex<LruCache<Vec<u8>, Vec<u8>>>>,
    rdb: Arc<rocksdb::DB>,
}

impl TrieStorage {
    // copy state_trie data from rocksdb to sqlite
    pub fn revert_state(&self) -> Result<(), rocksdb::Error> {
        self.rdb.cancel_all_background_work(true);
        let db = self.db.lock().unwrap();
        let iter = self.rdb.iterator(rocksdb::IteratorMode::Start);
        for node in iter {
            let (key, value) = node?;
            db.prepare_cached("INSERT OR REPLACE INTO state_trie (key, value) VALUES (?1, ?2)")
                .unwrap()
                .execute(rusqlite::params![key, value])
                .unwrap();
        }
        Ok(())
    }

    // migrate state_trie from sqlite to rocksdb, by simply iterating over every node (forced read)
    pub fn migrate_state(&self, root_hash: Hash) -> Result<()> {
        let trie_store = Arc::new(Self {
            db: self.db.clone(),
            rdb: self.rdb.clone(),
        });
        let state_trie = EthTrie::new(trie_store.clone()).at_root(root_hash.into());
        for (k, v) in state_trie.iter() {
            // for each account, load its storage trie
            let account_state = bincode::serde::decode_from_slice::<Account, _>(
                v.as_slice(),
                bincode::config::legacy(),
            )?
            .0
            .storage_root;
            let account_trie = EthTrie::new(trie_store.clone()).at_root(account_state.0.into());
            // force read account_storage trie
            tracing::trace!(
                "Migrate {} ({})",
                hex::encode(&k),
                account_trie.iter().count()
            );
        }
        Ok(())
    }

    pub fn write_batch(
        &self,
        keys: Vec<Vec<u8>>,
        values: Vec<Vec<u8>>,
    ) -> Result<(), rocksdb::Error> {
        if keys.is_empty() {
            return Ok(());
        }

        assert_eq!(keys.len(), values.len());

        let mut batch = WriteBatchWithTransaction::<false>::default();
        for (key, value) in keys.into_iter().zip(values.into_iter()) {
            batch.put(key.as_slice(), value.as_slice());
        }
        self.rdb.write(batch)?;

        Ok(())
    }
}

impl eth_trie::DB for TrieStorage {
    type Error = eth_trie::TrieError;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        // read value from RocksDB with JIT migration
        if let Some(value) = self
            .rdb
            .get(key)
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?
        {
            tracing::trace!("HIT {}", hex::encode(key));
            return Ok(Some(value));
        }

        let value: Option<Vec<u8>> = self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT value FROM state_trie WHERE key = ?1")
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?
            .query_row([key], |row| row.get(0))
            .optional()
            .map_err(|e| eth_trie::TrieError::DB(e.to_string()))?;

        // JIT migration
        if let Some(value) = value {
            tracing::trace!("MISS {}", hex::encode(key));
            self.rdb
                .put(key, value.as_slice())
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
    use alloy::consensus::EMPTY_ROOT_HASH;
    use rand::{
        Rng, SeedableRng,
        distributions::{Distribution, Uniform},
    };
    use rand_chacha::ChaCha8Rng;
    use tempfile::tempdir;

    use super::*;
    use crate::{crypto::SecretKey, state::State};

    #[test]
    fn bincode1_bincode2_compatibility() {
        #[derive(Serialize)]
        struct Testdata {
            a: QuorumCertificate,
            b: BlsSignature,
            c: VecLogSqlable,
            d: MapScillaErrorSqlable,
        }

        let data = Testdata {
            a: QuorumCertificate::genesis(),
            b: BlsSignature::identity(),
            c: VecLogSqlable(Vec::new()),
            d: MapScillaErrorSqlable(BTreeMap::new()),
        };

        let bincode1 = bincode_v1::serialize(&data).unwrap(); // v1.3.3
        let bincode2 = bincode::serde::encode_to_vec(&data, bincode::config::legacy()).unwrap(); // v2.0 compatibility
        let bincode0 = bincode::serde::encode_to_vec(&data, bincode::config::standard()).unwrap(); // v2.0 new standard
        assert_ne!(bincode1, bincode0);
        assert_eq!(bincode1, bincode2);
    }

    #[test]
    fn query_planner_stability_guarantee() {
        let base_path = tempdir().unwrap();
        let base_path = base_path.path();
        let db = Db::new(Some(base_path), 0, 1024, None).unwrap();

        let sql = db.db.lock().unwrap();

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
            // "SELECT block_hash, blocks.view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks INNER JOIN tip_info ON blocks.view = tip_info.finalized_view", // tip_info is one record so scanning is fine
            "SELECT data, transactions.tx_hash FROM transactions INNER JOIN receipts ON transactions.tx_hash = receipts.tx_hash WHERE receipts.block_hash = ?1 ORDER BY receipts.tx_index ASC",
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
        let db = Db::new(Some(base_path), 0, 1024, None).unwrap();

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

        let checkpoint_path = db.get_checkpoint_dir().unwrap().unwrap();

        const SHARD_ID: u64 = 5000;

        let checkpoint_transactions = vec![];
        checkpoint_block_with_state(
            &checkpoint_block,
            &checkpoint_transactions,
            &checkpoint_parent,
            db.state_trie().unwrap(),
            SHARD_ID,
            &checkpoint_path,
        )
        .unwrap();

        // now load the checkpoint
        let (block, transactions, parent) = db
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

        // load the checkpoint again, to ensure idempotency
        let (block, transactions, parent) = db
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
