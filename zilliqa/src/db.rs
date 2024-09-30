use std::{
    collections::BTreeMap,
    fmt::Debug,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::primitives::Address;
use anyhow::{anyhow, Result};
use eth_trie::{EthTrie, Trie};
use itertools::Itertools;
use rusqlite::{
    named_params,
    types::{FromSql, FromSqlError, ToSqlOutput},
    Connection, OptionalExtension, Row, ToSql,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    crypto::{Hash, NodeSignature},
    exec::{ScillaError, ScillaException, ScillaTransition},
    message::{AggregateQc, Block, BlockHeader, QuorumCertificate},
    state::Account,
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, TransactionReceipt},
};

macro_rules! sqlify_with_bincode {
    ($type: ty) => {
        impl ToSql for $type {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                Ok(ToSqlOutput::from(
                    bincode::serialize(self)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e))?,
                ))
            }
        }
        impl FromSql for $type {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                bincode::deserialize(value.as_blob()?).map_err(|e| FromSqlError::Other(e))
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
sqlify_with_bincode!(NodeSignature);
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

enum BlockFilter {
    Hash(Hash),
    View(u64),
    Height(u64),
}

const CHECKPOINT_HEADER_BYTES: [u8; 8] = *b"ZILCHKPT";

#[derive(Debug)]
pub struct Db {
    db: Arc<Mutex<Connection>>,
    path: Option<Box<Path>>,
}

impl Db {
    pub fn new<P>(data_dir: Option<P>, shard_id: u64) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let (mut connection, path) = match data_dir {
            Some(path) => {
                let path = path.as_ref().join(shard_id.to_string());
                fs::create_dir_all(&path)?;
                (
                    Connection::open(path.join("db.sqlite3"))?,
                    Some(path.into_boxed_path()),
                )
            }
            None => (Connection::open_in_memory()?, None),
        };

        connection.trace(Some(|statement| tracing::trace!(statement, "sql executed")));

        Self::ensure_schema(&connection)?;

        Ok(Db {
            db: Arc::new(Mutex::new(connection)),
            path,
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
                is_canonical BOOLEAN NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash BLOB NOT NULL PRIMARY KEY,
                data BLOB NOT NULL);
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
                PRIMARY KEY (address, tx_hash));
            CREATE TABLE IF NOT EXISTS tip_info (
                latest_finalized_view INTEGER,
                high_qc BLOB,
                _single_row INTEGER DEFAULT 0 NOT NULL UNIQUE CHECK (_single_row = 0)); -- max 1 row
            CREATE TABLE IF NOT EXISTS state_trie (key BLOB NOT NULL PRIMARY KEY, value BLOB NOT NULL);
            ",
        )?;
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

    /// Fetch checkpoint data from file and initialise db state
    /// Return checkpointed block and transactions which must be executed after this function
    /// Return None if checkpoint already loaded
    pub fn load_trusted_checkpoint<P: AsRef<Path>>(
        &self,
        path: P,
        hash: &Hash,
        our_shard_id: u64,
    ) -> Result<Option<(Block, Vec<SignedTransaction>, Block)>> {
        // For now, only support a single version: you want to load the latest checkpoint, anyway.
        const SUPPORTED_VERSION: u32 = 2;

        let input = File::open(path)?;
        let mut reader = BufReader::with_capacity(8192 * 1024, input); // 8 MiB read chunks
        let trie_storage = Arc::new(self.state_trie()?);
        let mut state_trie = EthTrie::new(trie_storage.clone());

        // Decode and validate header
        let mut header: [u8; 21] = [0u8; 21];
        reader.read_exact(&mut header)?;
        let header = header;
        if header[0..8] != CHECKPOINT_HEADER_BYTES // magic bytes
            || header[20] != b'\n'
        // header must end in newline
        {
            return Err(anyhow!("Invalid checkpoint file: invalid header"));
        }
        let version = u32::from_be_bytes(header[8..12].try_into()?);
        // Only support a single version right now.
        if version != SUPPORTED_VERSION {
            return Err(anyhow!("Invalid checkpoint file: unsupported version."));
        }
        let shard_id = u64::from_be_bytes(header[12..20].try_into()?);
        if shard_id != our_shard_id {
            return Err(anyhow!("Invalid checkpoint file: wrong shard ID."));
        }

        // Decode and validate checkpoint block, its transactions and parent block
        let mut lines = reader.lines(); // V1 uses a plaintext, line-based format
        let block = lines.next().ok_or(anyhow!(
            "Invalid checkpoint file: missing block info on line 1"
        ))??;
        let block: Block = bincode::deserialize(&hex::decode(block.as_bytes())?)?;
        if block.hash() != *hash {
            return Err(anyhow!("Checkpoint does not match trusted hash"));
        }
        block.verify_hash()?;

        let transactions = lines.next().ok_or(anyhow!(
            "Invalid checkpoint file: missing transactions info on line 2"
        ))??;
        let transactions: Vec<SignedTransaction> =
            bincode::deserialize(&hex::decode(transactions.as_bytes())?)?;

        let parent = lines.next().ok_or(anyhow!(
            "Invalid checkpoint file: missing parent info on line 3"
        ))??;
        let parent: Block = bincode::deserialize(&hex::decode(parent.as_bytes())?)?;
        parent.verify_hash()?;

        if block.parent_hash() != parent.hash() {
            return Err(anyhow!("Invalid checkpoint file: parent's blockhash does not correspond to checkpoint block"));
        }

        if state_trie.iter().next().is_some() || self.get_highest_block_number()?.is_some() {
            // If checkpointed block already exists then assume checkpoint load already complete. Return None
            if self.get_block_by_hash(block.hash())?.is_some() {
                return Ok(None);
            }
            // This may not be strictly necessary, as in theory old values will, at worst, be orphaned
            // values not part of any state trie of any known block. With some effort, this could
            // even be supported.
            // However, without such explicit support, having old blocks MAY in fact cause
            // unexpected and unwanted behaviour. Thus we currently forbid loading a checkpoint in
            // a node that already contains previous state, until (and unless) there's ever a
            // usecase for going through the effort to support it and ensure it works as expected.
            if let Some(db_block) = self.get_block_by_hash(parent.hash())? {
                if db_block.parent_hash() != parent.parent_hash() {
                    return Err(anyhow!("Inconsistent checkpoint file: block loaded from checkpoint and block stored in database with same hash have differing parent hashes"));
                } else {
                    // In this case, the database already has the block contained in this checkpoint. We assume the
                    // database contains the full state for that block too and thus return early, without actually
                    // loading the checkpoint file.
                    return Ok(Some((block, transactions, parent)));
                }
            } else {
                return Err(anyhow!("Inconsistent checkpoint file: block loaded from checkpoint file does not exist in non-empty database"));
            }
        }

        // then decode state
        for (idx, line) in lines.enumerate() {
            let idx = idx + 2; // +1 because first line is just serialised block, +1 for 1-indexing
            let line = line?;
            let (account, trie) = line
                .split_once(';')
                .ok_or(anyhow!("Invalid checkpoint file at line {idx}"))?;
            let (account_hash, serialized_account) = account.split_once(':').ok_or(anyhow!(
                "Invalid checkpoint file: invalid state account information at line {idx}"
            ))?;
            let serialized_account = hex::decode(serialized_account)?;
            let mut account_trie = EthTrie::new(trie_storage.clone());
            for (storage_idx, storage_entry) in trie.split(',').enumerate() {
                if storage_entry.is_empty() {
                    continue;
                }
                let (key, val) = storage_entry.split_once(':').ok_or(anyhow!(
                    "Invalid checkpoint file: invalid storage entry at line {idx}, index {storage_idx}",
                ))?;
                account_trie.insert(&hex::decode(key)?, &hex::decode(val)?)?;
            }
            let account_trie_root =
                bincode::deserialize::<Account>(&serialized_account)?.storage_root;
            if account_trie.root_hash()?.as_slice() != account_trie_root {
                return Err(anyhow!(
                    "Invalid checkpoint file: account trie root hash mismatch, at line {idx}: calculated {}, checkpoint file contained {}", hex::encode(account_trie.root_hash()?.as_slice()), hex::encode(account_trie_root)
                ));
            }
            state_trie.insert(&hex::decode(account_hash)?, &serialized_account)?;
        }
        if state_trie.root_hash()? != parent.state_root_hash().0 {
            return Err(anyhow!("Invalid checkpoint file: state root hash mismatch"));
        }

        let parent_ref: &Block = &parent; // for moving into the closure
        self.with_sqlite_tx(move |tx| {
            self.insert_block_with_db_tx(tx, parent_ref)?;
            self.set_latest_finalized_view_with_db_tx(tx, parent_ref.view())?;
            self.set_high_qc_with_db_tx(tx, block.header.qc)?;
            Ok(())
        })?;

        Ok(Some((block, transactions, parent)))
    }

    pub fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage {
            db: self.db.clone(),
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
            .query_row_and_then(
                "SELECT block_hash FROM blocks WHERE view = ?1",
                [view],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn set_latest_finalized_view_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        view: u64,
    ) -> Result<()> {
        sqlite_tx
            .execute("INSERT INTO tip_info (latest_finalized_view) VALUES (?1) ON CONFLICT DO UPDATE SET latest_finalized_view = ?1",
                     [view])?;
        Ok(())
    }

    pub fn set_latest_finalized_view(&self, view: u64) -> Result<()> {
        self.set_latest_finalized_view_with_db_tx(&self.db.lock().unwrap(), view)
    }

    pub fn get_latest_finalized_view(&self) -> Result<Option<u64>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row("SELECT latest_finalized_view FROM tip_info", (), |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn get_highest_block_number(&self) -> Result<Option<u64>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row_and_then(
                "SELECT height FROM blocks WHERE is_canonical = TRUE ORDER BY height DESC LIMIT 1",
                (),
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn get_highest_block_hashes(&self, how_many: usize) -> Result<Vec<Hash>> {
        Ok(self
            .block_store
            .lock()
           .unwrap()
           .prepare_cached(
               "select block_hash from blocks where height in (select height from main_chain_canonical_blocks ORDER BY height DESC LIMIT ?1)")?
           .query_map([how_many], |row| row.get(0))?.collect::<Result<Vec<Hash>, _>>()?)
    }

    pub fn set_high_qc_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        high_qc: QuorumCertificate,
    ) -> Result<()> {
        sqlite_tx.execute(
            "INSERT INTO tip_info (high_qc) VALUES (?1) ON CONFLICT DO UPDATE SET high_qc = ?1",
            [high_qc],
        )?;
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
            .query_row("SELECT high_qc FROM tip_info", (), |row| row.get(0))
            .optional()?)
    }

    pub fn add_touched_address(&self, address: Address, txn_hash: Hash) -> Result<()> {
        self.db.lock().unwrap().execute(
            "INSERT INTO touched_address_index (address, tx_hash) VALUES (?1, ?2)",
            (AddressSqlable(address), txn_hash),
        )?;
        Ok(())
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

    pub fn get_transaction(&self, txn_hash: &Hash) -> Result<Option<SignedTransaction>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT data FROM transactions WHERE tx_hash = ?1",
                [txn_hash],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn contains_transaction(&self, hash: &Hash) -> Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT 1 FROM transactions WHERE tx_hash = ?1",
                [hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    pub fn insert_transaction_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        hash: &Hash,
        tx: &SignedTransaction,
    ) -> Result<()> {
        sqlite_tx.execute(
            "INSERT INTO transactions (tx_hash, data) VALUES (?1, ?2)",
            (hash, tx),
        )?;
        Ok(())
    }

    /// Insert a transaction whose hash was precalculated, to save a call to calculate_hash() if it
    /// is already known
    pub fn insert_transaction(&self, hash: &Hash, tx: &SignedTransaction) -> Result<()> {
        self.insert_transaction_with_db_tx(&self.db.lock().unwrap(), hash, tx)
    }

    pub fn remove_transactions_executed_in_block(&self, block_hash: &Hash) -> Result<()> {
        // foreign key triggers will take care of receipts and touched_address_index
        self.db.lock().unwrap().execute(
            "DELETE FROM transactions WHERE tx_hash IN (SELECT tx_hash FROM receipts WHERE block_hash = ?1)",
            [block_hash],
        )?;
        Ok(())
    }

    pub fn get_block_hash_reverse_index(&self, tx_hash: &Hash) -> Result<Option<Hash>> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT block_hash FROM receipts WHERE tx_hash = ?1",
                [tx_hash],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn insert_block_with_db_tx(&self, sqlite_tx: &Connection, block: &Block) -> Result<()> {
        sqlite_tx.execute(
            "INSERT INTO blocks
                (block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg, is_canonical)
            VALUES (:block_hash, :view, :height, :qc, :signature, :state_root_hash, :transactions_root_hash, :receipts_root_hash, :timestamp, :gas_used, :gas_limit, :agg, TRUE)",
            named_params! {
                ":block_hash": block.header.hash,
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
        self.db.lock().unwrap().execute(
            "UPDATE blocks SET is_canonical = TRUE WHERE block_hash = ?1",
            [hash],
        )?;
        Ok(())
    }

    pub fn mark_block_as_non_canonical(&self, hash: Hash) -> Result<()> {
        self.db.lock().unwrap().execute(
            "UPDATE blocks SET is_canonical = FALSE WHERE block_hash = ?1",
            [hash],
        )?;
        Ok(())
    }

    pub fn insert_block(&self, block: &Block) -> Result<()> {
        self.insert_block_with_db_tx(&self.db.lock().unwrap(), block)
    }

    pub fn remove_block(&self, block: &Block) -> Result<()> {
        self.db.lock().unwrap().execute(
            "DELETE FROM blocks WHERE block_hash = ?1",
            [block.header.hash],
        )?;
        Ok(())
    }

    fn get_transactionless_block(&self, filter: BlockFilter) -> Result<Option<Block>> {
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
        macro_rules! query_block {
            ($cond: tt, $key: tt) => {
                self.db.lock().unwrap().query_row(concat!("SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks WHERE ", $cond), [$key], make_block).optional()?
            };
        }
        Ok(match filter {
            BlockFilter::Hash(hash) => {
                query_block!("block_hash = ?1", hash)
            }
            BlockFilter::View(view) => {
                query_block!("view = ?1", view)
            }
            BlockFilter::Height(height) => {
                query_block!("height = ?1 AND is_canonical = TRUE", height)
            }
        })
    }

    fn get_block(&self, filter: BlockFilter) -> Result<Option<Block>> {
        let Some(mut block) = self.get_transactionless_block(filter)? else {
            return Ok(None);
        };
        let transaction_hashes = self
            .db
            .lock()
            .unwrap()
            .prepare_cached("SELECT tx_hash FROM receipts WHERE block_hash = ?1")?
            .query_map([block.header.hash], |row| row.get(0))?
            .collect::<Result<Vec<Hash>, _>>()?;
        block.transactions = transaction_hashes;
        Ok(Some(block))
    }

    pub fn get_block_by_hash(&self, block_hash: &Hash) -> Result<Option<Block>> {
        self.get_block(BlockFilter::Hash(*block_hash))
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        self.get_block(BlockFilter::View(view))
    }

    pub fn get_canonical_block_by_number(&self, number: u64) -> Result<Option<Block>> {
        self.get_block(BlockFilter::Height(number))
    }

    pub fn contains_block(&self, block_hash: &Hash) -> Result<bool> {
        Ok(self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT 1 FROM blocks WHERE block_hash = ?1",
                [block_hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    fn make_view_range(row: &Row) -> rusqlite::Result<Range<u64>> {
        // Add one to end because the range returned from SQL is inclusive.
        let start: u64 = row.get(0)?;
        let end_inc: u64 = row.get(1)?;
        Ok(Range {
            start,
            end: end_inc + 1,
        })
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
        sqlite_tx.execute(
            "INSERT INTO receipts
                (tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions)
            VALUES (:tx_hash, :block_hash, :tx_index, :success, :gas_used, :cumulative_gas_used, :contract_address, :logs, :transitions, :accepted, :errors, :exceptions)",
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

    pub fn get_transaction_receipt(&self, txn_hash: &Hash) -> Result<Option<TransactionReceipt>> {
        Ok(self.db.lock().unwrap().query_row("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE tx_hash = ?1", [txn_hash], Self::make_receipt).optional()?)
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: &Hash,
    ) -> Result<Vec<TransactionReceipt>> {
        Ok(self.db.lock().unwrap().prepare_cached("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1")?.query_map([block_hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn remove_transaction_receipts_in_block(&self, block_hash: &Hash) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute("DELETE FROM receipts WHERE block_hash = ?1", [block_hash])?;
        Ok(())
    }

    pub fn get_total_transaction_count(&self) -> Result<usize> {
        let count: usize =
            self.db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Retrieve a list of the views in our db.
    /// This is a bit horrific. What we actually do here is to find the view lower and upper bounds for the contiguous block ranges in the database.
    /// See block_store.rs::availability() for details.
    pub fn get_view_ranges(&self) -> Result<Vec<Range<u64>>> {
        // The island field is technically redundant, but it helps with debugging.
        Ok(self.block_store.lock().unwrap()
            .prepare_cached("SELECT MIN(vlb), MAX(vub), MIN(height),MAX(height),height-rank AS island FROM ( SELECT height,vlb,vub,ROW_NUMBER() OVER (ORDER BY height) AS rank FROM
 (SELECT height,MIN(view) as vlb, MAX(view) as vub from blocks GROUP BY height ) )  GROUP BY island ORDER BY MIN(height) ASC")?
           .query_map([], Self::make_view_range)?.collect::<Result<Vec<_>,_>>()?)
    }

    /// Forget about a range of blocks; this saves space, but also allows us to test our block fetch algorithm.
    /// If canonical is true, we'll forget the canonical block mappings for this range too - uses less space, but not so good for security.
    pub fn forget_block_range(&self, blocks: Range<u64>) -> Result<()> {
        self.with_sqlite_tx(move |tx| {
            // Remove everything!
            tx.execute("DELETE FROM tip_info WHERE latest_finalized_view IN (SELECT view FROM blocks WHERE height >= :low AND height < :high)",
                       named_params! {
                           ":low" : blocks.start,
                           ":high" : blocks.end } )?;
            // @TODO can't yet remove transactions - we don't know the hashes.
            tx.execute("DELETE FROM receipts WHERE block_hash IN (SELECT block_hash FROM main_chain_canonical_blocks WHERE height >= :low AND height < :high)",
                       named_params! {
                           ":low": blocks.start,
                           ":high": blocks.end })?;
            tx.execute(
                "DELETE FROM main_chain_canonical_blocks WHERE height >= :low AND height < :high",
                named_params! {
                    ":low": blocks.start,
                    ":high": blocks.end },
            )?;
            tx.execute(
                "DELETE FROM blocks WHERE height >= :low AND height < :high",
                named_params! {
                ":low": blocks.start,
                ":high" : blocks.end },
            )?;
            Ok(())
        })
    }
}

pub fn get_checkpoint_filename<P: AsRef<Path> + Debug>(
    output_dir: P,
    block: &Block,
) -> Result<PathBuf> {
    Ok(output_dir.as_ref().join(block.number().to_string()))
}

pub fn checkpoint_block_with_state<P: AsRef<Path> + Debug>(
    block: &Block,
    transactions: &Vec<SignedTransaction>,
    parent: &Block,
    state_trie_storage: TrieStorage,
    shard_id: u64,
    output_dir: P,
) -> Result<()> {
    const VERSION: u32 = 2;

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
    let mut writer = BufWriter::with_capacity(8192 * 1024, outfile_temp); // 8 MiB chunks

    // write the header:
    writer.write_all(&CHECKPOINT_HEADER_BYTES)?; // file identifier
    writer.write_all(&VERSION.to_be_bytes())?; // 4 BE bytes for version
    writer.write_all(&shard_id.to_be_bytes())?; // 8 BE bytes for shard ID
    writer.write_all(b"\n")?;

    // write the block...
    writer.write_all(hex::encode(bincode::serialize(&block)?).as_bytes())?; // TODO: better serialization (#1007)
    writer.write_all(b"\n")?;

    // write transactions
    writer.write_all(hex::encode(bincode::serialize(&transactions)?).as_bytes())?; // TODO: better serialization (#1007)
    writer.write_all(b"\n")?;

    // and its parent, to keep the qc tracked
    writer.write_all(hex::encode(bincode::serialize(&parent)?).as_bytes())?; // TODO: better serialization (#1007)
    writer.write_all(b"\n")?;

    // then write state
    let accounts =
        EthTrie::new(state_trie_storage.clone()).at_root(parent.state_root_hash().into());
    let account_storage = EthTrie::new(state_trie_storage);
    let mut account_key_buf = [0u8; 64]; // save a few allocations, since account keys are fixed length

    for (key, val) in accounts.iter() {
        let account_storage =
            account_storage.at_root(bincode::deserialize::<Account>(&val)?.storage_root);

        // export the account itself
        hex::encode_to_slice(key, &mut account_key_buf)?;
        writer.write_all(&account_key_buf)?;
        writer.write_all(b":")?;
        writer.write_all(hex::encode(val).as_bytes())?;
        writer.write_all(b";")?;

        // now the account storage
        for (storage_key, storage_val) in account_storage.iter() {
            writer.write_all(hex::encode(storage_key).as_bytes())?;
            writer.write_all(b":")?;
            writer.write_all(hex::encode(storage_val).as_bytes())?;
            writer.write_all(b",")?;
        }
        writer.write_all(b"\n")?;
    }
    writer.flush()?;

    fs::rename(&temp_filename, &output_filename)?;

    Ok(())
}

/// An implementor of [eth_trie::DB] which uses a [Connection] to persist data.
#[derive(Debug, Clone)]
pub struct TrieStorage {
    db: Arc<Mutex<Connection>>,
}

impl eth_trie::DB for TrieStorage {
    type Error = rusqlite::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let value = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM state_trie WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO state_trie (key, value) VALUES (?1, ?2)",
            (key, value),
        )?;
        Ok(())
    }

    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        if keys.is_empty() {
            return Ok(());
        }

        assert_eq!(keys.len(), values.len());

        // https://www.sqlite.org/limits.html#max_variable_number
        let maximum_sql_parameters = 32766;
        // Each key-value pair needs two parameters.
        let chunk_size = maximum_sql_parameters / 2;

        let keys = keys.chunks(chunk_size);
        let values = values.chunks(chunk_size);

        for (keys, values) in keys.zip(values) {
            // Generate the SQL substring of the form "(?1, ?2), (?3, ?4), (?5, ?6), ...". There will be one pair of
            // parameters for each key. Note that parameters are one-indexed.
            #[allow(unstable_name_collisions)]
            let params_stmt: String = (0..keys.len())
                .map(|i| format!("(?{}, ?{})", i * 2 + 1, i * 2 + 2))
                .intersperse(",".to_owned())
                .collect();
            let query =
                format!("INSERT OR REPLACE INTO state_trie (key, value) VALUES {params_stmt}");
            let params = keys.iter().zip(values).flat_map(|(k, v)| [k, v]);
            self.db
                .lock()
                .unwrap()
                .execute(&query, rusqlite::params_from_iter(params))?;
        }

        Ok(())
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
        distributions::{Distribution, Uniform},
        Rng, SeedableRng,
    };
    use rand_chacha::ChaCha8Rng;
    use tempfile::tempdir;

    use super::*;
    use crate::{crypto::SecretKey, state::State};

    #[test]
    fn checkpoint_export_import() {
        let base_path = tempdir().unwrap();
        let base_path = base_path.path();
        let db = Db::new(Some(base_path), 0).unwrap();

        // Seed db with data
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let distribution = Uniform::new(1, 50);
        let mut root_trie = EthTrie::new(Arc::new(db.state_trie().unwrap()));
        for _ in 0..100 {
            let account_address: [u8; 20] = rng.gen();
            let mut account_trie = EthTrie::new(Arc::new(db.state_trie().unwrap()));
            let mut key = Vec::<u8>::with_capacity(50);
            let mut value = Vec::<u8>::with_capacity(50);
            for _ in 0..distribution.sample(&mut rng) {
                for _ in 0..distribution.sample(&mut rng) {
                    key.push(rng.gen());
                }
                for _ in 0..distribution.sample(&mut rng) {
                    value.push(rng.gen());
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
                    &bincode::serialize(&account).unwrap(),
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

        // Return None if checkpointed block already executed
        db.insert_block(&checkpoint_block).unwrap();
        let result = db
            .load_trusted_checkpoint(
                checkpoint_path.join(checkpoint_block.number().to_string()),
                &checkpoint_block.hash(),
                SHARD_ID,
            )
            .unwrap();
        assert!(result.is_none());
    }
}
