use std::{
    collections::BTreeMap,
    fmt::Debug,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::primitives::Address;
use anyhow::{anyhow, Result};
use eth_trie::{EthTrie, Trie};
use itertools::Either;
use rusqlite::{
    named_params,
    types::{FromSql, FromSqlError, ToSqlOutput},
    Connection, OptionalExtension, Row, ToSql,
};
use serde::{Deserialize, Serialize};
use sled::{Batch, Tree};
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

const STATE_TRIE_TREE: &[u8] = b"state_trie";

const CHECKPOINT_HEADER_BYTES: [u8; 8] = *b"ZILCHKPT";

#[derive(Debug)]
pub struct Db {
    state_root: sled::Db,
    block_store: Mutex<Connection>,
    path: Option<Box<Path>>,
}

impl Db {
    pub fn new<P>(data_dir: Option<P>, shard_id: u64) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let (db, mut connection, path) = match data_dir {
            Some(path) => {
                let path = path.as_ref().join(shard_id.to_string());
                (
                    sled::open(path.join("state"))?,
                    Connection::open(path.join("blockdata.db"))?,
                    Some(path.into_boxed_path()),
                )
            }
            None => (
                sled::Config::new().temporary(true).open()?,
                Connection::open_in_memory()?,
                None,
            ),
        };

        connection.trace(Some(|statement| tracing::trace!(statement, "sql executed")));

        Self::ensure_schema(&connection)?;

        Ok(Db {
            state_root: db,
            block_store: Mutex::new(connection),
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
                agg BLOB);
            CREATE TABLE IF NOT EXISTS main_chain_canonical_blocks (
                height INTEGER NOT NULL PRIMARY KEY,
                block_hash TEXT NOT NULL REFERENCES blocks (block_hash));
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
            CREATE TABLE IF NOT EXISTS touched_address_index (
                address BLOB,
                tx_hash BLOB REFERENCES transactions (tx_hash) ON DELETE CASCADE,
                PRIMARY KEY (address, tx_hash));
            CREATE TABLE IF NOT EXISTS tip_info (
                latest_finalized_view INTEGER,
                high_qc BLOB,
                _single_row INTEGER DEFAULT 0 NOT NULL UNIQUE CHECK (_single_row = 0)); -- max 1 row
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

    pub fn load_trusted_checkpoint<P: AsRef<Path>>(
        &self,
        path: P,
        hash: &Hash,
        our_shard_id: u64,
    ) -> Result<Block> {
        // For now, only support a single version: you want to load the latest checkpoint, anyway.
        const SUPPORTED_VERSION: u32 = 1;

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

        // Decode checkpoint block and parent block, and validate
        let mut lines = reader.lines(); // V1 uses a plaintext, line-based format
        let block = lines.next().ok_or(anyhow!(
            "Invalid checkpoint file: missing block info on line 1"
        ))??;
        let block: Block = bincode::deserialize(&hex::decode(block.as_bytes())?)?;
        if block.hash() != *hash {
            return Err(anyhow!("Checkpoint does not match trusted hash"));
        }
        block.verify_hash()?;

        let parent = lines.next().ok_or(anyhow!(
            "Invalid checkpoint file: missing parent info on line 2"
        ))??;
        let parent: Block = bincode::deserialize(&hex::decode(parent.as_bytes())?)?;
        parent.verify_hash()?;

        if block.parent_hash() != parent.hash() {
            return Err(anyhow!("Invalid checkpoint file: parent's blockhash does not correspond to checkpoint block"));
        }

        if !trie_storage.db.is_empty() || self.get_highest_block_number()?.is_some() {
            // This may not be strictly necessary, as in theory old values will, at worst, be orphaned
            // values not part of any state trie of any known block. With some effort, this could
            // even be supported.
            // However, without such explicit support, having old blocks MAY in fact cause
            // unexpected and unwanted behaviour. Thus we currently forbid loading a checkpoint in
            // a node that already contains previous state, until (and unless) there's ever a
            // usecase for going through the effort to support it and ensure it works as expected.
            if let Some(db_block) = self.get_block_by_hash(&block.hash())? {
                if db_block != block {
                    return Err(anyhow!("Inconsistent checkpoint file: block loaded from checkpoint and block stored in database with same hash have differing parent hashes"));
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
        if state_trie.root_hash()? != block.state_root_hash().0 {
            return Err(anyhow!("Invalid checkpoint file: state root hash mismatch"));
        }

        let block_ref = &block; // for moving into the closure
        self.with_sqlite_tx(move |tx| {
            self.insert_block_with_db_tx(tx, block_ref)?;
            self.insert_block_with_db_tx(tx, &parent)?;
            self.set_latest_finalized_view_with_db_tx(tx, block_ref.view())?;
            self.set_high_qc_with_db_tx(tx, block_ref.header.qc)?;
            self.set_canonical_block_number_with_db_tx(tx, block_ref.number(), block_ref.hash())?;
            self.set_canonical_block_number_with_db_tx(tx, parent.number(), parent.hash())?;
            Ok(())
        })?;

        Ok(block)
    }

    pub fn flush_state(&self) {
        while self.state_root.flush().unwrap() > 0 {}
    }

    pub fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage::new(
            self.state_root.open_tree(STATE_TRIE_TREE)?,
        ))
    }

    pub fn with_sqlite_tx(&self, operations: impl FnOnce(&Connection) -> Result<()>) -> Result<()> {
        let mut sqlite_tx = self.block_store.lock().unwrap();
        let sqlite_tx = sqlite_tx.transaction()?;
        operations(&sqlite_tx)?;
        Ok(sqlite_tx.commit()?)
    }

    pub fn set_canonical_block_number_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        number: u64,
        hash: Hash,
    ) -> Result<()> {
        sqlite_tx.execute("INSERT OR REPLACE INTO main_chain_canonical_blocks (height, block_hash) VALUES (?1, ?2)",
            (number, hash))?;
        Ok(())
    }

    pub fn set_canonical_block_number(&self, number: u64, hash: Hash) -> Result<()> {
        self.set_canonical_block_number_with_db_tx(&self.block_store.lock().unwrap(), number, hash)
    }

    pub fn get_canonical_block_number(&self, number: u64) -> Result<Option<Hash>> {
        Ok(self
            .block_store
            .lock()
            .unwrap()
            .query_row_and_then(
                "SELECT block_hash FROM main_chain_canonical_blocks WHERE height = ?1",
                [number],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn revert_canonical_block_number(&self, number: u64) -> Result<()> {
        self.block_store.lock().unwrap().execute(
            "DELETE FROM main_chain_canonical_blocks WHERE height = ?1",
            [number],
        )?;
        Ok(())
    }

    pub fn get_block_hash_by_view(&self, view: u64) -> Result<Option<Hash>> {
        Ok(self
            .block_store
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
        self.set_latest_finalized_view_with_db_tx(&self.block_store.lock().unwrap(), view)
    }

    pub fn get_latest_finalized_view(&self) -> Result<Option<u64>> {
        Ok(self
            .block_store
            .lock()
            .unwrap()
            .query_row("SELECT latest_finalized_view FROM tip_info", (), |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn get_highest_block_number(&self) -> Result<Option<u64>> {
        Ok(self
            .block_store
            .lock()
            .unwrap()
            .query_row_and_then(
                "SELECT height FROM main_chain_canonical_blocks ORDER BY height DESC LIMIT 1",
                (),
                |row| row.get(0),
            )
            .optional()?)
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
        self.set_high_qc_with_db_tx(&self.block_store.lock().unwrap(), high_qc)
    }

    pub fn get_high_qc(&self) -> Result<Option<QuorumCertificate>> {
        Ok(self
            .block_store
            .lock()
            .unwrap()
            .query_row("SELECT high_qc FROM tip_info", (), |row| row.get(0))
            .optional()?)
    }

    pub fn add_touched_address(&self, address: Address, txn_hash: Hash) -> Result<()> {
        self.block_store.lock().unwrap().execute(
            "INSERT INTO touched_address_index (address, tx_hash) VALUES (?1, ?2)",
            (AddressSqlable(address), txn_hash),
        )?;
        Ok(())
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        // TODO: this is only ever used in one API, so keep an eye on performance - in case e.g.
        // the index table might need to be denormalised to simplify this lookup
        Ok(self
            .block_store
            .lock()
            .unwrap()
            .prepare_cached("SELECT tx_hash FROM touched_address_index JOIN receipts USING (tx_hash) JOIN blocks USING (block_hash) WHERE address = ?1 ORDER BY blocks.height, receipts.tx_index")?
            .query_map([AddressSqlable(address)], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_transaction(&self, txn_hash: &Hash) -> Result<Option<SignedTransaction>> {
        Ok(self
            .block_store
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
            .block_store
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
        self.insert_transaction_with_db_tx(&self.block_store.lock().unwrap(), hash, tx)
    }

    pub fn remove_transactions_executed_in_block(&self, block_hash: &Hash) -> Result<()> {
        // foreign key triggers will take care of receipts and touched_address_index
        self.block_store.lock().unwrap().execute(
            "DELETE FROM transactions WHERE tx_hash IN (SELECT tx_hash FROM receipts WHERE block_hash = ?1)",
            [block_hash],
        )?;
        Ok(())
    }

    pub fn get_block_hash_reverse_index(&self, tx_hash: &Hash) -> Result<Option<Hash>> {
        Ok(self
            .block_store
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
                (block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg)
            VALUES (:block_hash, :view, :height, :qc, :signature, :state_root_hash, :transactions_root_hash, :receipts_root_hash, :timestamp, :gas_used, :gas_limit, :agg)",
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

    pub fn insert_block(&self, block: &Block) -> Result<()> {
        self.insert_block_with_db_tx(&self.block_store.lock().unwrap(), block)
    }

    fn get_transactionless_block(&self, key: Either<&Hash, &u64>) -> Result<Option<Block>> {
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
                self.block_store.lock().unwrap().query_row(concat!("SELECT block_hash, view, height, qc, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, gas_limit, agg FROM blocks WHERE ", $cond), [$key], make_block).optional()?
            };
        }
        Ok(match key {
            Either::Left(hash) => {
                query_block!("block_hash = ?1", hash)
            }
            Either::Right(view) => {
                query_block!("view = ?1", view)
            }
        })
    }

    pub fn get_block(&self, key: Either<&Hash, &u64>) -> Result<Option<Block>> {
        let Some(mut block) = self.get_transactionless_block(key)? else {
            return Ok(None);
        };
        let transaction_hashes = self
            .block_store
            .lock()
            .unwrap()
            .prepare_cached("SELECT tx_hash FROM receipts WHERE block_hash = ?1")?
            .query_map([block.header.hash], |row| row.get(0))?
            .collect::<Result<Vec<Hash>, _>>()?;
        block.transactions = transaction_hashes;
        Ok(Some(block))
    }

    pub fn get_block_by_hash(&self, block_hash: &Hash) -> Result<Option<Block>> {
        self.get_block(Either::Left(block_hash))
    }

    pub fn get_block_by_view(&self, view: &u64) -> Result<Option<Block>> {
        self.get_block(Either::Right(view))
    }

    pub fn contains_block(&self, block_hash: &Hash) -> Result<bool> {
        Ok(self
            .block_store
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
        self.insert_transaction_receipt_with_db_tx(&self.block_store.lock().unwrap(), receipt)
    }

    pub fn get_transaction_receipt(&self, txn_hash: &Hash) -> Result<Option<TransactionReceipt>> {
        Ok(self.block_store.lock().unwrap().query_row("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE tx_hash = ?1", [txn_hash], Self::make_receipt).optional()?)
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: &Hash,
    ) -> Result<Vec<TransactionReceipt>> {
        Ok(self.block_store.lock().unwrap().prepare_cached("SELECT tx_hash, block_hash, tx_index, success, gas_used, cumulative_gas_used, contract_address, logs, transitions, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1")?.query_map([block_hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn remove_transaction_receipts_in_block(&self, block_hash: &Hash) -> Result<()> {
        self.block_store
            .lock()
            .unwrap()
            .execute("DELETE FROM receipts WHERE block_hash = ?1", [block_hash])?;
        Ok(())
    }

    pub fn get_total_transaction_count(&self) -> Result<usize> {
        let count: usize = self.block_store.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM transactions",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn get_receipt_count_in_range(&self, start_height: u64, end_height: u64) -> Result<usize> {
        let count: usize = self.block_store.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM receipts
             JOIN blocks ON receipts.block_hash = blocks.block_hash
             WHERE blocks.height BETWEEN ?1 AND ?2",
            [start_height, end_height],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn count_blocks_in_last_seconds(&self, seconds: u64) -> Result<usize> {
        let now = SystemTime::now();
        let since = now - Duration::new(seconds, 0);
        let since_sql = SystemTimeSqlable(since);

        let count: usize = self.block_store.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM blocks WHERE timestamp >= ?1",
            [since_sql],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn count_receipts_in_blocks_in_last_seconds(&self, seconds: u64) -> Result<usize> {
        let now = SystemTime::now();
        let since = now - Duration::new(seconds, 0);
        let since_sql = SystemTimeSqlable(since);

        let count: usize = self.block_store.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM receipts
             JOIN blocks ON receipts.block_hash = blocks.block_hash
             WHERE blocks.timestamp >= ?1",
            [since_sql],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

pub fn checkpoint_block_with_state<P: AsRef<Path> + Debug>(
    block: &Block,
    parent: &Block,
    state_trie_storage: TrieStorage,
    shard_id: u64,
    output_dir: P,
) -> Result<()> {
    const VERSION: u32 = 1;

    fs::create_dir_all(&output_dir)?;

    let state_trie_storage = Arc::new(state_trie_storage);
    // quick sanity check
    if block.parent_hash() != parent.hash() {
        return Err(anyhow!(
            "Parent block parameter must match the checkpoint block's parent hash"
        ));
    }

    // Note: we ignore any existing file
    let output_filename = output_dir.as_ref().join(block.number().to_string());
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
    // and its parent, to keep the qc tracked
    writer.write_all(hex::encode(bincode::serialize(&parent)?).as_bytes())?; // TODO: better serialization (#1007)
    writer.write_all(b"\n")?;

    // then write state
    let accounts = EthTrie::new(state_trie_storage.clone()).at_root(block.state_root_hash().into());
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

/// An implementor of [eth_trie::DB] which uses a [sled::Tree] to persist data.
#[derive(Debug, Clone)]
pub struct TrieStorage {
    db: Tree,
}

impl TrieStorage {
    pub fn new(db: Tree) -> Self {
        Self { db }
    }
}

impl eth_trie::DB for TrieStorage {
    type Error = sled::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.db.get(key)?.map(|ivec| ivec.to_vec()))
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.db.insert(key, value)?;
        Ok(())
    }

    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        let mut batch = Batch::default();
        assert_eq!(keys.len(), values.len());
        for (key, value) in keys.into_iter().zip(values) {
            batch.insert(key, value);
        }
        self.db.apply_batch(batch)?;
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

    /// eth-trie.rs provides a way to cache reads and writes and periodically flush them.
    /// We delegate this to Sled and implement flush() as a no-op.
    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

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
        let test_db = sled::Config::new().temporary(true).open().unwrap();
        let base_path = tempdir().unwrap();
        let base_path = base_path.path();
        let db = Db::new(Some(base_path), 0).unwrap();

        let trie_db = Arc::new(TrieStorage::new(test_db.deref().to_owned()));

        // Seed db with data
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let distribution = Uniform::new(1, 50);
        let mut root_trie = EthTrie::new(trie_db.clone());
        for _ in 0..100 {
            let account_address: [u8; 20] = rng.gen();
            let mut account_trie = EthTrie::new(trie_db.clone());
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
        let parent_block = Block::genesis(state_hash.into());
        // bit of a hack to generate a successor block
        let mut qc2 = QuorumCertificate::genesis();
        qc2.block_hash = parent_block.hash();
        qc2.view = 1;
        let checkpoint_block = Block::from_qc(
            SecretKey::new().unwrap(),
            1,
            1,
            qc2,
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

        checkpoint_block_with_state(
            &checkpoint_block,
            &parent_block,
            trie_db.deref().clone(),
            SHARD_ID,
            &checkpoint_path,
        )
        .unwrap();

        // now parse the checkpoint
        db.load_trusted_checkpoint(
            checkpoint_path.join(checkpoint_block.number().to_string()),
            &checkpoint_block.hash(),
            SHARD_ID,
        )
        .unwrap();
    }
}
