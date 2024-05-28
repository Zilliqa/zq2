use std::{collections::BTreeMap, path::Path, sync::Mutex};

use alloy_primitives::Address;
use anyhow::{anyhow, Result};
use itertools::Either;
use rusqlite::{
    named_params,
    types::{FromSql, FromSqlError, ToSqlOutput},
    Connection, OptionalExtension, Row, ToSql,
};
use serde::{Deserialize, Serialize};
use sled::{Batch, Tree};

use crate::{
    crypto::{Hash, NodeSignature},
    exec::{ScillaError, ScillaException},
    message::{AggregateQc, Block, BlockHeader, QuorumCertificate},
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, TransactionReceipt},
};

#[derive(Debug)]
pub struct Db {
    state_root: sled::Db,
    block_store: Mutex<Connection>,
}

// database tree names
/// Key: trie hash; value: trie node
const STATE_TRIE_TREE: &[u8] = b"state_trie";
// /// Key: transaction hash; value: transaction data
// const TXS_TREE: &[u8] = b"txs_tree";
// /// Key: block hash; value: vector of transaction receipts in that block
// const RECEIPTS_TREE: &[u8] = b"receipts_tree";
// /// Key: tx_hash; value: corresponding block_hash
// const TX_BLOCK_INDEX: &[u8] = b"tx_block_index";
// /// Key: block hash; value: block header
// const BLOCK_HEADERS_TREE: &[u8] = b"block_headers_tree";
// /// Key: block number (on the current main branch); value: block hash
// const CANONICAL_BLOCK_NUMBERS_TREE: &[u8] = b"canonical_block_numbers_tree";
// /// Key: block view (on the current main branch); value: block hash
// const CANONICAL_BLOCK_VIEWS_TREE: &[u8] = b"canonical_block_views_tree";
// /// Key: block hash; value: entire block (with hashes for transactions)
// const BLOCKS_TREE: &[u8] = b"blocks_tree";
// /// Key: address; value: list of transactions which touched this address, in order of execution.
// const TOUCHED_ADDRESS_TREE: &[u8] = b"touched_address_tree";

// // single keys stored in default tree in DB
// /// value: u64
// const LATEST_FINALIZED_VIEW: &[u8] = b"latest_finalized_view";
// /// The highest block number we have seen and stored. It is guaranteed that we have the block at this number in our
// /// block store.
// const HIGHEST_BLOCK_NUMBER: &[u8] = b"highest_block_number";
// const HIGH_QC: &[u8] = b"high_qc";

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

make_wrapper!(SystemTime, SystemTimeSqlable);
impl ToSql for SystemTimeSqlable {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        // SQL can only store i64 as number - but for timestamps as seconds this should be
        // perfectly fine to convert (otherwise it'd have to be stored as text or raw blob)
        Ok(ToSqlOutput::from(
            self.0
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        ))
    }
}
impl FromSql for SystemTimeSqlable {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        // TODO
        bincode::deserialize(value.as_blob()?).map_err(|e| FromSqlError::Other(e))
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
        Ok(ToSqlOutput::from(hex::encode(self.0)))
    }
}
impl FromSql for Hash {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        // ugly...
        hex::decode(value.as_str()?)
            .map_err(|e| anyhow!(e))
            .and_then(|bytes| Hash::from_bytes(bytes).map_err(|e| anyhow!(e)))
            .map_err(|e| FromSqlError::Other(e.into()))
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

impl Db {
    pub fn new<P>(data_dir: Option<P>, shard_id: u64) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let (db, connection) = match data_dir {
            Some(path) => {
                let path = path.as_ref().join(shard_id.to_string());
                (
                    sled::open(path.join("state"))?,
                    Connection::open(path.join("blockdata"))?,
                )
            }
            None => (
                sled::Config::new().temporary(true).open()?,
                Connection::open_in_memory()?,
            ),
        };

        Self::ensure_schema(&connection)?;

        Ok(Db {
            state_root: db,
            block_store: Mutex::new(connection),
        })
    }

    fn ensure_schema(connection: &Connection) -> Result<()> {
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocks (
                hash TEXT NOT NULL PRIMARY KEY,
                view INTEGER NOT NULL UNIQUE,
                height INTEGER NOT NULL,
                parent_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                state_root_hash TEXT NOT NULL,
                timestamp NUMERIC NOT NULL,
                qc BLOB NOT NULL,
                agg BLOB,
                );
            CREATE TABLE IF NOT EXISTS main_chain_canonical_blocks (
                height INTEGER NOT NULL PRIMARY KEY,
                block_hash TEXT NOT NULL REFERENCES blocks (hash),
                );
            CREATE TABLE IF NOT EXISTS transactions (
                hash TEXT NOT NULL PRIMARY KEY,
                data BLOB NOT NULL,
                );
            CREATE TABLE IF NOT EXISTS receipts (
                tx_hash TEXT NOT NULL PRIMARY KEY REFERENCES transactions (hash),
                block_hash TEXT NOT NULL REFERENCES blocks (hash),
                index INTEGER NOT NULL,
                success INTEGER NOT NULL,
                gas_used INTEGER NOT NULL,
                contract_address BLOB,
                logs BLOB,
                accepted INTEGER,
                errors BLOB,
                exceptions BLOB
                );
            CREATE TABLE IF NOT EXISTS touched_address_index (
                address BLOB,
                tx_hash TEXT,
                PRIMARY KEY (address, tx_hash)
                );
            CREATE TABLE IF NOT EXISTS tip_info (
                latest_finalized_view INTEGER,
                high_qc BLOB,
                _single_row INTEGER DEFAULT 0 NOT NULL UNIQUE CHECK (_single_row = 0),
            )
            ",
        )?;
        Ok(())
    }

    pub fn flush_state(&self) {
        while self.state_root.flush().unwrap() > 0 {}
    }

    pub fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage::new(
            self.state_root.open_tree(STATE_TRIE_TREE)?,
        ))
    }

    pub fn do_sqlite_tx(&self, operations: impl Fn(&Connection) -> Result<()>) -> Result<()> {
        let mut sqlite_tx = self.block_store.lock().unwrap();
        let sqlite_tx = sqlite_tx.transaction()?;
        operations(&sqlite_tx)?;
        Ok(sqlite_tx.commit()?)
    }

    pub fn put_canonical_block_number(&self, number: u64, hash: Hash) -> Result<()> {
        self.block_store.lock().unwrap().execute("INSERT OR REPLACE INTO main_chain_canonical_blocks (height, block_hash) VALUES (?1, ?2)",
            (number, hash))?;
        Ok(())
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

    pub fn put_latest_finalized_view(&self, view: u64) -> Result<()> {
        self.block_store
            .lock()
            .unwrap()
            .execute("UPDATE tip_info SET latest_finalized_view = ?1", [view])?;
        Ok(())
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
                "SELECT height FROM blocks ORDER BY height DESC LIMIT 1",
                (),
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn set_high_qc(&self, high_qc: QuorumCertificate) -> Result<()> {
        self.block_store
            .lock()
            .unwrap()
            .execute("UPDATE tip_info SET high_qc = ?1", [high_qc])?;
        Ok(())
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

    pub fn get_touched_addresses(&self, address: Address) -> Result<Vec<Hash>> {
        Ok(self
            .block_store
            .lock()
            .unwrap()
            .prepare_cached("SELECT tx_hash FROM touched_address_index WHERE address = ?1")?
            .query_map([AddressSqlable(address)], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn get_transaction(&self, txn_hash: &Hash) -> Result<Option<SignedTransaction>> {
        Ok(self
            .block_store
            .lock()
            .unwrap()
            .query_row(
                "SELECT hash, data FROM transactions WHERE hash = ?1",
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
                "SELECT 1 FROM transactions WHERE hash = ?1",
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
            "INSERT INTO transactions (hash, data) VALUES (?1, ?2)",
            (hash, tx),
        )?;
        Ok(())
    }

    /// Insert a transaction whose hash was precalculated, to save a call to calculate_hash() if it
    /// is already known
    pub fn insert_transaction(&self, hash: &Hash, tx: &SignedTransaction) -> Result<()> {
        self.insert_transaction_with_db_tx(&self.block_store.lock().unwrap(), hash, tx)
    }

    pub fn remove_transactions_in_block(&self, block_hash: &Hash) -> Result<()> {
        self.block_store.lock().unwrap().execute(
            "DELETE FROM transactions WHERE block_hash = ?1",
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
                (hash, view, height, parent_hash, signature, state_root_hash, timestamp, qc, agg)
            VALUES (:hash, :view, :height, :parent_hash, :signature, :state_root_hash, :timestamp, :qc, :agg)",
            named_params! {
                ":hash": block.header.hash,
                ":view": block.header.view,
                ":height": block.header.number,
                ":parent_hash": block.header.parent_hash,
                ":signature": block.header.signature,
                ":state_root_hash": block.header.state_root_hash,
                ":timestamp": SystemTimeSqlable(block.header.timestamp),
                ":qc": block.qc,
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
                    parent_hash: row.get(3)?,
                    signature: row.get(4)?,
                    state_root_hash: row.get(5)?,
                    timestamp: row.get::<_, SystemTimeSqlable>(6)?.into(),
                },
                qc: row.get(7)?,
                agg: row.get(8)?,
                transactions: vec![],
            })
        }
        macro_rules! query_block {
            ($cond: tt, $key: tt) => {
                self.block_store.lock().unwrap().query_row(concat!("SELECT hash, view, height, parent_hash, signature, state_root_hash, timestamp, qc, agg FROM blocks WHERE ", $cond), [$key], make_block).optional()?
            };
        }
        Ok(match key {
            Either::Left(hash) => {
                query_block!("hash = ?1", hash)
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
        let transactions = self
            .block_store
            .lock()
            .unwrap()
            .prepare_cached("SELECT tx_hash FROM receipts WHERE block_hash = ?1")?
            .query_map([block.header.hash], |row| row.get(0))?
            .collect::<Result<Vec<Hash>, _>>()?;
        block.transactions = transactions;
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
                "SELECT 1 FROM blocks WHERE hash = ?1",
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
            contract_address: row.get::<_, Option<AddressSqlable>>(5)?.map(|a| a.into()),
            logs: row.get::<_, VecLogSqlable>(6)?.into(),
            accepted: row.get(7)?,
            errors: row.get::<_, MapScillaErrorSqlable>(8)?.into(),
            exceptions: row.get::<_, VecScillaExceptionSqlable>(9)?.into(),
        })
    }

    pub fn insert_transaction_receipt_with_db_tx(
        &self,
        sqlite_tx: &Connection,
        receipt: TransactionReceipt,
    ) -> Result<()> {
        sqlite_tx.execute(
            "INSERT INTO receipts
                (tx_hash, block_hash, index, success, gas_used, contract_address, logs, accepted, errors, exceptions)
            VALUES (:tx_hash, :block_hash, :index, :success, :gas_used, :contract_address, :logs, :accepted, :errors, :exceptions)
            ON CONFLICT DO NOTHING",
            named_params! {
                ":tx_hash": receipt.tx_hash,
                ":block_hash": receipt.block_hash,
                ":index": receipt.index,
                ":success": receipt.success,
                ":gas_used": receipt.gas_used,
                ":contract_address": receipt.contract_address.map(|a| AddressSqlable(a)),
                ":logs": VecLogSqlable(receipt.logs),
                ":accepted": receipt.accepted,
                ":errors": MapScillaErrorSqlable(receipt.errors.into()),
                ":exceptions": VecScillaExceptionSqlable(receipt.exceptions.into()),
            })?;

        Ok(())
    }

    pub fn insert_transaction_receipt(&self, receipt: TransactionReceipt) -> Result<()> {
        self.insert_transaction_receipt_with_db_tx(&self.block_store.lock().unwrap(), receipt)
    }

    pub fn get_transaction_receipt(&self, txn_hash: &Hash) -> Result<Option<TransactionReceipt>> {
        Ok(self.block_store.lock().unwrap().query_row("SELECT tx_hash, block_hash, index, success, gas_used, contract_address, logs, accepted, errors, exceptions FROM receipts WHERE tx_hash = ?1", [txn_hash], Self::make_receipt).optional()?)
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: &Hash,
    ) -> Result<Vec<TransactionReceipt>> {
        Ok(self.block_store.lock().unwrap().prepare_cached("SELECT tx_hash, block_hash, index, success, gas_used, contract_address, logs, accepted, errors, exceptions FROM receipts WHERE block_hash = ?1")?.query_map([block_hash], Self::make_receipt)?.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn remove_transaction_receipts_in_block(&self, block_hash: &Hash) -> Result<()> {
        self.block_store
            .lock()
            .unwrap()
            .execute("DELETE FROM receipts WHERE block_hash = ?1", [block_hash])?;
        Ok(())
    }
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
