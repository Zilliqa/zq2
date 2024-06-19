use std::{collections::BTreeMap, path::Path, sync::Mutex, time::Duration};

use alloy_primitives::Address;
use anyhow::Result;
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
    exec::{ScillaError, ScillaException, ScillaTransition},
    message::{AggregateQc, Block, BlockHeader, QuorumCertificate},
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, TransactionReceipt},
};

#[derive(Debug)]
pub struct Db {
    state_root: sled::Db,
    block_store: Mutex<Connection>,
}

const STATE_TRIE_TREE: &[u8] = b"state_trie";

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
        Ok(SystemTimeSqlable(
            SystemTime::UNIX_EPOCH + Duration::from_secs(u64::column_result(value)?),
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
                    Connection::open(path.join("blockdata.db"))?,
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
                block_hash BLOB NOT NULL PRIMARY KEY,
                view INTEGER NOT NULL UNIQUE,
                height INTEGER NOT NULL,
                parent_hash BLOB NOT NULL,
                signature BLOB NOT NULL,
                state_root_hash BLOB NOT NULL,
                transactions_root_hash BLOB NOT NULL,
                receipts_root_hash BLOB NOT NULL,
                timestamp NUMERIC NOT NULL,
                gas_used INTEGER NOT NULL,
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
            .execute("INSERT INTO tip_info (latest_finalized_view) VALUES (?1) ON CONFLICT DO UPDATE SET latest_finalized_view = ?1",
                     [view])?;
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
                "SELECT height FROM main_chain_canonical_blocks ORDER BY height DESC LIMIT 1",
                (),
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn set_high_qc(&self, high_qc: QuorumCertificate) -> Result<()> {
        self.block_store.lock().unwrap().execute(
            "INSERT INTO tip_info (high_qc) VALUES (?1) ON CONFLICT DO UPDATE SET high_qc = ?1",
            [high_qc],
        )?;
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
                (block_hash, view, height, parent_hash, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, qc, agg)
            VALUES (:block_hash, :view, :height, :parent_hash, :signature, :state_root_hash, :transactions_root_hash, :receipts_root_hash, :timestamp, :gas_used, :qc, :agg)",
            named_params! {
                ":block_hash": block.header.hash,
                ":view": block.header.view,
                ":height": block.header.number,
                ":parent_hash": block.header.parent_hash,
                ":signature": block.header.signature,
                ":state_root_hash": block.header.state_root_hash,
                ":transactions_root_hash": block.header.transactions_root_hash,
                ":receipts_root_hash": block.header.receipts_root_hash,
                ":timestamp": SystemTimeSqlable(block.header.timestamp),
                ":gas_used": block.header.gas_used,
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
                    transactions_root_hash: row.get(6)?,
                    receipts_root_hash: row.get(7)?,
                    timestamp: row.get::<_, SystemTimeSqlable>(8)?.into(),
                    gas_used: row.get(9)?,
                },
                qc: row.get(10)?,
                agg: row.get(11)?,
                transactions: vec![],
            })
        }
        macro_rules! query_block {
            ($cond: tt, $key: tt) => {
                self.block_store.lock().unwrap().query_row(concat!("SELECT block_hash, view, height, parent_hash, signature, state_root_hash, transactions_root_hash, receipts_root_hash, timestamp, gas_used, qc, agg FROM blocks WHERE ", $cond), [$key], make_block).optional()?
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
