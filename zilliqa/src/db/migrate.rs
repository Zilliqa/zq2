use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::Result;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use revm::primitives::Address;
use rusqlite::{
    types::{FromSql, FromSqlError, ToSqlOutput},
    Connection, ToSql,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::Db;
use crate::{
    crypto::{BlsSignature, Hash},
    exec::{ScillaError, ScillaException, ScillaTransition},
    message::{AggregateQc, Block, BlockHeader, QuorumCertificate},
    time::SystemTime,
    transaction::{EvmGas, Log, SignedTransaction, TransactionReceipt},
};

macro_rules! sqlify_with_bincode {
    ($type: ty) => {
        impl ToSql for $type {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                let data = bincode::serialize(self)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e))?;
                Ok(ToSqlOutput::from(data))
            }
        }
        impl FromSql for $type {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                let blob = value.as_blob()?;
                bincode::deserialize(blob).map_err(|e| FromSqlError::Other(e))
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

impl FromSql for Bytes {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        Ok(Self(
            value
                .as_bytes_or_null()?
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        ))
    }
}

struct Bytes(Vec<u8>);

struct BlockRow {
    block_hash: Hash,
    view: u64,
    height: u64,
    signature: Bytes,
    state_root_hash: Hash,
    transactions_root_hash: Hash,
    receipts_root_hash: Hash,
    timestamp: SystemTimeSqlable,
    gas_used: EvmGas,
    gas_limit: EvmGas,
    qc: Bytes,
    agg: Option<AggregateQc>,
    is_canonical: bool,
    transactions: Bytes,
}

impl Db {
    pub fn migrate_from(self, mut sql: Connection) -> Result<Db> {
        sql.trace(Some(|statement| tracing::trace!(statement, "sql executed")));

        let write = self.write()?;
        let mut blocks = write.blocks()?;
        let mut transactions = write.transactions()?;
        let mut receipts = write.receipts()?;
        let mut touched_address_index = write.touched_address_index()?;
        let mut finalized_view = write.finalized_view()?;
        let mut view = write.view()?;
        let mut high_qc = write.high_qc()?;
        let mut state_trie = write.state_trie()?;

        info!("migrating blocks");
        // FIXME: THIS EXCLUDES BLOCKS WITH NO TRANSACTIONS!!!
        let mut old_blocks = sql.prepare(
            r#"
            SELECT
                b.block_hash,
                b.view,
                b.height,
                b.signature,
                b.state_root_hash,
                b.transactions_root_hash,
                b.receipts_root_hash,
                b.timestamp,
                b.gas_used,
                b.gas_limit,
                b.qc,
                b.agg,
                b.is_canonical,
                r.tx_hashes
            FROM
                blocks b
                LEFT JOIN (
                    SELECT
                        block_hash,
                        GROUP_CONCAT(tx_hash, "") AS tx_hashes
                    FROM receipts
                    GROUP BY block_hash
                ) r USING (block_hash)
            ;
        "#,
        )?;
        let old_blocks = old_blocks
            .query_map((), |row| {
                Ok(BlockRow {
                    block_hash: row.get(0)?,
                    view: row.get(1)?,
                    height: row.get(2)?,
                    signature: row.get(3)?,
                    state_root_hash: row.get(4)?,
                    transactions_root_hash: row.get(5)?,
                    receipts_root_hash: row.get(6)?,
                    timestamp: row.get(7)?,
                    gas_used: row.get(8)?,
                    gas_limit: row.get(9)?,
                    qc: row.get(10)?,
                    agg: row.get(11)?,
                    is_canonical: row.get(12)?,
                })
            })?
            .collect::<Vec<_>>();
        info!("collected {} blocks", old_blocks.len());

        info!("collecting receipts");
        let mut old_receipts = sql.prepare(
            "
            SELECT
                block_hash,
                tx_index,
                tx_hash,
                success,
                gas_used,
                cumulative_gas_used,
                contract_address,
                logs,
                transitions,
                accepted,
                errors,
                exceptions
            FROM
                receipts
            ;
        ",
        )?;
        let mut old_receipts = old_receipts
            .query_map((), |row| {
                Ok(TransactionReceipt {
                    block_hash: row.get(0)?,
                    index: row.get(1)?,
                    tx_hash: row.get(2)?,
                    success: row.get(3)?,
                    gas_used: row.get(4)?,
                    cumulative_gas_used: row.get(5)?,
                    contract_address: row.get::<_, Option<AddressSqlable>>(6)?.map(|a| a.0),
                    logs: row.get::<_, VecLogSqlable>(7)?.0,
                    transitions: row.get::<_, VecScillaTransitionSqlable>(8)?.0,
                    accepted: row.get(9)?,
                    errors: row.get::<_, MapScillaErrorSqlable>(10)?.0,
                    exceptions: row.get::<_, VecScillaExceptionSqlable>(11)?.0,
                })
            })?
            .collect::<Result<Vec<_>, rusqlite::Error>>()?;
        info!("collected {} receipts", old_receipts.len());
        old_receipts.sort_unstable_by_key(|r| r.tx_hash.0);
        info!("sorted receipts");
        for receipt in &old_receipts {
            receipts.insert(receipt)?;
        }
        info!("migrated receipts");

        info!("building block to transaction map");
        let mut txn_map: FxHashMap<_, Vec<_>> =
            FxHashMap::with_capacity_and_hasher(old_blocks.len(), FxBuildHasher);
        for receipt in &old_receipts {
            txn_map
                .entry(receipt.block_hash)
                .or_default()
                .push(receipt.tx_hash);
        }

        let mut new_blocks: Vec<_> = Vec::with_capacity(old_blocks.len());
        old_blocks
            .into_par_iter()
            .map(|block| {
                let block = block.unwrap();
                let is_canonical = block.is_canonical;
                let block = Block {
                    header: BlockHeader {
                        view: block.view,
                        number: block.height,
                        hash: block.block_hash,
                        qc: bincode::deserialize(&block.qc.0).unwrap(),
                        signature: bincode::deserialize(&block.signature.0).unwrap(),
                        state_root_hash: block.state_root_hash,
                        transactions_root_hash: block.transactions_root_hash,
                        receipts_root_hash: block.receipts_root_hash,
                        timestamp: block.timestamp.into(),
                        gas_used: block.gas_used,
                        gas_limit: block.gas_limit,
                    },
                    agg: block.agg,
                    transactions: txn_map.get(&block.block_hash).cloned().unwrap_or_default(),
                };
                (block, is_canonical)
            })
            .collect_into_vec(&mut new_blocks);
        info!("converted blocks");
        // NO JOIN
        // 2025-01-15T23:08:31.434696Z  INFO zilliqa::db::migrate: 205: migrating blocks
        // 2025-01-15T23:09:21.089923Z  INFO zilliqa::db::migrate: 245: collected 6748697 blocks
        // 2025-01-15T23:10:52.074800Z  INFO zilliqa::db::migrate: 274: converted blocks
        // 2025-01-15T23:15:39.901029Z  INFO zilliqa::db::migrate: 284: migrating transactions

        // WITH JOIN
        // 2025-01-16T10:40:31.386692Z  INFO zilliqa::db::migrate: 205: migrating blocks
        // 2025-01-16T10:48:53.807207Z  INFO zilliqa::db::migrate: 253: collected 6748697 blocks
        // 2025-01-16T10:50:45.557635Z  INFO zilliqa::db::migrate: 282: converted blocks
        // 2025-01-16T10:53:50.503858Z  INFO zilliqa::db::migrate: 297: migrating transactions

        blocks.bulk_insert(new_blocks)?;
        info!("migrated blocks");

        info!("migrating transactions");
        let mut old_txns = sql.prepare(
            "
            SELECT
                tx_hash,
                data
            FROM
                transactions
            ;
        ",
        )?;
        let old_txns = old_txns
            .query_map((), |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Vec<_>>();
        for txn in old_txns {
            let (txn_hash, txn) = txn?;
            transactions.insert(txn_hash, &txn)?;
        }

        info!("migrating touched address index");
        let mut old_touched_address_index = sql.prepare(
            "
            SELECT
                address,
                tx_hash
            FROM
                touched_address_index
            ;
        ",
        )?;
        let old_touched_address_index = old_touched_address_index
            .query_map((), |row| {
                Ok((row.get::<_, AddressSqlable>(0)?, row.get(1)?))
            })?
            .collect::<Vec<_>>();

        for pair in old_touched_address_index {
            let (address, txn_hash) = pair?;
            touched_address_index.insert(address.0, txn_hash)?;
        }

        info!("migrating consensus info");
        let (old_finalized_view, old_view, old_high_qc, old_high_qc_updated_at) = sql.query_row(
            "
            SELECT
                finalized_view,
                view,
                high_qc,
                high_qc_updated_at
            FROM
                tip_info
            ;
            ",
            (),
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, SystemTimeSqlable>(3)?,
                ))
            },
        )?;

        finalized_view.set(old_finalized_view)?;
        view.set(old_view)?;
        high_qc.set_with_updated_at(&old_high_qc, old_high_qc_updated_at.0)?;

        info!("migrating state trie");
        let mut old_state_trie = sql.prepare(
            "
            SELECT
                key,
                value
            FROM
                state_trie
            ;
        ",
        )?;
        let old_state_trie = old_state_trie
            .query_map((), |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get(1)?)))?
            .collect::<Vec<_>>();

        for pair in old_state_trie {
            let (key, value) = pair?;
            state_trie.insert(&key, &value)?;
        }
        std::mem::drop((
            blocks,
            transactions,
            receipts,
            touched_address_index,
            finalized_view,
            view,
            high_qc,
            state_trie,
        ));

        info!("committing");
        write.commit()?;

        info!("compacting");
        let path = self.path.clone();
        let mut db = self.into_raw();
        db.compact()?;

        Ok(Db {
            db: Arc::new(db),
            path,
        })
    }
}
