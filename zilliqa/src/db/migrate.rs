use std::{collections::BTreeMap, mem, sync::Arc, time::Duration};

use anyhow::Result;
use indicatif::{ProgressBar, ProgressIterator, ProgressStyle};
use itertools::Itertools;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use revm::primitives::Address;
use rusqlite::{
    Connection, ToSql,
    types::{FromSql, FromSqlError, ToSqlOutput},
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
    pub fn migrate_from(self, sql: Connection) -> Result<Db> {
        sql.trace_v2(
            rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|statement| {
                if let rusqlite::trace::TraceEvent::Stmt(_, statement) = statement {
                    tracing::trace!(statement, "sql executed");
                }
            }),
        );

        let write = self.write()?;
        let mut blocks = write.blocks()?;
        let mut transactions = write.transactions()?;
        let mut receipts = write.receipts()?;
        let mut touched_address_index = write.touched_address_index()?;
        let mut finalized_view = write.finalized_view()?;
        let mut view = write.view()?;
        let mut high_qc = write.high_qc()?;
        let mut state_trie = write.state_trie()?;

        fn progress(message: &'static str) -> ProgressBar {
            ProgressBar::new_spinner()
                .with_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner} {human_pos} ({per_sec}) {msg}")
                        .unwrap(),
                )
                .with_message(message)
        }
        const CHUNK_SIZE: usize = 500_000;

        info!("migrating blocks");
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
                    transactions: row.get(13)?,
                })
            })?
            .progress_with(progress("migrating blocks"))
            .chunks(CHUNK_SIZE);
        let old_blocks = old_blocks.into_iter().flat_map(|chunk| {
            let chunk = chunk.collect_vec();
            let mut converted = Vec::with_capacity(chunk.len());
            chunk.into_par_iter().map(|row| {
                let block = row.unwrap();
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
                    transactions: block
                        .transactions
                        .0
                        .chunks_exact(32)
                        .map(|b| Hash::from_bytes(b).unwrap())
                        .collect(),
                };
                (block, is_canonical)
            }).collect_into_vec(&mut converted);
            converted
        });
        for (block, is_canonical) in old_blocks {
            blocks.insert(&block)?;
            if !is_canonical {
                blocks.set_non_canonical(block.view())?;
            }
        }

        info!("migrating receipts");
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
            ORDER BY tx_hash ASC
            ;
        ",
        )?;
        let old_receipts = old_receipts.query_map((), |row| {
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
        })?;
        for chunk in old_receipts
            .progress_with(progress("migrating receipts"))
            .chunks(CHUNK_SIZE)
            .into_iter()
        {
            let chunk = chunk.collect_vec();
            for receipt in chunk {
                receipts.insert(&receipt?)?;
            }
        }

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
        let old_txns = old_txns.query_map((), |row| Ok((row.get(0)?, row.get(1)?)))?;
        for chunk in old_txns
            .progress_with(progress("migrating transactions"))
            .chunks(CHUNK_SIZE)
            .into_iter()
        {
            let chunk = chunk.collect_vec();
            for txn in chunk {
                let (txn_hash, txn) = txn?;
                transactions.insert(txn_hash, &txn)?;
            }
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
        let old_touched_address_index = old_touched_address_index.query_map((), |row| {
            Ok((row.get::<_, AddressSqlable>(0)?, row.get(1)?))
        })?;

        for chunk in old_touched_address_index
            .progress_with(progress("migrating touched address index"))
            .chunks(CHUNK_SIZE)
            .into_iter()
        {
            let chunk = chunk.collect_vec();
            for pair in chunk {
                let (address, txn_hash) = pair?;
                touched_address_index.insert(address.0, txn_hash)?;
            }
        }

        info!("migrating consensus info");
        let (old_finalized_view, old_view, old_voted_in_view, old_high_qc, old_high_qc_updated_at) =
            sql.query_row(
                "
            SELECT
                finalized_view,
                view,
                voted_in_view,
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
                        row.get(3)?,
                        row.get::<_, SystemTimeSqlable>(4)?,
                    ))
                },
            )?;

        finalized_view.set(old_finalized_view)?;
        view.set(old_view, old_voted_in_view)?;
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
        let old_state_trie =
            old_state_trie.query_map((), |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get(1)?)))?;

        for chunk in old_state_trie
            .progress_with(progress("migrating state trie"))
            .chunks(CHUNK_SIZE)
            .into_iter()
        {
            let chunk = chunk.collect_vec();
            for pair in chunk {
                let (key, value) = pair?;
                state_trie.insert(&key, &value)?;
            }
        }
        mem::drop((
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
