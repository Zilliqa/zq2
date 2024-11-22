//! This module defines the tables in our database and provides the abstractions used to interact with them.
//!
//! Each logical table may be backed by one or more concrete tables, for additional indices.

#![allow(clippy::type_complexity)]

use std::{ops::RangeInclusive, time::Duration};

use anyhow::{Result, anyhow};
use bincode::{DefaultOptions, Options};
use redb::{
    MultimapTable, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable, ReadTransaction,
    ReadableMultimapTable, ReadableTable, ReadableTableMetadata, Table, TableDefinition,
    WriteTransaction,
};
use revm::primitives::Address;

use super::Db;
use crate::{
    crypto::Hash,
    message::{Block, QuorumCertificate},
    time::SystemTime,
    transaction::{SignedTransaction, TransactionReceipt},
};

// Each logical table consists of:
// 1. The `TableDefinition`s backing this table.
// 2. A table `struct` which contains the methods to access this table. The struct is generic, but in practice only
// takes two possible values - One returned by `ReadTx` and one returned by `WriteTx`. The concrete table consists of
// of the opened `redb` tables.
// 3. An `impl` block which contains all the read-only methods for the table. The implementation is generic over the
// `ReadableTable` trait, which means the methods are callable on both `ReadTx`s and `WriteTx`s.
// 4. An `impl` block which contains all the write-only methods for the table. The implementation uses the concrete
// mutable `Table` types and thus is only callable on a `WriteTx`.

// blocks: view -> block
// blocks_hash_index: hash -> view
// blocks_height_index: height -> [view]
// block_is_canonical: view -> bool
const BLOCKS: TableDefinition<u64, Vec<u8>> = TableDefinition::new("blocks");
const BLOCKS_HASH_INDEX: TableDefinition<&[u8; 32], u64> =
    TableDefinition::new("blocks_hash_index");
const BLOCKS_HEIGHT_INDEX: MultimapTableDefinition<u64, u64> =
    MultimapTableDefinition::new("blocks_height_index");
const BLOCK_IS_CANONICAL: TableDefinition<u64, bool> = TableDefinition::new("block_is_canonical");

pub struct BlocksTable<T1, T2, T3, T4> {
    blocks: T1,
    blocks_hash_index: T2,
    blocks_height_index: T3,
    block_is_canonical: T4,
}

impl<T1, T2, T3, T4> BlocksTable<T1, T2, T3, T4>
where
    T1: ReadableTable<u64, Vec<u8>>,
    T2: ReadableTable<&'static [u8; 32], u64>,
    T3: ReadableMultimapTable<u64, u64>,
    T4: ReadableTable<u64, bool>,
{
    pub fn by_view(&self, view: u64) -> Result<Option<Block>> {
        let Some(block) = self.blocks.get(view)? else {
            return Ok(None);
        };
        Ok(Some(bincode().deserialize(&block.value())?))
    }

    pub fn max_canonical_by_view(&self) -> Result<Option<Block>> {
        // Search the `block_is_canonical` table in reverse until we find the canonical block with the maximum view.
        for kv in self.block_is_canonical.iter()?.rev() {
            let (view, canonical) = kv?;
            if canonical.value() {
                let view = view.value();
                return self.by_view(view);
            }
        }

        // There are no canonical blocks.
        Ok(None)
    }

    pub fn max_by_view(&self) -> Result<Option<Block>> {
        let Some((_, block)) = self.blocks.last()? else {
            return Ok(None);
        };
        Ok(Some(bincode().deserialize(&block.value())?))
    }

    pub fn min_by_view(&self) -> Result<Option<Block>> {
        let Some((_, block)) = self.blocks.first()? else {
            return Ok(None);
        };
        Ok(Some(bincode().deserialize(&block.value())?))
    }

    pub fn max_canonical_by_view_count(&self, count: usize) -> Result<Vec<Block>> {
        let mut blocks = Vec::with_capacity(count);
        for kv in self.block_is_canonical.iter()?.rev() {
            let (view, canonical) = kv?;
            if canonical.value() {
                let view = view.value();
                blocks.push(self.by_view(view)?.ok_or(anyhow!("missing block"))?);
            }
            if blocks.len() == count {
                break;
            }
        }
        Ok(blocks)
    }

    pub fn by_hash(&self, hash: Hash) -> Result<Option<Block>> {
        let Some(view) = self.blocks_hash_index.get(&hash.0)? else {
            return Ok(None);
        };
        self.by_view(view.value())
    }

    pub fn canonical_by_height(&self, height: u64) -> Result<Option<Block>> {
        for view in self.blocks_height_index.get(height)? {
            // Check if this block is canonical.
            let view = view?.value();
            let canonical = self
                .block_is_canonical
                .get(view)?
                .ok_or(anyhow!("missing canonical"))?
                .value();
            if canonical {
                return self.by_view(view);
            }
        }

        Ok(None)
    }

    pub fn height_range(&self) -> Result<RangeInclusive<u64>> {
        let mut iter = self.blocks_height_index.iter()?;
        let (first, _) = iter.next().ok_or(anyhow!("no blocks"))??;
        let first = first.value();
        let last = match iter.last() {
            Some(last) => last?.0.value(),
            None => first,
        };

        Ok(first..=last)
    }

    pub fn contains(&self, view: u64) -> Result<bool> {
        Ok(self.blocks.get(view)?.is_some())
    }

    pub fn contains_hash(&self, hash: Hash) -> Result<bool> {
        Ok(self.blocks_hash_index.get(&hash.0)?.is_some())
    }

    pub fn iter(&self) -> Result<impl Iterator<Item = Result<Block>> + '_> {
        Ok(self
            .blocks
            .iter()?
            .map(|b| Ok(bincode().deserialize(&b?.1.value())?)))
    }
}

impl
    BlocksTable<
        Table<'_, u64, Vec<u8>>,
        Table<'_, &[u8; 32], u64>,
        MultimapTable<'_, u64, u64>,
        Table<'_, u64, bool>,
    >
{
    pub fn insert(&mut self, block: &Block) -> Result<()> {
        self.blocks
            .insert(block.view(), bincode().serialize(block)?)?;
        self.blocks_hash_index
            .insert(&block.hash().0, block.view())?;
        self.blocks_height_index
            .insert(block.number(), block.view())?;
        self.block_is_canonical.insert(block.view(), true)?;
        Ok(())
    }

    pub fn delete(&mut self, view: u64) -> Result<()> {
        let Some(block) = self.blocks.remove(view)? else {
            return Ok(());
        };
        let block: Block = bincode().deserialize(&block.value())?;
        self.blocks_hash_index.remove(&block.hash().0)?;
        self.blocks_height_index
            .remove(block.number(), block.view())?;
        self.block_is_canonical.remove(block.view())?;
        Ok(())
    }

    pub fn set_canonical(&mut self, view: u64) -> Result<()> {
        self.block_is_canonical.insert(view, true)?;
        Ok(())
    }

    pub fn set_non_canonical(&mut self, view: u64) -> Result<()> {
        self.block_is_canonical.insert(view, false)?;
        Ok(())
    }
}

const TRANSACTIONS: TableDefinition<&[u8; 32], Vec<u8>> = TableDefinition::new("transactions");

pub struct TransactionsTable<T>(T);

impl<T: ReadableTable<&'static [u8; 32], Vec<u8>>> TransactionsTable<T> {
    pub fn get(&self, hash: Hash) -> Result<Option<SignedTransaction>> {
        let Some(txn) = self.0.get(&hash.0)? else {
            return Ok(None);
        };
        Ok(Some(bincode().deserialize(&txn.value())?))
    }

    pub fn contains(&self, hash: Hash) -> Result<bool> {
        Ok(self.0.get(&hash.0)?.is_some())
    }
}

impl<T: ReadableTableMetadata> TransactionsTable<T> {
    pub fn count(&self) -> Result<u64> {
        Ok(self.0.len()?)
    }
}

impl TransactionsTable<Table<'_, &[u8; 32], Vec<u8>>> {
    pub fn insert(&mut self, hash: Hash, txn: &SignedTransaction) -> Result<()> {
        self.0.insert(&hash.0, bincode().serialize(&txn)?)?;
        Ok(())
    }

    fn delete(&mut self, hash: Hash) -> Result<()> {
        self.0.remove(&hash.0)?;
        Ok(())
    }
}

const RECEIPTS: TableDefinition<&[u8; 32], Vec<u8>> = TableDefinition::new("receipts");

pub struct ReceiptsTable<T>(T);

impl<T: ReadableTable<&'static [u8; 32], Vec<u8>>> ReceiptsTable<T> {
    pub fn get(&self, hash: Hash) -> Result<Option<TransactionReceipt>> {
        let Some(txn) = self.0.get(&hash.0)? else {
            return Ok(None);
        };
        Ok(Some(bincode().deserialize(&txn.value())?))
    }
}

impl ReceiptsTable<Table<'_, &'static [u8; 32], Vec<u8>>> {
    pub fn insert(&mut self, receipt: &TransactionReceipt) -> Result<()> {
        self.0
            .insert(&receipt.tx_hash.0, bincode().serialize(receipt)?)?;
        Ok(())
    }

    fn delete(&mut self, hash: Hash) -> Result<()> {
        self.0.remove(&hash.0)?;
        Ok(())
    }
}

// touched_address_index: address -> [(index, txn_hash)]
// The index of each entry is contiguous. This ensures values are returned in the same order they were inserted.
// touched_address_reverse_index: txn_hash -> (index, address)
const TOUCHED_ADDRESS_INDEX: MultimapTableDefinition<&[u8; 20], (u64, &[u8; 32])> =
    MultimapTableDefinition::new("touched_address_index");
const TOUCHED_ADDRESS_REVERSE_INDEX: TableDefinition<&[u8; 32], (u64, &[u8; 20])> =
    TableDefinition::new("touched_address_reverse_index");

pub struct TouchedAddressIndex<T1, T2> {
    index: T1,
    reverse_index: T2,
}

impl<T1, T2> TouchedAddressIndex<T1, T2>
where
    T1: ReadableMultimapTable<&'static [u8; 20], (u64, &'static [u8; 32])>,
    T2: ReadableTable<&'static [u8; 32], (u64, &'static [u8; 20])>,
{
    pub fn get(&self, address: Address) -> Result<Vec<Hash>> {
        let hashes = self.index.get(&<[u8; 20]>::from(address))?;
        hashes
            .map(|hash| Ok(Hash(*hash?.value().1)))
            .collect::<Result<_>>()
    }
}

impl
    TouchedAddressIndex<
        MultimapTable<'_, &[u8; 20], (u64, &[u8; 32])>,
        Table<'_, &[u8; 32], (u64, &[u8; 20])>,
    >
{
    pub fn insert(&mut self, address: Address, txn_hash: Hash) -> Result<()> {
        let key = &<[u8; 20]>::from(address);
        let next_index = self
            .index
            .get(key)?
            .next_back()
            .map(|value| Ok::<_, redb::Error>(value?.value().0 + 1))
            .transpose()?
            .unwrap_or(0);

        self.index.insert(key, (next_index, &txn_hash.0))?;
        self.reverse_index.insert(&txn_hash.0, (next_index, key))?;
        Ok(())
    }

    pub fn delete_by_txn_hash(&mut self, txn_hash: Hash) -> Result<()> {
        let Some(value) = self.reverse_index.remove(&txn_hash.0)? else {
            return Ok(());
        };
        let (index, address) = value.value();
        self.index.remove(address, (index, &txn_hash.0))?;
        Ok(())
    }
}

const FINALIZED_VIEW: TableDefinition<(), u64> = TableDefinition::new("finalized_view");

pub struct FinalizedViewTable<T>(T);

impl<T: ReadableTable<(), u64>> FinalizedViewTable<T> {
    pub fn get(&self) -> Result<Option<u64>> {
        Ok(self.0.get(())?.map(|v| v.value()))
    }
}

impl FinalizedViewTable<Table<'_, (), u64>> {
    pub fn set(&mut self, finalized_view: u64) -> Result<()> {
        self.0.insert((), finalized_view)?;
        Ok(())
    }
}

const VIEW: TableDefinition<(), (u64, bool)> = TableDefinition::new("view");

pub struct ViewTable<T>(T);

impl<T: ReadableTable<(), (u64, bool)>> ViewTable<T> {
    pub fn get(&self) -> Result<Option<u64>> {
        Ok(self.0.get(())?.map(|v| v.value().0))
    }

    pub fn voted(&self) -> Result<bool> {
        Ok(self.0.get(())?.map(|v| v.value().1).unwrap_or_default())
    }
}

impl ViewTable<Table<'_, (), (u64, bool)>> {
    /// Sets the provided view if it is greater than the existing view. Returns true if the value was updated.
    pub fn set(&mut self, view: u64, voted: bool) -> Result<bool> {
        let current = self.get()?;
        let update = current.map(|c| view > c).unwrap_or(true);
        if update {
            self.0.insert((), (view, voted))?;
        }
        Ok(update)
    }
}

const HIGH_QC: TableDefinition<(), (Vec<u8>, u64, u32)> = TableDefinition::new("high_qc");

pub struct HighQcTable<T>(T);

impl<T: ReadableTable<(), (Vec<u8>, u64, u32)>> HighQcTable<T> {
    pub fn get(&self) -> Result<Option<(QuorumCertificate, SystemTime)>> {
        let Some(value) = self.0.get(())? else {
            return Ok(None);
        };
        let (high_qc, updated_at_secs, updated_at_subsec_nanos) = value.value();
        let high_qc = bincode().deserialize(&high_qc)?;
        let high_qc_updated_at =
            SystemTime::UNIX_EPOCH + Duration::new(updated_at_secs, updated_at_subsec_nanos);
        Ok(Some((high_qc, high_qc_updated_at)))
    }
}

impl HighQcTable<Table<'_, (), (Vec<u8>, u64, u32)>> {
    pub fn set(&mut self, high_qc: &QuorumCertificate) -> Result<()> {
        let high_qc = bincode().serialize(high_qc)?;
        let high_qc_updated_at = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        self.0.insert(
            (),
            (
                high_qc,
                high_qc_updated_at.as_secs(),
                high_qc_updated_at.subsec_nanos(),
            ),
        )?;
        Ok(())
    }

    pub fn set_with_updated_at(
        &mut self,
        high_qc: &QuorumCertificate,
        updated_at: SystemTime,
    ) -> Result<()> {
        let high_qc = bincode().serialize(high_qc)?;
        let high_qc_updated_at = updated_at.duration_since(SystemTime::UNIX_EPOCH)?;
        self.0.insert(
            (),
            (
                high_qc,
                high_qc_updated_at.as_secs(),
                high_qc_updated_at.subsec_nanos(),
            ),
        )?;
        Ok(())
    }
}

const STATE_TRIE: TableDefinition<&[u8; 32], Vec<u8>> = TableDefinition::new("state_trie");

pub struct StateTrieTable<T>(T);

impl<T: ReadableTable<&'static [u8; 32], Vec<u8>>> StateTrieTable<T> {
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(&<[u8; 32]>::try_from(key)?)?.map(|v| v.value()))
    }
}

impl StateTrieTable<Table<'_, &'static [u8; 32], Vec<u8>>> {
    pub fn insert(&mut self, key: &[u8], value: &Vec<u8>) -> Result<()> {
        self.0.insert(&<[u8; 32]>::try_from(key)?, value)?;
        Ok(())
    }
}

fn bincode() -> DefaultOptions {
    // | Byte limit | Endianness | Int Encoding | Trailing Behavior |
    // |------------|------------|--------------|-------------------|
    // | Unlimited  | Little     | Varint       | Reject            |
    DefaultOptions::new()
}

impl Db {
    /// Begin a read transaction.
    ///
    /// Captures a snapshot of the database, so that only data committed before calling this method is visible in the
    /// transaction.
    ///
    /// Read transactions may exist concurrently with writes.
    pub fn read(&self) -> Result<TxRead> {
        Ok(TxRead(self.db.begin_read()?))
    }

    /// Begin a write transaction.
    ///
    /// Only a single write may be in progress at a time. If a write is in progress, this function will block until it
    /// completes.
    ///
    /// You must call `[TxWrite::commit]` to persist the writes performed in this transaction. After committting, all
    /// writes will be visible to future transactions.
    pub fn write(&self) -> Result<TxWrite> {
        let mut tx = self.db.begin_write()?;
        tx.set_quick_repair(true);
        Ok(TxWrite(tx))
    }
}

pub struct TxRead(ReadTransaction);

impl TxRead {
    pub fn blocks(
        &self,
    ) -> Result<
        BlocksTable<
            ReadOnlyTable<u64, Vec<u8>>,
            ReadOnlyTable<&'static [u8; 32], u64>,
            ReadOnlyMultimapTable<u64, u64>,
            ReadOnlyTable<u64, bool>,
        >,
    > {
        Ok(BlocksTable {
            blocks: self.0.open_table(BLOCKS)?,
            blocks_hash_index: self.0.open_table(BLOCKS_HASH_INDEX)?,
            blocks_height_index: self.0.open_multimap_table(BLOCKS_HEIGHT_INDEX)?,
            block_is_canonical: self.0.open_table(BLOCK_IS_CANONICAL)?,
        })
    }
    pub fn transactions(
        &self,
    ) -> Result<TransactionsTable<ReadOnlyTable<&'static [u8; 32], Vec<u8>>>> {
        Ok(TransactionsTable(self.0.open_table(TRANSACTIONS)?))
    }
    pub fn receipts(&self) -> Result<ReceiptsTable<ReadOnlyTable<&'static [u8; 32], Vec<u8>>>> {
        Ok(ReceiptsTable(self.0.open_table(RECEIPTS)?))
    }
    pub fn touched_address_index(
        &self,
    ) -> Result<
        TouchedAddressIndex<
            ReadOnlyMultimapTable<&'static [u8; 20], (u64, &'static [u8; 32])>,
            ReadOnlyTable<&'static [u8; 32], (u64, &'static [u8; 20])>,
        >,
    > {
        Ok(TouchedAddressIndex {
            index: self.0.open_multimap_table(TOUCHED_ADDRESS_INDEX)?,
            reverse_index: self.0.open_table(TOUCHED_ADDRESS_REVERSE_INDEX)?,
        })
    }
    pub fn finalized_view(&self) -> Result<FinalizedViewTable<ReadOnlyTable<(), u64>>> {
        Ok(FinalizedViewTable(self.0.open_table(FINALIZED_VIEW)?))
    }
    pub fn view(&self) -> Result<ViewTable<ReadOnlyTable<(), (u64, bool)>>> {
        Ok(ViewTable(self.0.open_table(VIEW)?))
    }
    pub fn high_qc(&self) -> Result<HighQcTable<ReadOnlyTable<(), (Vec<u8>, u64, u32)>>> {
        Ok(HighQcTable(self.0.open_table(HIGH_QC)?))
    }
    pub fn state_trie(&self) -> Result<StateTrieTable<ReadOnlyTable<&'static [u8; 32], Vec<u8>>>> {
        Ok(StateTrieTable(self.0.open_table(STATE_TRIE)?))
    }
}

pub struct TxWrite(WriteTransaction);

impl TxWrite {
    pub fn commit(self) -> Result<()> {
        self.0.commit()?;
        Ok(())
    }

    pub fn blocks(
        &self,
    ) -> Result<
        BlocksTable<
            Table<u64, Vec<u8>>,
            Table<&'static [u8; 32], u64>,
            MultimapTable<u64, u64>,
            Table<u64, bool>,
        >,
    > {
        Ok(BlocksTable {
            blocks: self.0.open_table(BLOCKS)?,
            blocks_hash_index: self.0.open_table(BLOCKS_HASH_INDEX)?,
            blocks_height_index: self.0.open_multimap_table(BLOCKS_HEIGHT_INDEX)?,
            block_is_canonical: self.0.open_table(BLOCK_IS_CANONICAL)?,
        })
    }
    pub fn transactions(&self) -> Result<TransactionsTable<Table<&'static [u8; 32], Vec<u8>>>> {
        Ok(TransactionsTable(self.0.open_table(TRANSACTIONS)?))
    }
    pub fn receipts(&self) -> Result<ReceiptsTable<Table<&'static [u8; 32], Vec<u8>>>> {
        Ok(ReceiptsTable(self.0.open_table(RECEIPTS)?))
    }
    pub fn touched_address_index(
        &self,
    ) -> Result<
        TouchedAddressIndex<
            MultimapTable<&'static [u8; 20], (u64, &'static [u8; 32])>,
            Table<&'static [u8; 32], (u64, &'static [u8; 20])>,
        >,
    > {
        Ok(TouchedAddressIndex {
            index: self.0.open_multimap_table(TOUCHED_ADDRESS_INDEX)?,
            reverse_index: self.0.open_table(TOUCHED_ADDRESS_REVERSE_INDEX)?,
        })
    }
    pub fn finalized_view(&self) -> Result<FinalizedViewTable<Table<(), u64>>> {
        Ok(FinalizedViewTable(self.0.open_table(FINALIZED_VIEW)?))
    }
    pub fn view(&self) -> Result<ViewTable<Table<(), (u64, bool)>>> {
        Ok(ViewTable(self.0.open_table(VIEW)?))
    }
    pub fn high_qc(&self) -> Result<HighQcTable<Table<(), (Vec<u8>, u64, u32)>>> {
        Ok(HighQcTable(self.0.open_table(HIGH_QC)?))
    }
    pub fn state_trie(&self) -> Result<StateTrieTable<Table<&'static [u8; 32], Vec<u8>>>> {
        Ok(StateTrieTable(self.0.open_table(STATE_TRIE)?))
    }

    /// Ensure all tables are created.
    pub fn create_all(&self) -> Result<()> {
        self.blocks()?;
        self.transactions()?;
        self.receipts()?;
        self.touched_address_index()?;
        self.finalized_view()?;
        self.view()?;
        self.high_qc()?;
        self.state_trie()?;
        Ok(())
    }

    /// Convenience method for deleting all references to a transaction.
    pub fn delete_transaction(&self, txn_hash: Hash) -> Result<()> {
        self.transactions()?.delete(txn_hash)?;
        self.receipts()?.delete(txn_hash)?;
        self.touched_address_index()?.delete_by_txn_hash(txn_hash)?;
        Ok(())
    }
}
