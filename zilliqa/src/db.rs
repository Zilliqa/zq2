use std::path::Path;

use alloy_primitives::Address;
use anyhow::Result;
use sled::{Batch, Tree};

use crate::{
    crypto::Hash,
    message::{Block, BlockHeader, QuorumCertificate},
    transaction::{SignedTransaction, TransactionReceipt},
};

#[derive(Debug)]
pub struct Db {
    root: sled::Db,
    block_header: Tree,
    block: Tree,
    canonical_block_number: Tree,
    canonical_block_view: Tree,
    /// Transactions that have been executed and included in a block, and their receipts.
    transaction: Tree,
    transaction_receipts: Tree,
    /// Lookup of block hashes for transaction hashes.
    block_hash_reverse_index: Tree,
    touched_address: Tree,
}

macro_rules! get_and_insert_methods {
    ($name: ident, $key: ty, $val: ty) => {
        // Paste lets us concatenate identifiers to form the method names we want.
        paste::paste! {
            #[allow(dead_code)]
            pub fn [<contains_ $name>](&self, key: &$key) -> Result<bool> {
                Ok(self.$name.contains_key(key.as_bytes())?)
            }

            #[allow(dead_code)]
            pub fn [<insert_ $name>](&self, key: &$key, val: &$val) -> Result<()> {
                self.$name.insert(key.as_bytes(), bincode::serialize(val)?)?;
                Ok(())
            }

            #[allow(dead_code)]
            pub fn [<remove_ $name>](&self, key: &$key) -> Result<()> {
                self.$name.remove(key.as_bytes())?;
                Ok(())
            }

            #[allow(dead_code)]
            pub fn [<get_ $name>](&self, key: &$key) -> Result<Option<$val>> {
                Ok(
                    self.$name
                        .get(key.as_bytes())?
                        .map(|b| bincode::deserialize(&b))
                        .transpose()?
                )
            }

            #[allow(dead_code)]
            pub fn [<insert_ $name _batch>](&self, items: &[($key, $val)]) -> Result<()> {
                let mut batch = sled::Batch::default();
                for (k, v) in items {
                    batch.insert(k.as_bytes(), bincode::serialize(&v)?);
                }
                self.$name.apply_batch(batch)?;
                Ok(())
            }
        }
    };
}

// database tree names
/// Key: trie hash; value: trie node
const STATE_TRIE_TREE: &[u8] = b"state_trie";
/// Key: transaction hash; value: transaction data
const TXS_TREE: &[u8] = b"txs_tree";
/// Key: block hash; value: vector of transaction receipts in that block
const RECEIPTS_TREE: &[u8] = b"receipts_tree";
/// Key: tx_hash; value: corresponding block_hash
const TX_BLOCK_INDEX: &[u8] = b"tx_block_index";
/// Key: block hash; value: block header
const BLOCK_HEADERS_TREE: &[u8] = b"block_headers_tree";
/// Key: block number (on the current main branch); value: block hash
const CANONICAL_BLOCK_NUMBERS_TREE: &[u8] = b"canonical_block_numbers_tree";
/// Key: block view (on the current main branch); value: block hash
const CANONICAL_BLOCK_VIEWS_TREE: &[u8] = b"canonical_block_views_tree";
/// Key: block hash; value: entire block (with hashes for transactions)
const BLOCKS_TREE: &[u8] = b"blocks_tree";
/// Key: address; value: list of transactions which touched this address, in order of execution.
const TOUCHED_ADDRESS_TREE: &[u8] = b"touched_address_tree";

// single keys stored in default tree in DB
/// value: u64
const LATEST_FINALIZED_VIEW: &[u8] = b"latest_finalized_view";
/// The highest block number we have seen and stored. It is guaranteed that we have the block at this number in our
/// block store.
const HIGHEST_BLOCK_NUMBER: &[u8] = b"highest_block_number";
const HIGH_QC: &[u8] = b"high_qc";

// database tree names

impl Db {
    pub fn new<P>(data_dir: Option<P>, shard_id: u64) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let db = match data_dir {
            Some(path) => sled::open(path.as_ref().join(shard_id.to_string()))?,
            None => sled::Config::new().temporary(true).open()?,
        };

        let block_header = db.open_tree(BLOCK_HEADERS_TREE)?;
        let block = db.open_tree(BLOCKS_TREE)?;
        let canonical_block_number = db.open_tree(CANONICAL_BLOCK_NUMBERS_TREE)?;
        let canonical_block_view = db.open_tree(CANONICAL_BLOCK_VIEWS_TREE)?;
        let transaction = db.open_tree(TXS_TREE)?;
        let transaction_receipt = db.open_tree(RECEIPTS_TREE)?;
        let block_hash_reverse_index = db.open_tree(TX_BLOCK_INDEX)?;
        let touched_address = db.open_tree(TOUCHED_ADDRESS_TREE)?;

        touched_address.set_merge_operator(|_, old, new| {
            let mut old = old.map(|o| o.to_vec()).unwrap_or_default();
            old.extend_from_slice(new);
            Some(old)
        });

        Ok(Db {
            root: db,
            block_header,
            block,
            canonical_block_number,
            canonical_block_view,
            transaction,
            transaction_receipts: transaction_receipt,
            block_hash_reverse_index,
            touched_address,
        })
    }

    pub fn flush(&self) {
        while self.root.flush().unwrap() > 0 {}
    }

    pub fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage::new(self.root.open_tree(STATE_TRIE_TREE)?))
    }

    pub fn put_canonical_block_number(&self, number: u64, hash: Hash) -> Result<()> {
        self.canonical_block_number
            .insert(number.to_be_bytes(), hash.as_bytes())?;
        Ok(())
    }

    pub fn get_canonical_block_number(&self, number: u64) -> Result<Option<Hash>> {
        self.canonical_block_number
            .get(number.to_be_bytes())?
            .map(Hash::from_bytes)
            .transpose()
    }

    pub fn put_canonical_block_view(&self, view: u64, hash: Hash) -> Result<()> {
        self.canonical_block_view
            .insert(view.to_be_bytes(), hash.as_bytes())?;
        Ok(())
    }

    pub fn get_canonical_block_view(&self, view: u64) -> Result<Option<Hash>> {
        self.canonical_block_view
            .get(view.to_be_bytes())?
            .map(Hash::from_bytes)
            .transpose()
    }

    pub fn put_latest_finalized_view(&self, view: u64) -> Result<()> {
        self.root
            .insert(LATEST_FINALIZED_VIEW, &view.to_be_bytes())?;
        Ok(())
    }

    pub fn get_latest_finalized_view(&self) -> Result<Option<u64>> {
        self.root
            .get(LATEST_FINALIZED_VIEW)?
            .map(|b| Ok(u64::from_be_bytes(b.as_ref().try_into()?)))
            .transpose()
    }

    pub fn put_highest_block_number(&self, number: u64) -> Result<()> {
        self.root
            .insert(HIGHEST_BLOCK_NUMBER, &number.to_be_bytes())?;
        Ok(())
    }

    pub fn get_highest_block_number(&self) -> Result<Option<u64>> {
        self.root
            .get(HIGHEST_BLOCK_NUMBER)?
            .map(|b| Ok(u64::from_be_bytes(b.as_ref().try_into()?)))
            .transpose()
    }

    pub fn set_high_qc(&self, high_qc: QuorumCertificate) -> Result<()> {
        self.root.insert(HIGH_QC, bincode::serialize(&high_qc)?)?;

        Ok(())
    }

    pub fn get_high_qc(&self) -> Result<Option<QuorumCertificate>> {
        self.root
            .get(HIGH_QC)?
            .map(|qc| Ok(bincode::deserialize(&qc)?))
            .transpose()
    }

    pub fn add_touched_address(&self, address: Address, txn_hash: Hash) -> Result<()> {
        self.touched_address.merge(address, txn_hash.as_bytes())?;
        Ok(())
    }

    pub fn get_touched_addresses(&self, address: Address) -> Result<Vec<Hash>> {
        Ok(self
            .touched_address
            .get(address)?
            .map(|b| b.chunks_exact(Hash::LEN).map(Hash::from_bytes).collect())
            .transpose()?
            .unwrap_or_default())
    }

    get_and_insert_methods!(block_header, Hash, BlockHeader);
    get_and_insert_methods!(block, Hash, Block);
    get_and_insert_methods!(transaction, Hash, SignedTransaction);
    get_and_insert_methods!(transaction_receipts, Hash, Vec<TransactionReceipt>);
    get_and_insert_methods!(block_hash_reverse_index, Hash, Hash);
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
