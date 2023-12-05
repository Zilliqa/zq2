use std::path::Path;

use anyhow::Result;
use sled::Tree;

use crate::{
    crypto::Hash,
    message::{Block, BlockHeader, QuorumCertificate},
    state::Address,
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
    transaction_receipt: Tree,
    /// An index of address to a list of transaction hashes, for which this address appeared somewhere in the
    /// transaction trace. The list of transations is ordered by execution order.
    touched_address_index: Tree,
    /// Lookup of block hashes for transaction hashes.
    block_hash_reverse_index: Tree,
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
/// Key: address; value: Vec<tx hash where this address was touched>
const ADDR_TOUCHED_INDEX: &[u8] = b"addresses_touched_index";
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

// single keys stored in default tree in DB
/// value: u64
const LATEST_FINALIZED_VIEW: &[u8] = b"latest_finalized_view";
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

        let touched_address_index = db.open_tree(ADDR_TOUCHED_INDEX)?;
        touched_address_index.set_merge_operator(|_k, old_value, additional_value| {
            // We unwrap all errors as we assume that the serialization should always be correct.
            // TODO: maybe use a smarter packing rather than calling bincode twice every time?
            let mut vec = if let Some(old_value) = old_value {
                bincode::deserialize::<Vec<Hash>>(old_value).unwrap()
            } else {
                vec![]
            };
            vec.push(Hash(additional_value.try_into().unwrap()));
            Some(bincode::serialize(&vec).unwrap())
        });

        Ok(Db {
            root: db,
            block_header,
            block,
            canonical_block_number,
            canonical_block_view,
            transaction,
            transaction_receipt,
            block_hash_reverse_index,
            touched_address_index,
        })
    }

    pub fn flush(&self) -> Result<()> {
        self.root.flush()?;
        Ok(())
    }

    pub fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage::new(self.root.open_tree(STATE_TRIE_TREE)?))
    }

    pub fn add_touched_address(&self, address: Address, hash: Hash) -> Result<()> {
        self.touched_address_index
            .merge(address.as_bytes(), hash.as_bytes())?;
        Ok(())
    }

    pub fn get_touched_address_index(&self, address: Address) -> Result<Vec<Hash>> {
        Ok(self
            .touched_address_index
            .get(address.as_bytes())?
            .map(|b| bincode::deserialize(&b))
            .transpose()?
            .unwrap_or_default())
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

    get_and_insert_methods!(block_header, Hash, BlockHeader);
    get_and_insert_methods!(block, Hash, Block);
    get_and_insert_methods!(transaction, Hash, SignedTransaction);
    get_and_insert_methods!(transaction_receipt, Hash, Vec<TransactionReceipt>);
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

    fn remove(&self, _key: &[u8]) -> Result<(), Self::Error> {
        // we keep old state to function as an archive node, therefore no-op
        Ok(())
    }

    /// eth-trie.rs provides a way to cache reads and writes and periodically flush them.
    /// We delegate this to Sled and implement flush() as a no-op.
    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
