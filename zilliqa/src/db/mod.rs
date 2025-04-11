mod migrate;
mod tables;

use std::{
    fmt::Debug,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use eth_trie::{DB, EthTrie, MemoryDB, Trie};
use lz4::{Decoder, EncoderBuilder};
use redb::{Database, backends::InMemoryBackend};
pub use tables::*;
use tracing::{debug, info, warn};

use crate::{crypto::Hash, message::Block, state::Account, transaction::SignedTransaction};

const CHECKPOINT_HEADER_BYTES: [u8; 8] = *b"ZILCHKPT";

/// Version string that is written to disk along with the persisted database. This should be bumped whenever we make a
/// backwards incompatible change to our database format.
const CURRENT_DB_VERSION: u8 = 2;

#[derive(Debug)]
pub struct Db {
    db: Arc<Database>,
    path: Option<Box<Path>>,
}

pub trait ArcDb {
    fn state_trie(&self) -> Result<TrieStorage>;
    fn load_trusted_checkpoint<P: AsRef<Path>>(
        &self,
        path: P,
        hash: &Hash,
        our_shard_id: u64,
    ) -> Result<Option<(Block, Vec<SignedTransaction>, Block)>>;
}

impl ArcDb for Arc<Db> {
    fn state_trie(&self) -> Result<TrieStorage> {
        Ok(TrieStorage { db: self.clone() })
    }

    /// Fetch checkpoint data from file and initialise db state
    /// Return checkpointed block and transactions which must be executed after this function
    /// Return None if checkpoint already loaded
    fn load_trusted_checkpoint<P: AsRef<Path>>(
        &self,
        path: P,
        hash: &Hash,
        our_shard_id: u64,
    ) -> Result<Option<(Block, Vec<SignedTransaction>, Block)>> {
        // For now, only support a single version: you want to load the latest checkpoint, anyway.
        const SUPPORTED_VERSION: u32 = 3;

        // Decompress file and write to temp file
        let input_filename = path.as_ref();
        let temp_filename = input_filename.with_extension("part");
        decompress_file(input_filename, &temp_filename)?;

        // Read decompressed file
        let input = File::open(&temp_filename)?;

        let mut reader = BufReader::with_capacity(128 * 1024 * 1024, input); // 128 MiB read chunks
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
        let mut block_len_buf = [0u8; std::mem::size_of::<u64>()];
        reader.read_exact(&mut block_len_buf)?;
        let mut block_ser = vec![0u8; usize::try_from(u64::from_be_bytes(block_len_buf))?];
        reader.read_exact(&mut block_ser)?;
        let block: Block = bincode::deserialize(&block_ser)?;
        if block.hash() != *hash {
            return Err(anyhow!("Checkpoint does not match trusted hash"));
        }
        block.verify_hash()?;

        let mut transactions_len_buf = [0u8; std::mem::size_of::<u64>()];
        reader.read_exact(&mut transactions_len_buf)?;
        let mut transactions_ser =
            vec![0u8; usize::try_from(u64::from_be_bytes(transactions_len_buf))?];
        reader.read_exact(&mut transactions_ser)?;
        let transactions: Vec<SignedTransaction> = bincode::deserialize(&transactions_ser)?;

        let mut parent_len_buf = [0u8; std::mem::size_of::<u64>()];
        reader.read_exact(&mut parent_len_buf)?;
        let mut parent_ser = vec![0u8; usize::try_from(u64::from_be_bytes(parent_len_buf))?];
        reader.read_exact(&mut parent_ser)?;
        let parent: Block = bincode::deserialize(&parent_ser)?;
        if block.parent_hash() != parent.hash() {
            return Err(anyhow!(
                "Invalid checkpoint file: parent's blockhash does not correspond to checkpoint block"
            ));
        }

        let read = self.read()?;

        if state_trie.iter().next().is_some() || read.blocks()?.max_canonical_by_view()?.is_some() {
            // If checkpointed block already exists then assume checkpoint load already complete. Return None
            if read.blocks()?.by_hash(block.hash())?.is_some() {
                return Ok(None);
            }
            // This may not be strictly necessary, as in theory old values will, at worst, be orphaned
            // values not part of any state trie of any known block. With some effort, this could
            // even be supported.
            // However, without such explicit support, having old blocks MAY in fact cause
            // unexpected and unwanted behaviour. Thus we currently forbid loading a checkpoint in
            // a node that already contains previous state, until (and unless) there's ever a
            // usecase for going through the effort to support it and ensure it works as expected.
            if let Some(db_block) = read.blocks()?.by_hash(parent.hash())? {
                if db_block.parent_hash() != parent.parent_hash() {
                    return Err(anyhow!(
                        "Inconsistent checkpoint file: block loaded from checkpoint and block stored in database with same hash have differing parent hashes"
                    ));
                } else {
                    // In this case, the database already has the block contained in this checkpoint. We assume the
                    // database contains the full state for that block too and thus return early, without actually
                    // loading the checkpoint file.
                    return Ok(Some((block, transactions, parent)));
                }
            } else {
                return Err(anyhow!(
                    "Inconsistent checkpoint file: block loaded from checkpoint file does not exist in non-empty database"
                ));
            }
        }

        // Helper function used for inserting entries from memory (which backs storage trie) into persistent storage
        let db_flush = |db: Arc<TrieStorage>, cache: Arc<MemoryDB>| -> Result<()> {
            let mut cache_storage = cache.storage.write();
            let (keys, values): (Vec<_>, Vec<_>) = cache_storage.drain().unzip();
            debug!("Doing write to db with total items {}", keys.len());
            db.insert_batch(keys, values)?;
            Ok(())
        };

        let mut processed_accounts = 0;
        let mut processed_storage_items = 0;
        const COMPUTE_ROOT_HASH_EVERY_ACCOUNTS: usize = 10000;
        const FLUSH_STORAGE_CHANGES_EVERY: usize = 10000;
        let mem_storage = Arc::new(MemoryDB::new(true));

        // then decode state
        loop {
            // Read account key and the serialised Account
            let mut account_hash = [0u8; 32];
            match reader.read_exact(&mut account_hash) {
                // Read successful
                Ok(_) => (),
                // Break loop here if weve reached the end of the file
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => return Err(e.into()),
            };

            let mut serialised_account_len_buf = [0u8; std::mem::size_of::<u64>()];
            reader.read_exact(&mut serialised_account_len_buf)?;
            let mut serialised_account =
                vec![0u8; usize::try_from(u64::from_be_bytes(serialised_account_len_buf))?];
            reader.read_exact(&mut serialised_account)?;

            // Read entire account storage as a buffer
            let mut account_storage_len_buf = [0u8; std::mem::size_of::<u64>()];
            reader.read_exact(&mut account_storage_len_buf)?;
            let account_storage_len = usize::try_from(u64::from_be_bytes(account_storage_len_buf))?;
            let mut account_storage = vec![0u8; account_storage_len];
            reader.read_exact(&mut account_storage)?;

            // Pull out each storage key and value
            let mut account_trie = EthTrie::new(mem_storage.clone());
            let mut pointer: usize = 0;
            while account_storage_len > pointer {
                let storage_key_len_buf: &[u8] =
                    &account_storage[pointer..(pointer + std::mem::size_of::<u64>())];
                let storage_key_len =
                    usize::try_from(u64::from_be_bytes(storage_key_len_buf.try_into()?))?;
                pointer += std::mem::size_of::<u64>();
                let storage_key: &[u8] = &account_storage[pointer..(pointer + storage_key_len)];
                pointer += storage_key_len;

                let storage_val_len_buf: &[u8] =
                    &account_storage[pointer..(pointer + std::mem::size_of::<u64>())];
                let storage_val_len =
                    usize::try_from(u64::from_be_bytes(storage_val_len_buf.try_into()?))?;
                pointer += std::mem::size_of::<u64>();
                let storage_val: &[u8] = &account_storage[pointer..(pointer + storage_val_len)];
                pointer += storage_val_len;

                account_trie.insert(storage_key, storage_val)?;

                processed_storage_items += 1;
            }

            let account_trie_root =
                bincode::deserialize::<Account>(&serialised_account)?.storage_root;
            if account_trie.root_hash()?.as_slice() != account_trie_root {
                return Err(anyhow!(
                    "Invalid checkpoint file: account trie root hash mismatch: calculated {}, checkpoint file contained {}",
                    hex::encode(account_trie.root_hash()?.as_slice()),
                    hex::encode(account_trie_root)
                ));
            }
            if processed_storage_items > FLUSH_STORAGE_CHANGES_EVERY {
                db_flush(trie_storage.clone(), mem_storage.clone())?;
                processed_storage_items = 0;
            }

            state_trie.insert(&account_hash, &serialised_account)?;

            processed_accounts += 1;
            // Occasionally flush the cached state changes to disk to minimise memory usage.
            if processed_accounts % COMPUTE_ROOT_HASH_EVERY_ACCOUNTS == 0 {
                let _ = state_trie.root_hash()?;
            }
        }

        db_flush(trie_storage.clone(), mem_storage.clone())?;

        if state_trie.root_hash()? != parent.state_root_hash().0 {
            return Err(anyhow!("Invalid checkpoint file: state root hash mismatch"));
        }

        let write = self.write()?;
        write.blocks()?.insert(&parent)?;
        write.finalized_view()?.set(parent.view())?;
        write.high_qc()?.set(&block.header.qc)?;
        write.view()?.set(parent.view() + 1, false)?;
        write.commit()?;

        fs::remove_file(temp_filename)?;

        Ok(Some((block, transactions, parent)))
    }
}

impl Db {
    pub fn new<P>(data_dir: Option<P>, shard_id: u64, cache_size: usize) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let db = match data_dir {
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
                let version: u8 = if version.is_empty() {
                    CURRENT_DB_VERSION
                } else {
                    version.parse()?
                };

                let migrate = if version == CURRENT_DB_VERSION {
                    false
                } else if version == CURRENT_DB_VERSION - 1 {
                    // We support migrations from the previous DB version.
                    true
                } else {
                    return Err(anyhow!(
                        "data is incompatible with this version - please delete the data and re-sync"
                    ));
                };

                let db = Database::builder()
                    .set_cache_size(cache_size)
                    .set_repair_callback(|repair| {
                        info!(progress = repair.progress(), "repairing database");
                    })
                    .create(path.join("db.redb"))?;
                let mut db = Db {
                    db: Arc::new(db),
                    path: Some(path.clone().into_boxed_path()),
                };

                if migrate {
                    let sql_path = path.join("db.sqlite3");
                    db = db.migrate_from(rusqlite::Connection::open(&sql_path)?)?;
                    fs::rename(sql_path, path.join("db.sqlite3.backup"))?;
                }

                version_file.seek(SeekFrom::Start(0))?;
                version_file.write_all(CURRENT_DB_VERSION.to_string().as_bytes())?;

                db
            }
            None => Db {
                db: Arc::new(Database::builder().create_with_backend(InMemoryBackend::new())?),
                path: None,
            },
        };

        // Ensure tables exist.
        let write = db.write()?;
        write.create_all()?;
        write.commit()?;

        Ok(db)
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

    pub fn into_raw(self) -> Database {
        Arc::into_inner(self.db).unwrap()
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
    let mut writer = BufWriter::with_capacity(8192 * 1024, outfile_temp); // 8 MiB chunks

    // write the header:
    writer.write_all(&CHECKPOINT_HEADER_BYTES)?; // file identifier
    writer.write_all(&VERSION.to_be_bytes())?; // 4 BE bytes for version
    writer.write_all(&shard_id.to_be_bytes())?; // 8 BE bytes for shard ID
    writer.write_all(b"\n")?;

    // write the block...
    let block_ser = &bincode::serialize(&block)?;
    writer.write_all(&u64::try_from(block_ser.len())?.to_be_bytes())?;
    writer.write_all(block_ser)?;

    // write transactions
    let transactions_ser = &bincode::serialize(&transactions)?;
    writer.write_all(&u64::try_from(transactions_ser.len())?.to_be_bytes())?;
    writer.write_all(transactions_ser)?;

    // and its parent, to keep the qc tracked
    let parent_ser = &bincode::serialize(&parent)?;
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
        let account_storage = account_storage
            .at_root(bincode::deserialize::<Account>(&serialised_account)?.storage_root);
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

/// Read lz4 compressed file and write into output file
fn decompress_file<P: AsRef<Path> + Debug>(input_file_path: P, output_file_path: P) -> Result<()> {
    let reader: BufReader<File> = BufReader::new(File::open(input_file_path)?);
    let mut decoder = Decoder::new(reader)?;

    let mut writer = BufWriter::new(File::create(output_file_path)?);
    let mut buffer = [0u8; 1024 * 64]; // read 64KB chunks at a time
    loop {
        let bytes_read = decoder.read(&mut buffer)?; // Read a chunk of decompressed data
        if bytes_read == 0 {
            break; // End of file
        }
        writer.write_all(&buffer[..bytes_read])?;
    }

    writer.flush()?;

    Ok(())
}

/// An implementor of [eth_trie::DB] which uses a [Db] to persist data.
#[derive(Debug, Clone)]
pub struct TrieStorage {
    db: Arc<Db>,
}

impl eth_trie::DB for TrieStorage {
    type Error = anyhow::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.read()?.state_trie()?.get(key)
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        let write = self.db.write()?;
        write.state_trie()?.insert(key, &value)?;
        write.commit()
    }

    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        if keys.is_empty() {
            return Ok(());
        }

        assert_eq!(keys.len(), values.len());

        let write = self.db.write()?;
        for (key, value) in keys.into_iter().zip(values) {
            write.state_trie()?.insert(&key, &value)?;
        }
        write.commit()?;

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
        Rng, SeedableRng,
        distributions::{Distribution, Uniform},
    };
    use rand_chacha::ChaCha8Rng;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        crypto::SecretKey, message::QuorumCertificate, state::State, time::SystemTime,
        transaction::EvmGas,
    };

    #[test]
    fn checkpoint_export_import() {
        let base_path = tempdir().unwrap();
        let base_path = base_path.path();
        let db = Arc::new(Db::new(Some(base_path), 0, 1024).unwrap());

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
        let write = db.write().unwrap();
        write.blocks().unwrap().insert(&checkpoint_block).unwrap();
        write.commit().unwrap();
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
