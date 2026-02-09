use std::{
    fs::File,
    io::{BufReader, Read, Seek, Write},
    path::Path,
    sync::Arc,
};

use alloy::hex;
use anyhow::{Result, anyhow, ensure};
use eth_trie::{DB, EthTrie, MemoryDB, Trie};
use lz4::Decoder;
use tempfile::SpooledTempFile;

use crate::{
    crypto::Hash, db::Db, message::Block, precompiles::ViewHistory, state::Account,
    transaction::SignedTransaction, trie_storage::TrieStorage,
};

pub const CHECKPOINT_HEADER_BYTES: [u8; 8] = *b"ZILCHKPT";

pub fn load_state_trie(
    reader: &mut Decoder<BufReader<File>>,
    trie_storage: Arc<TrieStorage>,
    parent: &Block,
) -> Result<()> {
    let mem_storage = Arc::new(MemoryDB::new(true));
    let mut state_trie = EthTrie::new(trie_storage.clone());

    // Implement the logic to load the state trie from the checkpoint file
    // Return an error if the state trie cannot be loaded
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
        }

        let account_trie_root = Account::try_from(serialised_account.as_slice())?.storage_root;
        if account_trie.root_hash()?.as_slice() != account_trie_root {
            return Err(anyhow!(
                "Account trie root hash mismatch: {} != {}",
                hex::encode(account_trie.root_hash()?.as_slice()),
                hex::encode(account_trie_root)
            ));
        } else {
            // flush memory to disk
            let (keys, vals): (Vec<_>, Vec<_>) = mem_storage.storage.write().drain().unzip();
            tracing::debug!("Writing {} keys to disk", keys.len());
            trie_storage.insert_batch(keys, vals)?;
        }
        state_trie.insert(&account_hash, &serialised_account)?;
    }
    // flush the cached state changes to disk
    if state_trie.root_hash()? != parent.state_root_hash().0 {
        return Err(anyhow!(
            "State root hash mismatch: {} != {}",
            hex::encode(state_trie.root_hash()?.as_slice()),
            hex::encode(parent.state_root_hash().0)
        ));
    }

    Ok(())
}

pub fn get_checkpoint_block(
    reader: &mut Decoder<BufReader<File>>,
    hash: &Hash,
    our_shard_id: u64,
) -> Result<Option<(Block, Vec<SignedTransaction>, Block)>> {
    // For now, only support a single version: you want to load the latest checkpoint, anyway.
    const SUPPORTED_VERSION: u32 = 3;

    // Decode and validate header
    let mut header: [u8; 21] = [0u8; 21];
    reader.read_exact(&mut header)?;
    let header = header;
    if header[0..8] != CHECKPOINT_HEADER_BYTES // magic bytes
           || header[20] != b'\n'
    // header must end in newline
    {
        return Err(anyhow!("Invalid header"));
    }
    let version = u32::from_be_bytes(header[8..12].try_into()?);
    // Only support a single version right now.
    if version != SUPPORTED_VERSION {
        return Err(anyhow!("Invalid checkpoint version."));
    }
    let shard_id = u64::from_be_bytes(header[12..20].try_into()?);
    if shard_id != our_shard_id {
        return Err(anyhow!("Invalid checkpoint shard ID."));
    }

    // Decode and validate checkpoint block, its transactions and parent block
    let mut block_len_buf = [0u8; std::mem::size_of::<u64>()];
    reader.read_exact(&mut block_len_buf)?;
    let mut block_ser = vec![0u8; usize::try_from(u64::from_be_bytes(block_len_buf))?];
    reader.read_exact(&mut block_ser)?;
    let block: Block = bincode::serde::decode_from_slice(&block_ser, bincode::config::legacy())?.0;
    if block.hash() != *hash {
        return Err(anyhow!("Checkpoint does not match trusted hash"));
    }
    block.verify_hash()?;

    let mut transactions_len_buf = [0u8; std::mem::size_of::<u64>()];
    reader.read_exact(&mut transactions_len_buf)?;
    let mut transactions_ser =
        vec![0u8; usize::try_from(u64::from_be_bytes(transactions_len_buf))?];
    reader.read_exact(&mut transactions_ser)?;
    let transactions =
        bincode::serde::decode_from_slice(&transactions_ser, bincode::config::legacy())?.0;

    let mut parent_len_buf = [0u8; std::mem::size_of::<u64>()];
    reader.read_exact(&mut parent_len_buf)?;
    let mut parent_ser = vec![0u8; usize::try_from(u64::from_be_bytes(parent_len_buf))?];
    reader.read_exact(&mut parent_ser)?;
    let parent: Block =
        bincode::serde::decode_from_slice(&parent_ser, bincode::config::legacy())?.0;
    if block.parent_hash() != parent.hash() {
        return Err(anyhow!("Invalid checkpoint parent blockhash"));
    }

    Ok(Some((block, transactions, parent)))
}

// old checkpoint format
pub fn load_trusted_checkpoint_v1<P: AsRef<Path>>(
    db: Arc<Db>,
    path: P,
    hash: &Hash,
    our_shard_id: u64,
) -> Result<Option<(Block, Vec<SignedTransaction>, Block)>> {
    tracing::info!(%hash, "Checkpoint V1");
    // Decompress the file for processing
    let input_file = File::open(path.as_ref())?;
    let buf_reader: BufReader<File> = BufReader::with_capacity(128 * 1024 * 1024, input_file);
    let mut reader = Decoder::new(buf_reader)?;
    let Some((block, transactions, parent)) =
        crate::checkpoint::get_checkpoint_block(&mut reader, hash, our_shard_id)?
    else {
        return Err(anyhow!("Invalid checkpoint file"));
    };

    let trie_storage = Arc::new(db.state_trie()?);
    let state_trie = EthTrie::new(trie_storage.clone());

    // INITIAL CHECKPOINT LOAD
    // If no state trie exists and no blocks are known, then we are in a fresh database.
    // We can safely load the checkpoint.
    if state_trie.iter().next().is_none() && db.get_highest_canonical_block_number()?.is_none() {
        tracing::info!(state = %parent.state_root_hash(), "Restoring checkpoint");
        crate::checkpoint::load_state_trie(&mut reader, trie_storage, &parent)?;

        let parent_ref: &Block = &parent; // for moving into the closure
        db.with_sqlite_tx(|tx| {
            db.insert_block_with_db_tx(tx, parent_ref)?;
            db.set_finalized_view_with_db_tx(tx, parent_ref.view())?;
            db.set_high_qc_with_db_tx(tx, block.header.qc)?;
            db.set_view_with_db_tx(tx, parent_ref.view() + 1, false)?;
            Ok(())
        })?;

        return Ok(Some((block, transactions, parent)));
    }

    Ok(None)
}

const BIN_CONFIG: bincode::config::Configuration = bincode::config::standard();
const CKPT_VERSION: &str = "ZILCHKPT/2.0";

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Checkpoint {
    pub account_count: u64,
    pub record_count: u64,
    pub chain_id: u64,
    pub block_hash: Hash,
}

fn load_ckpt_meta(path: &Path, chain_id: u64, block_hash: &Hash) -> Result<Checkpoint> {
    let mut zipreader = zip::ZipArchive::new(std::fs::File::open(path)?)?;

    // Currently checks that the version matches exactly.
    // This check also ensures that the file is a ZIP file by reading the EOCD.
    // In the future, we may handle different versions separately,
    //
    // - ZILCHKPT/2.0 : Checkpoint 2.0
    ensure!(
        zipreader.comment() == CKPT_VERSION.as_bytes(),
        "Invalid checkpoint version",
    );

    let meta = {
        let mut file = zipreader.by_name("metadata.json")?;
        let meta: Checkpoint = serde_json::from_reader(&mut file)?;
        ensure!(
            meta.chain_id == chain_id,
            "Chain ID {} mismatch",
            meta.chain_id
        );
        ensure!(
            meta.block_hash == *block_hash,
            "Bock hash {} mistmatch",
            meta.block_hash
        );
        meta
    };
    Ok(meta)
}

pub fn load_ckpt_blocks(path: &Path) -> Result<(Block, Vec<SignedTransaction>, Block)> {
    let mut zipreader = zip::ZipArchive::new(std::fs::File::open(path)?)?;
    ensure!(
        zipreader.comment() == CKPT_VERSION.as_bytes(),
        "Invalid checkpoint version",
    );

    let block = {
        let mut file = zipreader.by_name("block.bincode")?;
        let block: crate::message::Block =
            bincode::serde::decode_from_std_read(&mut file, BIN_CONFIG)?;
        ensure!(
            block.verify_hash().is_ok(),
            "Block hash {} invalid",
            block.hash()
        );
        block
    };
    let parent = {
        let mut file = zipreader.by_name("parent.bincode")?;
        let parent: crate::message::Block =
            bincode::serde::decode_from_std_read(&mut file, BIN_CONFIG)?;
        ensure!(
            parent.verify_hash().is_ok(),
            "Parent hash {} invalid",
            parent.hash()
        );
        parent
    };
    ensure!(block.parent_hash() == parent.hash(), "Parent hash mismatch");

    // Verify transactions list
    let transactions = {
        let mut file = zipreader.by_name("transactions.bincode")?;
        let transactions: Vec<SignedTransaction> =
            bincode::serde::decode_from_std_read(&mut file, BIN_CONFIG)?;
        let mut transactions_trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
        for tx in &transactions {
            let hash = tx.calculate_hash();
            transactions_trie.insert(hash.as_bytes(), hash.as_bytes())?;
        }
        let transactions_root_hash = Hash(transactions_trie.root_hash()?.into());
        ensure!(
            block.header.transactions_root_hash == transactions_root_hash,
            "Transactions root hash {transactions_root_hash} mismatch",
        );
        transactions
    };
    Ok((block, transactions, parent))
}

pub fn load_ckpt_state(
    path: &Path,
    trie_storage: Arc<TrieStorage>,
    state_root_hash: &Hash,
) -> Result<(u64, u64)> {
    let mut zipreader = zip::ZipArchive::new(std::fs::File::open(path)?)?;
    ensure!(
        zipreader.comment() == CKPT_VERSION.as_bytes(),
        "Invalid checkpoint version",
    );

    // reconstruct the state trie from accounts/storage leaf nodes
    let (account_count, record_count) = {
        let mut state_trie = EthTrie::new(trie_storage.clone());
        let mem_storage = Arc::new(MemoryDB::new(true));

        let mut account_count = u64::MIN;
        let mut record_count = u64::MIN;

        let mut reader = zipreader.by_name("state.bincode")?;
        while let Ok(account_key) =
            bincode::decode_from_std_read::<Vec<u8>, _, _>(&mut reader, BIN_CONFIG)
        {
            if account_count.is_multiple_of(10_000) {
                tracing::debug!(account=%account_count, record=%record_count, "Loaded");
                // Due to the way EthTrie works, we need to flush the trie to disk from time-to-time.
                //
                // Otherwise, we may run out of memory when the final root_hash() is called as it
                // takes up double the memory space when converting the data from its internal form
                // into a set of vectors that are passed to insert_batch().
                //
                // Unfortunately, this introduces intermediate states that will not be used normally.
                // So, we do this in batches.
                if account_count.is_multiple_of(100_000) {
                    state_trie.root_hash()?;
                }
            }

            let account_val: Vec<u8> = bincode::decode_from_std_read(&mut reader, BIN_CONFIG)?;
            state_trie.insert(account_key.as_slice(), account_val.as_slice())?;
            let account_root = Account::try_from(account_val.as_slice())?.storage_root;

            // load the storage trie
            let mut account_trie = EthTrie::new(mem_storage.clone());
            let count: usize = bincode::serde::decode_from_std_read(&mut reader, BIN_CONFIG)?;
            for _ in 0..count {
                let key: Vec<u8> = bincode::decode_from_std_read(&mut reader, BIN_CONFIG)?;
                let val: Vec<u8> = bincode::decode_from_std_read(&mut reader, BIN_CONFIG)?;
                account_trie.insert(key.as_slice(), val.as_slice())?;
                record_count += 1;
            }

            // compute the root trie for this account
            let root_hash = account_trie.root_hash()?;
            ensure!(
                *root_hash == *account_root,
                "Account storage root {root_hash} mismatch",
            );

            // commit the account-trie to disk
            let (keys, vals): (Vec<_>, Vec<_>) = mem_storage.storage.write().drain().unzip();
            trie_storage.insert_batch(keys, vals)?;

            account_count += 1;
        }
        tracing::info!(account=%account_count, record=%record_count, "Loaded"); // final update

        // compute state_root_hash for parent block; flushes nodes to disk.
        let root_hash = Hash(state_trie.root_hash()?.into());
        ensure!(
            root_hash == *state_root_hash,
            "State root hash {root_hash} mismatch",
        );
        (account_count, record_count)
    };

    Ok((account_count, record_count))
}

pub fn load_ckpt_history(path: &Path) -> Result<ViewHistory> {
    let mut zipreader = zip::ZipArchive::new(std::fs::File::open(path)?)?;
    ensure!(
        zipreader.comment() == CKPT_VERSION.as_bytes(),
        "Invalid checkpoint version",
    );
    let mut file = zipreader.by_name("history.bincode")?;
    let view_history: ViewHistory = bincode::serde::decode_from_std_read(&mut file, BIN_CONFIG)?;
    Ok(view_history)
}

#[allow(clippy::type_complexity)]
pub fn load_ckpt(
    path: &Path,
    trie_storage: Arc<TrieStorage>,
    chain_id: u64,
    block_hash: &Hash,
) -> Result<Option<(Block, Vec<SignedTransaction>, Block, ViewHistory)>> {
    let meta = load_ckpt_meta(path, chain_id, block_hash)?;
    let (block, transactions, parent) = load_ckpt_blocks(path)?;
    let (account_count, record_count) =
        load_ckpt_state(path, trie_storage.clone(), &parent.state_root_hash())?;

    ensure!(
        meta.record_count == record_count,
        "Record count {record_count} mismatch",
    );
    ensure!(
        meta.account_count == account_count,
        "Account count {account_count} mismatch",
    );

    let view_history = load_ckpt_history(path)?;

    tracing::info!(account=%account_count, record=%record_count, "Loaded"); // final update
    Ok(Some((block, transactions, parent, view_history)))
}

#[derive(Debug)]
struct AccountBlob {
    pub key: Vec<u8>,
    pub serialised_account: Vec<u8>,
    pub count: u64,
    pub spool: SpooledTempFile,
}

pub fn save_ckpt(
    path: &Path,
    trie_storage: Arc<TrieStorage>,
    block: &Block,
    transactions: &Vec<SignedTransaction>,
    parent: &Block,
    chain_id: u64,
    view_history: ViewHistory,
) -> Result<()> {
    // parent
    ensure!(
        block.parent_hash() == parent.hash(),
        "Parent hash {} mismatch",
        parent.hash()
    );
    // transactions
    let mut transactions_trie = EthTrie::new(Arc::new(MemoryDB::new(true)));
    for tx in transactions {
        let hash = tx.calculate_hash();
        transactions_trie.insert(hash.as_bytes(), hash.as_bytes())?;
    }
    let transactions_root_hash = Hash(transactions_trie.root_hash()?.into());
    ensure!(
        transactions_root_hash == block.header.transactions_root_hash,
        "Transactions root hash {transactions_root_hash} mismatch",
    );

    // Start writing the checkpoint file
    let zipfile = std::fs::File::create(path)?;
    let options = zip::write::SimpleFileOptions::default()
        .large_file(true)
        .compression_method(zip::CompressionMethod::Zstd);

    let mut zipwriter = zip::ZipWriter::new(zipfile);

    // write history.json
    zipwriter.start_file("history.bincode", options)?;
    bincode::serde::encode_into_std_write(view_history, &mut zipwriter, BIN_CONFIG)?;

    // write block.json
    zipwriter.start_file("block.bincode", options)?;
    bincode::serde::encode_into_std_write(block, &mut zipwriter, BIN_CONFIG)?;

    // write parent.json
    zipwriter.start_file("parent.bincode", options)?;
    bincode::serde::encode_into_std_write(parent, &mut zipwriter, BIN_CONFIG)?;

    // write transactions.json
    zipwriter.start_file("transactions.bincode", options)?;
    bincode::serde::encode_into_std_write(transactions, &mut zipwriter, BIN_CONFIG)?;

    // write the accounts in the state trie at this point
    zipwriter.start_file("state.bincode", options)?;

    let mut account_count = u64::MIN;
    let mut record_count = u64::MIN;
    let num_workers = crate::available_threads().max(1) * 2; // 2 x CPUs
    let (work_tx, work_rx) = crossbeam::channel::bounded::<(Vec<u8>, Vec<u8>)>(num_workers * 2); // 2 x Threads
    let (blob_tx, blob_rx) = crossbeam::channel::bounded::<AccountBlob>(num_workers * 2); // 2 x Threads

    // iterate over accounts and save the accounts to the checkpoint file.
    // This is done in parallel, using crossbeam, to speed up the process.
    // While the ordering of the accounts being saved is not guaranteed, it is not a problem as long as every account is completely saved.
    let state_trie = EthTrie::new(trie_storage.clone()).at_root(parent.state_root_hash().into());
    crossbeam::thread::scope(|s| {
        // Consumer: receive processed blobs and write them sequentially into the zip writer.
        let consumer = s.spawn(|_s| -> Result<u64> {
            let mut counter = u64::MIN;
            while let Ok(mut blob) = blob_rx.recv() {
                if account_count.is_multiple_of(10_000) {
                    tracing::info!(account=%account_count, record=%record_count, "Saved");
                }
                bincode::encode_into_std_write(&blob.key, &mut zipwriter, BIN_CONFIG)?;
                bincode::encode_into_std_write(
                    &blob.serialised_account,
                    &mut zipwriter,
                    BIN_CONFIG,
                )?;
                bincode::serde::encode_into_std_write(blob.count, &mut zipwriter, BIN_CONFIG)?;
                std::io::copy(&mut blob.spool, &mut zipwriter)?;
                record_count += blob.count;
                account_count += 1;
                counter += 1;
            }
            Ok(counter)
        });

        // Producer: iterate the state_trie and push work to workers.
        let producer = s.spawn(move |_s| -> Result<u64> {
            let mut counter = u64::MIN;
            for akv in state_trie.iter() {
                let (key, serialised_account) = akv?;
                work_tx.send((key.to_vec(), serialised_account.to_vec()))?;
                counter += 1;
            }
            drop(work_tx); // Close the work channel so Workers exit when done
            Ok(counter)
        });

        // Workers: concurrently construct each account blob
        let mut workers = Vec::with_capacity(num_workers);
        for _worker in 0..num_workers {
            let work_rx = work_rx.clone();
            let blob_tx = blob_tx.clone();
            let trie_storage = trie_storage.clone();

            let handle = s.spawn(move |_s| -> Result<u64> {
                let mut counter = u64::MIN;
                while let Ok((key, serialised_account)) = work_rx.recv() {
                    // iterate over account storage keys, and save them to the checkpoint file.
                    // use a single-pass strategy to reduce disk I/O and memory usage.
                    let account_root =
                        Account::try_from(serialised_account.as_slice())?.storage_root;
                    let account_trie = EthTrie::new(trie_storage.clone()).at_root(account_root);

                    let mut count = u64::MIN;
                    // write to spooled file, avoiding OOM.
                    let mut spool = tempfile::spooled_tempfile(1024 * 1024);
                    for skv in account_trie.iter() {
                        let (storage_key, storage_val) = skv?;
                        bincode::encode_into_std_write(&storage_key, &mut spool, BIN_CONFIG)?;
                        bincode::encode_into_std_write(&storage_val, &mut spool, BIN_CONFIG)?;
                        count += 1;
                    }
                    spool.flush()?; // flush data to spool
                    spool.rewind()?; // reset spool for reading

                    let blob = AccountBlob {
                        key,
                        serialised_account,
                        count,
                        spool,
                    };

                    blob_tx.send(blob)?;
                    counter += 1;
                }
                Ok(counter)
            });
            workers.push(handle);
        }

        // wait for all workers to finish
        for handle in workers {
            let _ = handle.join().expect("worker panicked").unwrap();
        }
        drop(blob_tx); // Close channel so that Consumer can exit.

        // assert checks
        let producer_count = producer.join().expect("producer panicked").unwrap();
        let consumer_count = consumer.join().expect("consumer panicked").unwrap();
        assert_eq!(producer_count, consumer_count);
    })
    .expect("Failed concurrent checkpoint generation");

    tracing::info!(account=%account_count, record=%record_count, "Saved"); // final update

    let meta = Checkpoint {
        account_count,
        record_count,
        chain_id,
        block_hash: block.hash(),
    };

    // write the V2.0 metadata
    zipwriter.start_file("metadata.json", options)?;
    serde_json::to_writer(&mut zipwriter, &meta)?;

    zipwriter.set_comment(CKPT_VERSION);
    zipwriter.finish()?;
    Ok(())
}
