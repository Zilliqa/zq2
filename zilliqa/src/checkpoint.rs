use anyhow::{Result, anyhow};
use eth_trie::{DB, EthTrie, MemoryDB, Trie};
use lz4::Decoder;
use std::{
    fs::File,
    io::{BufReader, Read},
    sync::Arc,
};

use crate::{crypto::Hash, db::TrieStorage, state::Account};
use crate::{message::Block, transaction::SignedTransaction};

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

        let account_trie_root = bincode::serde::decode_from_slice::<Account, _>(
            &serialised_account,
            bincode::config::legacy(),
        )?
        .0
        .storage_root;
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
        return Err(anyhow!(
            "Invalid checkpoint file: parent's blockhash does not correspond to checkpoint block"
        ));
    }

    Ok(Some((block, transactions, parent)))
}
