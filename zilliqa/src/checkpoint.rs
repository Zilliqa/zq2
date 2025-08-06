use anyhow::{Result, anyhow};
use lz4::Decoder;
use std::{
    fs::File,
    io::{BufReader, Read},
};

use crate::crypto::Hash;
use crate::{message::Block, transaction::SignedTransaction};

pub const CHECKPOINT_HEADER_BYTES: [u8; 8] = *b"ZILCHKPT";

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
