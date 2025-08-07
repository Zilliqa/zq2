use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use eth_trie::EthTrie;
use tempfile::tempdir;
use zilliqa::{crypto::Hash, db::Db, state::Account};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file name e.g. 008099089.dat
    #[arg(long)]
    input: String,

    /// Checkpoint block hash e.g. 2ec445e87624dd05d5ccfdd38382ab41c3b1e18893297ce7f43c89037a315693
    #[arg(long)]
    hash: String,

    /// Shard ID
    #[arg(long)]
    id: u64,

    /// Output file name e.g. 008099089.ckpt
    #[arg(long)]
    output: String,
}

fn main() -> Result<()> {
    println!("Checkpoint Converter");
    let args = Args::parse();

    let hash = Hash::from_bytes(hex::decode(args.hash.as_bytes())?)?;
    let path = PathBuf::from(args.input);

    let db = Db::new::<PathBuf>(Some(tempdir()?.into_path()), args.id, 0, None)?;
    let db = Arc::new(db);

    // let state = State::new_with_genesis(db.state_trie()?, config, db.clone());

    let Some((block, transactions, parent)) = db.load_trusted_checkpoint(path, &hash, args.id)?
    else {
        return Err(anyhow::anyhow!("Input checkpoint error"));
    };

    println!("{:?}", zip::SUPPORTED_COMPRESSION_METHODS);

    let bincfg = bincode::config::standard();

    let options = zip::write::SimpleFileOptions::default()
        .large_file(true)
        .with_aes_encryption(zip::AesMode::Aes256, &args.hash)
        .compression_method(zip::CompressionMethod::Bzip2);
    let mut zipwriter = zip::ZipWriter::new(std::fs::File::create(args.output)?);

    println!("{:?}", options.get_compression_level());

    // write block.json
    zipwriter.start_file("block.bin", options)?;
    bincode::serde::encode_into_std_write(&block, &mut zipwriter, bincfg)?;

    // write parent.json
    zipwriter.start_file("parent.bin", options)?;
    bincode::serde::encode_into_std_write(&parent, &mut zipwriter, bincfg)?;

    // write transactions.json
    zipwriter.start_file("transactions.bin", options)?;
    bincode::serde::encode_into_std_write(&transactions, &mut zipwriter, bincfg)?;

    zipwriter.start_file("state_trie.bin", options)?;
    let state_trie_storage = Arc::new(db.state_trie()?);
    let accounts =
        EthTrie::new(state_trie_storage.clone()).at_root(parent.state_root_hash().into());
    let account_storage = EthTrie::new(state_trie_storage);

    for (key, serialised_account) in accounts.iter() {
        bincode::serde::encode_into_std_write(&key, &mut zipwriter, bincfg)?;
        bincode::serde::encode_into_std_write(&serialised_account, &mut zipwriter, bincfg)?;

        let account_storage = account_storage.at_root(
            bincode::serde::decode_from_slice::<Account, _>(
                &serialised_account,
                bincode::config::legacy(),
            )?
            .0
            .storage_root,
        );

        for (storage_key, storage_val) in account_storage.iter() {
            bincode::serde::encode_into_std_write(&storage_key, &mut zipwriter, bincfg)?;
            bincode::serde::encode_into_std_write(&storage_val, &mut zipwriter, bincfg)?;
        }
    }

    zipwriter.set_comment("ZILCHKPT");
    zipwriter.set_zip64_comment(Some(args.hash));
    zipwriter.finish()?;
    Ok(())
}
