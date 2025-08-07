/// cargo run --bin convert-ckpt -- \
/// --input 001641600.dat \
/// --output 001641600.ckpt \
/// --hash 2ec445e87624dd05d5ccfdd38382ab41c3b1e18893297ce7f43c89037a315693 \
/// --id 33469
/// --verify
///
use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use eth_trie::{EthTrie, MemoryDB, Trie};
use revm::primitives::FixedBytes;
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

    /// Verify
    #[arg(long, default_value_t = false)]
    verify: bool,
}

fn validate_args(args: &Args) -> Result<()> {
    if !args.input.ends_with(".dat") {
        return Err(anyhow::anyhow!("Input file name must end with .dat"));
    }
    if args.hash.len() != 64 {
        return Err(anyhow::anyhow!("Checkpoint block hash must be 256-bits"));
    }
    if args.id == 0 {
        return Err(anyhow::anyhow!("Shard ID must be greater than 0"));
    }
    if !args.output.ends_with(".ckpt") {
        return Err(anyhow::anyhow!("Output file name must end with .ckpt"));
    }
    Ok(())
}

fn main() -> Result<()> {
    println!("Checkpoint Converter");
    let args = Args::parse();
    validate_args(&args)?;

    let zipfile = match std::fs::File::create_new(args.output.clone()) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            eprintln!("Output file already exists");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to create output file: {}", e);
            std::process::exit(1);
        }
    };
    let hash = Hash::from_bytes(hex::decode(args.hash.as_bytes())?)?;

    let dbpath = tempdir()?.into_path();
    println!("READ {} -> {}", args.input, dbpath.display());
    let path = PathBuf::from(args.input);
    let db = Db::new::<PathBuf>(Some(dbpath), args.id, 0, None)?;
    let db = Arc::new(db);

    // let state = State::new_with_genesis(db.state_trie()?, config, db.clone());
    let Some((block, transactions, parent)) = db.load_trusted_checkpoint(path, &hash, args.id)?
    else {
        return Err(anyhow::anyhow!("Input checkpoint error"));
    };

    println!("WRITE {}", args.output);
    let bincfg = bincode::config::standard();
    let options = zip::write::SimpleFileOptions::default()
        .large_file(true)
        // .with_aes_encryption(zip::AesMode::Aes256, &args.hash)
        .compression_method(zip::CompressionMethod::Bzip2);

    let mut zipwriter = zip::ZipWriter::new(zipfile);

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
    let account_storage = EthTrie::new(state_trie_storage.clone());

    for (key, serialised_account) in accounts.iter() {
        bincode::encode_into_std_write(&key, &mut zipwriter, bincfg)?;
        bincode::encode_into_std_write(&serialised_account, &mut zipwriter, bincfg)?;

        let account_root = bincode::serde::decode_from_slice::<Account, _>(
            &serialised_account,
            bincode::config::legacy(),
        )?
        .0
        .storage_root;
        bincode::serde::encode_into_std_write(&account_root, &mut zipwriter, bincfg)?;
        let account_storage = account_storage.at_root(account_root);

        for (storage_key, storage_val) in account_storage.iter() {
            bincode::encode_into_std_write(&storage_key, &mut zipwriter, bincfg)?;
            bincode::encode_into_std_write(&storage_val, &mut zipwriter, bincfg)?;
        }
    }

    zipwriter.set_comment("ZILCHKPT");
    zipwriter.set_zip64_comment(Some(args.hash));
    // zipwriter.finish()?;

    let mut zipreader = zipwriter.finish_into_readable()?;

    if !args.verify {
        return Ok(());
    }

    println!("VERIFY");
    // READ TEST
    {
        let mut file = zipreader.by_name("block.bin")?;
        let block: zilliqa::message::Block =
            bincode::serde::decode_from_std_read(&mut file, bincfg)?;
        assert!(block.verify_hash().is_ok(), "Block hash mismatch");
    }
    {
        let mut file = zipreader.by_name("parent.bin")?;
        let block: zilliqa::message::Block =
            bincode::serde::decode_from_std_read(&mut file, bincfg)?;
        assert!(block.verify_hash().is_ok(), "Parent hash mismatch");
    }
    {
        let mem_storage = Arc::new(MemoryDB::default());
        let mut account_storage = EthTrie::new(mem_storage.clone());

        let mut reader = zipreader.by_name("state_trie.bin")?;
        loop {
            // let account_hash: Vec<u8> = match bincode::serde::decode_from_std_read(&mut reader, bincfg)
            let account_hash: Vec<u8> = match bincode::decode_from_std_read(&mut reader, bincfg) {
                Ok(h) => h,
                Err(_e) => {
                    break;
                }
            };
            let account_val: Vec<u8> = bincode::decode_from_std_read(&mut reader, bincfg)?;

            let account_trie_root: FixedBytes<32> =
                bincode::serde::decode_from_std_read(&mut reader, bincfg)?;

            let mut account_trie = EthTrie::new(mem_storage.clone());
            while account_trie.root_hash()? != account_trie_root {
                let storage_key: Vec<u8> = bincode::decode_from_std_read(&mut reader, bincfg)?;
                let storage_val: Vec<u8> = bincode::decode_from_std_read(&mut reader, bincfg)?;

                account_trie.insert(storage_key.as_slice(), storage_val.as_slice())?;
            }

            account_storage.insert(account_hash.as_slice(), account_val.as_slice())?;
        }
        assert_eq!(
            account_storage.root_hash()?.0,
            parent.state_root_hash().0,
            "State root hash mismatch"
        );
    }

    Ok(())
}
