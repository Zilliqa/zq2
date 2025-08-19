/// cargo run --bin convert-ckpt -- \
/// --input 001641600.dat \
/// --output 001641600.ckpt \
/// --hash 2ec445e87624dd05d5ccfdd38382ab41c3b1e18893297ce7f43c89037a315693 \
/// --id 33469
/// --verify
///
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::Result;
use clap::Parser;
use eth_trie::{DB, EthTrie, MemoryDB, Trie};
use tempfile::tempdir;
use zilliqa::{
    crypto::Hash,
    db::{Db, TrieStorage},
    message::Block,
    state::Account,
    transaction::SignedTransaction,
};

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

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Checkpoint {
    pub account_count: u64,
    pub record_count: u64,
}

const BIN_CONFIG: bincode::config::Configuration = bincode::config::standard();
const CKPT_VERSION: &str = "ZILCHKPT/2.0";

fn load_ckpt(path: &Path, trie_storage: Arc<TrieStorage>) -> Result<()> {
    let mut zipreader = zip::ZipArchive::new(std::fs::File::open(path)?)?;

    if zipreader.comment() != CKPT_VERSION.as_bytes() {
        return Err(anyhow::anyhow!("Invalid checkpoint version"));
    }

    let meta = {
        let mut file = zipreader.by_name("metadata.json")?;
        let meta: Checkpoint = serde_json::from_reader(&mut file)?;
        meta
    };

    // READ TEST
    let _block = {
        let mut file = zipreader.by_name("block.bin")?;
        let block: zilliqa::message::Block =
            bincode::serde::decode_from_std_read(&mut file, BIN_CONFIG)?;
        assert!(block.verify_hash().is_ok(), "Block hash mismatch");
        block
    };
    let parent = {
        let mut file = zipreader.by_name("parent.bin")?;
        let block: zilliqa::message::Block =
            bincode::serde::decode_from_std_read(&mut file, BIN_CONFIG)?;
        assert!(block.verify_hash().is_ok(), "Parent hash mismatch");
        block
    };
    let _transactions = {
        let mut file = zipreader.by_name("transactions.bin")?;
        let transactions: Vec<SignedTransaction> =
            bincode::serde::decode_from_std_read(&mut file, BIN_CONFIG)?;
        transactions
    };

    let (account_count, record_count) = {
        let mut account_storage = EthTrie::new(trie_storage.clone());

        let mut account_count = 0;
        let mut record_count = 0;

        let mut reader = zipreader.by_name("state_trie.bin")?;
        while let Ok(account_key) =
            bincode::decode_from_std_read::<Vec<u8>, _, _>(&mut reader, BIN_CONFIG)
        {
            let account_val: Vec<u8> = bincode::decode_from_std_read(&mut reader, BIN_CONFIG)?;

            let account_root = bincode::serde::decode_from_slice::<Account, _>(
                account_val.as_slice(),
                bincode::config::legacy(),
            )?
            .0
            .storage_root;

            let mem_storage = Arc::new(MemoryDB::new(true));
            let mut account_trie = EthTrie::new(mem_storage.clone());

            let count: usize = bincode::serde::decode_from_std_read(&mut reader, BIN_CONFIG)?;
            for _ in 0..count {
                let key: Vec<u8> = bincode::decode_from_std_read(&mut reader, BIN_CONFIG)?;
                let val: Vec<u8> = bincode::decode_from_std_read(&mut reader, BIN_CONFIG)?;
                account_trie.insert(key.as_slice(), val.as_slice())?;
                record_count += 1;
            }
            // compute the root trie for this account, commits the trie to storage
            let root_hash = account_trie.root_hash()?;
            assert_eq!(root_hash, account_root, "Account storage root mismatch");
            let (keys, vals): (Vec<_>, Vec<_>) = mem_storage.storage.write().drain().unzip();
            trie_storage.insert_batch(keys, vals)?;

            account_storage.insert(account_key.as_slice(), account_val.as_slice())?;
            account_count += 1;
        }
        assert_eq!(
            account_storage.root_hash()?.0,
            parent.state_root_hash().0,
            "State root hash mismatch"
        );

        (account_count, record_count)
    };

    assert_eq!(meta.account_count, account_count, "Account count mismatch");
    assert_eq!(meta.record_count, record_count, "Record count mismatch");

    Ok(())
}

fn save_ckpt(
    path: &Path,
    trie_storage: Arc<TrieStorage>,
    block: Block,
    transactions: Vec<SignedTransaction>,
    parent: Block,
) -> Result<()> {
    let zipfile = std::fs::File::create(path)?;
    let options = zip::write::SimpleFileOptions::default()
        .large_file(true)
        // .with_aes_encryption(zip::AesMode::Aes256, &args.hash)
        .compression_method(zip::CompressionMethod::Bzip2);

    let mut zipwriter = zip::ZipWriter::new(zipfile);

    // write block.json
    zipwriter.start_file("block.bin", options)?;
    bincode::serde::encode_into_std_write(&block, &mut zipwriter, BIN_CONFIG)?;

    // write parent.json
    zipwriter.start_file("parent.bin", options)?;
    bincode::serde::encode_into_std_write(&parent, &mut zipwriter, BIN_CONFIG)?;

    // write transactions.json
    zipwriter.start_file("transactions.bin", options)?;
    bincode::serde::encode_into_std_write(&transactions, &mut zipwriter, BIN_CONFIG)?;

    zipwriter.start_file("state_trie.bin", options)?;
    let state_trie_storage = trie_storage.clone();

    let accounts =
        EthTrie::new(state_trie_storage.clone()).at_root(parent.state_root_hash().into());
    let account_storage = EthTrie::new(state_trie_storage.clone());

    let mut account_count = 0;
    let mut record_count = 0;
    for (key, serialised_account) in accounts.iter() {
        bincode::encode_into_std_write(&key, &mut zipwriter, BIN_CONFIG)?;
        bincode::encode_into_std_write(&serialised_account, &mut zipwriter, BIN_CONFIG)?;

        let account_root = bincode::serde::decode_from_slice::<Account, _>(
            &serialised_account,
            bincode::config::legacy(),
        )?
        .0
        .storage_root;
        // bincode::serde::encode_into_std_write(account_root, &mut zipwriter, BIN_CONFIG)?;
        let account_trie = account_storage.at_root(account_root);
        let count = account_trie.iter().count();
        bincode::serde::encode_into_std_write(count, &mut zipwriter, BIN_CONFIG)?;

        for (storage_key, storage_val) in account_trie.iter() {
            bincode::encode_into_std_write(&storage_key, &mut zipwriter, BIN_CONFIG)?;
            bincode::encode_into_std_write(&storage_val, &mut zipwriter, BIN_CONFIG)?;
            record_count += 1;
        }

        account_count += 1;
    }

    let meta = Checkpoint {
        account_count,
        record_count,
    };

    zipwriter.start_file("metadata.json", options)?;
    serde_json::to_writer(&mut zipwriter, &meta)?;

    zipwriter.set_comment(CKPT_VERSION);
    zipwriter.finish()?;
    Ok(())
}

fn main() -> Result<()> {
    println!("ZILLIQA 2.0 Checkpoint Converter");
    let args = Args::parse();
    validate_args(&args)?;

    let hash = Hash::from_bytes(hex::decode(args.hash.as_bytes())?)?;

    let dbpath = tempdir()?.into_path();
    let path = PathBuf::from(args.input.clone());
    let db = Arc::new(Db::new::<PathBuf>(Some(dbpath.clone()), args.id, 0, None)?);

    let now = Instant::now();
    println!("READ {} -> {}", args.input, dbpath.display());
    let Some((block, transactions, parent)) = db.load_trusted_checkpoint(path, &hash, args.id)?
    else {
        return Err(anyhow::anyhow!("Input checkpoint error"));
    };
    println!("READ {:?}", now.elapsed());

    let path = PathBuf::from(args.output.clone());
    let now = Instant::now();
    println!("WRITE {}", args.output);
    save_ckpt(
        path.as_path(),
        Arc::new(db.state_trie()?),
        block,
        transactions,
        parent,
    )?;
    println!("WRITE {:?}", now.elapsed());

    if !args.verify {
        return Ok(());
    }

    let dbpath = tempdir()?.into_path();
    let path = PathBuf::from(args.output.clone());
    let db = Arc::new(Db::new::<PathBuf>(Some(dbpath.clone()), args.id, 0, None)?);

    let now = Instant::now();
    println!("VERIFY {} -> {}", args.output, dbpath.display());
    load_ckpt(path.as_path(), Arc::new(db.state_trie()?))?;
    println!("VERIFY {:?}", now.elapsed());

    Ok(())
}
