/// Zilliqa 2.0 Checkpoint File Converter
/// Tool to convert a .dat checkpoint file to a .ckpt one
///
/// cargo run --release --bin convert-ckpt -- \
/// --input 001641600.dat \
/// --output 001641600.ckpt \
/// --hash 2ec445e87624dd05d5ccfdd38382ab41c3b1e18893297ce7f43c89037a315693 \
/// --id 33469
/// --verify
///
use std::{path::PathBuf, sync::Arc, time::Instant};

use alloy::hex;
use anyhow::Result;
use clap::Parser;
use tempfile::tempdir;
use zilliqa::{crypto::Hash, db::Db, precompiles::ViewHistory};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file name e.g. 008099089.dat
    #[arg(long)]
    input: String,

    /// Checkpoint block hash e.g. 92cbcca99ea6349434de2258841de000c243f5904dc5acdeef5f1f53590766c6

    #[arg(long)]
    hash: String,

    /// Shard ID e.g. 33101
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

#[tokio::main]
async fn main() -> Result<()> {
    println!("ZILLIQA 2.0 Checkpoint Converter");
    let args = Args::parse();
    validate_args(&args)?;

    let hash = Hash::from_bytes(hex::decode(args.hash.as_bytes())?)?;

    let dbpath = tempdir()?.keep();
    let path = PathBuf::from(args.input.clone());
    let db = Arc::new(Db::new(
        Some(dbpath.clone()),
        args.id,
        None,
        zilliqa::cfg::DbConfig::default(),
    )?);

    let now = Instant::now();
    println!("READ {} -> {}", args.input, dbpath.display());
    let Some((block, transactions, parent)) =
        zilliqa::checkpoint::load_trusted_checkpoint_v1(db.clone(), path, &hash, args.id)?
    else {
        return Err(anyhow::anyhow!("Input checkpoint error"));
    };
    println!("READ {:?}", now.elapsed());

    let path = PathBuf::from(args.output.clone());
    let now = Instant::now();
    println!("WRITE {} -> {}", dbpath.display(), args.output);
    zilliqa::checkpoint::save_ckpt(
        path.as_path(),
        Arc::new(db.state_trie()?),
        &block,
        &transactions,
        &parent,
        args.id,
        ViewHistory::default(),
    )?;
    println!("WRITE {:?}", now.elapsed());

    if !args.verify {
        return Ok(());
    }

    let dbpath = tempdir()?.keep();
    let path = PathBuf::from(args.output.clone());
    let db = Arc::new(Db::new(
        Some(dbpath.clone()),
        args.id,
        None,
        zilliqa::cfg::DbConfig::default(),
    )?);

    let now = Instant::now();
    println!("VERIFY {} -> {}", args.output, dbpath.display());
    zilliqa::checkpoint::load_ckpt(
        path.as_path(),
        Arc::new(db.state_trie()?),
        args.id,
        &Hash::from_bytes(hex::decode(args.hash.as_bytes())?)?,
    )?;
    println!("VERIFY {:?}", now.elapsed());

    Ok(())
}
