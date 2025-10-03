/// Zilliqa 2.0 Checkpoint File Inspector
/// Tool to check if a checkpoint file contains the full missed view history
///
/// cargo run --release --bin inspect-ckpt -- \
/// --input 001641600.ckpt \
/// --hash 2ec445e87624dd05d5ccfdd38382ab41c3b1e18893297ce7f43c89037a315693 \
/// --id 33469
///
use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use tempfile::tempdir;
use zilliqa::{crypto::Hash, db::Db};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file name e.g. 008099089.ckpt
    #[arg(long)]
    input: String,

    /// Checkpoint block hash e.g. 92cbcca99ea6349434de2258841de000c243f5904dc5acdeef5f1f53590766c6

    #[arg(long)]
    hash: String,

    /// Shard ID e.g. 33101
    #[arg(long)]
    id: u64,
}

fn validate_args(args: &Args) -> Result<()> {
    if !args.input.ends_with(".ckpt") {
        return Err(anyhow::anyhow!("Input file name must end with .ckpt"));
    }
    if args.hash.len() != 64 {
        return Err(anyhow::anyhow!("Checkpoint block hash must be 256-bits"));
    }
    if args.id == 0 {
        return Err(anyhow::anyhow!("Shard ID must be greater than 0"));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("ZILLIQA 2.0 Checkpoint Inspector");
    let args = Args::parse();
    validate_args(&args)?;

    let dbpath = tempdir()?.keep();
    let path = PathBuf::from(args.input.clone());
    let db = Arc::new(Db::new::<PathBuf>(
        Some(dbpath.clone()),
        args.id,
        0,
        None,
        zilliqa::cfg::DbConfig::default(),
    )?);

    if let Some((block, _, _, view_history)) = zilliqa::checkpoint::load_ckpt(
        path.as_path(),
        Arc::new(db.state_trie()?),
        args.id,
        &Hash::from_bytes(hex::decode(args.hash.as_bytes())?)?,
    )? {
        if let Some((view, _)) = view_history.missed_views.front() {
            println!("{}", view_history);
            if match args.id {
                32769 => *view > 4770090,
                33101 => *view > 8099090,
                _ => false,
            } {
                println!("Missed view history incomplete!");
            }
        } else {
            if match args.id {
                32769 => block.number() == 4770089,
                33101 => block.number() == 8099089,
                _ => block.number() == 1,
            } {
                println!("Switchover or genesis checkpoint.");
            } else {
                println!("Empty missed view history only allowed in switchover checkpoint!");
            }
        }
    };
    Ok(())
}
