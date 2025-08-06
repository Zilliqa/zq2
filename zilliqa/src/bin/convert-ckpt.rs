use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use zilliqa::{crypto::Hash, db::Db};

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

    let db = Db::new::<PathBuf>(Some("/tmp/ckpt".into()), args.id, 0, None)?;
    let db = Arc::new(db);

    // let state = State::new_with_genesis(db.state_trie()?, config, db.clone());

    let Some((block, transactions, parent)) = db.load_trusted_checkpoint(path, &hash, args.id)?
    else {
        return Err(anyhow::anyhow!("Input checkpoint error"));
    };

    // println!("{block:?}");
    // println!("{transactions:?}");
    // println!("{parent:?}");

    Ok(())
}
