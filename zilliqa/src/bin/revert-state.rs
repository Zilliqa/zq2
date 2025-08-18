use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use zilliqa::db::Db;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input directory e.g. "./data"
    #[arg(long)]
    data_dir: String,

    /// Shard ID
    #[arg(long)]
    id: u64,
}

fn main() -> Result<()> {
    println!("ZILLIQA 2.0 Restore State");
    let args = Args::parse();

    let data_dir = PathBuf::from(args.data_dir.clone());
    let db = Arc::new(Db::new::<PathBuf>(Some(data_dir), args.id, 0, None)?);

    let trie_storage = Arc::new(db.state_trie()?);

    trie_storage.revert_state().unwrap();

    Ok(())
}
