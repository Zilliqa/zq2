use std::path::PathBuf;

use anyhow::{anyhow, Result};
use bytesize::ByteSize;
use clap::{Parser, Subcommand};
use redb::{DatabaseStats, MultimapTableHandle, ReadableTableMetadata, TableHandle, TableStats};
use zilliqa::{crypto::Hash, db::Db};

#[derive(Debug, Parser)]
struct Args {
    data_dir: PathBuf,
    shard_id: u64,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Stats,
    Compact,
    #[clap(subcommand)]
    Query(Query),
}

#[derive(Debug, Subcommand)]
enum Query {
    Block { query: String },
    Blocks,
}

fn print_db_stats(stats: DatabaseStats) {
    eprintln!("database stats");
    eprintln!("tree_height: {}", stats.tree_height());
    eprintln!("allocated_pages: {}", stats.allocated_pages());
    eprintln!("leaf_pages: {}", stats.leaf_pages());
    eprintln!("branch_pages: {}", stats.branch_pages());
    eprintln!(
        "stored_bytes: {}",
        ByteSize::b(stats.stored_bytes()).to_string_as(true)
    );
    eprintln!(
        "metadata_bytes: {}",
        ByteSize::b(stats.metadata_bytes()).to_string_as(true)
    );
    eprintln!(
        "fragmented_bytes: {}",
        ByteSize::b(stats.fragmented_bytes()).to_string_as(true)
    );
    eprintln!(
        "page_size: {}",
        ByteSize::b(stats.page_size() as u64).to_string_as(true)
    );
    eprintln!();
}

fn print_table_stats(name: String, len: u64, stats: TableStats) {
    eprintln!("{name} table stats");
    eprintln!("length: {len}");
    eprintln!("tree_height: {}", stats.tree_height());
    eprintln!("leaf_pages: {}", stats.leaf_pages());
    eprintln!("branch_pages: {}", stats.branch_pages());
    eprintln!(
        "stored_bytes: {}",
        ByteSize::b(stats.stored_bytes()).to_string_as(true)
    );
    eprintln!(
        "metadata_bytes: {}",
        ByteSize::b(stats.metadata_bytes()).to_string_as(true)
    );
    eprintln!(
        "fragmented_bytes: {}",
        ByteSize::b(stats.fragmented_bytes()).to_string_as(true)
    );
    eprintln!();
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let db = Db::new(Some(args.data_dir), args.shard_id, 0)?;

    match args.command {
        Command::Stats => {
            let db = db.into_raw();
            let write = db.begin_write()?;

            print_db_stats(write.stats()?);

            let tables: Vec<_> = write.list_tables()?.collect();
            let multimap_tables: Vec<_> = write.list_multimap_tables()?.collect();

            write.abort()?;

            let read = db.begin_read()?;
            for table in tables {
                let name = table.name().to_owned();
                let table = read.open_untyped_table(table)?;
                print_table_stats(name, table.len()?, table.stats()?);
            }

            for table in multimap_tables {
                let name = table.name().to_owned();
                let table = read.open_untyped_multimap_table(table)?;
                print_table_stats(name, table.len()?, table.stats()?);
            }
        }
        Command::Compact => {
            let mut db = db.into_raw();
            db.compact()?;
        }
        Command::Query(Query::Block { query }) => {
            let read = db.read()?;
            let blocks = read.blocks()?;

            if let Some(query) = query.strip_prefix("0x") {
                let hash = Hash::from_bytes(hex::decode(query)?)?;
                let block = blocks
                    .by_hash(hash)?
                    .ok_or_else(|| anyhow!("missing block"))?;
                println!("{block:?}");
            } else {
                let height: u64 = query.parse()?;
                let block = blocks
                    .canonical_by_height(height)?
                    .ok_or_else(|| anyhow!("missing block"))?;
                println!("{block:?}");
            }
        }
        Command::Query(Query::Blocks) => {
            let read = db.read()?;
            let blocks = read.blocks()?;

            for block in blocks.iter()? {
                let block = block?;
                println!(
                    "view={}, height={}, hash={:?}",
                    block.view(),
                    block.number(),
                    block.hash()
                );
            }
        }
    }

    Ok(())
}
