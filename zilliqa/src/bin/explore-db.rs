use std::path::PathBuf;

use anyhow::Result;
use bytesize::ByteSize;
use clap::{Parser, Subcommand};
use redb::{DatabaseStats, MultimapTableHandle, ReadableTableMetadata, TableHandle, TableStats};
use zilliqa::db::Db;

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
    eprintln!("page_size: {}", stats.page_size());
    eprintln!();
}

fn print_table_stats(name: String, stats: TableStats) {
    eprintln!("{name} table stats");
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
    let mut db = db.into_raw();

    match args.command {
        Command::Stats => {
            let write = db.begin_write()?;

            print_db_stats(write.stats()?);

            let tables: Vec<_> = write.list_tables()?.collect();
            let multimap_tables: Vec<_> = write.list_multimap_tables()?.collect();

            write.abort()?;

            let read = db.begin_read()?;
            for table in tables {
                let name = table.name().to_owned();
                let stats = read.open_untyped_table(table)?.stats()?;
                print_table_stats(name, stats);
            }

            for table in multimap_tables {
                let name = table.name().to_owned();
                let stats = read.open_untyped_multimap_table(table)?.stats()?;
                print_table_stats(name, stats);
            }
        }
        Command::Compact => {
            db.compact()?;
        }
    }

    Ok(())
}
