use std::{collections::HashSet, fs, path::PathBuf, str::FromStr};

use alloy::hex;
use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Parser;
use revm::primitives::Address;
use sha2::{Digest, Sha256};
use zilliqa::zq1_staking::{ENTRIES_PER_BLOCK, StakedZil, StakedZils, encode, last_block};

#[derive(Parser)]
#[clap(about = "Generate a staked zils list from a source,destination,amount CSV file")]
struct Args {
    #[clap(long, help = "Output path for the generated file")]
    out: PathBuf,
    #[clap(help = "CSV with source, destination and amount columns")]
    csv: PathBuf,
}

fn parse_address(field: &str) -> Result<Address> {
    if field.starts_with("zil1") {
        return match bech32::decode(field) {
            Ok((hrp, data)) if hrp.as_str() == "zil" => <[u8; 20]>::try_from(data.as_slice())
                .map(Address::from)
                .map_err(|_| anyhow!("{field:?} decodes to {} bytes, expected 20", data.len())),
            Ok((hrp, _)) => Err(anyhow!("{field:?} has HRP {hrp}, expected 'zil'")),
            Err(e) => Err(anyhow!("{field:?} is not valid bech32: {e}")),
        };
    }
    ensure!(
        field.starts_with("0x") || field.starts_with("0X"),
        "{field:?} is neither bech32 nor 0x-prefixed"
    );
    let body = &field[2..];
    ensure!(
        body.len() == 40 && body.bytes().all(|b| b.is_ascii_hexdigit()),
        "{field:?} is not 0x plus 40 hex digits"
    );
    let mixed_case = body.bytes().any(|b| b.is_ascii_lowercase())
        && body.bytes().any(|b| b.is_ascii_uppercase());
    if mixed_case {
        Address::parse_checksummed(field, None)
            .map_err(|e| anyhow!("{field:?} fails its EIP-55 checksum: {e}"))
    } else {
        Ok(Address::from_str(field)?)
    }
}

fn parse_amount(field: &str) -> Result<u128> {
    ensure!(
        !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()),
        "{field:?} is not an unsigned decimal integer"
    );
    field
        .parse::<u128>()
        .map_err(|e| anyhow!("{field:?} does not fit u128: {e}"))
}

fn fields(line: &str) -> Vec<&str> {
    line.split(',')
        .map(|field| field.trim_matches(|c: char| c.is_whitespace() || c == '"'))
        .collect()
}

fn column(header: &[&str], name: &str) -> Result<usize> {
    let matches: Vec<usize> = header
        .iter()
        .enumerate()
        .filter(|(_, h)| h.eq_ignore_ascii_case(name))
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => bail!("no {name} column among {header:?}"),
        _ => bail!("{} {name} columns among {header:?}", matches.len()),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let path = &args.csv;
    let text = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let mut lines = text.lines().enumerate();

    let (_, header) = lines.next().ok_or_else(|| anyhow!("{path:?} is empty"))?;
    let header = fields(header);
    let source_col = column(&header, "source").with_context(|| format!("{path:?} line 1"))?;
    let destination_col =
        column(&header, "destination").with_context(|| format!("{path:?} line 1"))?;
    let amount_col = column(&header, "amount").with_context(|| format!("{path:?} line 1"))?;

    let mut entries: Vec<StakedZil> = Vec::new();
    for (index, line) in lines {
        if line.trim().is_empty() {
            continue;
        }
        let row = fields(line);
        let context = || format!("{path:?} line {}: {line:?}", index + 1);
        ensure!(
            row.len() == header.len(),
            "{}: {} fields, header has {}",
            context(),
            row.len(),
            header.len()
        );
        let entry = StakedZil {
            source: parse_address(row[source_col]).with_context(context)?,
            destination: parse_address(row[destination_col]).with_context(context)?,
            amount: parse_amount(row[amount_col]).with_context(context)?,
        };
        ensure!(
            entry.source != entry.destination,
            "{}: source and destination are the same",
            context()
        );
        entries.push(entry);
    }
    ensure!(!entries.is_empty(), "{path:?} contains no entries");

    let sources: HashSet<Address> = entries.iter().map(|e| e.source).collect();
    if let Some(entry) = entries.iter().find(|e| sources.contains(&e.destination)) {
        bail!(
            "{} is both a destination and a source; the payout would depend on processing order",
            entry.destination
        );
    }

    let bytes = encode(&entries);
    fs::write(&args.out, &bytes).with_context(|| format!("writing {:?}", args.out))?;

    let list = StakedZils::load(&args.out)?;
    ensure!(
        list.count() == entries.len() as u64,
        "read-back count {} != {}",
        list.count(),
        entries.len()
    );
    let start = 1u64;
    let mut read_back = Vec::with_capacity(entries.len());
    for height in start..=last_block(start, list.count()) {
        read_back.extend(list.batch(start, height)?);
    }
    ensure!(read_back == entries, "read-back list differs from the CSV");

    let total: u128 = entries.iter().map(|e| e.amount).sum();
    println!(
        "{}: {} entries, {} unique sources, {total} total amount, {} bytes, {} blocks of {}",
        args.out.display(),
        entries.len(),
        sources.len(),
        bytes.len(),
        (entries.len() as u64).div_ceil(ENTRIES_PER_BLOCK),
        ENTRIES_PER_BLOCK,
    );
    println!("sha256: {}", hex::encode(Sha256::digest(&bytes)));
    println!("verified: read-back through StakedZils matches all CSV entries");
    Ok(())
}
