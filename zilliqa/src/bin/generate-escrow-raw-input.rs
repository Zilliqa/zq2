//! Generates an escrow lodge list (format: [`zilliqa::escrow_raw_input`]) from per-token holder
//! CSV files, one destination token per file, lodged in the order given.
//!
//! ```text
//! generate-escrow-raw-input --out escrow_raw_lists/escrow_lodge_001.bin \
//!     gzil-holders.csv=0x1234...abcd xsgd-holders.csv=0x5678...ef01
//! ```
//!
//! Strictness over convenience - the output is consensus-critical, so anything unexpected
//! aborts rather than being skipped:
//!
//! - The first line of each CSV is a header naming an address column (`address`, `addr` or
//!   `wallet`, overridable with `--address-column`) and an amount column (`amount` or
//!   `balance`, overridable with `--amount-column`), matched case-insensitively.
//! - Addresses are `zil1...` bech32 or `0x` + 40 hex, EIP-55-checked when mixed-case. Amounts
//!   are unsigned decimal integers in the token's base units and must fit `u128`.
//! - Tokens must be EIP-55 checksummed. A (user, token) pair may appear only once: the
//!   contract's `lodge` assigns rather than accumulates, so a repeat would silently overwrite.
//! - Zero amounts are dropped (a zero lodge is a no-op) and reported.
//!
//! After writing, the file is read back with the node's own parser ([`EscrowRawInput`]) and every
//! entry of the whole schedule is compared against the list built from the CSVs.

use std::{collections::HashSet, fs, path::PathBuf, str::FromStr};

use alloy::hex;
use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Parser;
use revm::primitives::Address;
use sha2::{Digest, Sha256};
use zilliqa::escrow_raw_input::{ENTRIES_PER_BLOCK, EscrowRawInput, encode, last_lodge_block};

#[derive(Parser)]
#[clap(about = "Generate an escrow lodge list from per-token holder CSV files")]
struct Args {
    /// Output path for the generated file.
    #[clap(long)]
    out: PathBuf,
    /// Header of the column holding the user address.
    #[clap(long)]
    address_column: Option<String>,
    /// Header of the column holding the amount to lodge.
    #[clap(long)]
    amount_column: Option<String>,
    /// `<csv>=<0x token>` pairs, lodged in the order given.
    #[clap(required = true, value_parser = parse_source)]
    sources: Vec<(PathBuf, Address)>,
}

fn parse_source(s: &str) -> Result<(PathBuf, Address), String> {
    let (path, token) = s
        .rsplit_once('=')
        .ok_or_else(|| format!("expected <csv>=<0x token>, got {s:?}"))?;
    let token = Address::parse_checksummed(token, None)
        .map_err(|e| format!("token {token:?} is not a checksummed address: {e}"))?;
    Ok((PathBuf::from(path), token))
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

/// Index of the single header matching one of `names` (case-insensitive).
fn column(header: &[&str], names: &[&str], what: &str) -> Result<usize> {
    let matches: Vec<usize> = header
        .iter()
        .enumerate()
        .filter(|(_, h)| names.iter().any(|n| h.eq_ignore_ascii_case(n)))
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        [] => bail!("no {what} column among {header:?} (looked for {names:?})"),
        _ => bail!("{} {what} columns among {header:?}", matches.len()),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let address_names: Vec<&str> = match &args.address_column {
        Some(name) => vec![name.as_str()],
        None => vec!["address", "addr", "wallet"],
    };
    let amount_names: Vec<&str> = match &args.amount_column {
        Some(name) => vec![name.as_str()],
        None => vec!["amount", "balance"],
    };

    let mut entries: Vec<(Address, u128)> = Vec::new();
    let mut seen: HashSet<(Address, Address)> = HashSet::new();
    let mut regions: Vec<(u64, Address)> = Vec::new();
    let mut total_zero = 0u64;

    for (path, token) in &args.sources {
        let text = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
        let mut lines = text.lines().enumerate();

        let (_, header) = lines.next().ok_or_else(|| anyhow!("{path:?} is empty"))?;
        let header = fields(header);
        let address_col = column(&header, &address_names, "address")
            .with_context(|| format!("{path:?} line 1"))?;
        let amount_col =
            column(&header, &amount_names, "amount").with_context(|| format!("{path:?} line 1"))?;
        ensure!(
            address_col != amount_col,
            "{path:?}: address and amount resolve to the same column"
        );

        let region_start = entries.len() as u64;
        let (mut added, mut zeros) = (0u64, 0u64);
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
            let user = parse_address(row[address_col]).with_context(context)?;
            let amount = parse_amount(row[amount_col]).with_context(context)?;
            ensure!(
                seen.insert((user, *token)),
                "{}: {user} already lodged into {token}",
                context()
            );
            if amount == 0 {
                zeros += 1;
                continue;
            }
            entries.push((user, amount));
            added += 1;
        }
        ensure!(added + zeros > 0, "{path:?} contains no entries");
        total_zero += zeros;

        // A file whose token matches the previous region's folds into it; a file contributing
        // nothing adds no region at all.
        if added > 0 && regions.last().map(|(_, t)| t) != Some(token) {
            regions.push((region_start, *token));
        }
        println!(
            "{}: {added} entries (dropped {zeros} zero amounts) -> {token}",
            path.display()
        );
    }
    ensure!(!entries.is_empty(), "no entries to lodge");

    let bytes = encode(&regions, &entries);
    fs::write(&args.out, &bytes).with_context(|| format!("writing {:?}", args.out))?;

    // Read back with the node's own parser and require the full schedule to match.
    let lodge = EscrowRawInput::load(&args.out)?;
    ensure!(
        lodge.count() == entries.len() as u64,
        "read-back count {} != {}",
        lodge.count(),
        entries.len()
    );
    let start = 1u64;
    let mut read_back = Vec::with_capacity(entries.len());
    for height in start..=last_lodge_block(start, lodge.count()) {
        read_back.extend(lodge.batch(start, height)?);
    }
    let expected: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(i, (user, amount))| {
            let token = regions
                .iter()
                .rev()
                .find(|(first, _)| *first <= i as u64)
                .map(|(_, token)| *token)
                .expect("a region begins at 0");
            (token, *user, *amount)
        })
        .collect();
    let read_back: Vec<_> = read_back
        .iter()
        .map(|e| (e.token, e.user, e.amount))
        .collect();
    ensure!(
        read_back == expected,
        "read-back schedule differs from the CSVs"
    );

    println!(
        "\n{}: {} entries, {} regions, {} zero amounts dropped, {} bytes, {} lodge blocks of {} entries",
        args.out.display(),
        entries.len(),
        regions.len(),
        total_zero,
        bytes.len(),
        (entries.len() as u64).div_ceil(ENTRIES_PER_BLOCK),
        ENTRIES_PER_BLOCK,
    );
    println!("sha256: {}", hex::encode(Sha256::digest(&bytes)));
    println!("verified: read-back through EscrowRawInput matches all CSV entries");
    Ok(())
}
