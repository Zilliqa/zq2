//! Generates `blocked_recipients.bin` (format: [`zilliqa::blocked_recipients`]) from exchange
//! CSV files, one sweep destination per file, swept in the order given.
//!
//! ```text
//! generate-blocked-recipients --out blocked_recipients.bin \
//!     binance.csv=0x48df1c337F04649687557608f7f2E65aeA93754C ...
//! ```
//!
//! Strictness over convenience - the output is consensus-critical, so anything unexpected
//! aborts rather than being skipped:
//!
//! - The first line of each CSV is a header and must not contain an address; every later
//!   non-empty line must contain exactly one address-shaped field (`zil1...` bech32, decoded
//!   with the same `bech32::decode` the node's API uses, or `0x` + 40 hex, EIP-55-checked when
//!   mixed-case). Other columns are ignored.
//! - Destinations must be EIP-55 checksummed, and must not themselves appear in the blocked
//!   list - a blocked destination would have its own swept funds re-swept, making the outcome
//!   order-dependent.
//! - Duplicate addresses collapse to their first occurrence, allowed only when both
//!   occurrences sweep to the same destination.
//!
//! After writing, the file is read back with the node's own parser ([`BlockedRecipients`]) and
//! every `(address, destination)` pair of the whole schedule is compared against the list built
//! from the CSVs.

use std::{collections::HashMap, fs, path::PathBuf, str::FromStr};

use alloy::hex;
use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Parser;
use revm::primitives::Address;
use sha2::{Digest, Sha256};
use zilliqa::blocked_recipients::{ACCOUNTS_PER_BLOCK, BlockedRecipients, last_blocked_block};

#[derive(Parser)]
#[clap(about = "Generate blocked_recipients.bin from per-exchange CSV files")]
struct Args {
    /// Output path for the generated file.
    #[clap(long)]
    out: PathBuf,
    /// `<csv>=<0x destination>` pairs, swept in the order given.
    #[clap(required = true, value_parser = parse_source)]
    sources: Vec<(PathBuf, Address)>,
}

fn parse_source(s: &str) -> Result<(PathBuf, Address), String> {
    let (path, destination) = s
        .rsplit_once('=')
        .ok_or_else(|| format!("expected <csv>=<0x destination>, got {s:?}"))?;
    let destination = Address::parse_checksummed(destination, None)
        .map_err(|e| format!("destination {destination:?} is not a checksummed address: {e}"))?;
    Ok((PathBuf::from(path), destination))
}

/// `Some` if the field is address-shaped; the inner result then insists it decodes, so a
/// malformed address is an error, never a skipped field.
fn try_address(field: &str) -> Option<Result<Address>> {
    if field.starts_with("zil1") {
        Some(match bech32::decode(field) {
            Ok((hrp, data)) if hrp.as_str() == "zil" => <[u8; 20]>::try_from(data.as_slice())
                .map(Address::from)
                .map_err(|_| anyhow!("{field:?} decodes to {} bytes, expected 20", data.len())),
            Ok((hrp, _)) => Err(anyhow!("{field:?} has HRP {hrp}, expected 'zil'")),
            Err(e) => Err(anyhow!("{field:?} is not valid bech32: {e}")),
        })
    } else if field.starts_with("0x") || field.starts_with("0X") {
        Some(decode_hex_address(field))
    } else {
        None
    }
}

fn decode_hex_address(field: &str) -> Result<Address> {
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

/// The line's single address, or `None` for an empty line. More or fewer than one
/// address-shaped field is an error.
fn line_address(line: &str) -> Result<Option<Address>> {
    if line.trim().is_empty() {
        return Ok(None);
    }
    let mut found = Vec::new();
    for field in line.split(',') {
        let field = field.trim_matches(|c: char| c.is_whitespace() || c == '"');
        if let Some(address) = try_address(field) {
            found.push(address?);
        }
    }
    match found.as_slice() {
        [address] => Ok(Some(*address)),
        [] => bail!("no address-shaped field"),
        _ => bail!("{} address-shaped fields, expected exactly 1", found.len()),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // (address, destination) in sweep order; the map holds the same assignment for lookups.
    let mut schedule: Vec<(Address, Address)> = Vec::new();
    let mut destination_of: HashMap<Address, Address> = HashMap::new();
    let mut regions: Vec<(u64, Address)> = Vec::new();

    for (path, destination) in &args.sources {
        let text = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
        let mut lines = text.lines().enumerate();

        let (_, header) = lines.next().ok_or_else(|| anyhow!("{path:?} is empty"))?;
        ensure!(
            line_address(header).is_err(),
            "{path:?} line 1 contains an address; expected a header line"
        );

        let region_start = schedule.len() as u64;
        let (mut added, mut duplicates) = (0u64, 0u64);
        for (index, line) in lines {
            let address = line_address(line)
                .with_context(|| format!("{path:?} line {}: {line:?}", index + 1))?;
            let Some(address) = address else { continue };
            match destination_of.get(&address) {
                None => {
                    destination_of.insert(address, *destination);
                    schedule.push((address, *destination));
                    added += 1;
                }
                Some(previous) if previous == destination => duplicates += 1,
                Some(previous) => bail!(
                    "{path:?} line {}: {address} already swept to {previous}, cannot also sweep to {destination}",
                    index + 1,
                ),
            }
        }
        ensure!(added + duplicates > 0, "{path:?} contains no addresses");

        // A file whose destination matches the previous region's folds into it; a file
        // contributing nothing new adds no region at all.
        if added > 0 && regions.last().map(|(_, d)| d) != Some(destination) {
            regions.push((region_start, *destination));
        }
        if *destination == Address::ZERO {
            eprintln!("WARNING: {path:?} sweeps to the zero address (placeholder?)");
        }
        println!(
            "{}: {added} addresses (skipped {duplicates} duplicates) -> {destination}",
            path.display()
        );
    }

    for (_, destination) in &regions {
        ensure!(
            !destination_of.contains_key(destination),
            "destination {destination} is itself in the blocked list"
        );
    }

    let mut bytes = Vec::with_capacity(12 + regions.len() * 28 + schedule.len() * 20);
    bytes.extend_from_slice(&u32::try_from(regions.len())?.to_le_bytes());
    bytes.extend_from_slice(&(schedule.len() as u64).to_le_bytes());
    for (first_index, destination) in &regions {
        bytes.extend_from_slice(&first_index.to_le_bytes());
        bytes.extend_from_slice(destination.as_slice());
    }
    for (address, _) in &schedule {
        bytes.extend_from_slice(address.as_slice());
    }
    fs::write(&args.out, &bytes).with_context(|| format!("writing {:?}", args.out))?;

    // Read back with the node's own parser and require the full schedule to match.
    let blocked = BlockedRecipients::load(&args.out)?;
    ensure!(
        blocked.count() == schedule.len() as u64,
        "read-back count {} != {}",
        blocked.count(),
        schedule.len()
    );
    let start = 1u64;
    let mut read_back = Vec::with_capacity(schedule.len());
    for height in start..=last_blocked_block(start, blocked.count()) {
        read_back.extend(blocked.batch(start, height)?);
    }
    ensure!(
        read_back == schedule,
        "read-back schedule differs from the CSVs"
    );

    println!(
        "\n{}: {} addresses, {} regions, {} bytes, {} sweep blocks of {} accounts",
        args.out.display(),
        schedule.len(),
        regions.len(),
        bytes.len(),
        (schedule.len() as u64).div_ceil(ACCOUNTS_PER_BLOCK),
        ACCOUNTS_PER_BLOCK,
    );
    println!("sha256: {}", hex::encode(Sha256::digest(&bytes)));
    println!("verified: read-back through BlockedRecipients matches all CSV pairs");
    Ok(())
}
