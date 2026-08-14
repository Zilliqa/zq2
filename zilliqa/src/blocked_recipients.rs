//! Staged sweep of a large account list. Each list is a file named by
//! [`crate::cfg::Fork::blocked_recipients_file`] and resolved against the node's
//! `blocked_recipients_dir` (falling back to `data_dir`), so successive forks can each activate
//! an independent list.
//!
//! From [`crate::cfg::Fork::blocked_recipients_start_height`], each block sweeps
//! [`ACCOUNTS_PER_BLOCK`] accounts: balance to the region destination, nonce to
//! [`BLOCKED_NONCE_FLOOR`]. Several million addresses, never held in memory.
//!
//! Little-endian. No magic, version or checksum.
//!
//! ```text
//! region_count   u32       >= 1, <= MAX_REGIONS
//! address_count  u64
//! regions        region_count x { first_index: u64, destination: 20 bytes }
//! addresses      address_count x 20 bytes
//! ```
//!
//! Regions are sorted from 0; address `i` sweeps to the last region with `first_index <= i`.

use std::{fs::File, os::unix::fs::FileExt, path::Path};

use anyhow::{Result, ensure};
use revm::primitives::Address;

pub const ACCOUNTS_PER_BLOCK: u64 = 100;

/// Freezes, not just blocks: revm rejects a `u64::MAX` tx nonce (EIP-2681), so a swept account
/// can never send, and so can never move off this value. `exec.rs` matches it with `==`.
pub const BLOCKED_NONCE_FLOOR: u64 = u64::MAX;

const ADDRESS_BYTES: usize = 20;

/// `region_count` + `address_count`.
const FIXED_HEADER_BYTES: u64 = 4 + 8;

/// `first_index` + `destination`.
const REGION_BYTES: u64 = 8 + ADDRESS_BYTES as u64;

/// Caps the region table allocation, made before anything vouches for `region_count`.
const MAX_REGIONS: u32 = 1024;

/// Last height at which the sweep does any work. `total` is [`BlockedRecipients::count`].
pub fn last_blocked_block(start_height: u64, total: u64) -> u64 {
    if total == 0 {
        return start_height;
    }
    start_height.saturating_add(total.div_ceil(ACCOUNTS_PER_BLOCK)) - 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    first_index: u64,
    destination: Address,
}

#[derive(Debug)]
pub struct BlockedRecipients {
    file: File,
    regions: Vec<Region>,
    count: u64,
    /// Header plus region table.
    body_offset: u64,
}

impl BlockedRecipients {
    /// Reads the header and region table only, never the body.
    ///
    /// Self-consistency checks only. **Nothing here is pinned to the binary** - the address count
    /// comes from the header and the address bytes are not read, so any well-formed file loads.
    /// A file the network does not share means a different state root, so failure is fatal to the
    /// caller and agreeing on the file is an operational problem.
    pub fn load(path: &Path) -> Result<Self> {
        let file =
            File::open(path).map_err(|e| anyhow::anyhow!("opening {}: {e}", path.display()))?;
        let file_len = file.metadata()?.len();

        ensure!(
            file_len >= FIXED_HEADER_BYTES,
            "{} is {file_len} bytes, too short to hold a header",
            path.display(),
        );
        let mut fixed = [0u8; FIXED_HEADER_BYTES as usize];
        file.read_exact_at(&mut fixed, 0)?;

        let region_count = u32::from_le_bytes(fixed[..4].try_into()?);
        ensure!(
            (1..=MAX_REGIONS).contains(&region_count),
            "{} declares {region_count} regions, expected 1..={MAX_REGIONS}",
            path.display(),
        );
        let count = u64::from_le_bytes(fixed[4..12].try_into()?);

        // `count` is bounded only by this: a file long enough to hold what it claims.
        let body_offset = FIXED_HEADER_BYTES + u64::from(region_count) * REGION_BYTES;
        let expected_len = count
            .checked_mul(ADDRESS_BYTES as u64)
            .and_then(|body| body_offset.checked_add(body))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} declares {count} addresses, which cannot fit",
                    path.display()
                )
            })?;
        ensure!(
            file_len == expected_len,
            "{} is {file_len} bytes, expected {expected_len} for {region_count} regions and {count} addresses",
            path.display(),
        );

        let mut region_bytes = vec![0u8; (u64::from(region_count) * REGION_BYTES) as usize];
        file.read_exact_at(&mut region_bytes, FIXED_HEADER_BYTES)?;
        let regions = parse_regions(&region_bytes, count)?;

        Ok(Self {
            file,
            regions,
            count,
            body_offset,
        })
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// `(blocked, destination)` pairs for `block_number`; empty outside the schedule, short on
    /// its last block. One 2 KiB read. The index is derived from the height alone, so a restart
    /// mid-schedule needs no saved progress.
    pub fn batch(&self, start_height: u64, block_number: u64) -> Result<Vec<(Address, Address)>> {
        let Some(offset) = block_number.checked_sub(start_height) else {
            return Ok(Vec::new());
        };
        let Some(index) = offset.checked_mul(ACCOUNTS_PER_BLOCK) else {
            return Ok(Vec::new());
        };
        if index >= self.count {
            return Ok(Vec::new());
        }
        let len = ACCOUNTS_PER_BLOCK.min(self.count - index);

        let mut bytes = vec![0u8; (len * ADDRESS_BYTES as u64) as usize];
        self.file
            .read_exact_at(&mut bytes, self.body_offset + index * ADDRESS_BYTES as u64)?;

        Ok(bytes
            .chunks_exact(ADDRESS_BYTES)
            .enumerate()
            .map(|(i, address)| {
                (
                    Address::from_slice(address),
                    destination_of(&self.regions, index + i as u64),
                )
            })
            .collect())
    }
}

fn destination_of(regions: &[Region], index: u64) -> Address {
    // `parse_regions` guarantees a region at 0, so the partition point is never 0.
    let position = regions.partition_point(|region| region.first_index <= index);
    regions[position - 1].destination
}

fn parse_regions(bytes: &[u8], count: u64) -> Result<Vec<Region>> {
    let regions: Vec<Region> = bytes
        .chunks_exact(REGION_BYTES as usize)
        .map(|chunk| {
            Ok(Region {
                first_index: u64::from_le_bytes(chunk[..8].try_into()?),
                destination: Address::from_slice(&chunk[8..]),
            })
        })
        .collect::<Result<_>>()?;

    ensure!(
        regions[0].first_index == 0,
        "the first region begins at index {}, expected 0",
        regions[0].first_index,
    );
    for pair in regions.windows(2) {
        ensure!(
            pair[0].first_index < pair[1].first_index,
            "regions are not sorted: {} then {}",
            pair[0].first_index,
            pair[1].first_index,
        );
    }
    if let Some(last) = regions.last() {
        ensure!(
            last.first_index < count,
            "region begins at index {} but there are only {count} addresses",
            last.first_index,
        );
    }

    Ok(regions)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn address(i: u64) -> Address {
        let mut bytes = [0u8; ADDRESS_BYTES];
        bytes[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(bytes)
    }

    /// In a range `address` never reaches, so the two are distinguishable.
    fn destination(i: u64) -> Address {
        let mut bytes = [0xffu8; ADDRESS_BYTES];
        bytes[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(bytes)
    }

    fn addresses(n: u64) -> Vec<Address> {
        (0..n).map(address).collect()
    }

    fn build(regions: &[(u64, Address)], addresses: &[Address]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(regions.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(addresses.len() as u64).to_le_bytes());
        for (first_index, dest) in regions {
            bytes.extend_from_slice(&first_index.to_le_bytes());
            bytes.extend_from_slice(dest.as_slice());
        }
        for address in addresses {
            bytes.extend_from_slice(address.as_slice());
        }
        bytes
    }

    fn write(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn load_ok(name: &str, regions: &[(u64, Address)], addrs: &[Address]) -> BlockedRecipients {
        let path = write(name, &build(regions, addrs));
        BlockedRecipients::load(&path).unwrap()
    }

    /// `exec.rs` matches with `==`, safe only while no account can move off this value. Lowering
    /// it would hand a blocked account a send, and that send would unblock it.
    #[test]
    fn the_blocked_nonce_floor_freezes_the_account() {
        assert_eq!(BLOCKED_NONCE_FLOOR, u64::MAX);
        assert!(BLOCKED_NONCE_FLOOR.checked_add(1).is_none());
    }

    #[test]
    fn batches_cover_every_address_exactly_once_in_order() {
        let addrs = addresses(250);
        let blocked = load_ok("br_cover.bin", &[(0, destination(1))], &addrs);
        let start = 1_000;

        let mut seen = Vec::new();
        for block in start..=last_blocked_block(start, addrs.len() as u64) {
            seen.extend(blocked.batch(start, block).unwrap());
        }

        assert_eq!(
            seen.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            addrs,
            "every address exactly once, in file order"
        );
    }

    #[test]
    fn final_batch_is_short_and_the_schedule_then_stops() {
        let blocked = load_ok("br_short.bin", &[(0, destination(1))], &addresses(250));
        let start = 1_000;
        let last = last_blocked_block(start, 250);

        assert_eq!(last, 1_002);
        assert_eq!(blocked.batch(start, 1_000).unwrap().len(), 100);
        assert_eq!(blocked.batch(start, 1_001).unwrap().len(), 100);
        assert_eq!(blocked.batch(start, last).unwrap().len(), 50);
        assert!(blocked.batch(start, last + 1).unwrap().is_empty());
    }

    #[test]
    fn blocks_before_the_start_do_nothing() {
        let blocked = load_ok("br_before.bin", &[(0, destination(1))], &addresses(100));
        assert!(blocked.batch(1_000, 999).unwrap().is_empty());
        assert!(blocked.batch(1_000, 0).unwrap().is_empty());
        assert_eq!(blocked.batch(1_000, 1_000).unwrap().len(), 100);
    }

    #[test]
    fn an_exact_multiple_leaves_no_trailing_block() {
        let blocked = load_ok("br_exact.bin", &[(0, destination(1))], &addresses(200));
        let start = 5;

        assert_eq!(last_blocked_block(start, 200), 6);
        assert_eq!(blocked.batch(start, 6).unwrap().len(), 100);
        assert!(blocked.batch(start, 7).unwrap().is_empty());
    }

    #[test]
    fn each_address_maps_to_its_regions_destination() {
        let regions = [
            (0, destination(1)),
            (120, destination(2)),
            (210, destination(3)),
        ];
        let blocked = load_ok("br_regions.bin", &regions, &addresses(250));
        let start = 7;

        let all: Vec<_> = (start..=last_blocked_block(start, 250))
            .flat_map(|block| blocked.batch(start, block).unwrap())
            .collect();

        assert_eq!(all[0].1, destination(1));
        assert_eq!(all[119].1, destination(1), "last of the first region");
        assert_eq!(all[120].1, destination(2), "first of the second region");
        assert_eq!(all[209].1, destination(2));
        assert_eq!(all[210].1, destination(3), "first of the third region");
        assert_eq!(all[249].1, destination(3));
    }

    /// A boundary inside a batch must not bleed one destination into the next region.
    #[test]
    fn a_region_boundary_inside_a_batch_is_respected() {
        let blocked = load_ok(
            "br_straddle.bin",
            &[(0, destination(1)), (150, destination(2))],
            &addresses(200),
        );

        let second = blocked.batch(0, 1).unwrap();
        assert_eq!(second[49].1, destination(1), "index 149");
        assert_eq!(second[50].1, destination(2), "index 150");
    }

    /// Nothing is pinned to the binary: neither the addresses nor how many of them there are.
    #[test]
    fn load_accepts_any_self_consistent_file() {
        let regions = [(0, destination(1))];
        let path = write("br_tamper.bin", &build(&regions, &addresses(4)[1..]));

        let blocked = BlockedRecipients::load(&path).unwrap();
        assert_eq!(blocked.count(), 3);
        assert_eq!(blocked.batch(0, 0).unwrap()[0].0, address(1));
    }

    #[test]
    fn load_refuses_a_truncated_file() {
        let mut bytes = build(&[(0, destination(1))], &addresses(3));
        bytes.truncate(bytes.len() - 1);
        let path = write("br_truncated.bin", &bytes);

        let error = BlockedRecipients::load(&path).unwrap_err().to_string();
        assert!(error.contains("expected"), "{error}");
    }

    /// Nothing downstream vouches for the header.
    #[test]
    fn load_refuses_a_header_it_cannot_trust() {
        let path = write("br_stub.bin", &[0u8; 5]);
        let error = BlockedRecipients::load(&path).unwrap_err().to_string();
        assert!(error.contains("too short to hold a header"), "{error}");

        let good = build(&[(0, destination(1))], &addresses(3));

        let mut no_regions = good.clone();
        no_regions[..4].copy_from_slice(&0u32.to_le_bytes());
        let path = write("br_no_regions.bin", &no_regions);
        let error = BlockedRecipients::load(&path).unwrap_err().to_string();
        assert!(error.contains("declares 0 regions"), "{error}");

        let mut too_many = good;
        too_many[..4].copy_from_slice(&(MAX_REGIONS + 1).to_le_bytes());
        let path = write("br_too_many.bin", &too_many);
        let error = BlockedRecipients::load(&path).unwrap_err().to_string();
        assert!(
            error.contains(&format!("declares {} regions", MAX_REGIONS + 1)),
            "{error}"
        );
    }

    #[test]
    fn load_refuses_regions_that_are_unsorted_or_do_not_start_at_zero() {
        let unsorted = build(
            &[
                (0, destination(1)),
                (200, destination(2)),
                (100, destination(3)),
            ],
            &addresses(250),
        );
        let path = write("br_unsorted.bin", &unsorted);
        assert!(
            BlockedRecipients::load(&path)
                .unwrap_err()
                .to_string()
                .contains("not sorted")
        );

        let late_start = build(&[(5, destination(1))], &addresses(250));
        let path = write("br_late.bin", &late_start);
        assert!(
            BlockedRecipients::load(&path)
                .unwrap_err()
                .to_string()
                .contains("expected 0")
        );
    }

    #[test]
    fn load_refuses_a_region_beyond_the_end_of_the_list() {
        let bytes = build(
            &[(0, destination(1)), (300, destination(2))],
            &addresses(250),
        );
        let path = write("br_beyond.bin", &bytes);

        let error = BlockedRecipients::load(&path).unwrap_err().to_string();
        assert!(error.contains("only 250 addresses"), "{error}");
    }

    #[test]
    fn load_refuses_a_missing_file() {
        let path = std::env::temp_dir().join("br_absent.bin");
        let _ = fs::remove_file(&path);

        assert!(BlockedRecipients::load(&path).is_err());
    }

    /// `batch`'s offset arithmetic is all that locates an address; check it at the far end.
    #[test]
    fn the_last_address_of_a_long_list_reads_back() {
        let total = 6_589;
        let addrs = addresses(total);
        let blocked = load_ok("br_long.bin", &[(0, destination(1))], &addrs);

        assert_eq!(blocked.count(), total);
        let last_index = total - 1;
        let last_block = last_index / ACCOUNTS_PER_BLOCK;
        let batch = blocked.batch(0, last_block).unwrap();
        assert_eq!(batch.last().unwrap().0, address(last_index));
    }
}
