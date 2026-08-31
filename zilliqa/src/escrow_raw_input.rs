//! Staged lodging of token balances into the mintable escrow contract. Each list is a file named
//! by [`crate::cfg::Fork::escrow_lodge_file`], resolved against the node's
//! `escrow_raw_lists_dir` (falling back to `data_dir`) like the blocked-recipient lists.
//!
//! From [`crate::cfg::Fork::escrow_lodge_start_height`], each block lodges
//! [`ENTRIES_PER_BLOCK`] entries through a system call to `lodge(token, users, amounts)` on the
//! mintable escrow, one call per token in the batch. Never held in memory.
//!
//! Little-endian. No magic, version or checksum.
//!
//! ```text
//! region_count   u32       >= 1, <= MAX_REGIONS
//! entry_count    u64
//! regions        region_count x { first_index: u64, token: 20 bytes }
//! entries        entry_count x { user: 20 bytes, amount: u128 }
//! ```
//!
//! Regions are sorted from 0; entry `i` lodges into the last region with `first_index <= i`.
//! A (user, token) pair appears at most once per file: the contract assigns, not accumulates.

use std::{fs::File, os::unix::fs::FileExt, path::Path};

use anyhow::{Result, ensure};
use revm::primitives::Address;

pub const ENTRIES_PER_BLOCK: u64 = 100;

/// Upper bound on the gas one entry costs inside `lodge`: a fresh SSTORE plus the `Lodged`
/// event, measured at ~25.7k. `exec.rs` holds the contract to half of this, and startup
/// refuses a chain whose block gas limit cannot fit a full block's batch under it.
pub const LODGE_GAS_PER_ENTRY: u64 = 60_000;

const ADDRESS_BYTES: usize = 20;
const AMOUNT_BYTES: usize = 16;
const ENTRY_BYTES: usize = ADDRESS_BYTES + AMOUNT_BYTES;

/// `region_count` + `entry_count`.
const FIXED_HEADER_BYTES: u64 = 4 + 8;

/// `first_index` + `token`.
const REGION_BYTES: u64 = 8 + ADDRESS_BYTES as u64;

/// Caps the region table allocation, made before anything vouches for `region_count`.
const MAX_REGIONS: u32 = 1024;

/// Last height at which the schedule does any work. `total` is [`EscrowRawInput::count`].
pub fn last_lodge_block(start_height: u64, total: u64) -> u64 {
    if total == 0 {
        return start_height;
    }
    start_height.saturating_add(total.div_ceil(ENTRIES_PER_BLOCK)) - 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    first_index: u64,
    token: Address,
}

/// One `lodge` call's worth of entries: `(token, [(user, amount)])`.
pub type TokenBatch = (Address, Vec<(Address, u128)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LodgeEntry {
    pub token: Address,
    pub user: Address,
    pub amount: u128,
}

#[derive(Debug)]
pub struct EscrowRawInput {
    file: File,
    regions: Vec<Region>,
    count: u64,
    /// Header plus region table.
    body_offset: u64,
}

impl EscrowRawInput {
    /// Reads the header and region table only, never the body. Self-consistency checks only;
    /// as with blocked recipients, a file the network does not share means a different state
    /// root, so agreeing on the file is an operational problem.
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

        let body_offset = FIXED_HEADER_BYTES + u64::from(region_count) * REGION_BYTES;
        let expected_len = count
            .checked_mul(ENTRY_BYTES as u64)
            .and_then(|body| body_offset.checked_add(body))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} declares {count} entries, which cannot fit",
                    path.display()
                )
            })?;
        ensure!(
            file_len == expected_len,
            "{} is {file_len} bytes, expected {expected_len} for {region_count} regions and {count} entries",
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

    /// Every token the file lodges into, in region order.
    pub fn tokens(&self) -> impl Iterator<Item = Address> + '_ {
        self.regions.iter().map(|region| region.token)
    }

    /// Entries for `block_number`; empty outside the schedule, short on its last block. The
    /// index is derived from the height alone, so a restart mid-schedule needs no saved progress.
    pub fn batch(&self, start_height: u64, block_number: u64) -> Result<Vec<LodgeEntry>> {
        let Some(offset) = block_number.checked_sub(start_height) else {
            return Ok(Vec::new());
        };
        let Some(index) = offset.checked_mul(ENTRIES_PER_BLOCK) else {
            return Ok(Vec::new());
        };
        if index >= self.count {
            return Ok(Vec::new());
        }
        let len = ENTRIES_PER_BLOCK.min(self.count - index);

        let mut bytes = vec![0u8; (len * ENTRY_BYTES as u64) as usize];
        self.file
            .read_exact_at(&mut bytes, self.body_offset + index * ENTRY_BYTES as u64)?;

        bytes
            .chunks_exact(ENTRY_BYTES)
            .enumerate()
            .map(|(i, entry)| {
                Ok(LodgeEntry {
                    token: token_of(&self.regions, index + i as u64),
                    user: Address::from_slice(&entry[..ADDRESS_BYTES]),
                    amount: u128::from_le_bytes(entry[ADDRESS_BYTES..].try_into()?),
                })
            })
            .collect()
    }

    /// [`Self::batch`] grouped by token, in file order: one `lodge` call per group.
    pub fn batch_by_token(&self, start_height: u64, block_number: u64) -> Result<Vec<TokenBatch>> {
        let mut groups: Vec<TokenBatch> = Vec::new();
        for entry in self.batch(start_height, block_number)? {
            match groups.last_mut() {
                Some((token, users)) if *token == entry.token => {
                    users.push((entry.user, entry.amount))
                }
                _ => groups.push((entry.token, vec![(entry.user, entry.amount)])),
            }
        }
        Ok(groups)
    }
}

fn token_of(regions: &[Region], index: u64) -> Address {
    // `parse_regions` guarantees a region at 0, so the partition point is never 0.
    let position = regions.partition_point(|region| region.first_index <= index);
    regions[position - 1].token
}

fn parse_regions(bytes: &[u8], count: u64) -> Result<Vec<Region>> {
    let regions: Vec<Region> = bytes
        .chunks_exact(REGION_BYTES as usize)
        .map(|chunk| {
            Ok(Region {
                first_index: u64::from_le_bytes(chunk[..8].try_into()?),
                token: Address::from_slice(&chunk[8..]),
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
            "region begins at index {} but there are only {count} entries",
            last.first_index,
        );
    }

    Ok(regions)
}

/// Serialises a schedule in the file format; the generator and the tests share it.
pub fn encode(regions: &[(u64, Address)], entries: &[(Address, u128)]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        FIXED_HEADER_BYTES as usize
            + regions.len() * REGION_BYTES as usize
            + entries.len() * ENTRY_BYTES,
    );
    bytes.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (first_index, token) in regions {
        bytes.extend_from_slice(&first_index.to_le_bytes());
        bytes.extend_from_slice(token.as_slice());
    }
    for (user, amount) in entries {
        bytes.extend_from_slice(user.as_slice());
        bytes.extend_from_slice(&amount.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn user(i: u64) -> Address {
        let mut bytes = [0u8; ADDRESS_BYTES];
        bytes[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(bytes)
    }

    /// In a range `user` never reaches, so the two are distinguishable.
    fn token(i: u64) -> Address {
        let mut bytes = [0xffu8; ADDRESS_BYTES];
        bytes[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(bytes)
    }

    fn entries(n: u64) -> Vec<(Address, u128)> {
        (0..n).map(|i| (user(i), 1_000 + i as u128)).collect()
    }

    fn write(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn load_ok(
        name: &str,
        regions: &[(u64, Address)],
        entries: &[(Address, u128)],
    ) -> EscrowRawInput {
        let path = write(name, &encode(regions, entries));
        EscrowRawInput::load(&path).unwrap()
    }

    #[test]
    fn batches_cover_every_entry_exactly_once_in_order() {
        let list = entries(250);
        let lodge = load_ok("el_cover.bin", &[(0, token(1))], &list);
        let start = 1_000;

        let mut seen = Vec::new();
        for block in start..=last_lodge_block(start, list.len() as u64) {
            seen.extend(lodge.batch(start, block).unwrap());
        }

        assert_eq!(
            seen.iter().map(|e| (e.user, e.amount)).collect::<Vec<_>>(),
            list,
            "every entry exactly once, in file order"
        );
        assert!(seen.iter().all(|e| e.token == token(1)));
    }

    #[test]
    fn final_batch_is_short_and_the_schedule_then_stops() {
        let lodge = load_ok("el_short.bin", &[(0, token(1))], &entries(250));
        let start = 1_000;
        let last = last_lodge_block(start, 250);

        assert_eq!(last, 1_002);
        assert_eq!(lodge.batch(start, 1_000).unwrap().len(), 100);
        assert_eq!(lodge.batch(start, 1_001).unwrap().len(), 100);
        assert_eq!(lodge.batch(start, last).unwrap().len(), 50);
        assert!(lodge.batch(start, last + 1).unwrap().is_empty());
        assert!(lodge.batch(start, 999).unwrap().is_empty());
    }

    #[test]
    fn amounts_round_trip_at_full_width() {
        let list = vec![(user(1), u128::MAX), (user(2), 0), (user(3), 1 << 100)];
        let lodge = load_ok("el_width.bin", &[(0, token(1))], &list);
        let seen: Vec<_> = lodge
            .batch(0, 0)
            .unwrap()
            .into_iter()
            .map(|e| (e.user, e.amount))
            .collect();
        assert_eq!(seen, list);
    }

    #[test]
    fn regions_assign_tokens_and_group_batches() {
        let regions = [(0, token(1)), (150, token(2)), (160, token(3))];
        let lodge = load_ok("el_regions.bin", &regions, &entries(200));
        assert_eq!(
            lodge.tokens().collect::<Vec<_>>(),
            vec![token(1), token(2), token(3)]
        );

        // Block 0: indices 0..100, all token 1.
        let groups = lodge.batch_by_token(0, 0).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, token(1));
        assert_eq!(groups[0].1.len(), 100);

        // Block 1: indices 100..200 straddle all three regions, in order.
        let groups = lodge.batch_by_token(0, 1).unwrap();
        assert_eq!(
            groups
                .iter()
                .map(|(t, users)| (*t, users.len()))
                .collect::<Vec<_>>(),
            vec![(token(1), 50), (token(2), 10), (token(3), 40)]
        );
        assert_eq!(groups[1].1[0], (user(150), 1_150));
    }

    #[test]
    fn last_lodge_block_arithmetic() {
        assert_eq!(last_lodge_block(10, 0), 10);
        assert_eq!(last_lodge_block(10, 1), 10);
        assert_eq!(last_lodge_block(10, 100), 10);
        assert_eq!(last_lodge_block(10, 101), 11);
    }

    #[test]
    fn malformed_files_are_rejected() {
        let good = encode(&[(0, token(1))], &entries(10));

        // Truncated body.
        let path = write("el_trunc.bin", &good[..good.len() - 1]);
        assert!(EscrowRawInput::load(&path).is_err());

        // Trailing garbage.
        let mut long = good.clone();
        long.push(0);
        let path = write("el_long.bin", &long);
        assert!(EscrowRawInput::load(&path).is_err());

        // No regions.
        let path = write("el_noregion.bin", &encode(&[], &entries(10)));
        assert!(EscrowRawInput::load(&path).is_err());

        // First region not at 0, unsorted regions, region past the end.
        for regions in [
            vec![(1, token(1))],
            vec![(0, token(1)), (5, token(2)), (3, token(3))],
            vec![(0, token(1)), (10, token(2))],
        ] {
            let path = write("el_badregion.bin", &encode(&regions, &entries(10)));
            assert!(EscrowRawInput::load(&path).is_err(), "{regions:?}");
        }

        // Too short for a header.
        let path = write("el_header.bin", &[0u8; 5]);
        assert!(EscrowRawInput::load(&path).is_err());
    }
}
