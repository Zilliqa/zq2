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

pub const LODGE_GAS_PER_ENTRY: u64 = 60_000;

const ADDRESS_BYTES: usize = 20;
const AMOUNT_BYTES: usize = 16;
const ENTRY_BYTES: usize = ADDRESS_BYTES + AMOUNT_BYTES;

const FIXED_HEADER_BYTES: u64 = 4 + 8;

const REGION_BYTES: u64 = 8 + ADDRESS_BYTES as u64;

const MAX_REGIONS: u32 = 1024;

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
    body_offset: u64,
}

impl EscrowRawInput {
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

    pub fn tokens(&self) -> impl Iterator<Item = Address> + '_ {
        self.regions.iter().map(|region| region.token)
    }

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
            .as_chunks::<ENTRY_BYTES>()
            .0
            .iter()
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
    let position = regions.partition_point(|region| region.first_index <= index);
    regions[position - 1].token
}

fn parse_regions(bytes: &[u8], count: u64) -> Result<Vec<Region>> {
    let regions: Vec<Region> = bytes
        .as_chunks::<{ REGION_BYTES as usize }>()
        .0
        .iter()
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
