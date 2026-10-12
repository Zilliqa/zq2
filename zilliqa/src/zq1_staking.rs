use std::{
    fs::File,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};

use alloy::{consensus::EMPTY_ROOT_HASH, primitives::Address};
use anyhow::{Result, anyhow, ensure};
use revm::{context::result::ResultAndState, context_interface::TransactionType};
use tracing::{info, warn};

use crate::{
    blocked_recipients::BLOCKED_NONCE_FLOOR,
    cfg::{ForkName, Forks, NodeConfig},
    contracts,
    error::ensure_success,
    exec::{BaseFeeAndNonceCheck, ExecType, ExtraOpts},
    inspector,
    message::BlockHeader,
    state::{State, contract_addr},
};

pub const ENTRIES_PER_BLOCK: u64 = 100;

const ADDRESS_BYTES: usize = 20;
const AMOUNT_BYTES: usize = 16;
const ENTRY_BYTES: usize = 2 * ADDRESS_BYTES + AMOUNT_BYTES;
const HEADER_BYTES: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakedZil {
    pub source: Address,
    pub destination: Address,
    pub amount: u128,
}

#[derive(Debug)]
pub struct StakedZils {
    file: File,
    count: u64,
}

impl StakedZils {
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|e| anyhow!("opening {}: {e}", path.display()))?;
        let file_len = file.metadata()?.len();
        ensure!(
            file_len >= HEADER_BYTES,
            "{} is {file_len} bytes, too short to hold a header",
            path.display(),
        );
        let mut header = [0u8; HEADER_BYTES as usize];
        file.read_exact_at(&mut header, 0)?;
        let count = u64::from_le_bytes(header);
        let expected_len = count
            .checked_mul(ENTRY_BYTES as u64)
            .and_then(|body| body.checked_add(HEADER_BYTES))
            .ok_or_else(|| {
                anyhow!(
                    "{} declares {count} entries, which cannot fit",
                    path.display()
                )
            })?;
        ensure!(
            file_len == expected_len,
            "{} is {file_len} bytes, expected {expected_len} for {count} entries",
            path.display(),
        );
        Ok(Self { file, count })
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn batch(&self, start_height: u64, block_number: u64) -> Result<Vec<StakedZil>> {
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
            .read_exact_at(&mut bytes, HEADER_BYTES + index * ENTRY_BYTES as u64)?;

        bytes
            .as_chunks::<ENTRY_BYTES>()
            .0
            .iter()
            .map(|entry| {
                Ok(StakedZil {
                    source: Address::from_slice(&entry[..ADDRESS_BYTES]),
                    destination: Address::from_slice(&entry[ADDRESS_BYTES..2 * ADDRESS_BYTES]),
                    amount: u128::from_le_bytes(entry[2 * ADDRESS_BYTES..].try_into()?),
                })
            })
            .collect()
    }
}

pub fn last_block(start_height: u64, count: u64) -> u64 {
    if count == 0 {
        return start_height;
    }
    start_height.saturating_add(count.div_ceil(ENTRIES_PER_BLOCK)) - 1
}

pub fn encode(entries: &[StakedZil]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES as usize + entries.len() * ENTRY_BYTES);
    bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(entry.source.as_slice());
        bytes.extend_from_slice(entry.destination.as_slice());
        bytes.extend_from_slice(&entry.amount.to_le_bytes());
    }
    bytes
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    pub contract: Address,
    pub file: String,
    pub start_height: u64,
    pub replaced_at: Option<u64>,
}

pub fn schedules(forks: &Forks) -> Result<Vec<Schedule>> {
    let mut schedules: Vec<Schedule> = Vec::new();
    let mut open: Option<usize> = None;
    let mut previous = (Address::ZERO, "");
    for fork in forks.iter() {
        let pair = (
            fork.invalidate_zq1_staking_contract,
            fork.staked_zils_file.as_str(),
        );
        if pair == previous {
            continue;
        }
        ensure!(
            !pair.0.is_zero() || pair.1.is_empty(),
            "fork at height {}: staked_zils_file requires invalidate_zq1_staking_contract",
            fork.at_height,
        );
        if let Some(index) = open.take() {
            schedules[index].replaced_at = Some(fork.at_height);
        }
        if !pair.0.is_zero() {
            ensure!(
                fork.at_height != 0,
                "invalidate_zq1_staking_contract cannot activate at genesis"
            );
            ensure!(
                pair.1.is_empty() || schedules.iter().all(|s| s.file != pair.1),
                "staked zils file {} is referenced by two forks",
                pair.1,
            );
            schedules.push(Schedule {
                contract: pair.0,
                file: pair.1.to_owned(),
                start_height: fork.at_height,
                replaced_at: None,
            });
            open = Some(schedules.len() - 1);
        }
        previous = pair;
    }
    Ok(schedules)
}

#[derive(Debug)]
pub struct Zq1Staking {
    schedules: Vec<(Schedule, Option<StakedZils>)>,
}

impl Zq1Staking {
    pub fn load(config: &NodeConfig, forks: &Forks) -> Result<Self> {
        let escrow_height =
            forks.find_height_fork_first_activated(ForkName::DeployEscrowContractV1);
        let mut loaded = Vec::new();
        for schedule in schedules(forks)? {
            let list = if schedule.file.is_empty() {
                None
            } else {
                let dir = config
                    .blocked_recipients_dir
                    .as_ref()
                    .or(config.data_dir.as_ref())
                    .ok_or_else(|| {
                        anyhow!(
                            "a fork names {} but neither blocked_recipients_dir nor data_dir is set",
                            schedule.file,
                        )
                    })?;
                let path = PathBuf::from(dir).join(&schedule.file);
                let list = StakedZils::load(&path)?;
                ensure!(
                    escrow_height.is_some_and(|height| height <= schedule.start_height),
                    "{} starts at {} but the escrow contract is not deployed by then",
                    schedule.file,
                    schedule.start_height,
                );
                info!(
                    count = list.count(),
                    start_height = schedule.start_height,
                    path = %path.display(),
                    "opened staked zils list"
                );
                Some(list)
            };
            let last = last_block(
                schedule.start_height,
                list.as_ref().map_or(0, StakedZils::count),
            );
            if let Some(replaced_at) = schedule.replaced_at {
                ensure!(
                    last < replaced_at,
                    "zq1 staking schedule from {} runs until block {last} but is replaced by a fork at {replaced_at}",
                    schedule.start_height,
                );
            }
            loaded.push((schedule, list));
        }
        Ok(Self { schedules: loaded })
    }

    pub fn apply(&self, state: &mut State, header: BlockHeader) -> Result<()> {
        let number = header.number;
        let Some((schedule, list)) = self.schedules.iter().find(|(schedule, _)| {
            schedule.start_height <= number
                && schedule
                    .replaced_at
                    .is_none_or(|replaced_at| number < replaced_at)
        }) else {
            return Ok(());
        };
        if let Some(list) = list {
            for entry in list.batch(schedule.start_height, number)? {
                state.pay_out_staked_zil(entry, header)?;
            }
        }
        if number
            == last_block(
                schedule.start_height,
                list.as_ref().map_or(0, StakedZils::count),
            )
        {
            state.empty_scilla_contract(schedule.contract)?;
        }
        Ok(())
    }
}

impl State {
    fn pay_out_staked_zil(&mut self, entry: StakedZil, header: BlockHeader) -> Result<()> {
        let StakedZil {
            source,
            destination,
            amount,
        } = entry;
        let payout = self
            .get_account(source)?
            .balance
            .checked_add(amount)
            .ok_or_else(|| anyhow!("staked zils payout for {source} overflows"))?;

        if destination == contract_addr::ESCROW_PROXY {
            self.mutate_account(source, |account| {
                account.balance = payout;
                if account.nonce == BLOCKED_NONCE_FLOOR {
                    account.nonce = 0;
                }
                Ok(())
            })?;
            let nonce = self.get_account(source)?.nonce;
            let (ResultAndState { result, state }, ..) = self.apply_transaction_evm(
                source,
                Some(destination),
                0,
                None,
                self.block_gas_limit,
                payout,
                contracts::escrow_init::LODGE.encode_input(&[])?,
                Some(nonce),
                None,
                None,
                header,
                inspector::noop(),
                false,
                BaseFeeAndNonceCheck::Ignore,
                ExtraOpts {
                    disable_eip3607: true,
                    exec_type: ExecType::Transact,
                    tx_type: TransactionType::Legacy,
                },
            )?;
            ensure_success(result)
                .map_err(|e| anyhow!("escrow lodge of {payout} for {source} failed: {e}"))?;
            self.apply_delta_evm(&state, header.number)?;
        } else {
            self.mutate_account(destination, |account| {
                account.balance = account
                    .balance
                    .checked_add(payout)
                    .ok_or_else(|| anyhow!("balance overflow paying {payout} to {destination}"))?;
                Ok(())
            })?;
        }

        self.mutate_account(source, |account| {
            account.balance = 0;
            account.nonce = BLOCKED_NONCE_FLOOR;
            Ok(())
        })
    }

    pub fn empty_scilla_contract(&mut self, address: Address) -> Result<()> {
        if !self.get_account(address)?.code.is_scilla() {
            warn!(%address, "invalidate_zq1_staking_contract names an account that is not a Scilla contract; left untouched");
            return Ok(());
        }
        let burned = self.mutate_account(address, |account| {
            let balance = account.balance;
            account.balance = 0;
            account.storage_root = EMPTY_ROOT_HASH;
            Ok(balance)
        })?;
        info!(%address, burned, "emptied Scilla contract");
        Ok(())
    }
}
