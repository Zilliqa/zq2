#![allow(unused_imports)]

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{self, Stdio},
    time::Duration,
};

use alloy_consensus::{TxEip1559, TxEip2930, TxLegacy, EMPTY_ROOT_HASH};
use alloy_primitives::{Address, Parity, Signature, TxKind, B256, U256};
use anyhow::{anyhow, Context, Result};
use bitvec::bitvec;
use clap::{Parser, Subcommand};
use ethabi::Token;
use git2::Repository;
use indicatif::{ProgressBar, ProgressFinish, ProgressIterator, ProgressStyle};
use itertools::Itertools;
use revm::primitives::ResultAndState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tempfile::TempDir;
use tracing::{trace, warn};
use zilliqa::{
    cfg::Config,
    consensus::Validator,
    contracts,
    crypto::{Hash, SecretKey},
    db::Db,
    exec::BaseFeeCheck,
    inspector,
    message::{Block, BlockHeader, QuorumCertificate, Vote},
    schnorr,
    state::{contract_addr, Account, Code, State},
    time::SystemTime,
    transaction::{
        EvmGas, EvmLog, Log, ScillaGas, SignedTransaction, TransactionReceipt, TxZilliqa, ZilAmount,
    },
};

use crate::zq1;

pub async fn convert_persistence(
    zq1_db: zq1::Db,
    zq2_db: Db,
    zq2_config: Config,
    secret_key: SecretKey,
    skip_accounts: bool,
) -> Result<()> {
    let style = ProgressStyle::with_template(
        "{msg} {wide_bar} [{per_sec}] {human_pos}/~{human_len} ({elapsed}/~{duration})",
    )
    .unwrap();

    let node_config = &zq2_config.nodes[0];
    let mut state = State::new_with_genesis(zq2_db.state_trie()?, node_config.consensus.clone())?;

    if !skip_accounts {
        // Calculate an estimate for the number of accounts by taking the first 100 accounts, calculating the distance
        // between pairs of adjacent addresses, taking the average and extrapolating to the end of the key space.
        let distance_sum: u64 = zq1_db
            .accounts()
            .map(|(addr, _)| addr)
            .take(100)
            .tuple_windows()
            .map(|(a, b)| {
                // Downsample the addresses to 8 bytes, treating them as `u64`s, for ease of computation.
                let a = u64::from_be_bytes(a.as_slice()[..8].try_into().unwrap());
                let b = u64::from_be_bytes(b.as_slice()[..8].try_into().unwrap());

                b - a
            })
            .sum();
        let average_distance = distance_sum as f64 / 99.;
        let address_count = ((u64::MAX as f64) / average_distance) as u64;

        let progress = ProgressBar::new(address_count)
            .with_style(style.clone())
            .with_message("collect accounts")
            .with_finish(ProgressFinish::AndLeave);
        let accounts: Vec<_> = zq1_db.accounts().progress_with(progress).collect();

        let progress = ProgressBar::new(accounts.len() as u64)
            .with_style(style.clone())
            .with_message("convert accounts")
            .with_finish(ProgressFinish::AndLeave);
        for (address, zq1_account) in accounts.into_iter().progress_with(progress) {
            if address.is_zero() {
                continue;
            }
            let zq1_account = zq1::Account::from_proto(zq1_account)?;

            let account = Account {
                nonce: zq1_account.nonce,
                balance: zq1_account.balance * 10u128.pow(6),
                code: Code::Evm(vec![]), // TODO: Convert contract code and state
                storage_root: EMPTY_ROOT_HASH,
            };

            state.save_account(address, account)?;

            trace!(?address, "account inserted");
        }
    }

    // Add stake for this validator. For now, we just assume they've always had 64 ZIL staked.
    // This assumptions will need to change for the actual testnet and mainnet launches, where we cannot invent ZIL
    // out of thin air (like we do below).
    let data = contracts::deposit::SET_STAKE.encode_input(&[
        Token::Bytes(secret_key.node_public_key().as_bytes()),
        Token::Bytes(
            secret_key
                .to_libp2p_keypair()
                .public()
                .to_peer_id()
                .to_bytes(),
        ),
        Token::Address(ethabi::Address::from_low_u64_be(1)),
        Token::Uint((64 * 10u128.pow(18)).into()),
    ])?;
    let (
        ResultAndState {
            result,
            state: result_state,
        },
        ..,
    ) = state.apply_transaction_evm(
        Address::ZERO,
        Some(contract_addr::DEPOSIT),
        *node_config.consensus.gas_price,
        node_config.consensus.eth_block_gas_limit,
        0,
        data,
        None,
        0,
        BlockHeader::default(),
        inspector::noop(),
        BaseFeeCheck::Ignore,
    )?;
    if !result.is_success() {
        return Err(anyhow!("setting stake failed: {result:?}"));
    }
    state.apply_delta_evm(&result_state)?;

    let max_block = zq1_db.get_tx_blocks_aux("MaxTxBlockNumber")?.unwrap();

    let current_block = zq2_db.get_latest_finalized_view()?.unwrap_or(0);

    let progress = ProgressBar::new(max_block)
        .with_style(style.clone())
        .with_message("collect blocks")
        .with_finish(ProgressFinish::AndLeave);
    let mut tx_blocks: Vec<_> = zq1_db
        .tx_blocks()?
        .progress_with(progress)
        .map(|kv| kv.unwrap())
        .collect();
    tx_blocks.sort_unstable_by_key(|(n, _)| *n);

    let progress = ProgressBar::new(tx_blocks.len() as u64)
        .with_style(style)
        .with_message("convert blocks")
        .with_finish(ProgressFinish::AndLeave);
    for chunk in tx_blocks
        .into_iter()
        .progress_with(progress)
        .skip_while(|(n, _)| *n <= current_block)
        .chunks(1000)
        .into_iter()
    {
        let mut transactions = Vec::new();
        let mut receipts = Vec::new();
        let mut blocks = Vec::new();
        let mut parent_hash = Hash::ZERO;

        for (block_number, block) in chunk {
            let block = zq1::TxBlock::from_proto(block)?;
            // TODO: Retain ZQ1 block hash, so we can return it in APIs.

            let txn_hashes: Vec<_> = block
                .mb_infos
                .iter()
                .filter_map(|mbi| {
                    let key = zq1_db.get_micro_block_key(mbi.hash).unwrap()?;
                    zq1_db.get_micro_block(&key).unwrap()
                })
                .flat_map(|micro_block| {
                    micro_block
                        .tranhashes
                        .into_iter()
                        .map(|txn| B256::from_slice(&txn))
                })
                .collect();

            let vote = Vote::new(
                secret_key,
                parent_hash,
                secret_key.node_public_key(),
                block.block_num - 1,
            );
            let qc = QuorumCertificate::new(
                &[vote.signature()],
                bitvec![u8, bitvec::order::Msb0; 1; 1],
                parent_hash,
                block.block_num - 1,
            );
            let block = Block::from_qc(
                secret_key,
                block.block_num,
                block.block_num,
                qc,
                parent_hash,
                state.root_hash()?,
                txn_hashes.iter().map(|h| Hash(h.0)).collect(),
                SystemTime::UNIX_EPOCH + Duration::from_micros(block.timestamp),
                ScillaGas(block.gas_used).into(),
            );

            for (index, txn_hash) in txn_hashes.iter().enumerate() {
                let Some(transaction) = zq1_db.get_tx_body(block_number, *txn_hash)? else {
                    warn!(?txn_hash, %block_number, "missing transaction");
                    continue;
                };
                let transaction = zq1::Transaction::from_proto(block_number, transaction)?;
                if *txn_hash != transaction.id {
                    return Err(anyhow!("txn hash mismatch"));
                }

                let chain_id = (transaction.version >> 16) as u16;
                let version = (transaction.version & 0xffff) as u16;
                // We know all mainnet transactions before this block were not EVM. However, some of them had bugs
                // with their `version` which cause them to be marked as EVM. So we use the block number to figure
                // disambiguate.
                let pre_evm = block_number < 2_828_325;

                let (transaction, receipt) = match (pre_evm, version) {
                    // TODO: Why are versions other than 1 possible here?
                    (true, _) | (false, 1) => {
                        let from_addr = transaction.sender_pub_key.zil_addr();

                        let contract_address = transaction.to_addr.is_zero().then(|| {
                            let mut hasher = Sha256::new();
                            hasher.update(from_addr.as_slice());
                            hasher.update(transaction.nonce.to_be_bytes());
                            let hashed = hasher.finalize();
                            Address::from_slice(&hashed[12..])
                        });

                        let receipt = TransactionReceipt {
                            block_hash: block.hash(),
                            tx_hash: Hash(txn_hash.0),
                            index: index as u64,
                            success: transaction.receipt.success,
                            gas_used: EvmGas(transaction.receipt.cumulative_gas),
                            cumulative_gas_used: EvmGas(transaction.receipt.cumulative_gas),
                            contract_address,
                            logs: transaction
                                .receipt
                                .event_logs
                                .iter()
                                .map(|log| {
                                    let log = log.to_eth_log()?;

                                    Ok(Log::Evm(EvmLog {
                                        address: log.address,
                                        topics: log.topics,
                                        data: log.data,
                                    }))
                                })
                                .collect::<Result<_>>()?,
                            transitions: vec![],
                            accepted: None,
                            errors: BTreeMap::new(),
                            exceptions: vec![],
                        };

                        let transaction = SignedTransaction::Zilliqa {
                            tx: TxZilliqa {
                                chain_id,
                                nonce: transaction.nonce,
                                gas_price: ZilAmount::from_amount(transaction.gas_price),
                                gas_limit: ScillaGas(transaction.gas_limit),
                                to_addr: transaction.to_addr,
                                amount: ZilAmount::from_amount(transaction.amount),
                                code: transaction
                                    .code
                                    .map(String::from_utf8)
                                    .transpose()?
                                    .unwrap_or_default(),
                                data: transaction
                                    .data
                                    .map(String::from_utf8)
                                    .transpose()?
                                    .unwrap_or_default(),
                            },
                            key: schnorr::PublicKey::from_sec1_bytes(
                                transaction.sender_pub_key.as_ref(),
                            )?,
                            sig: schnorr::Signature::from_slice(transaction.signature.as_slice())?,
                        };

                        (transaction, receipt)
                    }
                    (false, 2..=4) => {
                        let from_addr = transaction.sender_pub_key.eth_addr();

                        let contract_address = transaction
                            .to_addr
                            .is_zero()
                            .then(|| from_addr.create(transaction.nonce - 1));

                        let receipt = TransactionReceipt {
                            block_hash: block.hash(),
                            tx_hash: Hash(txn_hash.0),
                            index: index as u64,
                            success: transaction.receipt.success,
                            gas_used: EvmGas(transaction.receipt.cumulative_gas),
                            cumulative_gas_used: EvmGas(transaction.receipt.cumulative_gas),
                            contract_address,
                            logs: transaction
                                .receipt
                                .event_logs
                                .iter()
                                .map(|log| {
                                    let log = log.to_eth_log()?;

                                    Ok(Log::Evm(EvmLog {
                                        address: log.address,
                                        topics: log.topics,
                                        data: log.data,
                                    }))
                                })
                                .collect::<Result<_>>()?,
                            transitions: vec![],
                            accepted: None,
                            errors: BTreeMap::new(),
                            exceptions: vec![],
                        };

                        let transaction =
                            infer_eth_signature(*txn_hash, version, chain_id + 0x8000, transaction)
                                .with_context(|| {
                                    format!(
                                        "failed to infer signature of transaction: {txn_hash:?}"
                                    )
                                })?;

                        (transaction, receipt)
                    }
                    _ => {
                        return Err(anyhow!(
                            "invalid transaction version {version}: {txn_hash:?}"
                        ));
                    }
                };

                transactions.push((Hash(txn_hash.0), transaction));
                receipts.push(receipt);
                //trace!(?txn_hash, "transaction inserted");
            }

            zq2_db.put_canonical_block_number(block_number, block.hash())?;
            zq2_db.set_high_qc(block.qc.clone())?;
            blocks.push(block.clone());
            zq2_db.put_latest_finalized_view(block_number)?;

            trace!(%block_number, "block inserted");
            parent_hash = block.hash();
        }

        zq2_db.with_sqlite_tx(|sqlite_tx| {
            for (hash, transaction) in &transactions {
                zq2_db.insert_transaction_with_db_tx(sqlite_tx, hash, transaction)?;
            }
            for receipt in &receipts {
                zq2_db.insert_transaction_receipt_with_db_tx(sqlite_tx, receipt.to_owned())?;
            }
            for block in &blocks {
                zq2_db.insert_block_with_db_tx(sqlite_tx, block)?;
            }
            Ok(())
        })?;
    }

    println!(
        "Persistence conversion done up to block {}",
        zq2_db.get_highest_block_number()?.unwrap()
    );

    Ok(())
}

fn infer_eth_signature(
    txn_hash: B256,
    version: u16,
    chain_id: u16,
    transaction: zq1::Transaction,
) -> Result<SignedTransaction> {
    let r = U256::try_from_be_slice(&transaction.signature.0[..32]).unwrap();
    let s = U256::try_from_be_slice(&transaction.signature.0[32..]).unwrap();

    for y_is_odd in [false, true] {
        let mut parity = Parity::Parity(y_is_odd);
        // Legacy transactions should have the chain ID included in their parity.
        if version == 2 {
            parity = parity.with_chain_id(chain_id as u64);
        }
        let sig = Signature::from_rs_and_parity(r, s, parity)?;
        let payload = transaction
            .code
            .as_ref()
            .map(|c| {
                c.strip_prefix(b"EVM")
                    .ok_or_else(|| anyhow!("missing EVM prefix"))
            })
            .transpose()?
            .map(|c| c.to_vec())
            .or(transaction.data.as_ref().cloned())
            .unwrap_or_default();

        let transaction = match version {
            2 => SignedTransaction::Legacy {
                tx: TxLegacy {
                    // Legacy transactions without a chain ID are not supported in ZQ1.
                    chain_id: Some(chain_id.into()),
                    nonce: transaction.nonce - 1,
                    gas_price: transaction.gas_price,
                    gas_limit: transaction.gas_limit as u128,
                    to: if transaction.to_addr.is_zero() {
                        TxKind::Create
                    } else {
                        TxKind::Call(transaction.to_addr)
                    },
                    value: transaction.amount.try_into()?,
                    input: payload.into(),
                },
                sig,
            },
            3 => SignedTransaction::Eip2930 {
                tx: TxEip2930 {
                    chain_id: chain_id.into(),
                    nonce: transaction.nonce - 1,
                    gas_price: transaction.gas_price,
                    gas_limit: transaction.gas_limit as u128,
                    to: if transaction.to_addr.is_zero() {
                        TxKind::Create
                    } else {
                        TxKind::Call(transaction.to_addr)
                    },
                    value: transaction.amount.try_into()?,
                    input: payload.into(),
                    access_list: transaction.access_list.clone(),
                },
                sig,
            },
            4 => SignedTransaction::Eip1559 {
                tx: TxEip1559 {
                    chain_id: chain_id.into(),
                    nonce: transaction.nonce - 1,
                    gas_limit: transaction.gas_limit as u128,
                    to: if transaction.to_addr.is_zero() {
                        TxKind::Create
                    } else {
                        TxKind::Call(transaction.to_addr)
                    },
                    value: transaction.amount.try_into()?,
                    input: payload.into(),
                    access_list: transaction.access_list.clone(),
                    max_priority_fee_per_gas: transaction
                        .max_priority_fee_per_gas
                        .ok_or_else(|| anyhow!("no max_priority_fee_per_gas"))?,
                    max_fee_per_gas: transaction
                        .max_fee_per_gas
                        .ok_or_else(|| anyhow!("no max_fee_per_gas"))?,
                },
                sig,
            },
            _ => unreachable!(),
        };

        let transaction = transaction.verify()?;
        if transaction.hash == txn_hash.into() {
            return Ok(transaction.tx);
        }
    }

    Err(anyhow!(
        "failed to infer eth transaction signature: {txn_hash:?}"
    ))
}

pub async fn print_tx_in_block(zq1_persistence_dir: &str, block_number: u64) -> Result<()> {
    let db = zq1::Db::new(zq1_persistence_dir)?;
    let block = db
        .get_tx_block(block_number)?
        .ok_or_else(|| anyhow!("block not found"))?;
    let block = zq1::TxBlock::from_proto(block)?;
    let txn_hashes: Vec<_> = block
        .mb_infos
        .iter()
        .map(|mbi| {
            let key = db.get_micro_block_key(mbi.hash).unwrap().unwrap();
            db.get_micro_block(&key).unwrap().unwrap()
        })
        .flat_map(|micro_block| {
            micro_block
                .tranhashes
                .into_iter()
                .map(|txn| B256::from_slice(&txn))
        })
        .collect();

    println!("{txn_hashes:?}");
    Ok(())
}

pub async fn print_tx_by_hash(
    zq1_persistence_dir: &str,
    block_number: u64,
    txn_hash: B256,
) -> Result<()> {
    let db = zq1::Db::new(zq1_persistence_dir)?;
    let tx = db
        .get_tx_body(block_number, txn_hash)?
        .ok_or_else(|| anyhow!("transaction not found"))?;
    let tx = zq1::Transaction::from_proto(block_number, tx)?;

    println!("{tx:?}");
    Ok(())
}
