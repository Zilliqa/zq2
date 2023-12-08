use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, Result};
use bitvec::bitvec;
use clap::Parser;
use evm_ds::protos::evm_proto::Log;
use indicatif::{ProgressBar, ProgressFinish, ProgressIterator, ProgressStyle};
use itertools::Itertools;
use primitive_types::H256;
use rlp::RlpStream;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use tracing::*;
use zilliqa::{
    cfg::ConsensusConfig,
    consensus::Validator,
    crypto::{Hash, SecretKey},
    message::{Block, Committee, QuorumCertificate, Vote},
    schnorr,
    state::{Account, Address, State},
    time::SystemTime,
    transaction::{
        EthSignature, SignedTransaction, TransactionReceipt, TxEip1559, TxEip2930, TxLegacy,
        TxZilliqa,
    },
    zq1,
};

#[derive(Parser, Debug)]
struct Args {
    zq1_persistence_directory: PathBuf,
    zq2_data_dir: PathBuf,
    #[clap(value_parser = SecretKey::from_hex)]
    secret_key: SecretKey,
    chain_id: u64,
    #[clap(long)]
    skip_accounts: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let zq1_db = zq1::db::Db::new(args.zq1_persistence_directory)?;
    let zq2_db = zilliqa::db::Db::new(Some(args.zq2_data_dir), args.chain_id)?;

    let style = ProgressStyle::with_template(
        "{msg} {wide_bar} [{per_sec}] {human_pos}/~{human_len} ({elapsed}/~{duration})",
    )
    .unwrap();

    let config = ConsensusConfig {
        is_main: true,
        main_shard_id: None,
        consensus_timeout: Duration::from_secs(5),
        tx_retries: 10,
        block_tx_limit: 10,
        genesis_committee: vec![],
        genesis_hash: None,
        genesis_accounts: vec![],
    };
    let mut state = State::new_with_genesis(zq2_db.state_trie()?, config)?;

    if !args.skip_accounts {
        // Calculate an estimate for the number of accounts by taking the first 100 accounts, calculating the distance
        // between pairs of adjacent addresses, taking the average and extrapolating to the end of the key space.
        let distance_sum: u64 = zq1_db
            .accounts()
            .map(|(addr, _)| addr)
            .take(100)
            .tuple_windows()
            .map(|(a, b)| {
                // Downsample the addresses to 8 bytes, treating them as `u64`s, for ease of computation.
                let a = u64::from_be_bytes(a.as_bytes()[..8].try_into().unwrap());
                let b = u64::from_be_bytes(b.as_bytes()[..8].try_into().unwrap());

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
            let zq1_account = zq1::persistence::Account::from_proto(zq1_account)?;

            let account = Account {
                nonce: zq1_account.nonce,
                code: zq1_account
                    .contract
                    .as_ref()
                    .map(|_| zq1_db.get_contract_code(address).unwrap().unwrap())
                    .unwrap_or_default(),
                storage_root: None,
            };

            state.save_account(address, account)?;
            state.set_native_balance(address, (zq1_account.balance * 10u128.pow(6)).into())?;

            trace!(?address, "account inserted");
        }
    }

    let committee = Committee::new(Validator {
        public_key: args.secret_key.node_public_key(),
        peer_id: args.secret_key.to_libp2p_keypair().public().to_peer_id(),
        weight: 100,
    });

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
        let mut block_headers = Vec::new();
        let mut blocks = Vec::new();
        let mut parent_hash = Hash::ZERO;

        for (block_number, block) in chunk {
            let block = zq1::persistence::TxBlock::from_proto(block)?;
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
                        .map(|txn| H256::from_slice(&txn))
                })
                .collect();

            let vote = Vote::new(
                args.secret_key,
                parent_hash,
                args.secret_key.node_public_key(),
                block.block_num - 1,
            );
            let qc = QuorumCertificate::new(
                &[vote.signature()],
                bitvec![u8, bitvec::order::Msb0; 1; 1],
                parent_hash,
                block.block_num - 1,
            );
            let block = Block::from_qc(
                args.secret_key,
                block.block_num,
                block.block_num,
                qc,
                parent_hash,
                state.root_hash()?,
                txn_hashes.iter().map(|h| Hash(h.0)).collect(),
                SystemTime::UNIX_EPOCH + Duration::from_micros(block.timestamp),
                committee.clone(),
            );

            let mut block_receipts = Vec::new();

            for txn_hash in &txn_hashes {
                let Some(transaction) = zq1_db.get_tx_body(block_number, H256(txn_hash.0))? else {
                    warn!(?txn_hash, %block_number, "missing transaction");
                    continue;
                };
                let transaction =
                    zq1::persistence::Transaction::from_proto(block_number, transaction)?;
                if *txn_hash != transaction.id {
                    return Err(anyhow!("txn hash mismatch"));
                }

                let chain_id = (transaction.version >> 16) as u16;
                let version = (transaction.version & 0xffff) as u16;

                let (transaction, receipt) = match version {
                    // TODO: Why are there versions other than 1 here?
                    1 | 8 | 333 => {
                        let from_addr = transaction.sender_pub_key.zil_addr();

                        let contract_address = transaction.to_addr.is_zero().then(|| {
                            let mut hasher = Sha256::new();
                            hasher.update(from_addr.as_bytes());
                            hasher.update(transaction.nonce.to_be_bytes());
                            let hashed = hasher.finalize();
                            Address::from_slice(&hashed[12..])
                        });

                        let receipt = TransactionReceipt {
                            block_hash: block.hash(),
                            tx_hash: Hash(txn_hash.0),
                            success: transaction.receipt.success,
                            gas_used: transaction.receipt.cumulative_gas,
                            contract_address,
                            logs: transaction
                                .receipt
                                .event_logs
                                .iter()
                                .map(|log| {
                                    let log = log.to_eth_log()?;

                                    Ok(Log {
                                        address: log.address,
                                        topics: log.topics,
                                        data: log.data,
                                    })
                                })
                                .collect::<Result<_>>()?,
                        };

                        let transaction = SignedTransaction::Zilliqa {
                            tx: TxZilliqa {
                                chain_id,
                                nonce: transaction.nonce,
                                gas_price: transaction.gas_price,
                                gas_limit: transaction.gas_limit,
                                to_addr: transaction.to_addr,
                                amount: transaction.amount,
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
                            sig: schnorr::Signature::from_slice(transaction.signature.as_bytes())?,
                        };

                        (transaction, receipt)
                    }
                    2..=4 => {
                        let from_addr = transaction.sender_pub_key.eth_addr();

                        let contract_address = transaction.to_addr.is_zero().then(|| {
                            let mut rlp = RlpStream::new_list(2);
                            rlp.append(&from_addr);
                            rlp.append(&(transaction.nonce - 1));
                            let hashed = Keccak256::digest(&rlp.out());
                            Address::from_slice(&hashed[12..])
                        });

                        let receipt = TransactionReceipt {
                            block_hash: block.hash(),
                            tx_hash: Hash(txn_hash.0),
                            success: transaction.receipt.success,
                            gas_used: transaction.receipt.cumulative_gas,
                            contract_address,
                            logs: transaction
                                .receipt
                                .event_logs
                                .iter()
                                .map(|log| {
                                    let log = log.to_eth_log()?;

                                    Ok(Log {
                                        address: log.address,
                                        topics: log.topics,
                                        data: log.data,
                                    })
                                })
                                .collect::<Result<_>>()?,
                        };

                        let transaction = infer_eth_signature(
                            *txn_hash,
                            version,
                            chain_id + 0x8000,
                            transaction,
                        )?;

                        (transaction, receipt)
                    }
                    _ => {
                        return Err(anyhow!(
                            "invalid transaction version {version}: {txn_hash:?}"
                        ));
                    }
                };

                transactions.push((Hash(txn_hash.0), transaction));
                block_receipts.push(receipt);
                zq2_db.insert_block_hash_reverse_index(&Hash(txn_hash.0), &block.hash())?;

                //trace!(?txn_hash, "transaction inserted");
            }

            receipts.push((block.hash(), block_receipts));
            zq2_db.put_canonical_block_number(block_number, block.hash())?;
            zq2_db.put_canonical_block_view(block_number, block.hash())?;
            block_headers.push((block.hash(), block.header));
            zq2_db.set_high_qc(block.qc.clone())?;
            blocks.push((block.hash(), block.clone()));
            zq2_db.put_latest_finalized_view(block_number)?;
            zq2_db.put_highest_block_number(block_number)?;

            trace!(%block_number, "block inserted");
            parent_hash = block.hash();
        }

        zq2_db.insert_transaction_batch(&transactions)?;
        zq2_db.insert_transaction_receipt_batch(&receipts)?;
        zq2_db.insert_block_header_batch(&block_headers)?;
        zq2_db.insert_block_batch(&blocks)?;
    }

    println!(
        "Persistence conversion done up to block {}",
        zq2_db.get_highest_block_number()?.unwrap()
    );

    Ok(())
}

fn infer_eth_signature(
    txn_hash: H256,
    version: u16,
    chain_id: u16,
    transaction: zq1::persistence::Transaction,
) -> Result<SignedTransaction> {
    let r = transaction.signature.0[..32].try_into().unwrap();
    let s = transaction.signature.0[32..].try_into().unwrap();

    for y_is_odd in [false, true] {
        let sig = EthSignature { r, s, y_is_odd };
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
                    // TODO: Handle `None` chain IDs - How are they represented in ZQ1 persistence?
                    chain_id: Some(chain_id.into()),
                    nonce: transaction.nonce - 1,
                    gas_price: transaction.gas_price,
                    gas_limit: transaction.gas_limit,
                    to_addr: (!transaction.to_addr.is_zero()).then_some(transaction.to_addr),
                    amount: transaction.amount,
                    payload,
                },
                sig,
            },
            3 => SignedTransaction::Eip2930 {
                tx: TxEip2930 {
                    chain_id: chain_id.into(),
                    nonce: transaction.nonce - 1,
                    gas_price: transaction.gas_price,
                    gas_limit: transaction.gas_limit,
                    to_addr: (!transaction.to_addr.is_zero()).then_some(transaction.to_addr),
                    amount: transaction.amount,
                    payload,
                    access_list: transaction
                        .access_list
                        .iter()
                        .map(|(a, k)| (*a, k.clone()))
                        .collect(),
                },
                sig,
            },
            4 => SignedTransaction::Eip1559 {
                tx: TxEip1559 {
                    chain_id: chain_id.into(),
                    nonce: transaction.nonce - 1,
                    gas_limit: transaction.gas_limit,
                    to_addr: (!transaction.to_addr.is_zero()).then_some(transaction.to_addr),
                    amount: transaction.amount,
                    payload,
                    access_list: transaction
                        .access_list
                        .iter()
                        .map(|(a, k)| (*a, k.clone()))
                        .collect(),
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
