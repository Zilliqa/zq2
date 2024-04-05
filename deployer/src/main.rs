mod zq1;

use std::{
    fs,
    path::PathBuf,
    process::{self, Stdio},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use bitvec::bitvec;
use revm::primitives::ResultAndState;
use clap::{Parser, Subcommand};
use ethabi::Token;
use git2::Repository;
use indicatif::{ProgressBar, ProgressFinish, ProgressIterator, ProgressStyle};
use itertools::Itertools;
use primitive_types::{H160, H256};
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tempfile::TempDir;
use tracing::{trace, warn};
use zilliqa::{
    cfg::Config, consensus::Validator, contracts, crypto::{Hash, SecretKey}, db::Db, exec::{BLOCK_GAS_LIMIT, GAS_PRICE}, message::{Block, BlockHeader, Committee, QuorumCertificate, Vote}, schnorr, state::{contract_addr, Account, State}, time::SystemTime, transaction::{
        EthSignature, Log, SignedTransaction, TransactionReceipt, TxEip1559, TxEip2930, TxLegacy,
        TxZilliqa,
    }
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    New {
        name: String,
        gcp_project: String,
        binary_bucket: String,
    },
    Upgrade {
        config_file: PathBuf,
    },
    ConvertPersistence {
        zq1_persistence_directory: PathBuf,
        zq2_data_dir: PathBuf,
        zq2_config_file: PathBuf,
        #[clap(long)]
        skip_accounts: bool,
    },
    PrintTransactionsInBlock {
        zq1_persistence_directory: PathBuf,
        block_number: u64,
    },
    PrintTransaction {
        zq1_persistence_directory: PathBuf,
        block_number: u64,
        txn_hash: H256,
    },
}

#[derive(Deserialize, Serialize)]
struct NetworkConfig {
    name: String,
    version: String,
    gcp_project: String,
    binary_bucket: String,
}

impl NetworkConfig {
    fn new(name: String, gcp_project: String, binary_bucket: String) -> Self {
        Self {
            name,
            version: "main".to_owned(),
            gcp_project,
            binary_bucket,
        }
    }
}

fn get_local_block_number(instance: &str, zone: &str) -> Result<u64> {
    let inner_command = r#"curl -s http://localhost:4201 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}'"#;
    let output = process::Command::new("gcloud")
        .args(["compute", "ssh"])
        .arg(instance)
        .args(["--zone", zone])
        .args(["--command", inner_command])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!("getting local block number failed: {output:?}"));
    }

    let response: Value = serde_json::from_slice(&output.stdout)?;
    let block_number = response
        .get("result")
        .ok_or_else(|| anyhow!("response has no result"))?
        .as_str()
        .ok_or_else(|| anyhow!("result is not a string"))?
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("result does not start with 0x"))?;
    let block_number = u64::from_str_radix(block_number, 16)?;

    Ok(block_number)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Command::New {
            name,
            gcp_project,
            binary_bucket,
        } => {
            let config = NetworkConfig::new(name.clone(), gcp_project, binary_bucket);
            let config = toml::to_string_pretty(&config)?;
            fs::write(format!("{name}.toml"), config)?;
        }
        Command::Upgrade { config_file } => {
            let config = fs::read_to_string(config_file)?;
            let config: NetworkConfig = toml::from_str(&config)?;

            // Checkout Zilliqa 2 source
            let repo_dir: TempDir = TempDir::new()?;
            let repo = Repository::clone("https://github.com/Zilliqa/zq2", repo_dir.path())?;
            let (object, _) = repo
                .revparse_ext(&format!("origin/{}", config.version))
                .or_else(|_| repo.revparse_ext(&config.version))?;
            repo.checkout_tree(&object, None)?;

            let binary_name = format!("zilliqa_{}", object.id());
            let binary_location = format!("gs://{}/{binary_name}", config.binary_bucket);

            // Check if binary already exists
            let status = process::Command::new("gsutil")
                .args(["-q", "stat"])
                .arg(&binary_location)
                .status()?;
            if !status.success() {
                println!("Building binary");

                // Build binary
                let status = process::Command::new("cross")
                    .args([
                        "build",
                        "--target",
                        "x86_64-unknown-linux-gnu",
                        "--profile",
                        "release",
                        "--bin",
                        "zilliqa",
                    ])
                    .current_dir(repo_dir.path())
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("build failed"));
                }

                println!("Binary built, uploading to GCS");

                // Upload binary to GCS
                let binary = repo_dir
                    .path()
                    .join("target")
                    .join("x86_64-unknown-linux-gnu")
                    .join("release")
                    .join("zilliqa");
                let status = process::Command::new("gcloud")
                    .args(["storage", "cp"])
                    .arg(binary)
                    .arg(&binary_location)
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("upload failed"));
                }

                println!("Binary uploaded to GCS");
            } else {
                println!("Binary already exists in GCS");
            }

            // Get the list of instances we need to update.
            let output = process::Command::new("gcloud")
                .args(["compute", "instances", "list"])
                .args(["--format", "json"])
                .args(["--filter", &format!("labels.zq2-network={}", config.name)])
                .output()?;
            if !output.status.success() {
                return Err(anyhow!("listing instances failed"));
            }
            let output: Value = serde_json::from_slice(&output.stdout)?;
            let instances: Vec<_> = output
                .as_array()
                .ok_or_else(|| anyhow!("instances is not an array"))?
                .iter()
                .map(|i| {
                    let name = i
                        .get("name")
                        .ok_or_else(|| anyhow!("name is missing"))?
                        .as_str()
                        .ok_or_else(|| anyhow!("name is not a string"))?;
                    let zone = i
                        .get("zone")
                        .ok_or_else(|| anyhow!("zone is missing"))?
                        .as_str()
                        .ok_or_else(|| anyhow!("zone is not a string"))?;
                    Ok((name, zone))
                })
                .collect::<Result<_>>()?;

            if instances.is_empty() {
                println!("No instances found");
            }

            for (instance, zone) in instances {
                println!("Upgrading instance {instance}");

                let inner_command = format!(
                    r#"
                    sudo gcloud storage cp {binary_location} /{binary_name} &&
                    sudo chmod +x /{binary_name} &&
                    sudo rm /zilliqa &&
                    sudo ln -s /{binary_name} /zilliqa &&
                    sudo systemctl restart zilliqa.service
                "#
                );
                let status = process::Command::new("gcloud")
                    .args(["-q", "compute", "ssh"])
                    .arg(instance)
                    .args(["--zone", zone])
                    .args(["--command", &inner_command])
                    .stderr(Stdio::null())
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("upgrade failed"));
                }

                // Check the node is making progress
                let first_block_number = get_local_block_number(instance, zone)?;
                loop {
                    let next_block_number = get_local_block_number(instance, zone)?;
                    println!(
                        "Polled block number at {next_block_number}, waiting for {} more blocks",
                        (first_block_number + 10).saturating_sub(next_block_number)
                    );
                    if next_block_number >= first_block_number + 10 {
                        break;
                    }
                }
            }
        }
        Command::ConvertPersistence {
            zq1_persistence_directory,
            zq2_data_dir,
            zq2_config_file,
            skip_accounts,
        } => {
            let zq1_db = zq1::Db::new(zq1_persistence_directory)?;
            let zq2_config = fs::read_to_string(zq2_config_file)?;
            let zq2_config: zilliqa::cfg::Config = toml::from_str(&zq2_config)?;
            let shard_id: u64 = match zq2_config
                .nodes
                .get(0)
                .and_then(|node| Some(node.eth_chain_id))
            {
                Some(id) => id,
                None => 0,
            };
            let zq2_db = Db::new(Some(zq2_data_dir), shard_id)?;

            convert_persistence(zq1_db, zq2_db, zq2_config, skip_accounts)?;
        }
        Command::PrintTransactionsInBlock {
            zq1_persistence_directory,
            block_number,
        } => {
            let db = zq1::Db::new(zq1_persistence_directory)?;
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
                        .map(|txn| H256::from_slice(&txn))
                })
                .collect();

            println!("{txn_hashes:?}");
        }
        Command::PrintTransaction {
            zq1_persistence_directory,
            block_number,
            txn_hash,
        } => {
            let db = zq1::Db::new(zq1_persistence_directory)?;
            let tx = db
                .get_tx_body(block_number, txn_hash)?
                .ok_or_else(|| anyhow!("transaction not found"))?;
            let tx = zq1::Transaction::from_proto(block_number, tx)?;

            println!("{tx:?}");
        }
    }

    Ok(())
}

fn convert_persistence(
    zq1_db: zq1::Db,
    zq2_db: Db,
    zq2_config: Config,
    skip_accounts: bool,
) -> Result<()> {
    let secret_key = SecretKey::new()?; // TODO

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
            let zq1_account = zq1::Account::from_proto(zq1_account)?;

            let account = Account {
                nonce: zq1_account.nonce,
                balance: zq1_account.balance * 10u128.pow(6),
                code: zq1_account
                    .contract
                    .as_ref()
                    .map(|_| zq1_db.get_contract_code(address).unwrap().unwrap())
                    .unwrap_or_default(),
                storage_root: None,
            };

            state.save_account(address, account)?;

            trace!(?address, "account inserted");
        }
    }

    let committee = Committee::new(Validator {
        public_key: secret_key.node_public_key(),
        peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
    });
    // Add stake for this validator. For now, we just assume they've always had 100 ZIL staked.
    // This assumptions will need to change for the actual testnet and mainnet launches, where we cannot invent ZIL
    // out of thin air (like we do below).
    let data = contracts::deposit::SET_STAKE.encode_input(&[
        Token::Bytes(secret_key.node_public_key().as_bytes()),
        Token::Address(H160::from_low_u64_be(1)),
        Token::Uint(100.into()),
    ])?;
    let ResultAndState {
        result,
        state: result_state,
    } = state.apply_transaction_inner(
        H160::zero(),
        Some(contract_addr::DEPOSIT),
        GAS_PRICE,
        BLOCK_GAS_LIMIT,
        0,
        data,
        None,
        0,
        BlockHeader::default(),
    )?;
    if !result.is_success() {
        return Err(anyhow!("setting stake failed: {result:?}"));
    }
    state.apply_delta(result_state)?;

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
                        .map(|txn| H256::from_slice(&txn))
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
                committee.clone(),
            );

            let mut block_receipts = Vec::new();

            for txn_hash in &txn_hashes {
                let Some(transaction) = zq1_db.get_tx_body(block_number, H256(txn_hash.0))? else {
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
                            hasher.update(from_addr.as_bytes());
                            hasher.update(transaction.nonce.to_be_bytes());
                            let hashed = hasher.finalize();
                            H160::from_slice(&hashed[12..])
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
                    (false, 2..=4) => {
                        let from_addr = transaction.sender_pub_key.eth_addr();

                        let contract_address = transaction.to_addr.is_zero().then(|| {
                            let mut rlp = RlpStream::new_list(2);
                            rlp.append(&from_addr);
                            rlp.append(&(transaction.nonce - 1));
                            let hashed = Keccak256::digest(&rlp.out());
                            H160::from_slice(&hashed[12..])
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
                            dbg!(version),
                            dbg!(chain_id) + 0x8000,
                            dbg!(transaction),
                        )
                        .with_context(|| {
                            format!("failed to infer signature of transaction: {txn_hash:?}")
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
        zq2_db.insert_transaction_receipts_batch(&receipts)?;
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
    transaction: zq1::Transaction,
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
