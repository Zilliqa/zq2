#![allow(unused_imports)]

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{self, Stdio},
    sync::Arc,
    time::Duration,
};

use alloy::{
    consensus::{TxEip1559, TxEip2930, TxLegacy, EMPTY_ROOT_HASH},
    primitives::{Address, Parity, Signature, TxKind, B256, U256},
};
use anyhow::{anyhow, Context, Result};
use bitvec::{bitarr, bitvec, order::Msb0};
use clap::{Parser, Subcommand};
use eth_trie::{EthTrie, MemoryDB, Trie};
use ethabi::Token;
use git2::Repository;
use indicatif::{ProgressBar, ProgressFinish, ProgressIterator, ProgressStyle};
use itertools::Itertools;
use libp2p::PeerId;
use revm::primitives::ResultAndState;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};
use zilliqa::{
    block_store::BlockStore,
    cfg::Config,
    consensus::Validator,
    contracts,
    crypto::{self, Hash, SecretKey},
    db::Db,
    exec::BaseFeeCheck,
    inspector,
    message::{Block, BlockHeader, QuorumCertificate, Vote, MAX_COMMITTEE_SIZE},
    node::{MessageSender, RequestId},
    schnorr,
    scilla::{storage_key, ParamValue},
    state::{contract_addr, Account, Code, State},
    time::SystemTime,
    transaction::{
        EvmGas, EvmLog, Log, ScillaGas, SignedTransaction, TransactionReceipt, TxZilliqa, ZilAmount,
    },
};

use crate::{zq1, zq1::Transaction};

fn create_acc_query_prefix(address: Address) -> String {
    format!("{:02x}", address)
}

const ZQ1_STATE_KEY_SEPARATOR: u8 = 0x16;

#[allow(clippy::type_complexity)]
fn convert_scilla_state(
    zq1_db: &zq1::Db,
    zq2_db: &Db,
    address: Address,
) -> Result<(B256, BTreeMap<String, (String, u8)>)> {
    let prefix = create_acc_query_prefix(address);

    let storage_entries_iter = zq1_db.get_contract_state_data_with_prefix(&prefix);

    let mut contract_values = vec![];
    let mut field_types: BTreeMap<String, (String, u8)> = BTreeMap::new();

    for elem in storage_entries_iter {
        let (key, value) = elem?;

        let chunks = key
            .as_bytes()
            .split(|item| *item == ZQ1_STATE_KEY_SEPARATOR)
            .map(|chunk| {
                String::from_utf8(chunk.to_vec()).expect("Unable to convert key chunk into string!")
            })
            .skip(1) // Skip contract address (which was a part of key in zq1)
            .collect::<Vec<_>>();

        if chunks.is_empty() {
            warn!("Malformed key name in contract storage!");
            continue;
        };

        // We handle this type of keys differently in zq2
        if chunks[0].contains("_fields_map_depth")
            || chunks[0].contains("_version")
            || chunks[0].contains("_hasmap")
            || chunks[0].contains("_addr")
        {
            continue;
        }

        let key_type = &chunks[0];
        let field_name = &chunks[1];

        if key_type.contains("_depth") {
            let value = String::from_utf8(value)
                .map_err(|err| anyhow!("Unable to convert _depth value into string: {err}"))?;
            let field_depth: u8 = std::str::FromStr::from_str(&value)?;

            let (field_type, _) = field_types
                .get(field_name)
                .cloned()
                .unwrap_or_else(|| (String::new(), field_depth));
            field_types.insert(field_name.into(), (field_type, field_depth));
            continue;
        } else if key_type.contains("_type") {
            let field_type = String::from_utf8(value)
                .map_err(|err| anyhow!("Unable to convert field_type into string: {err}"))?;
            let (_, depth) = field_types
                .get(field_name)
                .cloned()
                .unwrap_or_else(|| (String::new(), 0));
            field_types.insert(field_name.into(), (field_type, depth));
            continue;
        }

        // At this point we know it's a field value
        let field_name = &chunks[0];
        let mut indices = vec![];

        for chunk in chunks.iter().skip(1) {
            if !chunk.is_empty() {
                indices.push(chunk.as_bytes().to_vec())
            }
        }
        contract_values.push((field_name.to_owned(), (indices, value)));
    }

    let db = Arc::new(zq2_db.state_trie()?);
    let mut contract_trie = EthTrie::new(db.clone()).at_root(EMPTY_ROOT_HASH);

    for (key_name, (indices, value)) in contract_values {
        let storage_key = storage_key(&key_name, &indices);
        contract_trie.insert(&storage_key, &value)?
    }

    let storage_root = contract_trie.root_hash()?;

    Ok((storage_root, field_types))
}

fn convert_evm_state(zq1_db: &zq1::Db, zq2_db: &Db, address: Address) -> Result<B256> {
    let prefix = create_acc_query_prefix(address);

    let storage_entries_iter = zq1_db.get_contract_state_data_with_prefix(&prefix);

    let evm_prefix = "_evm_storage".as_bytes();

    let db = Arc::new(zq2_db.state_trie()?);
    let mut contract_trie = EthTrie::new(db.clone()).at_root(EMPTY_ROOT_HASH);

    for elem in storage_entries_iter {
        let (key, value) = elem?;

        let chunks = key
            .as_bytes()
            .split(|item| *item == ZQ1_STATE_KEY_SEPARATOR)
            .skip(1) // skip contract address which was a part of key in zq1
            .collect::<Vec<_>>();

        if chunks.len() < 2 || chunks[0] != evm_prefix {
            warn!("Malformed key name in contract storage!");
            continue;
        };

        let key = hex::decode(chunks[1])?;
        let key = State::account_storage_key(address, B256::from_slice(&key));

        contract_trie.insert(&key.0, &value)?;
    }

    Ok(contract_trie.root_hash()?)
}

fn get_contract_code(zq1_db: &zq1::Db, address: Address) -> Result<Code> {
    let Some(code) = zq1_db.get_contract_code(address)? else {
        return Ok(Code::Evm(vec![]));
    };

    let evm_prefix = b"EVM";

    if code.len() > 3 && code[0..3] == evm_prefix[0..3] {
        return Ok(Code::Evm(code[3..].to_vec()));
    }

    let init_data = zq1_db.get_contract_init_state_2(address)?;

    let init_data = match init_data {
        Some(data) => String::from_utf8(data)
            .map_err(|err| anyhow!("Unable to convert scilla initdata into string: {err}"))?,
        None => String::new(),
    };
    let init_data_vec = if init_data.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str::<Vec<ParamValue>>(&init_data).map_err(|err| {
            anyhow!("Unable to convert scilla init data into Vec<ParamValue>: {init_data} - {err}")
        })?
    };

    Ok(Code::Scilla {
        code: String::from_utf8(code)
            .map_err(|err| anyhow!("Unable to convert scilla code into string: {err}"))?,
        init_data: init_data_vec,
        types: BTreeMap::default(),
        transitions: vec![],
    })
}

pub async fn convert_persistence(
    zq1_db: zq1::Db,
    zq2_db: Db,
    zq2_config: Config,
    secret_key: SecretKey,
    convert_accounts: bool,
    convert_blocks: bool,
) -> Result<()> {
    let style = ProgressStyle::with_template(
        "{msg} {wide_bar} [{per_sec}] {human_pos}/~{human_len} ({elapsed}/~{duration})",
    )
    .unwrap();

    let (outbound_message_sender, _a) = mpsc::unbounded_channel();
    let (local_message_sender, _b) = mpsc::unbounded_channel();
    let message_sender = MessageSender {
        our_shard: 0,
        our_peer_id: PeerId::random(),
        outbound_channel: outbound_message_sender,
        local_channel: local_message_sender,
        request_id: RequestId::default(),
    };

    let zq2_db = Arc::new(zq2_db);
    let node_config = &zq2_config.nodes[0];
    let block_store = Arc::new(BlockStore::new(
        node_config,
        zq2_db.clone(),
        message_sender.clone(),
    )?);
    let mut state = State::new_with_genesis(
        zq2_db.clone().state_trie()?,
        node_config.clone(),
        block_store,
    )?;

    if convert_accounts {
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

            let code = get_contract_code(&zq1_db, address)?;

            let (code, storage_root) = match code {
                Code::Evm(evm_code) if !evm_code.is_empty() => {
                    let storage_root = convert_evm_state(&zq1_db, &zq2_db, address)?;
                    (Code::Evm(evm_code), storage_root)
                }
                Code::Scilla {
                    code, init_data, ..
                } => {
                    let (storage_root, types) = convert_scilla_state(&zq1_db, &zq2_db, address)?;
                    (
                        Code::Scilla {
                            code,
                            init_data,
                            types,
                            // TODO: transitions were not part of zq1 storage (they have to be recreated with scilla-checker)
                            transitions: vec![],
                        },
                        storage_root,
                    )
                }
                _ => (code, EMPTY_ROOT_HASH),
            };

            let account = Account {
                nonce: zq1_account.nonce,
                balance: zq1_account.balance * 10u128.pow(6),
                code,
                storage_root,
            };

            state.save_account(address, account)?;
            // Flush any pending changes to db
            let _ = state.root_hash()?;
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
        0,
        node_config.consensus.eth_block_gas_limit,
        0,
        data,
        None,
        BlockHeader::default(),
        inspector::noop(),
        BaseFeeCheck::Ignore,
    )?;
    if !result.is_success() {
        return Err(anyhow!("setting stake failed: {result:?}"));
    }
    state.apply_delta_evm(&result_state)?;

    // Flush any pending changes to db
    let _ = state.root_hash()?;

    if !convert_blocks {
        println!("Accounts converted. Skipping blocks.");
        return Ok(());
    }

    let max_block = zq1_db
        .get_tx_blocks_aux("MaxTxBlockNumber")?
        .unwrap_or_default();

    let current_block = zq2_db.get_latest_finalized_view()?.unwrap_or(1);

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

    let tx_blocks_iter = tx_blocks
        .into_iter()
        .progress_with(progress)
        .skip_while(|(n, _)| *n <= current_block);

    let mut parent_hash = Hash::ZERO;

    for (block_number, block) in tx_blocks_iter {
        let mut transactions = Vec::new();
        let mut receipts = Vec::new();

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

        let mut receipts_trie = eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));

        let mut transactions_trie = eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));

        // Block hash is built using receipt and transaction root hashes. This means we have to compute all receipts before creating a block.
        // Since receipt also contains block hash it belongs too - at the time it's being built it uses a placeholder: Hash::ZERO. Once all transactions are processed,
        // block hash can be calculated and each receipt is updated with final block hash (by replacing Hash::ZERO placeholder).

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

            let Ok((transaction, receipt)) =
                process_txn(transaction, *txn_hash, chain_id, version, index)
            else {
                return Err(anyhow!("Can't process transaction: {:?}", *txn_hash));
            };

            transactions_trie
                .insert(txn_hash.as_slice(), transaction.calculate_hash().as_bytes())?;

            let receipt_hash = receipt.compute_hash();
            receipts_trie.insert(receipt_hash.as_bytes(), receipt_hash.as_bytes())?;

            transactions.push((Hash(txn_hash.0), transaction));
            receipts.push(receipt);
            trace!(?txn_hash, "transaction inserted");
        }

        let qc = QuorumCertificate::new(
            &[vote.signature()],
            bitarr![u8, Msb0; 1; MAX_COMMITTEE_SIZE],
            parent_hash,
            block.block_num - 1,
        );
        let block = Block::from_qc(
            secret_key,
            block.block_num,
            block.block_num,
            qc,
            None,
            state.root_hash()?,
            Hash(transactions_trie.root_hash()?.into()),
            Hash(receipts_trie.root_hash()?.into()),
            txn_hashes.iter().map(|h| Hash(h.0)).collect(),
            SystemTime::UNIX_EPOCH + Duration::from_micros(block.timestamp),
            ScillaGas(block.gas_used).into(),
            ScillaGas(block.gas_limit).into(),
        );

        // For each receipt update block hash. This can be done once all receipts build receipt_root_hash which is used for calculating block hash
        for receipt in &mut receipts {
            receipt.block_hash = block.hash();
        }

        parent_hash = block.hash();

        zq2_db.with_sqlite_tx(|sqlite_tx| {
            zq2_db.insert_block_with_db_tx(sqlite_tx, &block)?;
            zq2_db.set_high_qc_with_db_tx(sqlite_tx, block.header.qc)?;
            zq2_db.set_latest_finalized_view_with_db_tx(sqlite_tx, block.view())?;
            trace!("{} block inserted", block.number());

            for (hash, transaction) in &transactions {
                if let Err(err) = zq2_db.insert_transaction_with_db_tx(sqlite_tx, hash, transaction)
                {
                    warn!(
                        "Unable to insert transaction with id: {:?} to db, err: {:?}",
                        *hash, err
                    );
                }
            }
            for receipt in &receipts {
                if let Err(err) =
                    zq2_db.insert_transaction_receipt_with_db_tx(sqlite_tx, receipt.to_owned())
                {
                    warn!(
                        "Unable to insert receipt with id: {:?} into db, err: {:?}",
                        receipt.tx_hash, err
                    );
                }
            }
            Ok(())
        })?;
    }

    // Let's insert another block (empty) which will be used as high_qc block when zq2 starts from converted persistence
    let highest_block = zq2_db.get_highest_block_number()?.unwrap();
    let highest_block = zq2_db.get_block_by_view(highest_block)?.unwrap();

    zq2_db.with_sqlite_tx(|sqlite_tx| {
        let empty_high_qc_block = create_empty_block_from_parent(&highest_block, secret_key);
        zq2_db.insert_block_with_db_tx(sqlite_tx, &empty_high_qc_block)?;
        zq2_db.set_high_qc_with_db_tx(sqlite_tx, empty_high_qc_block.header.qc)?;
        Ok(())
    })?;

    println!(
        "Persistence conversion done up to block {}",
        zq2_db.get_highest_block_number()?.unwrap_or(0)
    );

    Ok(())
}

fn create_empty_block_from_parent(parent_block: &Block, secret_key: SecretKey) -> Block {
    let vote = Vote::new(
        secret_key,
        parent_block.hash(),
        secret_key.node_public_key(),
        parent_block.number(),
    );

    let qc = QuorumCertificate::new(
        &[vote.signature()],
        bitarr![u8, Msb0; 1; MAX_COMMITTEE_SIZE],
        parent_block.hash(),
        parent_block.number(),
    );

    Block::from_qc(
        secret_key,
        parent_block.header.view + 1,
        parent_block.header.number + 1,
        qc,
        None,
        parent_block.header.state_root_hash,
        parent_block.transactions_root_hash(),
        parent_block.header.receipts_root_hash,
        vec![],
        parent_block.header.timestamp,
        parent_block.header.gas_used,
        parent_block.header.gas_limit,
    )
}

fn process_txn(
    transaction: Transaction,
    txn_hash: B256,
    chain_id: u16,
    version: u16,
    index: usize,
) -> Result<(SignedTransaction, TransactionReceipt)> {
    if let Ok(evm_result) =
        try_with_evm_transaction(transaction.clone(), txn_hash, chain_id, version, index)
    {
        return Ok(evm_result);
    }

    try_with_zil_transaction(transaction, txn_hash, chain_id, index)
}

fn try_with_zil_transaction(
    transaction: Transaction,
    txn_hash: B256,
    chain_id: u16,
    index: usize,
) -> Result<(SignedTransaction, TransactionReceipt)> {
    let from_addr = transaction.sender_pub_key.zil_addr();

    let contract_address = transaction.to_addr.is_zero().then(|| {
        let mut hasher = Sha256::new();
        hasher.update(from_addr.as_slice());
        hasher.update(transaction.nonce.to_be_bytes());
        let hashed = hasher.finalize();
        Address::from_slice(&hashed[12..])
    });

    let receipt = TransactionReceipt {
        tx_hash: Hash(txn_hash.0),
        block_hash: Hash::ZERO,
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
            gas_price: ZilAmount::from_raw(transaction.gas_price),
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
        key: schnorr::PublicKey::from_sec1_bytes(transaction.sender_pub_key.as_ref())?,
        sig: schnorr::Signature::from_slice(transaction.signature.as_slice())?,
    };

    Ok((transaction, receipt))
}

fn try_with_evm_transaction(
    transaction: Transaction,
    txn_hash: B256,
    chain_id: u16,
    version: u16,
    index: usize,
) -> Result<(SignedTransaction, TransactionReceipt)> {
    let from_addr = transaction.sender_pub_key.eth_addr();

    let contract_address = transaction
        .to_addr
        .is_zero()
        .then(|| from_addr.create(transaction.nonce - 1));

    let receipt = TransactionReceipt {
        tx_hash: Hash(txn_hash.0),
        // Block hash is not know at this point (we need to have all receipts to build receipt_root_hash which is needed for block_hash)
        block_hash: Hash::ZERO,
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

    let transaction = infer_eth_signature(txn_hash, version, chain_id + 0x8000, transaction)
        .with_context(|| format!("failed to infer signature of transaction: {txn_hash:?}"))?;

    Ok((transaction, receipt))
}

fn infer_eth_signature(
    txn_hash: B256,
    version: u16,
    chain_id: u16,
    transaction: zq1::Transaction,
) -> Result<SignedTransaction> {
    let r = U256::try_from_be_slice(&transaction.signature.0[..32])
        .context("Can retrieve r item from signature!")?;
    let s = U256::try_from_be_slice(&transaction.signature.0[32..])
        .context("Can retrieve s item from signature!")?;

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
                    gas_limit: transaction.gas_limit,
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
                    gas_limit: transaction.gas_limit,
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
                    gas_limit: transaction.gas_limit,
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
            _ => {
                return Err(anyhow!(
                    "Unable to parse evm transaction with version: {version}"
                ));
            }
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
