use std::{
    collections::BTreeMap,
    process::{self, Child, ExitStatus, Stdio},
    sync::Arc,
    time::Duration,
};

use alloy::{
    consensus::{EMPTY_ROOT_HASH, TxEip1559, TxEip2930, TxLegacy},
    hex,
    primitives::{Address, B256, Signature, TxKind, U256},
};
use anyhow::{Context, Result, anyhow};
use bitvec::{bitarr, order::Msb0};
use eth_trie::{EthTrie, MemoryDB, Trie};
use indicatif::{ProgressBar, ProgressFinish, ProgressIterator, ProgressStyle};
use itertools::Itertools;
use sha2::{Digest, Sha256};
use tracing::{debug, trace, warn};
use zilliqa::{
    cfg::{Amount, Config, NodeConfig, scilla_ext_libs_path_default},
    crypto::{Hash, SecretKey},
    db::{BlockFilter, Db},
    exec::store_external_libraries,
    message::{Block, MAX_COMMITTEE_SIZE, QuorumCertificate, Vote},
    schnorr,
    scilla::{CheckOutput, ParamValue, Transition, storage_key},
    state::{Account, Code, ContractInit, State},
    time::SystemTime,
    transaction::{ScillaGas, SignedTransaction, TransactionReceipt, TxZilliqa, ZilAmount},
};

use crate::{zq1, zq1::Transaction};

fn create_acc_query_prefix(address: Address) -> String {
    format!("{address:02x}")
}

const ZQ1_STATE_KEY_SEPARATOR: u8 = 0x16;

fn invoke_checker(state: &State, code: &str, init_data: &[ParamValue]) -> Result<CheckOutput> {
    let scilla = state.scilla();

    let contract_init = ContractInit::new(init_data.into());

    let scilla_ext_libs_path = scilla_ext_libs_path_default();

    let (ext_libs_dir_in_zq2, ext_libs_dir_in_scilla) = store_external_libraries(
        state,
        &scilla_ext_libs_path,
        contract_init.external_libraries()?,
    )?;

    let _cleanup_ext_libs_guard = scopeguard::guard((), |_| {
        // We need to ensure that in any case, the external libs directory will be removed.
        let _ = std::fs::remove_dir_all(ext_libs_dir_in_zq2.0);
    });

    scilla
        .check_contract(
            code,
            ScillaGas(10000000),
            &contract_init,
            &ext_libs_dir_in_scilla,
        )
        .and_then(|inner_result| {
            inner_result.map_err(|err| anyhow!("Contract check error: {err:?}"))
        })
        .map_err(|e| anyhow!("Failed to check contract code: {e:?}"))
}

#[allow(clippy::type_complexity)]
fn convert_scilla_state(
    zq1_db: &zq1::Db,
    zq2_db: &Db,
    state: &State,
    code: &str,
    init_data: &[ParamValue],
    address: Address,
) -> Result<(B256, BTreeMap<String, (String, u8)>, Vec<Transition>)> {
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
            debug!("Malformed key name: {} in contract storage!", key);
            continue;
        };

        // We handle this type of keys differently in zq2
        if chunks[0].as_str() == "_fields_map_depth"
            || chunks[0].as_str() == "_version"
            || chunks[0].as_str() == "_hasmap"
            || chunks[0].as_str() == "_addr"
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
    let checker_result = match invoke_checker(state, code, init_data) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("Checker failed for address {address:?} with error: {err:?}");
            // Return default values
            return Ok((
                storage_root,
                field_types,
                Vec::new(), // Default empty transitions
            ));
        }
    };
    let transitions = match checker_result.contract_info {
        Some(contract_info) => contract_info.transitions,
        _ => Vec::new(),
    };

    Ok((storage_root, field_types, transitions))
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
            debug!("Malformed key name: {} in contract storage!", key);
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

    if code.len() >= 3 && code[0..3] == evm_prefix[0..3] {
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

    let code = String::from_utf8(code)
        .map_err(|err| anyhow!("Unable to convert scilla code into string: {err}"))?;

    let scilla_code = Code::Scilla {
        code: code.clone(),
        init_data: init_data_vec,
        types: BTreeMap::default(),
        transitions: vec![],
    };

    Ok(scilla_code)
}

fn run_scilla_docker() -> Result<Child> {
    let name = "scilla-server";
    let child = std::process::Command::new("docker")
        .arg("run")
        .arg("--name")
        .arg(name)
        .arg("--network")
        .arg("host")
        .arg("--init")
        .arg("--rm")
        .arg("--volume")
        .arg("/tmp/scilla_ext_libs:/scilla_ext_libs")
        .arg("--volume")
        .arg("/tmp/scilla-state-server:/tmp/scilla-state-server")
        .arg("asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/scilla:abdb24b1")
        .arg("/scilla/0/bin/scilla-server-http")
        .spawn()?;

    // Wait for the container to be running.
    for i in 0.. {
        let status_output = std::process::Command::new("docker")
            .arg("inspect")
            .arg("-f")
            .arg("{{.State.Status}}")
            .arg(name)
            .output()
            .unwrap();
        let status = String::from_utf8(status_output.stdout).unwrap();
        if status.trim() == "running" {
            break;
        }
        if i >= 1200 {
            panic!("container is still not running");
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Ok(child)
}

fn stop_scilla_docker(child: &mut Child) -> Result<ExitStatus> {
    process::Command::new("docker")
        .arg("stop")
        .arg("--signal")
        .arg("SIGKILL")
        .arg("scilla-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .wait()
        .or(Err(anyhow!("Unable to stop docker container!")))
}

fn deduct_funds_from_zero_account(
    state: &mut State,
    config: &NodeConfig,
    zq2_zero_acc_nonce: u64,
) -> Result<()> {
    let total_requested_amount = 0_u128
        .checked_add(
            config
                .consensus
                .genesis_accounts
                .iter()
                .fold(0, |acc, item: &(Address, Amount)| acc + item.1.0),
        )
        .expect("Genesis accounts sum to more than max value of u128")
        .checked_add(
            config
                .consensus
                .genesis_deposits
                .iter()
                .fold(0, |acc, item| acc + item.stake.0),
        )
        .expect("Genesis accounts + genesis deposits sum to more than max value of u128");
    state.mutate_account(Address::ZERO, |acc| {
        acc.balance = acc.balance.checked_sub(total_requested_amount).expect("Sum of funds in genesis.deposit and genesis.accounts exceeds funds in ZeroAccount from zq1!");
        acc.nonce = zq2_zero_acc_nonce;
        Ok(())
    })?;

    // Flush any pending changes to db
    let _ = state.root_hash()?;
    Ok(())
}

pub async fn convert_persistence(
    zq1_db: zq1::Db,
    zq2_db: Db,
    zq2_config: Config,
    secret_keys: Vec<SecretKey>,
) -> Result<()> {
    let style = ProgressStyle::with_template(
        "{msg} {wide_bar} [{per_sec}] {human_pos}/~{human_len} ({elapsed}/~{duration})",
    )?;

    // let (outbound_message_sender, _a) = mpsc::unbounded_channel();
    // let (local_message_sender, _b) = mpsc::unbounded_channel();

    let zq2_db = Arc::new(zq2_db);
    let node_config = &zq2_config.nodes[0];
    let mut state = State::new_with_genesis(
        zq2_db.clone().state_trie()?,
        node_config.clone(),
        zq2_db.clone(),
    )?;

    let mut scilla_docker = run_scilla_docker()?;
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

    let zq2_zero_acc_nonce = state.must_get_account(Address::ZERO).nonce;

    for (address, zq1_account) in accounts.into_iter().progress_with(progress) {
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
                let (storage_root, types, transitions) =
                    convert_scilla_state(&zq1_db, &zq2_db, &state, &code, &init_data, address)?;
                (
                    Code::Scilla {
                        code,
                        init_data,
                        types,
                        transitions,
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

    stop_scilla_docker(&mut scilla_docker)?;

    deduct_funds_from_zero_account(&mut state, node_config, zq2_zero_acc_nonce)?;

    let max_block = zq1_db
        .get_tx_blocks_aux("MaxTxBlockNumber")?
        .unwrap_or_default();

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

    let tx_blocks_iter = tx_blocks.into_iter().progress_with(progress);

    let mut parent_hash = Hash::ZERO;

    let secret_key = secret_keys[0];

    for (block_number, block) in tx_blocks_iter {
        let mut transactions = Vec::new();
        let mut receipts = Vec::new();

        let zq1_block = zq1::TxBlock::from_proto(block)?;

        let txn_hashes: Vec<_> = zq1_block
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
            zq1_block.block_num - 1,
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
            zq1_block.block_num - 1,
        );
        let block = Block::from_qc(
            secret_key,
            zq1_block.block_num,
            zq1_block.block_num,
            qc,
            None,
            Hash::ZERO,
            Hash(transactions_trie.root_hash()?.into()),
            Hash(receipts_trie.root_hash()?.into()),
            txn_hashes.iter().map(|h| Hash(h.0)).collect(),
            SystemTime::UNIX_EPOCH + Duration::from_micros(zq1_block.timestamp),
            ScillaGas(zq1_block.gas_used).into(),
            ScillaGas(zq1_block.gas_limit).into(),
        );

        // For each receipt update block hash. This can be done once all receipts build receipt_root_hash which is used for calculating block hash
        for receipt in &mut receipts {
            receipt.block_hash = zq1_block.block_hash.into();
        }

        parent_hash = zq1_block.block_hash.into();

        zq2_db.with_sqlite_tx(|sqlite_tx| {
            zq2_db.insert_block_with_hash_with_db_tx(
                sqlite_tx,
                zq1_block.block_hash.into(),
                &block,
            )?;
            zq2_db.set_high_qc_with_db_tx(sqlite_tx, block.header.qc)?;
            zq2_db.set_finalized_view_with_db_tx(sqlite_tx, block.view())?;
            trace!("{} block inserted", block.number());

            for (hash, transaction) in &transactions {
                if let Err(err) = zq2_db.insert_transaction_with_db_tx(
                    sqlite_tx,
                    hash,
                    &transaction.clone().verify_bypass(*hash)?,
                ) {
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
    let highest_zq1_block = zq2_db.get_highest_canonical_block_number()?.unwrap();
    let highest_zq1_block = zq2_db
        .get_block(BlockFilter::View(highest_zq1_block))?
        .unwrap();
    let state_root_hash = state.root_hash()?;

    zq2_db.with_sqlite_tx(|sqlite_tx| {
        // Insert finalized zq2_block_1 with empty qc
        let empty_block =
            create_empty_block_from_parent(&highest_zq1_block, &secret_keys, state_root_hash);
        zq2_db.insert_block_with_db_tx(sqlite_tx, &empty_block)?;
        zq2_db.set_high_qc_with_db_tx(sqlite_tx, empty_block.header.qc)?;
        zq2_db.set_finalized_view_with_db_tx(sqlite_tx, empty_block.view())?;

        // Insert qc which points to zq2_block_1
        let qc = get_qc_for_block(&empty_block, &secret_keys);
        zq2_db.set_high_qc_with_db_tx(sqlite_tx, qc)?;

        Ok(())
    })?;

    println!(
        "Persistence conversion done up to block {}",
        zq2_db.get_highest_canonical_block_number()?.unwrap_or(0)
    );

    Ok(())
}

fn get_qc_for_block(block: &Block, keys: &[SecretKey]) -> QuorumCertificate {
    let mut cosigned = bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE];
    let mut votes = Vec::new();

    for (index, key) in keys.iter().enumerate() {
        cosigned.set(index, true);
        let vote = Vote::new(*key, block.hash(), key.node_public_key(), block.number());
        votes.push(vote.signature());
    }

    QuorumCertificate::new(&votes, cosigned, block.hash(), block.number())
}

fn create_empty_block_from_parent(
    parent_block: &Block,
    secret_keys: &[SecretKey],
    state_root_hash: Hash,
) -> Block {
    let qc = get_qc_for_block(parent_block, secret_keys);

    Block::from_qc(
        secret_keys[0],
        parent_block.header.view + 1,
        parent_block.header.number + 1,
        qc,
        None,
        state_root_hash,
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
        hasher.update((transaction.nonce - 1).to_be_bytes());
        let hashed = hasher.finalize();
        Address::from_slice(&hashed[12..])
    });

    let mut errors = BTreeMap::new();

    transaction
        .receipt
        .errors
        .into_iter()
        .for_each(|(key, value)| {
            let key = key.parse::<u64>().unwrap();
            let value = value
                .into_iter()
                .map(|err_as_int| err_as_int.into())
                .collect::<Vec<_>>();
            errors.entry(key).or_insert_with(Vec::new).extend(value);
        });

    let receipt = TransactionReceipt {
        tx_hash: Hash(txn_hash.0),
        block_hash: Hash::ZERO,
        index: index as u64,
        success: transaction.receipt.success,
        gas_used: ScillaGas(transaction.receipt.cumulative_gas).into(),
        cumulative_gas_used: ScillaGas(transaction.receipt.cumulative_gas).into(),
        contract_address,
        logs: transaction
            .receipt
            .event_logs
            .iter()
            .map(|log| log.to_zq2_log())
            .collect::<Result<_>>()?,
        transitions: transaction
            .receipt
            .transitions
            .into_iter()
            .map(|x| x.into())
            .collect(),
        accepted: transaction.receipt.accepted,
        errors,
        exceptions: transaction.receipt.exceptions,
    };

    let transaction = SignedTransaction::Zilliqa {
        tx: TxZilliqa {
            chain_id,
            nonce: transaction.nonce,
            gas_price: ZilAmount::from_raw(transaction.gas_price),
            gas_limit: ScillaGas(transaction.gas_limit),
            to_addr: transaction.to_addr,
            amount: ZilAmount::from_raw(transaction.amount),
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
        gas_used: ScillaGas(transaction.receipt.cumulative_gas).into(),
        cumulative_gas_used: ScillaGas(transaction.receipt.cumulative_gas).into(),
        contract_address,
        logs: transaction
            .receipt
            .event_logs
            .iter()
            .map(|log| log.to_zq2_log())
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
        let sig = Signature::new(r, s, y_is_odd);
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
