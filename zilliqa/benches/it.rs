use std::{
    cell::{RefCell, RefMut},
    env,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use alloy::{
    consensus::TxLegacy, network::TxSignerSync, primitives::Address, signers::local::LocalSigner,
};
use bitvec::{bitarr, order::Msb0};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use eth_trie::{MemoryDB, Trie};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use libp2p::PeerId;
use pprof::criterion::{Output, PProfProfiler};
use prost::Message;
use revm::primitives::{Bytes, TxKind};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use tokio::sync::mpsc;
use zilliqa::{
    cfg::{Amount, GenesisDeposit, NodeConfig},
    consensus::Consensus,
    crypto::{Hash, SecretKey},
    db::Db,
    message::{Block, ExternalMessage, Proposal, QuorumCertificate, Vote, MAX_COMMITTEE_SIZE},
    node::{MessageSender, RequestId},
    schnorr,
    time::{self, SystemTime},
    transaction::{
        EvmGas, ScillaGas, SignedTransaction, TxZilliqa, VerifiedTransaction, ZilAmount,
    },
    zq1_proto::{Nonce, ProtoTransactionCoreInfo},
};

fn process_empty(c: &mut Criterion) {
    tracing_subscriber::fmt::init();

    let mut group = c.benchmark_group("process-empty");
    group.throughput(Throughput::Elements(1));
    group
        .sample_size(500)
        .measurement_time(Duration::from_secs(10));

    let secret_key = SecretKey::new().unwrap();
    let (outbound_message_sender, _a) = mpsc::unbounded_channel();
    let (local_message_sender, _b) = mpsc::unbounded_channel();
    let (reset_timeout_sender, _c) = mpsc::unbounded_channel();
    let message_sender = MessageSender {
        our_shard: 0,
        our_peer_id: PeerId::random(),
        outbound_channel: outbound_message_sender,
        local_channel: local_message_sender,
        request_id: RequestId::default(),
    };
    let db = Db::new::<PathBuf>(None, 0, 1024).unwrap();
    let mut consensus = Consensus::new(
        secret_key,
        toml::from_str(&format!(
            r#"
                consensus.rewards_per_hour = "1"
                consensus.blocks_per_hour = 1
                consensus.minimum_stake = "1"
                consensus.eth_block_gas_limit = 1000000000
                consensus.gas_price = "1"
                consensus.genesis_accounts = [
                    [
                        "0x0000000000000000000000000000000000000000",
                        "1",
                    ],
                ]
                consensus.genesis_deposits = [
                    [
                        "{}",
                        "12D3KooWF4Zba8M8gkXS6aUe8oPa3stW5N17aX3eknSjW6bGAefe",
                        "1",
                        "0x0000000000000000000000000000000000000001",
                        "0x0000000000000000000000000000000000000001",
                    ],
                ]
            "#,
            secret_key.node_public_key()
        ))
        .unwrap(),
        message_sender,
        reset_timeout_sender,
        Arc::new(db),
    )
    .unwrap();

    let genesis = consensus.get_block_by_view(0).unwrap().unwrap();
    let mut state = consensus.state().at_root(genesis.state_root_hash().into());
    let mut parent_hash = genesis.hash();
    let mut proposals = (1..).map(|view| {
        // The reward per block above is configured to 1. The consensus algorithm splits this reward between the
        // proposer and the cosigners, rounding down. Effectively this means no rewards are issued to anyone with this
        // configuration. However, the reward code will still unconditionally mutate the state trie to apply this zero
        // reward. Therefore, to calculate a correct state root hash we need to ensure the state trie includes an empty
        // entry for the rewarded and zero addresses, even if they never actually changes from the default account.
        let reward_address: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        state.mutate_account(reward_address, |_| Ok(())).unwrap();
        state.mutate_account(Address::ZERO, |_| Ok(())).unwrap();

        let vote = Vote::new(
            secret_key,
            parent_hash,
            secret_key.node_public_key(),
            view - 1,
        );
        let qc = QuorumCertificate::new(
            &[vote.signature()],
            bitarr![u8, Msb0; 1; MAX_COMMITTEE_SIZE],
            parent_hash,
            view - 1,
        );

        let mut empty_trie = eth_trie::EthTrie::new(Arc::new(MemoryDB::new(true)));
        let empty_root_hash = Hash(empty_trie.root_hash().unwrap().into());

        let block = Block::from_qc(
            secret_key,
            view,
            view,
            qc,
            None,
            state.root_hash().unwrap(),
            empty_root_hash,
            empty_root_hash,
            vec![],
            SystemTime::UNIX_EPOCH,
            EvmGas(0),
            EvmGas(0),
        );
        parent_hash = block.hash();

        Proposal::from_parts(block, vec![])
    });

    group.bench_function("process-empty", |b| {
        b.iter(|| {
            let proposal = proposals.next().unwrap();
            let view = proposal.view();
            consensus
                .receive_block(PeerId::random(), black_box(proposal))
                .unwrap();
            consensus
                .get_block_by_view(black_box(view))
                .unwrap()
                .expect("missing block");
        })
    });
    group.finish();
}

fn consensus(
    genesis_accounts: &[(Address, u128)],
    genesis_deposits: &[(SecretKey, u128)],
    index: usize,
) -> Consensus {
    let secret_key = genesis_deposits[index].0;
    let (outbound_message_sender, a) = mpsc::unbounded_channel();
    let (local_message_sender, b) = mpsc::unbounded_channel();
    let (reset_timeout_sender, c) = mpsc::unbounded_channel();
    // Leak the receivers so they don't get dropped later.
    std::mem::forget((a, b, c));
    let message_sender = MessageSender {
        our_shard: 0,
        our_peer_id: PeerId::random(),
        outbound_channel: outbound_message_sender,
        local_channel: local_message_sender,
        request_id: RequestId::default(),
    };
    let data_dir = tempdir().unwrap();
    let db = Db::new(Some(data_dir.path()), 0, 1024).unwrap();
    let mut config: NodeConfig = toml::from_str(
        r#"
            consensus.rewards_per_hour = "1"
            consensus.blocks_per_hour = 1
            consensus.minimum_stake = "1"
            consensus.eth_block_gas_limit = 84000000
            consensus.gas_price = "1"
        "#,
    )
    .unwrap();
    config.consensus.genesis_accounts = genesis_accounts
        .iter()
        .map(|(a, v)| (*a, Amount(*v)))
        .collect();
    config.consensus.genesis_deposits = genesis_deposits
        .iter()
        .enumerate()
        .map(|(i, (k, v))| GenesisDeposit {
            public_key: k.node_public_key(),
            peer_id: k.to_libp2p_keypair().public().to_peer_id(),
            stake: Amount(*v),
            reward_address: Address::right_padding_from(&[i as u8 + 1]),
            control_address: Address::right_padding_from(&[i as u8 + 1]),
        })
        .collect();
    Consensus::new(
        secret_key,
        config,
        message_sender,
        reset_timeout_sender,
        Arc::new(db),
    )
    .unwrap()
}

fn full_blocks_evm_transfers(c: &mut Criterion) {
    let signer = LocalSigner::random();
    let to = Address::random();
    let txns = (0..).map(|nonce| {
        let mut tx = TxLegacy {
            chain_id: None,
            nonce,
            gas_price: 1,
            gas_limit: 21_000,
            to: TxKind::Call(to),
            value: alloy::primitives::U256::from(1),
            input: Bytes::new(),
        };
        let sig = signer.sign_transaction_sync(&mut tx).unwrap();
        let txn = SignedTransaction::Legacy { tx, sig };
        txn.verify().unwrap()
    });

    full_transaction_benchmark(c, "full-blocks-evm-transfers", signer.address(), txns);
}

fn full_blocks_zil_transfers(c: &mut Criterion) {
    let signer = schnorr::SecretKey::random(&mut rand::thread_rng());
    let key = signer.public_key();
    let to = Address::random();
    let txns = (0..).map(|nonce| {
        let chain_id = 700;
        let amount = 1;
        let gas_price = 1;
        let gas_limit = 50;
        let tx = TxZilliqa {
            chain_id,
            nonce: nonce + 1,
            gas_price: ZilAmount::from_raw(gas_price),
            gas_limit: ScillaGas(gas_limit),
            to_addr: to,
            amount: ZilAmount::from_raw(amount),
            code: String::new(),
            data: String::new(),
        };
        let version = ((chain_id as u32) << 16) | 1u32;
        let proto = ProtoTransactionCoreInfo {
            version,
            toaddr: to.0.to_vec(),
            senderpubkey: Some(key.to_sec1_bytes().into()),
            amount: Some(amount.to_be_bytes().to_vec().into()),
            gasprice: Some(gas_price.to_be_bytes().to_vec().into()),
            gaslimit: gas_limit,
            oneof2: Some(Nonce::Nonce(nonce + 1)),
            oneof8: None,
            oneof9: None,
        };
        let txn_data = proto.encode_to_vec();
        let sig = schnorr::sign(&txn_data, &signer);
        let txn = SignedTransaction::Zilliqa { tx, key, sig };
        txn.verify().unwrap()
    });

    let hashed = Sha256::digest(key.to_encoded_point(true).as_bytes());
    let address = Address::from_slice(&hashed[12..]);

    full_transaction_benchmark(c, "full-blocks-zil-transfers", address, txns);
}

/// Run a benchmark which produces blocks full of the provided transactions. `txns` should be infinitely iterable
/// so the benchmark can generate as many transactions as it needs.
fn full_transaction_benchmark(
    c: &mut Criterion,
    name: &str,
    genesis_address: Address,
    mut txns: impl Iterator<Item = VerifiedTransaction>,
) {
    let genesis_accounts = vec![(genesis_address, 1_000_000_000_000_000_000_000_000_000)];

    // We will create a dummy network with 2 validators - 'big' which has a large proportion of the stake and 'tiny'
    // which has a small amount of stake. The intention is that 'big' will always be the block proposer, because the
    // proposer is selected in proportion to the validators' relative stake. However, 'tiny' will still get to have a
    // vote on this proposal, despite its vote not being needed to reach a supermajority. The benchmark will execute
    // the following in each iteration:
    // 1. Get 'big' to process the previous vote and propose a block
    // 2. Get 'tiny' to vote on this block
    // 3. Get 'big' to vote on this block
    // Step 2 is important, because we want to measure the time it takes a validator to vote on a block it hasn't seen
    // before. In step 3, 'big' will skip most of the block validation logic because it knows it built the block
    // itself.

    let secret_key_big = SecretKey::new().unwrap();
    let secret_key_tiny = SecretKey::new().unwrap();
    let genesis_deposits = vec![
        (secret_key_big, 1_000_000_000_000_000_000_000_000_000),
        (secret_key_tiny, 1),
    ];

    let mut big = consensus(&genesis_accounts, &genesis_deposits, 0);
    let tiny = consensus(&genesis_accounts, &genesis_deposits, 1);

    time::sync_with_fake_time(|| {
        // Trigger a timeout to produce the vote for the genesis block.
        let (_, message) = big.timeout().unwrap().unwrap();
        let ExternalMessage::Vote(vote) = message else {
            panic!()
        };
        let mut vote = *vote;
        let from = big.peer_id();

        let big = RefCell::new(big);
        let tiny = RefCell::new(tiny);

        let mut group = c.benchmark_group(name);
        group.throughput(Throughput::Elements(1));
        group.sample_size(
            env::var("ZQ_TRANSACTION_BENCHMARK_SAMPLES")
                .map(|s| s.parse().unwrap())
                .unwrap_or(20),
        );
        group.measurement_time(Duration::from_secs(
            env::var("ZQ_TRANSACTION_BENCHMARK_MEASUREMENT_TIME_S")
                .map(|s| s.parse().unwrap())
                .unwrap_or(60),
        ));
        group.bench_function(name, |bench| {
            bench.iter_batched(
                || {
                    let mut big = big.borrow_mut();
                    let mut tiny = tiny.borrow_mut();
                    for txn in txns.by_ref().take(4000) {
                        let result = big.new_transaction(txn.clone()).unwrap();
                        assert!(result.was_added());
                        let result = tiny.new_transaction(txn).unwrap();
                        assert!(result.was_added());
                    }
                },
                |()| {
                    let mut big = big.borrow_mut();
                    let mut tiny = tiny.borrow_mut();

                    // We wrap each of these steps in a separate function call, so that they are listed separately in
                    // flamegraphs and we are able to measure the time spent in each. The function names are deliberately
                    // alphabetical, so they appear in order in the flamegraph.

                    // 1. Get 'big' to process the previous vote and propose a block.
                    let proposal = a_big_process_vote(&mut big, vote);

                    // 2. Get 'tiny' to vote on this block.
                    b_tiny_process_block(&mut tiny, from, proposal.clone());

                    // 3. Get 'big' to vote on this block
                    vote = c_big_process_block(&mut big, from, proposal);
                },
                BatchSize::SmallInput,
            );
        });
    });
}

fn a_big_process_vote(big: &mut RefMut<'_, Consensus>, vote: Vote) -> Proposal {
    let proposal = big
        .vote(black_box(vote))
        .unwrap()
        .map(|(b, t)| Proposal::from_parts(b, t));
    // The first vote should immediately result in a proposal. Subsequent views require a timeout before
    // the proposal is produced. Therefore, we trigger a timeout if there was not a proposal from the vote.
    let proposal = proposal.unwrap_or_else(|| {
        time::advance(Duration::from_secs(10));
        let (_, message) = big.timeout().unwrap().unwrap();
        let ExternalMessage::Proposal(p) = message else {
            panic!()
        };
        p
    });
    assert_eq!(
        proposal.transactions.len(),
        4000,
        "proposal {} is not full",
        proposal.view()
    );
    proposal
}

fn b_tiny_process_block(tiny: &mut RefMut<'_, Consensus>, from: PeerId, proposal: Proposal) {
    let (_, tiny_vote) = tiny
        .proposal(from, black_box(proposal), false)
        .unwrap()
        .unwrap();
    // We assert 'tiny' actually voted but don't do anything with its vote.
    assert!(matches!(tiny_vote, ExternalMessage::Vote(_)));
}

fn c_big_process_block(big: &mut RefMut<'_, Consensus>, from: PeerId, proposal: Proposal) -> Vote {
    let (_, vote) = big
        .proposal(from, black_box(proposal), false)
        .unwrap()
        .unwrap();
    let ExternalMessage::Vote(vote) = vote else {
        panic!()
    };
    *vote
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = process_empty, full_blocks_evm_transfers, full_blocks_zil_transfers,
);
criterion_main!(benches);
