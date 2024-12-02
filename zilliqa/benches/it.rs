use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::{
    consensus::TxLegacy, network::TxSignerSync, primitives::Address, signers::local::LocalSigner,
};
use bitvec::{bitarr, order::Msb0};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use eth_trie::{MemoryDB, Trie};
use indicatif::{ParallelProgressIterator, ProgressBar};
use libp2p::PeerId;
use pprof::criterion::{Output, PProfProfiler};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use revm::primitives::{Bytes, TxKind};
use tempfile::tempdir;
use tokio::sync::mpsc;
use zilliqa::{
    consensus::Consensus,
    crypto::{Hash, SecretKey},
    db::Db,
    message::{Block, ExternalMessage, Proposal, QuorumCertificate, Vote, MAX_COMMITTEE_SIZE},
    node::{MessageSender, RequestId},
    time::{self, SystemTime},
    transaction::{EvmGas, SignedTransaction},
};

pub fn process_empty(c: &mut Criterion) {
    tracing_subscriber::fmt::init();

    let mut group = c.benchmark_group("process-empty");
    group.throughput(criterion::Throughput::Elements(1));
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

pub fn produce_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("produce-full");
    group.throughput(criterion::Throughput::Elements(1));
    let sample_size = 10;
    group
        .sample_size(sample_size)
        .measurement_time(Duration::from_secs(60));

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
    let data_dir = tempdir().unwrap();
    let db = Db::new(Some(data_dir.path()), 0, 1024).unwrap();
    let signer = LocalSigner::random();
    let mut consensus = Consensus::new(
        secret_key,
        toml::from_str(&format!(
            r#"
                consensus.rewards_per_hour = "1"
                consensus.blocks_per_hour = 1
                consensus.minimum_stake = "1"
                consensus.eth_block_gas_limit = 84000000
                consensus.gas_price = "1"
                consensus.genesis_accounts = [
                    [
                        "{}",
                        "1_000_000_000_000_000_000_000_000_000",
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
            signer.address(),
            secret_key.node_public_key()
        ))
        .unwrap(),
        message_sender,
        reset_timeout_sender,
        Arc::new(db),
    )
    .unwrap();

    // Fill transaction pool with lots of basic transfers.
    let txn_count = (sample_size as u64 * 80) * 4000;
    let to = Address::random();
    let progress = ProgressBar::new(txn_count).with_message("generating transactions");
    let txns: Vec<_> = (0..txn_count)
        .into_par_iter()
        .progress_with(progress)
        .map(|nonce| {
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
        })
        .collect();
    for txn in txns {
        let result = consensus.new_transaction(txn, false).unwrap();
        assert!(result.was_added());
    }

    // Trigger a timeout to produce the vote for the genesis block.
    let (_, message) = consensus.timeout().unwrap().unwrap();
    let ExternalMessage::Vote(vote) = message else {
        panic!()
    };
    let mut vote = *vote;

    time::sync_with_fake_time(|| {
        group.bench_function("produce-full", |b| {
            b.iter(|| {
                let proposal = consensus
                    .vote(black_box(vote))
                    .unwrap()
                    .map(|(b, t)| Proposal::from_parts(b, t));
                // The first vote should immediately result in a proposal. Subsequent views require a timeout before
                // the proposal is produced. Therefore, we trigger a timeout if there was not a proposal from the vote.
                let proposal = proposal.unwrap_or_else(|| {
                    time::advance(Duration::from_secs(10));
                    let (_, message) = consensus.timeout().unwrap().unwrap();
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
                // Deliberately set the `from` to a different peer ID, so we don't decide to 'fast-forward' the
                // proposal because we know we've already executed it when building it.
                let (_, next_vote) = consensus
                    .proposal(PeerId::random(), black_box(proposal), false)
                    .unwrap()
                    .unwrap();
                let ExternalMessage::Vote(next_vote) = next_vote else {
                    panic!()
                };
                vote = *next_vote;
            })
        });
    });
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = process_empty, produce_full,
);
criterion_main!(benches);
