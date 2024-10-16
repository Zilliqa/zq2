use std::{path::PathBuf, sync::Arc, time::Duration};

use alloy::primitives::Address;
use bitvec::{bitarr, order::Msb0};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use eth_trie::{MemoryDB, Trie};
use libp2p::PeerId;
use tokio::sync::mpsc;
use zilliqa::{
    consensus::Consensus,
    crypto::{Hash, SecretKey},
    db::Db,
    message::{Block, Proposal, QuorumCertificate, Vote, MAX_COMMITTEE_SIZE},
    node::{MessageSender, RequestId},
    time::SystemTime,
    transaction::EvmGas,
};

pub fn process_blocks(c: &mut Criterion) {
    tracing_subscriber::fmt::init();

    let mut group = c.benchmark_group("process-blocks");
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
    let db = Db::new::<PathBuf>(None, 0).unwrap();
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

    group.bench_function("process-blocks", |b| {
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

criterion_group!(benches, process_blocks);
criterion_main!(benches);
