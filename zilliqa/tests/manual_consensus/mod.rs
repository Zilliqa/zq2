use libp2p::futures::StreamExt;
use tracing::trace;
use zilliqa::crypto::Hash;
use zilliqa::crypto::SecretKey;
use zilliqa::message::Block;
use zilliqa::message::Message;
use zilliqa::message::Vote;
use zilliqa::node_launcher::NodeLauncher;
use zilliqa::state::Transaction;

pub struct ManualConsensus {
    pub latest_block: Block,
    pub nodes: Vec<NodeLauncher>,
    pending_transactions: Vec<Transaction>,
}

impl ManualConsensus {
    pub fn new() -> Self {
        // 1. make node
        let mut nodes = Vec::new();
        for _ in 0..4 {
            let secret_key = SecretKey::new().unwrap();
            let wrapped_node = NodeLauncher::new(secret_key, toml::from_str("").unwrap()).unwrap();
            nodes.push(wrapped_node);
        }

        nodes.sort_unstable_by_key(|node| node.peer_id);
        trace!("Created all nodes");

        // 2. add them all as peers
        for wrapped_node in &nodes {
            for peer_node in &nodes {
                if wrapped_node.peer_id == peer_node.peer_id {
                    continue;
                }
                trace!(
                    "Adding node {} as peer of {}",
                    peer_node.peer_id,
                    wrapped_node.peer_id
                );
                wrapped_node
                    .node
                    .lock()
                    .unwrap()
                    .add_peer(peer_node.peer_id, peer_node.secret_key.bls_public_key())
                    .expect("Failed adding peer");
            }
        }

        Self {
            latest_block: Block::genesis(4),
            nodes,
            pending_transactions: Vec::new(),
        }
    }

    pub async fn mine_block(&mut self) -> &mut Self {
        self.latest_block = Self::progress_one_block(
            &mut self.nodes,
            self.latest_block.view() + 1,
            self.latest_block.hash(),
            &mut self.pending_transactions,
        )
        .await;
        self
    }

    pub async fn mine_blocks(&mut self, count: u8) -> &mut Self {
        for _ in 0..count {
            self.mine_block().await;
        }
        self
    }

    pub fn submit_transaction(&mut self, tx: Transaction) -> &mut Self {
        self.pending_transactions.push(tx);
        self
    }

    async fn progress_one_block(
        nodes: &mut Vec<NodeLauncher>,
        new_view: u64,
        current_hash: Hash,
        transactions: &mut [Transaction],
    ) -> Block {
        let leader_idx: usize = (new_view % nodes.len() as u64).try_into().unwrap();
        let leader_id = nodes[leader_idx].peer_id;

        let mut votes_to_leader = Vec::new();
        for (i, wrapped_node) in nodes.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            let (peer_id, msg) = wrapped_node.message_receiver.next().await.unwrap();
            assert_eq!(peer_id, leader_id);
            match msg {
                Message::Vote(Vote {
                    signature,
                    block_hash,
                    index,
                }) => {
                    assert_eq!(
                        signature,
                        wrapped_node.secret_key.sign(current_hash.as_bytes())
                    );
                    assert_eq!(block_hash, current_hash);
                    assert_eq!(index as usize, i);
                }
                _ => {
                    panic!("Wrong message received: expecting Vote")
                }
            };
            votes_to_leader.push((peer_id, msg));
        }

        let mut transaction_messages_from_leader = Vec::new();
        for tx in transactions.iter_mut() {
            nodes[leader_idx]
                .node
                .lock()
                .unwrap()
                .create_transaction(tx.clone())
                .unwrap();
            let (_, msg) = nodes[leader_idx].message_receiver.next().await.unwrap();
            match msg.clone() {
                Message::NewTransaction(Transaction {
                    nonce,
                    gas_price,
                    gas_limit,
                    signature,
                    pubkey: _,
                    contract_address: _, // TODO: unvalidated
                    from_addr,
                    to_addr,
                    amount,
                    payload,
                }) => {
                    assert_eq!(nonce, tx.nonce);
                    assert_eq!(gas_price, tx.gas_price);
                    assert_eq!(gas_limit, tx.gas_limit);
                    assert_eq!(from_addr, tx.from_addr);
                    assert_eq!(to_addr, tx.to_addr);
                    assert_eq!(amount, tx.amount);
                    assert_eq!(payload, tx.payload);
                    assert_eq!(signature, tx.signature);
                    assert_eq!(payload, tx.payload);
                    assert!(tx.verify().is_ok());
                }
                _ => {
                    panic!("Wrong message received: expecting NewTransaction for every submitted transaction");
                }
            };
            transaction_messages_from_leader.push(msg);
        }

        for (peer_id, msg) in votes_to_leader {
            nodes[leader_idx]
                .node
                .lock()
                .unwrap()
                .handle_message(peer_id, msg)
                .unwrap();
        }

        let tx_hashes = transactions.iter().map(|tx| tx.hash()).collect::<Vec<_>>();

        let (_peer_id, proposal_message) = nodes[leader_idx].message_receiver.next().await.unwrap();
        let block = match proposal_message.clone() {
            Message::Proposal(p) => {
                // TODO: potentially add more assertions on the state here?
                let (block, transactions) = p.into_parts();
                assert_eq!(block.view(), new_view);
                assert_eq!(block.parent_hash(), current_hash);
                let block_tx_hashes = transactions.iter().map(|tx| tx.hash()).collect::<Vec<_>>();
                for hash in tx_hashes {
                    assert!(block_tx_hashes.contains(&hash));
                }
                block
            }
            _ => {
                panic!("Wrong message recieved after voting on a block!")
            }
        };

        for (i, wrapped_node) in nodes.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            let mut node = wrapped_node.node.lock().unwrap();
            for tx_msg in transaction_messages_from_leader.clone() {
                println!("Sending new_tx message to node {}", i);
                node.handle_message(leader_id, tx_msg).unwrap();
            }
            println!("Sending proposal message to node {}", i);
            node.handle_message(leader_id, proposal_message.clone())
                .unwrap();
        }

        block
    }
}
