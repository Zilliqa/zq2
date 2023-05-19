use crate::state::Transaction;
use std::borrow::Cow;

use anyhow::Result;
use libp2p::PeerId;
use primitive_types::H256;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    api::types::{EthTransaction, EthTransactionReceipt},
    cfg::Config,
    consensus::Consensus,
    crypto::{Hash, PublicKey, SecretKey},
    message::{Block, BlockRequest, BlockResponse, Message, Proposal},
    state::{Account, Address},
};

/// The central data structure for a blockchain node.
///
/// # Transaction Lifecycle
/// 1. New transactions are created with a call to [`Node::new_transaction()`].
/// The node gossips the transaction to the network via a [`Message::NewTransaction`] message.
/// This initial node also stores the transaction hash in `pending_transactions`.
///
/// 1. When a node recieves a [`NewTransaction`] via [`Node::handle_message()`], it stores it in `new_transactions`.
/// This contains all transactions which have been receieved, but not yet executed.
///
/// 1. When the initial node is a leader of a block, it adds all transaction hashes in `pending_transactions` to the block.
///
/// 1. When a node recieves a block proposal, it looks up the transactions in `new_transactions` and executes them against its `state`.
/// Successfully executed transactions are added to `transactions` so they can be returned via APIs.
pub struct Node {
    pub config: Config,
    peer_id: PeerId,
    message_sender: UnboundedSender<(PeerId, Message)>,
    reset_timeout: UnboundedSender<()>,
    consensus: Consensus,
}

impl Node {
    pub fn new(
        config: Config,
        secret_key: SecretKey,
        message_sender: UnboundedSender<(PeerId, Message)>,
        reset_timeout: UnboundedSender<()>,
    ) -> Result<Node> {
        let node = Node {
            config,
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            message_sender,
            reset_timeout,
            consensus: Consensus::new(secret_key),
        };

        Ok(node)
    }

    // TODO: Multithreading - `&mut self` -> `&self`
    pub fn handle_message(&mut self, source: PeerId, message: Message) -> Result<()> {
        match message {
            Message::Proposal(m) => {
                if let Some((leader, vote)) = self.consensus.proposal(m.block)? {
                    self.reset_timeout.send(())?;
                    self.send_message(leader, Message::Vote(vote))?;
                }
            }
            Message::Vote(m) => {
                if let Some(proposal) = self.consensus.vote(source, m)? {
                    self.broadcast_message(Message::Proposal(Proposal { block: proposal }))?;
                }
            }
            Message::NewView(m) => {
                if let Some(proposal) = self.consensus.new_view(source, m)? {
                    self.broadcast_message(Message::Proposal(Proposal { block: proposal }))?;
                }
            }
            Message::BlockRequest(m) => {
                self.handle_block_request(source, m)?;
            }
            Message::BlockResponse(m) => {
                self.handle_block_response(source, m)?;
            }
            Message::NewTransaction(t) => {
                self.consensus.new_transaction(t)?;
            }
        }

        Ok(())
    }

    pub fn handle_timeout(&mut self) -> Result<()> {
        if let Some((leader, new_view)) = self.consensus.timeout()? {
            self.send_message(leader, Message::NewView(new_view))?;
        }

        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerId, public_key: PublicKey) -> Result<()> {
        if let Some((leader, vote)) = self.consensus.add_peer(peer, public_key)? {
            self.reset_timeout.send(())?;
            self.send_message(leader, Message::Vote(vote))?;
        }

        Ok(())
    }

    pub fn create_transaction(&mut self, txn: Transaction) -> Result<Hash> {
        let hash = txn.hash();
        self.broadcast_message(Message::NewTransaction(txn))?;

        Ok(hash)
    }

    pub fn view(&self) -> u64 {
        self.consensus.view()
    }

    pub fn call_contract(&self, contract: Address, data: Vec<u8>) -> Result<Vec<u8>> {
        self.consensus.state().call_contract(contract, data)
    }

    pub fn get_account(&self, address: Address) -> Result<Cow<'_, Account>> {
        Ok(self.consensus.state().get_account(address))
    }

    pub fn get_latest_block(&self) -> Option<&Block> {
        self.get_block_by_view(self.consensus.view().saturating_sub(1))
    }

    pub fn get_block_by_view(&self, view: u64) -> Option<&Block> {
        self.consensus.get_block_by_view(view)
    }

    pub fn get_block_by_hash(&self, hash: Hash) -> Option<&Block> {
        self.consensus.get_block(&hash).ok()
    }

    pub fn get_transaction_receipt(&self, hash: Hash) -> Option<EthTransactionReceipt> {
        let transaction = self.consensus.get_transaction_by_hash(hash)?;
        // TODO: Return error if block does not exist.
        let block = self
            .consensus
            .get_block_by_transaction_hash(transaction.hash())?;

        let receipt = EthTransactionReceipt {
            transaction_hash: H256(hash.0),
            transaction_index: block
                .transactions
                .iter()
                .position(|t| t.hash() == hash)
                .unwrap() as u64,
            block_hash: H256::from_slice(block.hash.as_bytes()),
            block_number: block.view,
            from: transaction.from_addr.0,
            to: transaction.to_addr.0,
            cumulative_gas_used: 0,
            effective_gas_price: 0,
            gas_used: 0,
            contract_address: transaction.contract_address.map(|a| a.0),
            logs: vec![],
            logs_bloom: [0; 256],
            ty: 0,
            status: true,
        };

        Some(receipt)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Option<EthTransaction> {
        let transaction = self.consensus.get_transaction_by_hash(hash)?;
        // TODO: Return error if block does not exist.
        let block = self
            .consensus
            .get_block_by_transaction_hash(transaction.hash())?;

        let response = EthTransaction {
            block_hash: H256(block.hash.0),
            block_number: block.view,
            from: transaction.from_addr.0,
            gas: 0,
            gas_price: transaction.gas_price as u64,
            input: transaction.payload.clone(),
            nonce: transaction.nonce,
            // `to` should be `None` if `transaction` is a contract creation.
            to: if transaction.contract_address.is_none() {
                Some(transaction.to_addr.0)
            } else {
                None
            },
            transaction_index: block
                .transactions
                .iter()
                .position(|t| t.hash() == hash)
                .unwrap() as u64,
            value: transaction.amount as u64,
            v: 0,
            r: [0; 32],
            s: [0; 32],
        };

        Some(response)
    }

    fn send_message(&mut self, peer: PeerId, message: Message) -> Result<()> {
        if peer == self.peer_id {
            // We need to 'send' this message to ourselves.
            self.handle_message(peer, message)?;
        } else {
            self.message_sender.send((peer, message))?;
        }
        Ok(())
    }

    fn broadcast_message(&mut self, message: Message) -> Result<()> {
        // FIXME: We broadcast everything, so the recipient doesn't matter.
        self.message_sender
            .send((PeerId::random(), message.clone()))?;
        // Also handle it ourselves
        self.handle_message(self.peer_id, message)?;
        Ok(())
    }

    fn handle_block_request(&mut self, source: PeerId, request: BlockRequest) -> Result<()> {
        let block = self.consensus.get_block(&request.hash)?;

        self.send_message(
            source,
            Message::BlockResponse(BlockResponse {
                block: block.clone(),
            }),
        )?;

        Ok(())
    }

    fn handle_block_response(&mut self, _: PeerId, response: BlockResponse) -> Result<()> {
        self.consensus.add_block(response.block);

        Ok(())
    }
}
