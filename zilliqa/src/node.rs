use crate::state::{Transaction, TransactionReceipt};
use std::borrow::Cow;

use anyhow::{anyhow, Result};
use libp2p::PeerId;
use primitive_types::U256;
use tokio::sync::mpsc::UnboundedSender;

use tracing::error;

use crate::{
    cfg::Config,
    consensus::Consensus,
    crypto::{Hash, NodePublicKey, SecretKey},
    message::{Block, BlockRequest, BlockResponse, Message, Proposal},
    state::{Account, Address},
};

/// The central data structure for a blockchain node.
///
/// # Transaction Lifecycle
/// 1. New transactions are created with a call to [`Node::new_transaction()`].
/// The node gossips the transaction to the network and itself via a [`Message::NewTransaction`] message.
/// This initial node also stores the transaction hash in `new_transactions`.
///
/// 1. When a node recieves a [`NewTransaction`] via [`Node::handle_message()`], it stores it in `new_transactions`.
/// This contains all transactions which have been receieved, but not yet executed.
///
/// 2. When the initial node is a leader of a block, it adds all transaction hashes in `new_transactions` to the block.
///
/// 3. When a node recieves a block proposal, it looks up the transactions in `new_transactions` and executes them against its `state`.
/// Successfully executed transactions are added to `transactions` so they can be returned via APIs.
#[derive(Debug)]
pub struct Node {
    pub config: Config,
    peer_id: PeerId,
    message_sender: UnboundedSender<(Option<PeerId>, Message)>,
    reset_timeout: UnboundedSender<()>,
    consensus: Consensus,
}

impl Node {
    pub fn new(
        config: Config,
        secret_key: SecretKey,
        message_sender: UnboundedSender<(Option<PeerId>, Message)>,
        reset_timeout: UnboundedSender<()>,
    ) -> Result<Node> {
        let node = Node {
            config: config.clone(),
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            message_sender,
            reset_timeout,
            consensus: Consensus::new(secret_key, config)?,
        };

        Ok(node)
    }

    // TODO: Multithreading - `&mut self` -> `&self`
    pub fn handle_message(&mut self, source: PeerId, message: Message) -> Result<()> {
        match message {
            Message::Proposal(m) => {
                if let Some((leader, vote)) = self.consensus.proposal(m)? {
                    self.reset_timeout.send(())?;
                    self.send_message(leader, Message::Vote(vote))?;
                }
            }
            Message::Vote(m) => {
                if let Some((block, transactions)) = self.consensus.vote(source, m)? {
                    self.broadcast_message(Message::Proposal(Proposal {
                        header: block.header,
                        qc: block.qc,
                        agg: block.agg,
                        transactions,
                    }))?;
                }
            }
            Message::NewView(m) => {
                if let Some(block) = self.consensus.new_view(source, m)? {
                    self.broadcast_message(Message::Proposal(Proposal {
                        header: block.header,
                        qc: block.qc,
                        agg: block.agg,
                        transactions: vec![],
                    }))?;
                }
            }
            Message::BlockRequest(m) => {
                self.handle_block_request(source, m)?;
            }
            Message::BlockResponse(m) => {
                self.handle_block_response(source, m)?;
            }
            Message::RequestResponse => {}
            Message::NewTransaction(t) => {
                match t.verify() {
                    Ok(_) => {
                        self.consensus.new_transaction(t)?;
                    }
                    Err(e) => {
                        error!(
                            "Received transaction from peer {:?} failed to verify: {}",
                            source, e
                        );
                        // todo: ban/downrate peer
                    }
                }
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

    pub fn add_peer(&mut self, peer: PeerId, public_key: NodePublicKey) -> Result<()> {
        if let Some((leader, vote)) = self.consensus.add_peer(peer, public_key)? {
            self.reset_timeout.send(())?;
            self.send_message(leader, Message::Vote(vote))?;
        }

        Ok(())
    }

    pub fn create_transaction(&mut self, txn: Transaction) -> Result<Hash> {
        let hash = txn.hash();

        txn.verify()?;

        // Make sure TX hasn't been seen before
        if !self.consensus.seen_tx_already(&hash) {
            self.broadcast_message(Message::NewTransaction(txn))?;
        }

        Ok(hash)
    }

    pub fn view(&self) -> u64 {
        self.consensus.view()
    }

    pub fn call_contract(
        &self,
        caller: Address,
        contract: Address,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        println!("call contract: {:?} {:?} {:?}", caller, contract, data);

        let current_block = self
            .get_latest_block()
            .ok_or_else(|| anyhow!("no blocks"))?
            .header;
        self.consensus.state().call_contract(
            caller,
            contract,
            data,
            self.config.eth_chain_id,
            current_block,
        )
    }

    pub fn get_account(&self, address: Address) -> Result<Cow<'_, Account>> {
        Ok(self.consensus.state().get_account(address))
    }

    pub fn get_native_balance(&self, address: Address) -> Result<U256> {
        self.consensus.state().get_native_balance(address)
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

    pub fn get_transaction_receipt(&self, hash: Hash) -> Option<TransactionReceipt> {
        self.consensus.get_transaction_receipt(hash)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Option<Transaction> {
        self.consensus.get_transaction_by_hash(hash)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Vec<Hash> {
        self.consensus.get_touched_transactions(address)
    }

    fn send_message(&mut self, peer: PeerId, message: Message) -> Result<()> {
        if peer == self.peer_id {
            // We need to 'send' this message to ourselves.
            self.handle_message(peer, message)?;
        } else {
            self.message_sender.send((Some(peer), message))?;
        }
        Ok(())
    }

    fn broadcast_message(&mut self, message: Message) -> Result<()> {
        self.message_sender.send((None, message.clone()))?;
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
