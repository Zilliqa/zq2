use crate::{
    cfg::NodeConfig,
    message::{BlockNumber, InternalMessage, Message},
    p2p_node::OutboundMessageTuple,
    state::{SignedTransaction, TransactionReceipt},
};
use primitive_types::H256;

use anyhow::{anyhow, Result};
use libp2p::PeerId;
use primitive_types::U256;
use tokio::sync::mpsc::UnboundedSender;
use tracing::*;

use crate::{
    consensus::Consensus,
    crypto::{Hash, NodePublicKey, SecretKey},
    message::{Block, BlockRequest, BlockResponse, ExternalMessage, Proposal},
    state::{Account, Address},
};

#[derive(Debug, Clone)]
pub struct MessageSender {
    our_shard: u64,
    our_peer_id: PeerId,
    outbound_channel: UnboundedSender<OutboundMessageTuple>,
}

impl MessageSender {
    /// Send message to the p2p/coordinator thread
    pub fn send_message_to_coordinator(&self, message: InternalMessage) -> Result<()> {
        self.outbound_channel
            .send((None, self.our_shard, Message::Internal(message)))?;
        Ok(())
    }

    /// Send a message to a locally running shard node
    pub fn send_message_to_shard(&self, shard: u64, message: InternalMessage) -> Result<()> {
        self.outbound_channel
            .send((None, shard, Message::Internal(message)))?;
        Ok(())
    }

    /// Send a message to a remote node of the same shard.
    pub fn send_external_message(&self, peer: PeerId, message: ExternalMessage) -> Result<()> {
        debug!(
            "sending {} from {} to {}",
            message.name(),
            self.our_peer_id,
            peer
        );
        self.outbound_channel
            .send((Some(peer), self.our_shard, Message::External(message)))?;
        Ok(())
    }

    /// Broadcast to the entire network of this shard
    pub fn broadcast_external_message(&self, message: ExternalMessage) -> Result<()> {
        self.outbound_channel
            .send((None, self.our_shard, Message::External(message)))?;
        Ok(())
    }
}

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
    pub config: NodeConfig,
    peer_id: PeerId,
    message_sender: MessageSender,
    reset_timeout: UnboundedSender<()>,
    consensus: Consensus,
}

impl Node {
    pub fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        message_sender_channel: UnboundedSender<OutboundMessageTuple>,
        reset_timeout: UnboundedSender<()>,
    ) -> Result<Node> {
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let message_sender = MessageSender {
            our_shard: config.eth_chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
        };
        let node = Node {
            config: config.clone(),
            peer_id,
            message_sender: message_sender.clone(),
            reset_timeout,
            consensus: Consensus::new(secret_key, config, message_sender)?,
        };
        Ok(node)
    }

    // TODO: Multithreading - `&mut self` -> `&self`
    pub fn handle_message(&mut self, from: PeerId, message: Message) -> Result<()> {
        let to = self.peer_id;
        let message_name = message.name();
        tracing::debug!(%from, %to, %message_name, "handling message");
        match message {
            Message::External(external_message) => match external_message {
                ExternalMessage::Proposal(m) => {
                    if let Some((leader, vote)) = self.consensus.proposal(m)? {
                        self.reset_timeout.send(())?;
                        self.message_sender
                            .send_external_message(leader, ExternalMessage::Vote(vote))?;
                    }
                }
                ExternalMessage::Vote(m) => {
                    if let Some((block, transactions)) = self.consensus.vote(m)? {
                        self.message_sender.broadcast_external_message(
                            ExternalMessage::Proposal(Proposal::from_parts(block, transactions)),
                        )?;
                    }
                }
                ExternalMessage::NewView(m) => {
                    if let Some(block) = self.consensus.new_view(from, *m)? {
                        self.message_sender.broadcast_external_message(
                            ExternalMessage::Proposal(Proposal::from_parts(block, vec![])),
                        )?;
                    }
                }
                ExternalMessage::BlockRequest(m) => {
                    self.handle_block_request(from, m)?;
                }
                ExternalMessage::BlockResponse(m) => {
                    self.handle_block_response(from, m)?;
                }
                ExternalMessage::RequestResponse => {}
                ExternalMessage::NewTransaction(t) => {
                    self.consensus.new_transaction(t)?;
                }
                ExternalMessage::JoinCommittee(public_key) => {
                    self.add_peer(from, public_key)?;
                }
            },
            Message::Internal(internal_message) => match internal_message {
                InternalMessage::AddPeer(public_key) => {
                    self.add_peer(from, public_key)?;
                }
                InternalMessage::LaunchShard(_) => {
                    warn!("LaunchShard messages should not be passed to the node.");
                }
            },
        }

        Ok(())
    }

    pub fn handle_timeout(&mut self) -> Result<()> {
        let (leader, new_view) = self.consensus.timeout()?;
        self.message_sender
            .send_external_message(leader, ExternalMessage::NewView(Box::new(new_view)))?;
        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerId, public_key: NodePublicKey) -> Result<()> {
        if let Some((dest, message)) = self.consensus.add_peer(peer, public_key)? {
            self.reset_timeout.send(())?;
            if let Some(leader) = dest {
                self.message_sender.send_external_message(leader, message)?;
            } else {
                self.message_sender.broadcast_external_message(message)?;
            }
        }
        Ok(())
    }

    pub fn create_transaction(&mut self, txn: SignedTransaction) -> Result<Hash> {
        let hash = txn.hash();

        info!(?hash, "seen new txn");

        // Make sure TX hasn't been seen before
        if !self.consensus.seen_tx_already(&hash)? {
            // There is a race on querying txn hash, so avoid it by immediately putting it into the pool
            self.consensus.new_transaction(txn.clone())?;

            self.message_sender
                .broadcast_external_message(ExternalMessage::NewTransaction(txn))?;
        }

        Ok(hash)
    }

    pub fn view(&self) -> u64 {
        self.consensus.view()
    }

    fn get_view(&self, block_number: BlockNumber) -> u64 {
        match block_number {
            BlockNumber::Number(n) => n,
            BlockNumber::Earliest => 0,
            BlockNumber::Latest => self.get_chain_tip(),
            BlockNumber::Pending => self.get_chain_tip(), // use latest for now
            BlockNumber::Finalized => self.get_chain_tip().saturating_sub(2),
            BlockNumber::Safe => self.get_chain_tip().saturating_sub(2), // same as finalized
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn call_contract(
        &self,
        block_number: BlockNumber,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let block = self
            .get_block_by_view(self.get_view(block_number))?
            .ok_or_else(|| anyhow!("block not found"))?;
        let state = self
            .consensus
            .state()
            .at_root(H256(block.state_root_hash().0));

        state.call_contract(
            from_addr,
            to_addr,
            data,
            self.config.eth_chain_id,
            block.header,
            true,
        )
    }

    pub fn get_gas_price(&self) -> u64 {
        self.consensus.state().get_gas_price().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        block_number: BlockNumber,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        gas: u64,
        gas_price: u64,
        value: U256,
    ) -> Result<u64> {
        // TODO: optimise this to get header directly once persistance is merged
        // (which will provide a header index)
        let block = self
            .get_block_by_view(self.get_view(block_number))?
            .ok_or_else(|| anyhow!("block not found"))?;
        let state = self
            .consensus
            .state()
            .at_root(H256(block.state_root_hash().0));

        state.estimate_gas(
            from_addr,
            to_addr,
            data,
            self.config.eth_chain_id,
            block.header,
            true,
            gas,
            gas_price,
            value,
        )
    }

    pub fn get_chain_id(&self) -> u64 {
        self.config.eth_chain_id // using eth as a universal ID for now
    }

    pub fn get_chain_tip(&self) -> u64 {
        self.consensus.get_chain_tip()
    }

    pub fn get_account(&self, address: Address, block_number: BlockNumber) -> Result<Account> {
        self.consensus
            .try_get_state_at(self.get_view(block_number))?
            .get_account(address)
    }

    pub fn get_account_storage(
        &self,
        address: Address,
        index: H256,
        block_number: BlockNumber,
    ) -> Result<H256> {
        self.consensus
            .try_get_state_at(self.get_view(block_number))?
            .get_account_storage(address, index)
    }

    pub fn get_native_balance(&self, address: Address, block_number: BlockNumber) -> Result<U256> {
        self.consensus
            .try_get_state_at(self.get_view(block_number))?
            .get_native_balance(address, false)
    }

    pub fn get_latest_block(&self) -> Result<Option<Block>> {
        self.get_block_by_view(self.get_chain_tip())
    }

    pub fn get_block_by_number(&self, block_number: BlockNumber) -> Result<Option<Block>> {
        self.get_block_by_view(self.get_view(block_number))
    }

    pub fn get_finalized_height(&self) -> u64 {
        self.consensus.finalized_view()
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        self.consensus.get_block_by_view(view)
    }

    pub fn get_block_by_hash(&self, hash: Hash) -> Result<Option<Block>> {
        self.consensus.get_block(&hash)
    }

    pub fn get_block_hash_from_transaction(&self, tx_hash: Hash) -> Result<Option<Hash>> {
        self.consensus.get_block_hash_from_transaction(&tx_hash)
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: Hash,
    ) -> Result<Option<Vec<TransactionReceipt>>> {
        self.consensus.get_transaction_receipts_in_block(block_hash)
    }

    pub fn get_transaction_receipt(&self, tx_hash: Hash) -> Result<Option<TransactionReceipt>> {
        self.consensus.get_transaction_receipt(&tx_hash)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<SignedTransaction>> {
        self.consensus.get_transaction_by_hash(hash)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.consensus.get_touched_transactions(address)
    }

    fn handle_block_request(&mut self, source: PeerId, request: BlockRequest) -> Result<()> {
        let block = match request.0 {
            crate::message::BlockRef::Hash(hash) => self.consensus.get_block(&hash),
            crate::message::BlockRef::View(view) => self.consensus.get_block_by_view(view),
        }?;
        let Some(block) = block else {
            debug!("ignoring block request for unknown block: {:?}", request.0);
            return Ok(());
        };

        self.message_sender.send_external_message(
            source,
            ExternalMessage::BlockResponse(BlockResponse { block }),
        )?;

        Ok(())
    }

    fn handle_block_response(&mut self, _: PeerId, response: BlockResponse) -> Result<()> {
        self.consensus.receive_block(response.block)?;

        Ok(())
    }
}
