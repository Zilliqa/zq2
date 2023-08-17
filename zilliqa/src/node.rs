use crate::{
    message::BlockNumber,
    state::{SignedTransaction, TransactionReceipt},
};
use primitive_types::H256;

use anyhow::{anyhow, Result};
use libp2p::PeerId;
use primitive_types::U256;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info};

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

        println!("Constructing new node with identity: {}", secret_key.node_public_key());
        println!("Constructing new node with peer id: {}", secret_key.to_libp2p_keypair().public().to_peer_id());

        let node = Node {
            config: config.clone(),
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
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
            Message::Proposal(m) => {
                if let Some((leader, vote)) = self.consensus.proposal(m)? {
                    self.reset_timeout.send(())?;
                    self.send_message(leader, Message::Vote(vote))?;
                }
            }
            Message::Vote(m) => {
                if let Some((block, transactions)) = self.consensus.vote(m)? {
                    self.broadcast_message(Message::Proposal(Proposal::from_parts(
                        block,
                        transactions,
                    )))?;
                }
            }
            Message::NewView(m) => {
                if let Some(block) = self.consensus.new_view(from, *m)? {
                    self.broadcast_message(Message::Proposal(Proposal::from_parts(block, vec![])))?;
                }
            }
            Message::BlockRequest(m) => {
                self.handle_block_request(from, m)?;
            }
            Message::BlockResponse(m) => {
                self.handle_block_response(from, m)?;
            }
            Message::RequestResponse => {}
            Message::NewTransaction(t) => {
                self.consensus.new_transaction(t)?;
            }
            Message::JoinCommittee(public_key) => {
                self.add_peer(from, public_key)?;
            }
        }

        Ok(())
    }

    pub fn handle_timeout(&mut self) -> Result<()> {
        if self.consensus.blockchain_active() {
            println!("No committee members, skipping timeout");
            return Ok(());
        } else {
            println!("some committee members, allowing timeout {:?}", self.consensus.committee());
        }

        let (leader, new_view) = self.consensus.timeout()?;

        self.send_message(leader, Message::NewView(Box::new(new_view)))?;

        let (leader, new_view) = self.consensus.timeout()?;

        self.send_message(leader, Message::NewView(Box::new(new_view)))?;

        Ok(())
    }

    pub fn add_peer(&mut self, peer: PeerId, public_key: NodePublicKey) -> Result<()> {
        if let Some((dest, message)) = self.consensus.add_peer(peer, public_key)? {
            self.reset_timeout.send(())?;
            if let Some(dest) = dest {
                self.send_message(dest, message)?;
            } else {
                self.broadcast_message(message)?;
            }
        }

        Ok(())
    }

    pub fn create_transaction(&mut self, txn: SignedTransaction) -> Result<Hash> {
        let hash = txn.hash();

        info!(?hash, "seen new txn");

        txn.verify()?;

        // Make sure TX hasn't been seen before
        if !self.consensus.seen_tx_already(&hash)? {
            self.broadcast_message(Message::NewTransaction(txn))?;
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
        // TODO: optimise this to get header directly once persistance is merged
        // (which will provide a header index)
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
        )
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
            .get_native_balance(address)
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

    pub fn get_transaction_receipt(&self, hash: Hash) -> Result<Option<TransactionReceipt>> {
        self.consensus.get_transaction_receipt(hash)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<SignedTransaction>> {
        self.consensus.get_transaction_by_hash(hash)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.consensus.get_touched_transactions(address)
    }

    fn send_message(&mut self, peer: PeerId, message: Message) -> Result<()> {
        tracing::debug!(
            "sending {} from {} to {}",
            message.name(),
            self.peer_id,
            peer
        );
        self.message_sender.send((Some(peer), message))?;
        Ok(())
    }

    fn broadcast_message(&mut self, message: Message) -> Result<()> {
        self.message_sender.send((None, message))?;
        Ok(())
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

        self.send_message(source, Message::BlockResponse(BlockResponse { block }))?;

        Ok(())
    }

    fn handle_block_response(&mut self, _: PeerId, response: BlockResponse) -> Result<()> {
        self.consensus.receive_block(response.block)?;

        Ok(())
    }
}
