use std::sync::Arc;

use anyhow::{anyhow, Result};
use evm_ds::protos::evm_proto::{self as EvmProto};
use libp2p::PeerId;
use primitive_types::{H256, U256};
use scilla::scilla_server_run::reconstruct_kv_pairs;
use tokio::sync::mpsc::UnboundedSender;
use tracing::*;

use crate::{
    cfg::NodeConfig,
    consensus::Consensus,
    crypto::{Hash, NodePublicKey, SecretKey},
    db::Db,
    evm_backend::EvmBackend,
    message::{
        Block, BlockBatchRequest, BlockBatchResponse, BlockNumber, BlockRequest, BlockResponse,
        ExternalMessage, InternalMessage, IntershardCall, Proposal,
    },
    p2p_node::{LocalMessageTuple, OutboundMessageTuple},
    state::{Account, Address},
    transaction::{SignedTransaction, TransactionReceipt, TxIntershard, VerifiedTransaction},
};

#[derive(Debug, Clone)]
pub struct MessageSender {
    our_shard: u64,
    our_peer_id: PeerId,
    outbound_channel: UnboundedSender<OutboundMessageTuple>,
    local_channel: UnboundedSender<LocalMessageTuple>,
}

impl MessageSender {
    /// Send message to the p2p/coordinator thread
    pub fn send_message_to_coordinator(&self, message: InternalMessage) -> Result<()> {
        self.local_channel
            .send((self.our_shard, self.our_shard, message))?;
        Ok(())
    }

    /// Send a message to a locally running shard node
    pub fn send_message_to_shard(
        &self,
        destination_shard: u64,
        message: InternalMessage,
    ) -> Result<()> {
        self.local_channel
            .send((self.our_shard, destination_shard, message))?;
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
            .send((Some(peer), self.our_shard, message))?;
        Ok(())
    }

    /// Broadcast to the entire network of this shard
    pub fn broadcast_external_message(&self, message: ExternalMessage) -> Result<()> {
        self.outbound_channel
            .send((None, self.our_shard, message))?;
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
    pub db: Arc<Db>,
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
        local_sender_channel: UnboundedSender<LocalMessageTuple>,
        reset_timeout: UnboundedSender<()>,
    ) -> Result<Node> {
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let message_sender = MessageSender {
            our_shard: config.eth_chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
            local_channel: local_sender_channel,
        };
        let db = Arc::new(Db::new(config.data_dir.as_ref(), config.eth_chain_id)?);
        let node = Node {
            config: config.clone(),
            peer_id,
            message_sender: message_sender.clone(),
            reset_timeout,
            db: db.clone(),
            consensus: Consensus::new(secret_key, config, message_sender, db)?,
        };
        Ok(node)
    }

    // TODO: Multithreading - `&mut self` -> `&self`
    pub fn handle_network_message(&mut self, from: PeerId, message: ExternalMessage) -> Result<()> {
        let to = self.peer_id;
        let to_self = from == to;
        let message_name = message.name();
        tracing::debug!(%from, %to, %message_name, "handling message");
        match message {
            ExternalMessage::Proposal(m) => {
                let m_view = m.header.view;

                if let Some((leader, vote)) = self.consensus.proposal(m, false)? {
                    self.reset_timeout.send(())?;
                    self.message_sender
                        .send_external_message(leader, ExternalMessage::Vote(vote))?;
                } else {
                    info!("We had nothing to respond to proposal, lets try to join committee for view {m_view:}");
                    self.message_sender.send_external_message(
                        from,
                        ExternalMessage::JoinCommittee(self.consensus.public_key()),
                    )?;
                }
            }
            ExternalMessage::Vote(m) => {
                if let Some((block, transactions)) = self.consensus.vote(m)? {
                    self.message_sender
                        .broadcast_external_message(ExternalMessage::Proposal(
                            Proposal::from_parts(block, transactions),
                        ))?;
                }
            }
            ExternalMessage::NewView(m) => {
                if let Some(block) = self.consensus.new_view(from, *m)? {
                    self.message_sender
                        .broadcast_external_message(ExternalMessage::Proposal(
                            Proposal::from_parts(block, vec![]),
                        ))?;
                }
            }
            ExternalMessage::BlockRequest(m) => {
                if !to_self {
                    self.handle_block_request(from, m)?;
                } else {
                    debug!("ignoring block request to self");
                }
            }
            ExternalMessage::BlockResponse(m) => {
                if !to_self {
                    self.handle_block_response(from, m)?;
                } else {
                    debug!("ignoring block response to self");
                }
            }
            ExternalMessage::BlockBatchRequest(m) => {
                if !to_self {
                    self.handle_block_batch_request(from, m)?;
                } else {
                    debug!("ignoring blocks request to self");
                }
            }
            ExternalMessage::BlockBatchResponse(m) => {
                if !to_self {
                    self.handle_blocks_response(from, m)?;
                } else {
                    debug!("ignoring blocks response to self");
                }
            }
            ExternalMessage::RequestResponse => {}
            ExternalMessage::NewTransaction(t) => {
                self.consensus.new_transaction(t.verify()?)?;
            }
            ExternalMessage::JoinCommittee(public_key) => {
                self.add_peer(from, public_key)?;
            }
        }

        Ok(())
    }

    pub fn handle_internal_message(&mut self, from: u64, message: InternalMessage) -> Result<()> {
        let to = self.config.eth_chain_id;
        let message_name = message.name();
        tracing::debug!(%from, %to, %message_name, "handling message");
        match message {
            InternalMessage::IntershardCall(intershard_call) => {
                self.inject_intershard_transaction(intershard_call)?
            }
            InternalMessage::LaunchShard(_) => {
                warn!("LaunchShard messages should be handled by the coordinator, not forwarded to a node.");
            }
        }
        Ok(())
    }

    fn inject_intershard_transaction(&mut self, intershard_call: IntershardCall) -> Result<()> {
        let tx = SignedTransaction::Intershard {
            tx: TxIntershard {
                chain_id: self.config.eth_chain_id,
                nonce: intershard_call.nonce,
                gas_price: intershard_call.gas_price,
                gas_limit: intershard_call.gas_limit,
                to_addr: intershard_call.target_address,
                payload: intershard_call.calldata,
            },
            from: intershard_call.source_address,
        };
        self.consensus.new_transaction(tx.verify()?)?;
        Ok(())
    }

    // handle timeout - true if something happened
    pub fn handle_timeout(&mut self) -> Result<bool> {
        if let Some((leader, response)) = self.consensus.timeout()? {
            self.message_sender
                .send_external_message(leader, response)
                .unwrap();
            return Ok(true);
        }
        Ok(false)
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
        let hash = txn.calculate_hash();

        info!(?hash, "seen new txn {:?}", txn);

        if self.consensus.new_transaction(txn.clone().verify()?)? {
            self.message_sender
                .broadcast_external_message(ExternalMessage::NewTransaction(txn))?;
        }

        Ok(hash)
    }

    pub fn number(&self) -> u64 {
        self.consensus.head_block().header.number
    }

    // todo: this doesn't respect two-chain finalization
    pub fn get_number(&self, block_number: BlockNumber) -> u64 {
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
        amount: U256,
        tracing: bool,
    ) -> Result<EvmProto::EvmResult> {
        let block = self
            .get_block_by_number(self.get_number(block_number))?
            .ok_or_else(|| anyhow!("block not found"))?;

        trace!("call_contract: block={:?}", block);

        let state = self
            .consensus
            .state()
            .at_root(H256(block.state_root_hash().0));

        state.call_contract(
            from_addr,
            to_addr,
            data,
            amount,
            self.config.eth_chain_id,
            block.header,
            true,
            tracing,
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
            .get_block_by_number(self.get_number(block_number))?
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
        self.consensus.head_block().header.number
    }

    pub fn get_account(&self, address: Address, block_number: BlockNumber) -> Result<Account> {
        self.consensus
            .try_get_state_at(self.get_number(block_number))?
            .get_account(address)
    }

    pub fn get_account_storage(
        &self,
        address: Address,
        index: H256,
        block_number: BlockNumber,
    ) -> Result<H256> {
        self.consensus
            .try_get_state_at(self.get_number(block_number))?
            .get_account_storage(address, index)
    }

    pub fn get_scilla_kv_pairs(
        &self,
        address: Address,
        block_number: BlockNumber,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let block_header = self
            .get_block_by_blocknum(block_number)
            .unwrap()
            .unwrap()
            .header;
        let backend = EvmBackend::new(
            self.consensus.state(),
            U256::zero(),
            address,
            0,
            block_header,
        );
        Ok(reconstruct_kv_pairs(&backend, address))
    }

    pub fn get_native_balance(&self, address: Address, block_number: BlockNumber) -> Result<U256> {
        self.consensus
            .try_get_state_at(self.get_number(block_number))?
            .get_native_balance(address, false)
    }

    pub fn get_latest_block(&self) -> Result<Option<Block>> {
        self.get_block_by_number(self.get_chain_tip())
    }

    pub fn get_block_by_blocknum(&self, block_number: BlockNumber) -> Result<Option<Block>> {
        let block_number = self.get_number(block_number);
        self.consensus.get_block_by_number(block_number)
    }

    pub fn get_block_by_number(&self, block_number: u64) -> Result<Option<Block>> {
        self.consensus.get_block_by_number(block_number)
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: Hash,
    ) -> Result<Vec<TransactionReceipt>> {
        Ok(self
            .db
            .get_transaction_receipts(&block_hash)?
            .unwrap_or_default())
    }

    pub fn get_finalized_height(&self) -> u64 {
        self.consensus.finalized_view()
    }

    pub fn get_genesis_hash(&self) -> Result<Hash> {
        Ok(self
            .consensus
            .get_block_by_number(0)
            .unwrap()
            .unwrap()
            .hash())
    }

    pub fn get_block_by_view(&self, view: u64) -> Result<Option<Block>> {
        self.consensus.get_block_by_view(view)
    }

    pub fn get_block_by_hash(&self, hash: Hash) -> Result<Option<Block>> {
        self.consensus.get_block(&hash)
    }

    pub fn get_transaction_receipt(&self, tx_hash: Hash) -> Result<Option<TransactionReceipt>> {
        self.consensus.get_transaction_receipt(&tx_hash)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<VerifiedTransaction>> {
        self.consensus.get_transaction_by_hash(hash)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.consensus.get_touched_transactions(address)
    }

    fn handle_block_request(&mut self, source: PeerId, request: BlockRequest) -> Result<()> {
        let block = match request.0 {
            crate::message::BlockRef::Hash(hash) => self.consensus.get_block(&hash),
            crate::message::BlockRef::View(view) => self.consensus.get_block_by_view(view), // todo: consider removing
            crate::message::BlockRef::Number(number) => self.consensus.get_block_by_number(number),
        }?;
        let Some(block) = block else {
            debug!("ignoring block request for unknown block: {:?}", request.0);
            return Ok(());
        };

        self.message_sender.send_external_message(
            source,
            ExternalMessage::BlockResponse(BlockResponse {
                proposal: self.block_to_proposal(block),
            }),
        )?;

        Ok(())
    }

    fn handle_block_response(&mut self, _: PeerId, response: BlockResponse) -> Result<()> {
        let _ = self.consensus.receive_block(response.proposal)?;

        Ok(())
    }

    // Convenience function to convert a block to a proposal (add full txs)
    fn block_to_proposal(&self, block: Block) -> Proposal {
        let txs: Vec<SignedTransaction> = block
            .transactions
            .iter()
            .map(|tx_hash| {
                self.consensus
                    .get_transaction_by_hash(*tx_hash)
                    .unwrap()
                    .unwrap()
                    .tx
            })
            .collect::<Vec<_>>();

        Proposal::from_parts(block, txs)
    }

    fn handle_block_batch_request(
        &mut self,
        source: PeerId,
        request: BlockBatchRequest,
    ) -> Result<()> {
        let block = match request.0 {
            crate::message::BlockRef::Hash(hash) => self.consensus.get_block(&hash),
            crate::message::BlockRef::View(view) => self.consensus.get_block_by_view(view),
            crate::message::BlockRef::Number(number) => self.consensus.get_block_by_number(number),
        }?;

        let block = match block {
            Some(block) => block,
            None => {
                debug!("ignoring blocks request for unknown block: {:?}", request.0);
                return Ok(());
            }
        };

        let mut proposal = self.block_to_proposal(block);
        let block_number = proposal.header.number;
        let mut proposals: Vec<Proposal> = Vec::new();

        for i in block_number..block_number + 100 {
            let block = self.consensus.get_block_by_number(i);
            if let Ok(Some(block)) = block {
                proposal = self.block_to_proposal(block);
                proposals.push(proposal);
            } else {
                break;
            }
        }

        trace!(
            "Responding to new blocks request of {:?} starting {} with {} blocks",
            request,
            block_number,
            proposals.len()
        );

        self.message_sender.send_external_message(
            source,
            ExternalMessage::BlockBatchResponse(BlockBatchResponse { proposals }),
        )?;

        Ok(())
    }

    fn handle_blocks_response(&mut self, _: PeerId, response: BlockBatchResponse) -> Result<()> {
        trace!(
            "Received blocks response of length {}",
            response.proposals.len()
        );
        let mut was_new = false;
        let length_recvd = response.proposals.len();

        for block in response.proposals {
            was_new = self.consensus.receive_block(block)?;
        }

        if was_new && length_recvd > 1 {
            trace!(
                "Requesting additional blocks after successful block download. Start: {}",
                self.consensus.head_block().header.number
            );
            self.consensus.download_blocks_up_to_head()?;
        }

        Ok(())
    }
}
