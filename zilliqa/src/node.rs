use std::{
    fmt::Debug,
    sync::{Arc, atomic::AtomicUsize},
    time::{Duration, Instant},
};

use alloy::{
    eips::{BlockId, BlockNumberOrTag, RpcBlockHash},
    primitives::Address,
    rpc::types::{
        TransactionInfo,
        trace::{
            geth::{
                FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType,
                GethDebugTracingOptions, GethTrace, NoopFrame, TraceResult,
            },
            parity::{TraceResults, TraceType},
        },
    },
};
use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use itertools::Itertools;
use libp2p::{PeerId, request_response::OutboundFailure};
use parking_lot::RwLock;
use rand::RngCore;
use revm::context_interface::{result::ExecutionResult, transaction::AccessList};
use revm_context::TxEnv;
use revm_inspector::Inspector;
use revm_inspectors::tracing::{
    FourByteInspector, MuxInspector, TracingInspector, TracingInspectorConfig, TransactionContext,
    js::JsInspector,
};
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tracing::*;

use crate::{
    api::types::filters::Filters,
    cfg::{ForkName, NodeConfig},
    consensus::Consensus,
    crypto::{Hash, SecretKey},
    db::{BlockFilter, Db},
    evm::ZQ2EvmContext,
    exec::{ExtraOpts, PendingState, TransactionApplyResult},
    inspector::{self, ScillaInspector},
    message::{
        Block, BlockHeader, BlockTransactionsReceipts, ExternalMessage, InjectedProposal,
        InternalMessage, IntershardCall, Proposal,
    },
    node_launcher::ResponseChannel,
    p2p_node::{LocalMessageTuple, OutboundMessageTuple},
    pool::TxAddResult,
    state::State,
    sync::SyncPeers,
    transaction::{
        EvmGas, SignedTransaction, TransactionReceipt, TxIntershard, VerifiedTransaction,
    },
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct RequestId(u64);

impl RequestId {
    pub fn random() -> Self {
        Self(rand::thread_rng().next_u64())
    }
}

#[derive(Debug)]
pub struct OutgoingMessageFailure {
    pub peer: PeerId,
    pub request_id: RequestId,
    pub error: OutboundFailure,
}

#[derive(Debug, Clone)]
pub struct MessageSender {
    pub our_shard: u64,
    pub our_peer_id: PeerId,
    pub outbound_channel: UnboundedSender<OutboundMessageTuple>,
    pub local_channel: UnboundedSender<LocalMessageTuple>,
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

    pub fn next_request_id(&self) -> RequestId {
        RequestId::random()
    }

    /// Send a message to a remote node of the same shard.
    /// Note that if this ever fails for individual messages (rather than because the channel is closed),
    /// you will need to adjust consensus.rs to attempt to retain as much of multiple block responses
    /// as possible.
    pub fn send_external_message(
        &self,
        peer: PeerId,
        message: ExternalMessage,
    ) -> Result<RequestId> {
        debug!("sending {message} from {} to {}", self.our_peer_id, peer);
        let request_id = self.next_request_id();
        self.outbound_channel
            .send((Some((peer, request_id)), self.our_shard, message))?;
        Ok(request_id)
    }

    /// Broadcast to the entire network of this shard
    pub fn broadcast_external_message(&self, message: ExternalMessage) -> Result<()> {
        self.outbound_channel
            .send((None, self.our_shard, message))?;
        Ok(())
    }

    /// Broadcast to the entire network of this shard
    // This is a duplicate of [MessageSender::broadcast_external_message] but it allows for
    // a separate treatment for proposals, if desired for debugging or future purposes.
    pub fn broadcast_proposal(&self, message: ExternalMessage) -> Result<()> {
        self.outbound_channel
            .send((None, self.our_shard, message))?;
        Ok(())
    }
}

/// Messages sent by [Consensus].
/// Tuple of (destination, message).
pub type NetworkMessage = (Option<PeerId>, ExternalMessage);

/// The central data structure for a blockchain node.
///
/// # Transaction Lifecycle
/// 1. New transactions are created with a call to [`Node::new_transaction()`].
///    The node gossips the transaction to the network and itself via a [`Message::NewTransaction`] message.
///    This initial node also stores the transaction hash in `new_transactions`.
///
/// 1. When a node recieves a [`NewTransaction`] via [`Node::handle_message()`], it stores it in `new_transactions`.
///    This contains all transactions which have been receieved, but not yet executed.
///
/// 2. When the initial node is a leader of a block, it adds all transaction hashes in `new_transactions` to the block.
///
/// 3. When a node recieves a block proposal, it looks up the transactions in `new_transactions` and executes them against its `state`.
///    Successfully executed transactions are added to `transactions` so they can be returned via APIs.
#[derive(Debug)]
pub struct Node {
    pub config: NodeConfig,
    pub db: Arc<Db>,
    peer_id: PeerId,
    message_sender: MessageSender,
    /// Send responses to requests down this channel. The `ResponseChannel` passed must correspond to a
    /// `ResponseChannel` received via `handle_request`.
    request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    reset_timeout: UnboundedSender<Duration>,
    pub consensus: Arc<RwLock<Consensus>>,
    peer_num: Arc<AtomicUsize>,
    pub chain_id: ChainId,
    pub filters: Arc<Filters>,
    swarm_peers: Arc<ArcSwap<Vec<PeerId>>>,
}

#[derive(Debug, Copy, Clone)]
pub struct ChainId {
    pub eth: u64,
}

impl ChainId {
    pub fn new(eth_chain_id: u64) -> Self {
        ChainId { eth: eth_chain_id }
    }
    pub fn zil(&self) -> u64 {
        self.eth - 0x8000
    }
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        message_sender_channel: UnboundedSender<OutboundMessageTuple>,
        local_sender_channel: UnboundedSender<LocalMessageTuple>,
        request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
        reset_timeout: UnboundedSender<Duration>,
        peer_num: Arc<AtomicUsize>,
        sync_peers: Arc<SyncPeers>,
        swarm_peers: Arc<ArcSwap<Vec<PeerId>>>,
    ) -> Result<Node> {
        config.validate()?;
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let message_sender = MessageSender {
            our_shard: config.eth_chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
            local_channel: local_sender_channel,
        };
        let executable_blocks_height = config
            .consensus
            .get_forks()?
            .find_height_fork_first_activated(ForkName::ExecutableBlocks);
        let db = Arc::new(Db::new(
            config.data_dir.as_ref(),
            config.eth_chain_id,
            executable_blocks_height,
            config.db.clone(),
        )?);
        let node = Node {
            config: config.clone(),
            peer_id,
            message_sender: message_sender.clone(),
            request_responses,
            reset_timeout: reset_timeout.clone(),
            db: db.clone(),
            chain_id: ChainId::new(config.eth_chain_id),
            consensus: Arc::new(RwLock::new(Consensus::new(
                secret_key,
                config,
                message_sender,
                reset_timeout,
                db,
                sync_peers,
            )?)),
            peer_num,
            filters: Arc::new(Filters::new()),
            swarm_peers,
        };
        Ok(node)
    }

    pub fn handle_broadcast(
        &self,
        from: PeerId,
        message: ExternalMessage,
        response_channel: ResponseChannel,
    ) -> Result<()> {
        debug!(%from, to = %self.peer_id, %message, "handling broadcast");
        match message {
            // Repeated `NewView`s might get broadcast.
            ExternalMessage::NewView(m) => {
                if let Some(network_message) = self.consensus.write().new_view(from, *m)? {
                    self.handle_network_message_response(network_message)?;
                }
            }
            // RFC-161 sync algorithm, phase 2.
            ExternalMessage::MultiBlockRequest(request) => {
                let message = self
                    .consensus
                    .write()
                    .sync
                    .handle_multiblock_request(from, request)?;
                self.request_responses.send((response_channel, message))?;
            }
            ExternalMessage::PassiveSyncRequest(request) => {
                let message = self
                    .consensus
                    .write()
                    .sync
                    .handle_passive_request(from, request)?;
                self.request_responses.send((response_channel, message))?;
            }
            // RFC-161 sync algorithm, phase 1.
            ExternalMessage::MetaDataRequest(request) => {
                let message = self
                    .consensus
                    .write()
                    .sync
                    .handle_active_request(from, request)?;
                self.request_responses.send((response_channel, message))?;
            }
            // Respond to block probe requests.
            ExternalMessage::BlockRequest(request) => {
                // respond with an invalid response
                let message = self
                    .consensus
                    .write()
                    .sync
                    .handle_block_request(from, request)?;
                self.request_responses.send((response_channel, message))?;
            }
            // `Proposals` are re-routed to `handle_request()`
            msg => {
                warn!(%msg, "unexpected message type");
            }
        }
        Ok(())
    }

    pub fn handle_broadcast_transactions(
        &self,
        transactions: Vec<VerifiedTransaction>,
    ) -> Result<()> {
        let from_broadcast = true;
        self.consensus
            .write()
            .handle_new_transactions(transactions, from_broadcast)?;
        Ok(())
    }

    pub fn try_to_apply_transactions(&mut self) -> Result<()> {
        self.consensus.write().try_early_proposal_after_txn_batch()
    }

    pub fn handle_request(
        &self,
        from: PeerId,
        id: &str,
        message: ExternalMessage,
        response_channel: ResponseChannel,
    ) -> Result<()> {
        debug!(%from, to = %self.peer_id, %id, %message, "handling request");
        match message {
            ExternalMessage::Vote(m) => {
                // Acknowledge this vote.
                self.request_responses
                    .send((response_channel, ExternalMessage::Acknowledgement))?;

                let network_message = self.consensus.write().vote(from, *m)?;
                if let Some(network_message) = network_message {
                    self.handle_network_message_response(network_message)?;
                }
            }
            ExternalMessage::NewView(m) => {
                // Acknowledge this new view.
                self.request_responses
                    .send((response_channel, ExternalMessage::Acknowledgement))?;

                let network_message = self.consensus.write().new_view(from, *m)?;
                if let Some(network_message) = network_message {
                    self.handle_network_message_response(network_message)?;
                }
            }
            // Handle requests which contain a block proposal. Initially sent as a broadcast, it is re-routed into
            // a Request by the underlying layer, with a faux request-id. This is to mitigate issues when there are
            // too many transactions in the broadcast queue.
            ExternalMessage::Proposal(m) => {
                if from != self.peer_id {
                    self.handle_proposal(from, m)?;

                    // Acknowledge the proposal.
                    self.request_responses
                        .send((response_channel, ExternalMessage::Acknowledgement))?;
                } else {
                    debug!("Ignoring own Proposal broadcast")
                }
            }
            // This just breaks down group block messages into individual messages to stop them blocking threads
            // for long periods.
            ExternalMessage::InjectedProposal(p) => {
                self.handle_injected_proposal(from, p)?;
            }
            msg => {
                warn!(%msg, "unexpected message type");
            }
        }

        Ok(())
    }

    pub fn handle_request_failure(
        &self,
        to: PeerId,
        failure: OutgoingMessageFailure,
    ) -> Result<()> {
        debug!(from = %self.peer_id, %to, ?failure, "handling message failure");
        self.consensus
            .write()
            .sync
            .handle_request_failure(to, failure)?;
        Ok(())
    }

    pub fn handle_response(&self, from: PeerId, message: ExternalMessage) -> Result<()> {
        debug!(%from, to = %self.peer_id, %message, "handling response");
        match message {
            // 0.6.0
            ExternalMessage::MultiBlockResponse(response) => self
                .consensus
                .write()
                .sync
                .handle_multiblock_response(from, Some(response))?,
            // 0.7.0
            ExternalMessage::SyncBlockHeaders(response) => self
                .consensus
                .write()
                .sync
                .handle_active_response(from, Some(response))?,
            // 0.8.0 probe response
            ExternalMessage::BlockResponse(response) => self
                .consensus
                .write()
                .sync
                .handle_block_response(from, response)?,
            // 0.8.0 passive sync
            ExternalMessage::PassiveSyncResponse(response) => self
                .consensus
                .write()
                .sync
                .handle_passive_response(from, Some(response))?,
            ExternalMessage::PassiveSyncResponseLZ(response) => {
                // decompress the block
                let mut decoder = lz4::Decoder::new(std::io::Cursor::new(response))?;
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut decoder, &mut buf).unwrap();
                let response =
                    cbor4ii::serde::from_slice::<BlockTransactionsReceipts>(&buf).unwrap();
                self.consensus
                    .write()
                    .sync
                    .handle_passive_response(from, Some(vec![response]))?;
            }
            ExternalMessage::Acknowledgement => {} // do nothing
            msg => {
                warn!(%msg, "unexpected message type");
            }
        }

        Ok(())
    }

    pub fn handle_internal_message(&self, from: u64, message: InternalMessage) -> Result<()> {
        let to = self.chain_id.eth;
        tracing::debug!(%from, %to, %message, "handling message");
        match message {
            InternalMessage::IntershardCall(intershard_call) => {
                self.inject_intershard_transaction(intershard_call)?
            }
            InternalMessage::LaunchLink(source) => {
                self.message_sender
                    .send_message_to_coordinator(InternalMessage::LaunchShard(source))?;
            }
            _ => {
                warn!(
                    "{message} type messages should be handled by the coordinator, not forwarded to a node.",
                );
            }
        }
        Ok(())
    }

    fn inject_intershard_transaction(&self, intershard_call: IntershardCall) -> Result<()> {
        let tx = SignedTransaction::Intershard {
            tx: TxIntershard {
                chain_id: self.chain_id.eth,
                bridge_nonce: intershard_call.bridge_nonce,
                source_chain: intershard_call.source_chain_id,
                gas_price: intershard_call.gas_price,
                gas_limit: intershard_call.gas_limit,
                to_addr: intershard_call.target_address,
                payload: intershard_call.calldata,
            },
            from: intershard_call.source_address,
        };
        let verified_tx = tx.verify()?;
        trace!("Injecting intershard transaction {}", verified_tx.hash);

        self.consensus.write().new_transaction(verified_tx, true)?;
        Ok(())
    }

    fn broadcast_and_execute_proposal(&self, proposal: Proposal) -> Result<()> {
        self.message_sender
            .broadcast_proposal(ExternalMessage::Proposal(proposal.clone()))?;
        self.handle_proposal(self.peer_id, proposal)?;
        Ok(())
    }

    fn handle_network_message_response(&self, message: NetworkMessage) -> Result<()> {
        let (peer_id, response) = message;
        if let Some(peer_id) = peer_id {
            self.message_sender
                .send_external_message(peer_id, response)?;
        } else if let ExternalMessage::Proposal(new_proposal) = response {
            // Recursively process own Proposal
            self.broadcast_and_execute_proposal(new_proposal)?;
        } else {
            self.message_sender.broadcast_external_message(response)?;
        }
        Ok(())
    }

    // handle timeout - true if something happened
    pub fn handle_timeout(&self) -> Result<bool> {
        let network_message = self.consensus.write().timeout()?;

        if self.db.config.state_sync {
            let (_, remaining, _) = self.consensus.read().get_consensus_timeout_params()?;
            let period = Duration::from_millis(remaining) / 4; // steal < 250ms
            let now = Instant::now();
            while now.elapsed() < period {
                match self.consensus.write().migrate_state_trie() {
                    Ok(done) if done => break,
                    Err(e) => tracing::error!(err=%e, "State-sync failed"), // log and ignore errors
                    _ => {}
                };
            }
        }

        if let Some(network_message) = network_message {
            self.handle_network_message_response(network_message)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn create_transaction(&self, txn: VerifiedTransaction) -> Result<(Hash, TxAddResult)> {
        let hash = txn.hash;

        let from_broadcast = false;
        let result = self
            .consensus
            .read()
            .handle_new_transactions(vec![txn], from_broadcast)?;
        if !result[0].was_added() {
            debug!(?result, "Transaction cannot be added to mempool");
        }

        Ok((hash, result[0]))
    }

    pub fn process_transactions_to_broadcast(&self) -> Result<()> {
        let txns_to_broadcast = self
            .consensus
            .read()
            .transaction_pool
            .write()
            .pull_txns_to_broadcast()?;
        if txns_to_broadcast.is_empty() {
            return Ok(());
        }
        self.message_sender
            .broadcast_external_message(ExternalMessage::BatchedTransactions(txns_to_broadcast))
    }

    pub fn number(&self) -> u64 {
        self.consensus.read().head_block().header.number
    }

    pub fn resolve_block_number(&self, block_number: BlockNumberOrTag) -> Result<Option<Block>> {
        match block_number {
            BlockNumberOrTag::Number(n) => self.consensus.read().get_canonical_block_by_number(n),

            BlockNumberOrTag::Earliest => self.consensus.read().get_canonical_block_by_number(0),
            BlockNumberOrTag::Latest => Ok(Some(self.consensus.read().head_block())),
            BlockNumberOrTag::Pending => self.consensus.read().get_pending_block(),
            BlockNumberOrTag::Finalized => {
                let Some(view) = self.db.get_finalized_view()? else {
                    return self.resolve_block_number(BlockNumberOrTag::Earliest);
                };
                let Some(block) = self.db.get_block(BlockFilter::View(view))? else {
                    return self.resolve_block_number(BlockNumberOrTag::Earliest);
                };
                Ok(Some(block))
            }
            // Safe block tag in our consensus refers to the block that the node's highQC points to
            // (high_qc means it's the latest = high, and it's a QC where 2/3 validators voted for it).
            BlockNumberOrTag::Safe => {
                let block_hash = self.consensus.read().high_qc.block_hash;

                let Some(safe_block) = self.db.get_block(block_hash.into())? else {
                    return self.resolve_block_number(BlockNumberOrTag::Earliest);
                };
                Ok(Some(safe_block))
            }
        }
    }

    pub fn get_finalized_block(&self) -> Result<Option<Block>> {
        self.resolve_block_number(BlockNumberOrTag::Finalized)
    }

    pub fn get_finalized_block_number(&self) -> Result<u64> {
        match self.resolve_block_number(BlockNumberOrTag::Finalized)? {
            Some(block) => Ok(block.number()),
            None => Ok(0),
        }
    }

    pub fn get_block(&self, block_id: impl Into<BlockId>) -> Result<Option<Block>> {
        match block_id.into() {
            BlockId::Hash(RpcBlockHash {
                block_hash,
                require_canonical,
            }) => {
                // See https://eips.ethereum.org/EIPS/eip-1898
                let Some(block) = self.consensus.read().get_block(&block_hash.into())? else {
                    return Ok(None);
                };
                // Get latest finalized block number
                let finalized_block = self
                    .resolve_block_number(BlockNumberOrTag::Finalized)?
                    .ok_or_else(|| anyhow!("Unable to retrieve finalized block!"))?;
                let require_canonical = require_canonical.unwrap_or(false);

                // If the caller requests canonical block then it must be finalized
                if require_canonical && block.number() > finalized_block.number() {
                    return Ok(None);
                }

                Ok(Some(block))
            }
            BlockId::Number(number) => self.resolve_block_number(number),
        }
    }

    pub fn get_state(&self, block: &Block) -> Result<State> {
        Ok(self
            .consensus
            .read()
            .state()
            .at_root(block.state_root_hash().into()))
    }

    pub fn trace_evm_transaction(
        node: &Arc<Node>,
        txn_hash: Hash,
        trace_types: &revm::primitives::HashSet<TraceType>,
    ) -> Result<TraceResults> {
        let txn = node
            .get_transaction_by_hash(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;
        let receipt = node
            .get_transaction_receipt(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not mined: {txn_hash}"))?;

        let block = node
            .get_block(receipt.block_hash)?
            .ok_or_else(|| anyhow!("missing block: {}", receipt.block_hash))?;
        let parent = node
            .get_block(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block: {}", block.parent_hash()))?;

        let mut state = node
            .consensus
            .read()
            .state()
            .at_root(parent.state_root_hash().into());
        if state.is_empty() {
            return Err(anyhow!("State required to execute request does not exist"));
        }

        let fork = state.forks.get(block.number()).clone();

        for other_txn_hash in block.transactions {
            if txn_hash != other_txn_hash {
                let other_txn = node
                    .get_transaction_by_hash(other_txn_hash)?
                    .ok_or_else(|| anyhow!("transaction not found: {other_txn_hash}"))?;
                state.apply_transaction(other_txn, block.header, inspector::noop(), false)?;
            } else {
                let config = TracingInspectorConfig::from_parity_config(trace_types);
                let mut inspector = TracingInspector::new(config);
                let pending_state = PendingState::new(state.try_clone()?, fork.clone());

                let result = state.apply_transaction(txn, block.header, &mut inspector, true)?;

                let TransactionApplyResult::Evm(result, ..) = result else {
                    return Err(anyhow!("not an EVM transaction"));
                };

                let builder = inspector.into_parity_builder();
                let trace =
                    builder.into_trace_results_with_state(&result, trace_types, &pending_state)?;

                return Ok(trace);
            }
        }

        Err(anyhow!("transaction not found in block: {txn_hash}"))
    }

    pub fn replay_transaction<I: Inspector<ZQ2EvmContext> + ScillaInspector>(
        node: &Arc<Node>,
        txn_hash: Hash,
        inspector: I,
    ) -> Result<TransactionApplyResult> {
        let txn = node
            .get_transaction_by_hash(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;
        let receipt = node
            .get_transaction_receipt(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not mined: {txn_hash}"))?;

        let block = node
            .get_block(receipt.block_hash)?
            .ok_or_else(|| anyhow!("missing block: {}", receipt.block_hash))?;
        let parent = node
            .get_block(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block: {}", block.parent_hash()))?;

        let mut state = node
            .consensus
            .read()
            .state()
            .at_root(parent.state_root_hash().into());
        if state.is_empty() {
            return Err(anyhow!("State required to execute request does not exist"));
        }

        for other_txn_hash in block.transactions {
            if txn_hash != other_txn_hash {
                let other_txn = node
                    .get_transaction_by_hash(other_txn_hash)?
                    .ok_or_else(|| anyhow!("transaction not found: {other_txn_hash}"))?;
                state.apply_transaction(other_txn, parent.header, inspector::noop(), false)?;
            } else {
                let result = state.apply_transaction(txn, block.header, inspector, true)?;

                return Ok(result);
            }
        }

        Err(anyhow!("transaction not found in block: {txn_hash}"))
    }

    pub fn debug_trace_block(
        &self,
        block_number: BlockNumberOrTag,
        trace_opts: GethDebugTracingOptions,
    ) -> Result<Vec<TraceResult>> {
        let block = self
            .get_block(block_number)?
            .ok_or_else(|| anyhow!("missing block: {block_number}"))?;
        let parent = self
            .get_block(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block: {}", block.parent_hash()))?;
        let mut state = self
            .consensus
            .read()
            .state()
            .at_root(parent.state_root_hash().into());
        if state.is_empty() {
            return Err(anyhow!("State required to execute request does not exist"));
        }

        let mut traces: Vec<TraceResult> = Vec::new();

        for (index, &txn_hash) in block.transactions.iter().enumerate() {
            if let Ok(Some(trace)) = self.debug_trace_transaction(
                &mut state,
                txn_hash,
                index,
                &block,
                trace_opts.clone(),
            ) {
                traces.push(trace);
            }
        }

        Ok(traces)
    }

    pub fn debug_trace_transaction(
        &self,
        state: &mut State,
        txn_hash: Hash,
        txn_index: usize,
        block: &Block,
        trace_opts: GethDebugTracingOptions,
    ) -> Result<Option<TraceResult>> {
        let GethDebugTracingOptions {
            config,
            tracer,
            tracer_config,
            ..
        } = trace_opts;

        let txn = self
            .get_transaction_by_hash(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;

        let Some(tracer) = tracer else {
            let inspector_config = TracingInspectorConfig::from_geth_config(&config);
            let mut inspector = TracingInspector::new(inspector_config);

            let result = state.apply_transaction(txn, block.header, &mut inspector, true)?;

            let TransactionApplyResult::Evm(result, ..) = result else {
                return Ok(None);
            };

            let builder = inspector.into_geth_builder();
            let trace = builder.geth_traces(
                result.result.gas_used(),
                result.result.into_output().unwrap_or_default(),
                config,
            );
            return Ok(Some(TraceResult::Success {
                result: trace.into(),
                tx_hash: Some(txn_hash.0.into()),
            }));
        };

        let fork = state.forks.get(block.number()).clone();

        match tracer {
            GethDebugTracerType::BuiltInTracer(tracer) => match tracer {
                GethDebugBuiltInTracerType::Erc7562Tracer => todo!("Implement ERC7562 tracer"),
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config.into_call_config()?;
                    let mut inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_call_config(&call_config),
                    );

                    let result =
                        state.apply_transaction(txn, block.header, &mut inspector, true)?;

                    let TransactionApplyResult::Evm(result, ..) = result else {
                        return Ok(None);
                    };

                    let trace = inspector
                        .into_geth_builder()
                        .geth_call_traces(call_config, result.result.gas_used());

                    Ok(Some(TraceResult::Success {
                        result: trace.into(),
                        tx_hash: Some(txn_hash.0.into()),
                    }))
                }
                GethDebugBuiltInTracerType::FlatCallTracer => {
                    Err(anyhow!("`flatCallTracer` is not implemented"))
                }
                GethDebugBuiltInTracerType::FourByteTracer => {
                    let mut inspector = FourByteInspector::default();
                    let result =
                        state.apply_transaction(txn, block.header, &mut inspector, true)?;

                    let TransactionApplyResult::Evm(_) = result else {
                        return Ok(None);
                    };

                    Ok(Some(TraceResult::Success {
                        result: FourByteFrame::from(&inspector).into(),
                        tx_hash: Some(txn_hash.0.into()),
                    }))
                }
                GethDebugBuiltInTracerType::MuxTracer => {
                    let mux_config = tracer_config.into_mux_config()?;

                    let mut inspector = MuxInspector::try_from_config(mux_config)?;
                    let result =
                        state.apply_transaction(txn, block.header, &mut inspector, true)?;

                    let TransactionApplyResult::Evm(result, ..) = result else {
                        return Ok(None);
                    };
                    let pending_state = PendingState::new(state.try_clone()?, fork);
                    let state_ref = &pending_state;
                    let tx_info = TransactionInfo {
                        hash: Some(txn_hash.into()),
                        index: Some(txn_index as u64),
                        block_hash: Some(block.hash().into()),
                        block_number: Some(block.number()),
                        base_fee: state.gas_price.try_into().ok(),
                    };
                    let trace = inspector.try_into_mux_frame(&result, &state_ref, tx_info)?;
                    Ok(Some(TraceResult::Success {
                        result: trace.into(),
                        tx_hash: Some(txn_hash.0.into()),
                    }))
                }
                GethDebugBuiltInTracerType::NoopTracer => Ok(Some(TraceResult::Success {
                    result: NoopFrame::default().into(),
                    tx_hash: Some(txn_hash.0.into()),
                })),
                GethDebugBuiltInTracerType::PreStateTracer => {
                    let prestate_config = tracer_config.into_pre_state_config()?;

                    let mut inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_prestate_config(&prestate_config),
                    );
                    let result =
                        state.apply_transaction(txn, block.header, &mut inspector, true)?;

                    let TransactionApplyResult::Evm(result, ..) = result else {
                        return Ok(None);
                    };
                    let pending_state = PendingState::new(state.try_clone()?, fork);
                    let state_ref = &pending_state;
                    let trace = inspector.into_geth_builder().geth_prestate_traces(
                        &result,
                        &prestate_config,
                        state_ref,
                    )?;

                    Ok(Some(TraceResult::Success {
                        result: trace.into(),
                        tx_hash: Some(txn_hash.0.into()),
                    }))
                }
            },
            GethDebugTracerType::JsTracer(js_code) => {
                let config = tracer_config.into_json();

                let transaction_context = TransactionContext {
                    block_hash: Some(block.hash().0.into()),
                    tx_hash: Some(txn_hash.0.into()),
                    tx_index: txn_index.into(),
                };
                let mut inspector =
                    JsInspector::with_transaction_context(js_code, config, transaction_context)
                        .map_err(|e| anyhow!("Unable to create js inspector: {e}"))?;

                let result =
                    state.apply_transaction(txn.clone(), block.header, &mut inspector, true)?;

                let TransactionApplyResult::Evm(result) = result else {
                    return Ok(None);
                };

                let Ok(revm_txn) = TxEnv::try_from(txn) else {
                    return Ok(None);
                };

                let pending_state = PendingState::new(state.try_clone()?, fork);
                let result = inspector
                    .json_result(result, &revm_txn, &block, &pending_state)
                    .map_err(|e| anyhow!("Unable to create json result: {e}"))?;

                Ok(Some(TraceResult::Success {
                    result: GethTrace::JS(result),
                    tx_hash: Some(txn_hash.0.into()),
                }))
            }
        }
    }

    pub fn call_contract(
        &self,
        block: &Block,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: u128,
    ) -> Result<ExecutionResult> {
        trace!("call_contract: block={:?}", block);

        let state = self
            .consensus
            .read()
            .state()
            .at_root(block.state_root_hash().into());
        if state.is_empty() {
            return Err(anyhow!("State required to execute request does not exist"));
        }

        state.call_contract(from_addr, to_addr, data, amount, block.header)
    }

    pub fn get_proposer_reward_address(&self, header: BlockHeader) -> Result<Option<Address>> {
        // Return the zero address for the genesis block. There was no reward for it.
        if header.view == 0 {
            return Ok(None);
        }

        let parent = self
            .get_block(header.qc.block_hash)?
            .ok_or_else(|| anyhow!("missing parent: {}", header.qc.block_hash))?;

        let Some(proposer) = self.consensus.read().leader_at_block(&parent, header.view) else {
            return Ok(None);
        };

        self.consensus
            .read()
            .state()
            .get_reward_address(proposer.public_key)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.db.get_touched_transactions(address)
    }

    pub fn get_gas_price(&self) -> u128 {
        *self.config.consensus.gas_price
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &self,
        block_number: BlockNumberOrTag,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        gas: Option<EvmGas>,
        gas_price: Option<u128>,
        max_priority_fee_per_gas: Option<u128>,
        value: u128,
        access_list: Option<AccessList>,
        extra_opts: ExtraOpts,
    ) -> Result<u64> {
        let block = self
            .get_block(block_number)?
            .ok_or_else(|| anyhow!("missing block: {block_number}"))?;
        let state = self.get_state(&block)?;
        if state.is_empty() {
            return Err(anyhow!("State required to execute request does not exist"));
        }

        state.estimate_gas(
            from_addr,
            to_addr,
            data,
            block.header,
            gas,
            gas_price,
            max_priority_fee_per_gas,
            value,
            access_list,
            extra_opts,
        )
    }

    pub fn subscribe_to_new_blocks(&self) -> broadcast::Receiver<BlockHeader> {
        self.consensus.read().new_blocks.subscribe()
    }

    /// Returns a stream of pairs of (receipt, index of transaction in block)
    pub fn subscribe_to_receipts(&self) -> broadcast::Receiver<(TransactionReceipt, usize)> {
        self.consensus.read().new_receipts.subscribe()
    }

    pub fn subscribe_to_new_transactions(&self) -> broadcast::Receiver<VerifiedTransaction> {
        self.consensus.read().new_transactions.subscribe()
    }

    pub fn subscribe_to_new_transaction_hashes(&self) -> broadcast::Receiver<Hash> {
        self.consensus.read().new_transaction_hashes.subscribe()
    }

    pub fn get_chain_tip(&self) -> u64 {
        self.consensus.read().head_block().header.number
    }

    pub fn get_transaction_receipts_in_block(
        &self,
        block_hash: Hash,
    ) -> Result<Vec<TransactionReceipt>> {
        self.db.get_transaction_receipts_in_block(&block_hash)
    }

    pub fn get_finalized_height(&self) -> Result<u64> {
        self.consensus.read().get_finalized_view()
    }

    pub fn get_current_view(&self) -> Result<u64> {
        self.consensus.read().get_view()
    }

    pub fn get_transaction_receipt(&self, tx_hash: Hash) -> Result<Option<TransactionReceipt>> {
        self.consensus.read().get_transaction_receipt(&tx_hash)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<VerifiedTransaction>> {
        self.consensus.read().get_transaction_by_hash(hash)
    }

    pub fn txpool_content(&self) -> crate::pool::TxPoolContent {
        self.consensus.read().txpool_content()
    }

    pub fn txpool_content_from(&self, address: &Address) -> crate::pool::TxPoolContentFrom {
        self.consensus.read().txpool_content_from(address)
    }

    pub fn txpool_status(&self) -> crate::pool::TxPoolStatus {
        self.consensus.read().txpool_status()
    }

    pub fn get_peer_num(&self) -> usize {
        self.peer_num.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn handle_proposal(&self, from: PeerId, proposal: Proposal) -> Result<()> {
        let network_message = self
            .consensus
            .write()
            .proposal(from, proposal.clone(), false)?;
        if let Some(network_message) = network_message {
            self.reset_timeout
                .send(self.config.consensus.consensus_timeout)?;
            self.handle_network_message_response(network_message)?;
        }
        self.consensus.write().sync.sync_from_proposal(proposal)?;
        Ok(())
    }

    fn handle_injected_proposal(&self, from: PeerId, req: InjectedProposal) -> Result<()> {
        if from != self.consensus.read().peer_id() {
            warn!("Someone ({from}) sent me a InjectedProposal; illegal- ignoring");
            return Ok(());
        }
        let mut consensus = self.consensus.write();
        trace!("Handling proposal for view {0}", req.block.header.view);
        let block_number = req.block.number();
        let proposal = consensus.receive_block(from, req.block)?;
        // decrement after - if there are issues in receive_block() it will stop syncing;
        consensus.sync.mark_received_proposal(block_number)?;
        if let Some(proposal) = proposal {
            trace!(
                " ... broadcasting proposal for view {0}",
                proposal.header.view
            );
            self.message_sender
                .broadcast_proposal(ExternalMessage::Proposal(proposal))?;
        }
        Ok(())
    }

    pub fn get_peer_ids(&self) -> Result<(Vec<PeerId>, Vec<PeerId>)> {
        let sync_peers = self.consensus.read().sync.peer_ids();
        let swarm_peers = self.swarm_peers.load().iter().cloned().collect_vec();
        Ok((swarm_peers, sync_peers))
    }
}
