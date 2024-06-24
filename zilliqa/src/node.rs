use std::{collections::HashSet, sync::Arc, time::Duration};

use alloy_primitives::{Address, B256};
use alloy_rpc_types_trace::{
    geth::{
        FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
        GethTrace, NoopFrame, TraceResult,
    },
    parity::{TraceResults, TraceType},
};
use anyhow::{anyhow, Result};
use libp2p::PeerId;
use revm::Inspector;
use revm_inspectors::tracing::{
    js::{JsInspector, TransactionContext},
    FourByteInspector, MuxInspector, TracingInspector, TracingInspectorConfig,
};
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tracing::*;

use crate::{
    cfg::NodeConfig,
    consensus::Consensus,
    crypto::{Hash, SecretKey},
    db::Db,
    exec::TransactionApplyResult,
    inspector::{self, ScillaInspector},
    message::{
        Block, BlockBatchRequest, BlockBatchResponse, BlockHeader, BlockNumber, BlockRequest,
        BlockResponse, ExternalMessage, InternalMessage, IntershardCall, Proposal,
    },
    p2p_node::{LocalMessageTuple, OutboundMessageTuple},
    pool::TxPoolContent,
    state::{Account, State},
    transaction::{
        EvmGas, SignedTransaction, TransactionReceipt, TxIntershard, VerifiedTransaction,
    },
};

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

/// Messages sent by [Consensus].
/// Tuple of (destination, message).
pub type NetworkMessage = (Option<PeerId>, ExternalMessage);

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
    reset_timeout: UnboundedSender<Duration>,
    consensus: Consensus,
}

const DEFAULT_SLEEP_TIME_MS: Duration = Duration::from_millis(5000);

impl Node {
    pub fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        message_sender_channel: UnboundedSender<OutboundMessageTuple>,
        local_sender_channel: UnboundedSender<LocalMessageTuple>,
        reset_timeout: UnboundedSender<Duration>,
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
            reset_timeout: reset_timeout.clone(),
            db: db.clone(),
            consensus: Consensus::new(secret_key, config, message_sender, reset_timeout, db)?,
        };
        Ok(node)
    }

    // TODO: Multithreading - `&mut self` -> `&self`
    pub fn handle_network_message(&mut self, from: PeerId, message: ExternalMessage) -> Result<()> {
        let to = self.peer_id;
        let to_self = from == to;
        let message_name = message.name();
        debug!(%from, %to, %message_name, "handling message");
        match message {
            ExternalMessage::Proposal(m) => {
                if let Some((to, message)) = self.consensus.proposal(m, false)? {
                    self.reset_timeout.send(DEFAULT_SLEEP_TIME_MS)?;
                    if let Some(to) = to {
                        self.message_sender.send_external_message(to, message)?;
                    } else {
                        self.message_sender.broadcast_external_message(message)?;
                    }
                }
            }
            ExternalMessage::Vote(m) => {
                if let Some((block, transactions)) = self.consensus.vote(*m)? {
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
                let inserted = self.consensus.new_transaction(t.verify()?)?;
                if inserted {
                    if let Some((_, message)) = self.consensus.try_to_propose_new_block()? {
                        self.message_sender.broadcast_external_message(message)?;
                    }
                }
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
            InternalMessage::LaunchLink(source) => {
                self.message_sender
                    .send_message_to_coordinator(InternalMessage::LaunchShard(source))?;
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
        self.consensus.new_transaction(verified_tx)?;
        Ok(())
    }

    // handle timeout - true if something happened
    pub fn handle_timeout(&mut self) -> Result<bool> {
        if let Some((leader, response)) = self.consensus.timeout()? {
            if let Some(leader) = leader {
                self.message_sender
                    .send_external_message(leader, response)
                    .unwrap();
            } else {
                self.message_sender.broadcast_external_message(response)?;
            }
            return Ok(true);
        }
        Ok(false)
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

    pub fn get_number(&self, block_number: BlockNumber) -> u64 {
        match block_number {
            BlockNumber::Number(n) => n,
            BlockNumber::Earliest => 0,
            BlockNumber::Latest => self.get_chain_tip(),
            BlockNumber::Pending => self.get_chain_tip(), // use latest for now
            // Because block finality time is very low - we can assume that safe and finalized are almost the same
            BlockNumber::Finalized => {
                let Ok(Some(view)) = self.db.get_latest_finalized_view() else {
                    return 0u64;
                };
                let Ok(Some(block)) = self.db.get_block_by_view(&view) else {
                    return 0u64;
                };
                block.number()
            }
            // From whitepaper: If the proposed block’s view number
            // is one larger than its QC’s view number and
            // is larger or equal to the validator’s local
            // view number, the validator regards the
            // proposed block as safe (which is then referenced as head_block())
            BlockNumber::Safe => {
                let head_block = self.consensus.head_block();
                head_block.number()
            }
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn trace_evm_transaction(
        &self,
        txn_hash: Hash,
        trace_types: &HashSet<TraceType>,
    ) -> Result<TraceResults> {
        let txn = self
            .get_transaction_by_hash(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;
        let receipt = self
            .get_transaction_receipt(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not mined: {txn_hash}"))?;

        let block = self
            .get_block_by_hash(receipt.block_hash)?
            .ok_or_else(|| anyhow!("missing block: {}", receipt.block_hash))?;
        let parent = self
            .get_block_by_hash(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block: {}", block.parent_hash()))?;
        let mut state = self
            .consensus
            .state()
            .at_root(parent.state_root_hash().into());

        for other_txn_hash in block.transactions {
            if txn_hash != other_txn_hash {
                let other_txn = self
                    .get_transaction_by_hash(other_txn_hash)?
                    .ok_or_else(|| anyhow!("transaction not found: {other_txn_hash}"))?;
                state.apply_transaction(
                    other_txn,
                    self.get_chain_id(),
                    parent.header,
                    inspector::noop(),
                )?;
            } else {
                let config = TracingInspectorConfig::from_parity_config(trace_types);
                let mut inspector = TracingInspector::new(config);
                let pre_state = state.try_clone()?;

                let result = state.apply_transaction(
                    txn,
                    self.get_chain_id(),
                    parent.header,
                    &mut inspector,
                )?;

                let TransactionApplyResult::Evm(result, ..) = result else {
                    return Err(anyhow!("not an EVM transaction"));
                };

                let builder = inspector.into_parity_builder();
                let trace =
                    builder.into_trace_results_with_state(&result, trace_types, &pre_state)?;

                return Ok(trace);
            }
        }

        Err(anyhow!("transaction not found in block: {txn_hash}"))
    }

    pub fn replay_transaction<I: for<'s> Inspector<&'s State> + ScillaInspector>(
        &self,
        txn_hash: Hash,
        inspector: I,
    ) -> Result<TransactionApplyResult> {
        let txn = self
            .get_transaction_by_hash(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not found: {txn_hash}"))?;
        let receipt = self
            .get_transaction_receipt(txn_hash)?
            .ok_or_else(|| anyhow!("transaction not mined: {txn_hash}"))?;

        let block = self
            .get_block_by_hash(receipt.block_hash)?
            .ok_or_else(|| anyhow!("missing block: {}", receipt.block_hash))?;
        let parent = self
            .get_block_by_hash(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block: {}", block.parent_hash()))?;
        let mut state = self
            .consensus
            .state()
            .at_root(parent.state_root_hash().into());

        for other_txn_hash in block.transactions {
            if txn_hash != other_txn_hash {
                let other_txn = self
                    .get_transaction_by_hash(other_txn_hash)?
                    .ok_or_else(|| anyhow!("transaction not found: {other_txn_hash}"))?;
                state.apply_transaction(
                    other_txn,
                    self.get_chain_id(),
                    parent.header,
                    inspector::noop(),
                )?;
            } else {
                let result =
                    state.apply_transaction(txn, self.get_chain_id(), parent.header, inspector)?;

                return Ok(result);
            }
        }

        Err(anyhow!("transaction not found in block: {txn_hash}"))
    }

    pub fn debug_trace_block_by_number(
        &self,
        block_number: BlockNumber,
        trace_opts: GethDebugTracingOptions,
    ) -> Result<Vec<TraceResult>> {
        let block = self
            .get_block_by_blocknum(block_number)?
            .ok_or_else(|| anyhow!("missing block: {}", block_number))?;
        let parent = self
            .get_block_by_hash(block.parent_hash())?
            .ok_or_else(|| anyhow!("missing block: {}", block.parent_hash()))?;
        let mut state = self
            .consensus
            .state()
            .at_root(parent.state_root_hash().into());

        let mut traces: Vec<TraceResult> = Vec::new();

        for (index, &txn_hash) in block.transactions.iter().enumerate() {
            if let Ok(Some(trace)) = self.debug_trace_transaction(
                &mut state,
                txn_hash,
                index,
                &block,
                &parent,
                trace_opts.clone(),
            ) {
                traces.push(trace);
            }
        }

        Ok(traces)
    }

    fn debug_trace_transaction(
        &self,
        state: &mut State,
        txn_hash: Hash,
        txn_index: usize,
        block: &Block,
        parent_block: &Block,
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

            let result = state.apply_transaction(
                txn,
                self.get_chain_id(),
                parent_block.header,
                &mut inspector,
            )?;

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

        match tracer {
            GethDebugTracerType::BuiltInTracer(tracer) => match tracer {
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config.into_call_config()?;
                    let mut inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_call_config(&call_config),
                    );

                    let result = state.apply_transaction(
                        txn,
                        self.get_chain_id(),
                        parent_block.header,
                        &mut inspector,
                    )?;

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
                GethDebugBuiltInTracerType::FourByteTracer => {
                    let mut inspector = FourByteInspector::default();
                    let result = state.apply_transaction(
                        txn,
                        self.get_chain_id(),
                        parent_block.header,
                        &mut inspector,
                    )?;

                    let TransactionApplyResult::Evm(_, _) = result else {
                        return Ok(None);
                    };

                    Ok(Some(TraceResult::Success {
                        result: FourByteFrame::from(inspector).into(),
                        tx_hash: Some(txn_hash.0.into()),
                    }))
                }
                GethDebugBuiltInTracerType::MuxTracer => {
                    let mux_config = tracer_config.into_mux_config()?;

                    let mut inspector = MuxInspector::try_from_config(mux_config)?;
                    let result = state.apply_transaction(
                        txn,
                        self.get_chain_id(),
                        parent_block.header,
                        &mut inspector,
                    )?;

                    let TransactionApplyResult::Evm(result, ..) = result else {
                        return Ok(None);
                    };
                    let state_ref = &(*state);
                    let trace = inspector.try_into_mux_frame(&result, &state_ref)?;
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
                    let result = state.apply_transaction(
                        txn,
                        self.get_chain_id(),
                        parent_block.header,
                        &mut inspector,
                    )?;

                    let TransactionApplyResult::Evm(result, ..) = result else {
                        return Ok(None);
                    };
                    let state_ref = &(*state);
                    let trace = inspector.into_geth_builder().geth_prestate_traces(
                        &result,
                        prestate_config,
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

                let result = state.apply_transaction(
                    txn,
                    self.get_chain_id(),
                    parent_block.header,
                    &mut inspector,
                )?;

                let TransactionApplyResult::Evm(result, env) = result else {
                    return Ok(None);
                };
                let state_ref = &(*state);
                let result = inspector
                    .json_result(result, &env, &state_ref)
                    .map_err(|e| anyhow!("Unable to create json result: {e}"))?;

                Ok(Some(TraceResult::Success {
                    result: GethTrace::JS(result),
                    tx_hash: Some(txn_hash.0.into()),
                }))
            }
        }
    }

    pub fn call_contract(
        &mut self,
        block_number: BlockNumber,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        amount: u128,
    ) -> Result<Vec<u8>> {
        let block = self
            .get_block_by_number(self.get_number(block_number))?
            .ok_or_else(|| anyhow!("block not found"))?;

        trace!("call_contract: block={:?}", block);

        let state = self
            .consensus
            .state()
            .at_root(block.state_root_hash().into());

        state.call_contract(
            from_addr,
            to_addr,
            data,
            amount,
            self.config.eth_chain_id,
            block.header,
        )
    }

    pub fn get_proposer_reward_address(&self, header: BlockHeader) -> Result<Option<Address>> {
        // Return the zero address for the genesis block. There was no reward for it.
        if header.view == 0 {
            return Ok(None);
        }

        let parent = self
            .get_block_by_hash(header.parent_hash)?
            .ok_or_else(|| anyhow!("missing parent: {}", header.parent_hash))?;
        let proposer = self
            .consensus
            .leader_at_block(&parent, header.view)
            .unwrap()
            .public_key;

        self.consensus.state().get_reward_address(proposer)
    }

    pub fn get_touched_transactions(&self, address: Address) -> Result<Vec<Hash>> {
        self.consensus.get_touched_transactions(address)
    }

    pub fn get_gas_price(&self) -> u128 {
        *self.config.consensus.gas_price
    }

    #[allow(clippy::too_many_arguments)]
    pub fn estimate_gas(
        &mut self,
        block_number: BlockNumber,
        from_addr: Address,
        to_addr: Option<Address>,
        data: Vec<u8>,
        gas: Option<EvmGas>,
        gas_price: Option<u128>,
        value: u128,
    ) -> Result<u64> {
        // TODO: optimise this to get header directly once persistance is merged
        // (which will provide a header index)
        let block = self
            .get_block_by_number(self.get_number(block_number))?
            .ok_or_else(|| anyhow!("block not found"))?;
        let state = self
            .consensus
            .state()
            .at_root(block.state_root_hash().into());

        state.estimate_gas(
            from_addr,
            to_addr,
            data,
            self.config.eth_chain_id,
            block.header,
            gas,
            gas_price,
            value,
        )
    }

    pub fn subscribe_to_new_blocks(&self) -> broadcast::Receiver<BlockHeader> {
        self.consensus.new_blocks.subscribe()
    }

    /// Returns a stream of pairs of (receipt, index of transaction in block)
    pub fn subscribe_to_receipts(&self) -> broadcast::Receiver<(TransactionReceipt, usize)> {
        self.consensus.receipts.subscribe()
    }

    pub fn subscribe_to_new_transactions(&self) -> broadcast::Receiver<VerifiedTransaction> {
        self.consensus.new_transactions.subscribe()
    }

    pub fn subscribe_to_new_transaction_hashes(&self) -> broadcast::Receiver<Hash> {
        self.consensus.new_transaction_hashes.subscribe()
    }

    pub fn get_chain_id(&self) -> u64 {
        self.config.eth_chain_id // using eth as a universal ID for now
    }

    pub fn get_chain_tip(&self) -> u64 {
        self.consensus.head_block().header.number
    }

    pub fn state_at(&self, block_number: BlockNumber) -> Result<State> {
        self.consensus
            .try_get_state_at(self.get_number(block_number))
    }

    pub fn get_account(&self, address: Address, block_number: BlockNumber) -> Result<Account> {
        self.consensus
            .try_get_state_at(self.get_number(block_number))?
            .get_account(address)
    }

    pub fn get_account_storage(
        &self,
        address: Address,
        index: B256,
        block_number: BlockNumber,
    ) -> Result<B256> {
        self.consensus
            .try_get_state_at(self.get_number(block_number))?
            .get_account_storage(address, index)
    }

    pub fn get_native_balance(&self, address: Address, block_number: BlockNumber) -> Result<u128> {
        Ok(self
            .consensus
            .try_get_state_at(self.get_number(block_number))?
            .get_account(address)?
            .balance)
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
        self.db.get_transaction_receipts_in_block(&block_hash)
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

    pub fn get_transaction_receipt(&self, tx_hash: Hash) -> Result<Option<TransactionReceipt>> {
        self.consensus.get_transaction_receipt(&tx_hash)
    }

    pub fn get_transaction_by_hash(&self, hash: Hash) -> Result<Option<VerifiedTransaction>> {
        self.consensus.get_transaction_by_hash(hash)
    }

    pub fn txpool_content(&self) -> TxPoolContent {
        self.consensus.txpool_content()
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

    /// Convenience function to convert a block to a proposal (add full txs)
    /// NOTE: Includes intershard transactions. Should only be used for syncing history,
    /// not for consensus messages regarding new blocks.
    fn block_to_proposal(&self, block: Block) -> Proposal {
        let txs: Vec<_> = block
            .transactions
            .iter()
            .map(|tx_hash| {
                self.consensus
                    .get_transaction_by_hash(*tx_hash)
                    .unwrap()
                    .unwrap()
            })
            .collect();

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
            let (new, proposal) = self.consensus.receive_block(block)?;
            was_new = new;
            if let Some(proposal) = proposal {
                self.message_sender
                    .broadcast_external_message(ExternalMessage::Proposal(proposal))?;
            }
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
