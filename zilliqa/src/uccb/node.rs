#![allow(unused_imports)]
use crate::cfg::{NodeConfig, UCCBConfig};
use crate::message::{ExternalMessage, InternalMessage};
use crate::node::Node;
use crate::p2p_node::{LocalMessageTuple, OutboundMessageTuple};
use crate::transaction::{EvmLog, Log, TransactionReceipt};
use crate::uccb::contracts::{IDISPATCHER_EVENTS, IRELAYER_EVENTS};
use crate::uccb::external_network::ExternalNetwork;
use crate::uccb::launcher::{
    UCCBLocalMessageTuple, UCCBMessageFailure, UCCBOutboundMessageTuple, UCCBRequestId,
    UCCBResponseChannel,
};
use crate::uccb::message::{
    BridgeEvent, DispatchedMessage, RelayedMessage, SignedEvent, UCCBExternalMessage,
    UCCBInternalMessage,
};
use crate::uccb::signatures::Signatures;
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{TxHash, U256};
use alloy::sol_types::SolEvent;
use anyhow::{Result, anyhow};
use k256::ecdsa::SigningKey;
use libp2p::{PeerId, futures::StreamExt, request_response::OutboundFailure};
use opentelemetry::KeyValue;
use opentelemetry_semantic_conventions::{
    attribute::{
        ERROR_TYPE, MESSAGING_DESTINATION_NAME, MESSAGING_OPERATION_NAME, MESSAGING_SYSTEM,
    },
    metric::MESSAGING_PROCESS_DURATION,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    sync::Mutex,
    time::{Duration, SystemTime},
};
use tokio::{
    select,
    sync::mpsc::{self, UnboundedSender, error::SendError},
    task::JoinSet,
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;

// For the sake of some sort of sanity, we take the global transmission channels here, and
// adapt them in the implementation for the UCCB use case - the alternative would have been
// a lot of code duplication.
#[derive(Debug, Clone)]
pub struct UCCBMessageSender {
    pub our_shard: u64,
    pub our_peer_id: PeerId,
    pub outbound_channel: UnboundedSender<OutboundMessageTuple>,
    pub local_channel: UnboundedSender<LocalMessageTuple>,
    pub request_id: UCCBRequestId,
}

impl UCCBMessageSender {
    pub fn broadcast_external_message(&self, msg: UCCBExternalMessage) -> Result<()> {
        Ok(self
            .outbound_channel
            .send((None, self.our_shard, ExternalMessage::UCCB(msg)))?)
    }
    pub fn send_local_message(&self, msg: UCCBInternalMessage) -> Result<()> {
        self.local_channel
            .send((self.our_shard, self.our_shard, InternalMessage::UCCB(msg)))?;
        Ok(())
    }
}

pub struct UCCBNode {
    pub signing_key: SigningKey,
    pub node_config: NodeConfig,
    pub uccb_config: UCCBConfig,
    pub request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    pub sender: UCCBMessageSender,
    pub node: Arc<Mutex<Node>>,
    /// The latest block we've requested to scan on our native chain.
    pub latest_scanned_block: Option<u64>,
    /// Threads monitoring external networks
    pub external_threads: JoinSet<Result<()>>,
    /// The signatures we've collected so far, indexed by
    /// @todo Cache management!
    pub signatures: Signatures,
}

pub async fn handle_local(
    node: Arc<Mutex<UCCBNode>>,
    _id: u64,
    message: UCCBInternalMessage,
) -> Result<()> {
    debug!("uccb_handle_local(2): {:?}", message);
    match message {
        UCCBInternalMessage::RequestScan(blk) => node.lock().unwrap().scan_block(blk)?,
        _ => (),
    }
    Ok(())
}

// Here to avoid polluting messages.rs with zilliqa and sol_contract dependencies.
fn relayed_message_from_evm_log(
    chain_id: u64,
    blk: u64,
    tx_hash: TxHash,
    log_idx: usize,
    log: &EvmLog,
) -> Result<RelayedMessage> {
    let decoded = IRELAYER_EVENTS::Relayed::decode_raw_log(&log.topics, &log.data, true)?;
    Ok(RelayedMessage::from_relayed_event(
        U256::from(chain_id),
        blk,
        u64::try_from(log_idx)?,
        tx_hash,
        &decoded,
    ))
}

// Here to avoid polluting messages.rs with zilliqa and sol_contract dependencies.
fn dispatched_message_from_evm_log(
    chain_id: u64,
    blk: u64,
    tx_hash: TxHash,
    log_idx: usize,
    log: &EvmLog,
) -> Result<DispatchedMessage> {
    let decoded = IDISPATCHER_EVENTS::Dispatched::decode_raw_log(&log.topics, &log.data, true)?;
    Ok(DispatchedMessage::from_dispatched_event(
        U256::from(chain_id),
        blk,
        u64::try_from(log_idx)?,
        tx_hash,
        &decoded,
    ))
}

impl UCCBNode {
    /// Starts up the UCCBNode for NodeConfig.
    pub fn new(
        signing_key: SigningKey,
        peer_id: PeerId,
        node_config: NodeConfig,
        message_sender_channel: UnboundedSender<OutboundMessageTuple>,
        local_sender_channel: UnboundedSender<LocalMessageTuple>,
        request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
        node: Arc<Mutex<Node>>,
    ) -> Result<Self> {
        let sender = UCCBMessageSender {
            our_shard: node_config.eth_chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
            local_channel: local_sender_channel,
            request_id: UCCBRequestId::default(),
        };
        let external_threads = JoinSet::new();

        let uccb_config = node_config
            .clone()
            .uccb
            .ok_or(anyhow!("No UCCB config when instantiating UCCB node"))?;
        Ok(Self {
            signing_key,
            node_config,
            uccb_config,
            request_responses,
            sender,
            node,
            latest_scanned_block: None,
            external_threads,
            signatures: Default::default(),
        })
    }

    pub async fn start_external_networks(for_object: Arc<Mutex<UCCBNode>>) -> Result<()> {
        let mut node = for_object
            .lock()
            .map_err(|_| anyhow!("failed to lock uccb node mutex"))?;
        let networks = node.uccb_config.networks.clone();
        for (name, network) in networks.iter() {
            let mut ext_obj = ExternalNetwork::new(for_object.clone(), name, network.clone())?;
            info!("Starting network monitor for {name} .. ");
            node.external_threads
                .spawn(async move { ext_obj.start().await });
        }
        Ok(())
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.sender.our_peer_id
    }

    pub fn handle_broadcast(&mut self, from: PeerId, message: UCCBExternalMessage) -> Result<()> {
        trace!("from={from:?} message={message:?}");
        let result = match message {
            UCCBExternalMessage::Signature(ev) => self.incoming_signature(ev),
            _ => Ok(()),
        };
        if let Err(v) = result {
            warn!("Couldn't process incoming broadcast - {v:?}");
        }
        Ok(())
    }

    pub fn incoming_signature(&mut self, sig: SignedEvent) -> Result<()> {
        // Stash the signature and then let's see if we should issue this txn
        let merged = self.signatures.put(sig);
        info!("Got merged requests {merged:?}");
        Ok(())
    }

    pub fn handle_request(
        &mut self,
        _from: PeerId,
        _id: &str,
        _message: UCCBExternalMessage,
        _response_channel: ResponseChannel,
    ) -> Result<()> {
        debug!("uccb_handle_request()");
        Ok(())
    }

    pub fn handle_request_failure(
        &mut self,
        _from: PeerId,
        _message: UCCBMessageFailure,
    ) -> Result<()> {
        debug!("uccb_handle_request_failure()");
        Ok(())
    }

    pub fn handle_response(&mut self, _from: PeerId, _message: UCCBExternalMessage) -> Result<()> {
        debug!("uccb_handle_response()");
        Ok(())
    }

    pub fn scan_block(&mut self, blk: u64) -> Result<()> {
        // Do we have the block?
        // Slightly odd, but limits the locking scope to what we need.
        let chain_gateway_address = self.uccb_config.chain_gateway;
        let receipts = {
            let zq2_node = self.node.lock().unwrap();
            let block = zq2_node.get_block(blk)?.ok_or(anyhow!(
                "TODO: Attempt to scan a block {blk} that we do not have!"
            ))?;
            // Do we have the receipts?
            zq2_node.get_transaction_receipts_in_block(block.hash())?
        };
        // Now look through the receipts
        receipts
            .iter()
            .filter_map(|x| {
                // Unsuccessful transactions emit no relayer events
                if !x.success {
                    return None;
                }
                let valid_logs = x
                    .logs
                    .iter()
                    .filter_map(|l| match l {
                        Log::Evm(l) => Some(l),
                        _ => None,
                    })
                    .filter(|e| e.address == chain_gateway_address)
                    .enumerate()
                    .filter_map(|(log_idx, e)| {
                        // First topic should be the relayed topic
                        if let Some(v) = e.topics.first() {
                            match *v {
                                crate::uccb::contracts::IRELAYER_EVENTS::Relayed::SIGNATURE_HASH => {
                                    let relayed = relayed_message_from_evm_log(self.node_config.eth_chain_id, blk, x.tx_hash.into(), log_idx, e);
                                    if let Ok(r) = relayed {
                                        let signature = crate::uccb::crypto::sign_relayed_message(&r, &self.signing_key);
                                        if let Ok(s) = signature {
                                            return Some(SignedEvent::from_event(BridgeEvent::Relayed(r)).with_signature(self.get_peer_id(), &s));
                                        }
                                    }
                                },
                                crate::uccb::contracts::IDISPATCHER_EVENTS::Dispatched::SIGNATURE_HASH => {
                                    let dispatched = dispatched_message_from_evm_log(self.node_config.eth_chain_id, blk, x.tx_hash.into(), log_idx, e);
                                    if let Ok(d) = dispatched {
                                        let signature = crate::uccb::crypto::sign_dispatched_message(&d, &self.signing_key);
                                        if let Ok(s) = signature {
                                            return Some(SignedEvent::from_event(BridgeEvent::Dispatched(d)).with_signature(self.get_peer_id(), &s));
                                        }
                                    }
                                },
                                _ => ()
                            }
                        }
                        None
                    })
                    .collect::<Vec<SignedEvent>>();
                if valid_logs.is_empty() {
                    None
                } else {
                    Some(valid_logs)
                }
            })
            .flatten()
            .for_each(|ev| {
                if let Err(e) = self.sender.broadcast_external_message(UCCBExternalMessage::Signature(ev)) {
                    warn!("Cannot broadcast signature - {e:?}");
                }
            });
        Ok(())
    }

    pub fn handle_tick(&mut self) -> Result<()> {
        debug!("uccb_tick()");
        // Check for threads.
        if let Some(res) = self.external_threads.try_join_next() {
            info!("External thread terminated - dying");
            return Err(anyhow!("External thread terminated - {res:?}"));
        }
        // Find the latest safe block.
        if let Some(latest_finalized_block) = self
            .node
            .lock()
            .unwrap()
            .resolve_block_number(BlockNumberOrTag::Finalized)?
        {
            let latest_finalized_block_number = latest_finalized_block.number();
            debug!(
                "Latest finalised block is {}",
                latest_finalized_block_number
            );

            if let Some(v) = self.latest_scanned_block {
                // @todo - fix this! need to get the latest scanned block from the db so that
                // we don't end up with gaps, and also need to deal with checkpoints.
                ((v + 1)..(latest_finalized_block_number + 1)).for_each(|x| {
                    debug!("Requesting scan for block {x}");
                    if let Err(e) = self
                        .sender
                        .send_local_message(UCCBInternalMessage::RequestScan(x))
                    {
                        warn!("Failed to request scan for block {x} - {e}");
                    };
                });
            }
            self.latest_scanned_block = Some(latest_finalized_block_number);
        }
        Ok(())
    }
}
