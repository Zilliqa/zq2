#![allow(unused_imports)]
use crate::cfg::{NodeConfig, UCCBConfig, UCCBNetwork};
use crate::message::{ExternalMessage, InternalMessage};
use crate::node::Node;
use crate::p2p_node::{LocalMessageTuple, OutboundMessageTuple};
use crate::transaction::{EvmLog, Log, TransactionReceipt};
use crate::uccb::contracts::{IDISPATCHER_EVENTS, IRELAYER_EVENTS};
use crate::uccb::launcher::{
    UCCBLocalMessageTuple, UCCBMessageFailure, UCCBOutboundMessageTuple, UCCBRequestId,
    UCCBResponseChannel,
};
use crate::uccb::message::{
    RelayedMessage, SignedRelayedMessage, UCCBExternalMessage, UCCBInternalMessage,
};
use crate::uccb::node::UCCBNode;
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use alloy::eips::BlockNumberOrTag;
use alloy::eips::eip1898::BlockId;
use alloy::network::primitives::BlockTransactionsKind;
use alloy::sol_types::SolEvent;
use alloy::{
    primitives::{Address, B256, TxHash, U256},
    providers::{Provider, ProviderBuilder},
};
use anyhow::{Result, anyhow};
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
    time::{self, Instant, sleep},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;
use url::Url;

// Max # blocks to query via getLogs() - @todo: make this configurable.
const MAX_GETLOGS_BLOCKS: u64 = 100;

pub struct ExternalNetwork {
    parent: Arc<Mutex<UCCBNode>>,
    name: String,
    network: UCCBNetwork,
    next_block_to_scan: u64,
}

pub enum ShouldAbort {
    Continue,
    Abort(String),
}
impl ExternalNetwork {
    pub fn new(parent: Arc<Mutex<UCCBNode>>, name: &str, network: UCCBNetwork) -> Result<Self> {
        let next_block_to_scan = network.start_block;
        Ok(ExternalNetwork {
            parent,
            name: name.to_string(),
            network,
            next_block_to_scan,
        })
    }

    // Gets restarted on error after about a second; if we really want to abort, return ShouldAbort::Abort.
    pub async fn inner(&mut self) -> Result<ShouldAbort> {
        info!("Connect {}", self.network.rpc_url);
        let provider = ProviderBuilder::new().on_http(Url::parse(&self.network.rpc_url)?);
        let chain_id = provider.get_chain_id().await?;
        if chain_id != self.network.chain_id {
            return Ok(ShouldAbort::Abort(format!(
                "Chain id mismatch - network {} wanted chain id {} but got {chain_id}",
                &self.name, self.network.chain_id
            )));
        }

        let relay_contract = IRELAYER_EVENTS::new(self.network.chain_gateway, provider.clone());
        let dispatch_contract =
            IDISPATCHER_EVENTS::new(self.network.chain_gateway, provider.clone());
        let finalized_block = provider
            .get_block(
                BlockId::Number(BlockNumberOrTag::Finalized),
                BlockTransactionsKind::Hashes,
            )
            .await?;
        let finalized_block_num = finalized_block.map_or(0, |x| x.header.number);
        info!("latest finalized block is {}", finalized_block_num);

        // If we don't have a next block to scan, start scanning at the end.
        if self.next_block_to_scan == 0 {
            self.next_block_to_scan = finalized_block_num;
        }

        // Do a chunk, then restart.
        let to_block = std::cmp::min(
            finalized_block_num,
            self.next_block_to_scan + MAX_GETLOGS_BLOCKS,
        );
        if to_block >= self.next_block_to_scan {
            debug!(
                "External chain {} - querying logs {} to {to_block}",
                self.name, self.next_block_to_scan
            );
            let relayer_logs = relay_contract
                .Relayed_filter()
                .from_block(self.next_block_to_scan)
                .to_block(to_block)
                .query()
                .await?;

            let dispatcher_logs = dispatch_contract
                .Dispatched_filter()
                .from_block(self.next_block_to_scan)
                .to_block(to_block)
                .query()
                .await?;

            for (relayer_log, log) in relayer_logs {
                // we'll need these to query the txn if we need to re-sign later.
                if let (Some(tx_hash), Some(blk_num)) = (log.transaction_hash, log.block_number) {
                    // We've found a log and believe it to be authentic. Great! Sign it and send it off.
                    let msg = RelayedMessage::from_relayed_event(
                        U256::from(chain_id),
                        blk_num,
                        tx_hash,
                        &relayer_log,
                    );
                    let node = self.parent.lock().unwrap();
                    let signature =
                        crate::uccb::crypto::sign_relayed_message(&msg, &node.signing_key)?;
                    let signed = SignedRelayedMessage::from_message(msg)
                        .with_signature(node.get_peer_id(), &signature);
                    node.sender
                        .broadcast_external_message(UCCBExternalMessage::Signature(signed))?;
                }

                debug!(
                    "Got a relayer log - nonce {}, target {}",
                    relayer_log.targetChainId, relayer_log.nonce
                );
            }
            for (dispatcher_log, _) in dispatcher_logs {
                debug!(
                    "Got a disptatcher log -  nonce {}, source {}",
                    dispatcher_log.nonce, dispatcher_log.sourceChainId
                );
            }
            self.next_block_to_scan = to_block + 1;
        } else {
            debug!(
                "External chain {} - no blocks to query at {to_block}",
                self.name
            );
        }
        Ok(ShouldAbort::Continue)
    }

    pub async fn start(&mut self) -> Result<()> {
        loop {
            match self.inner().await {
                Err(v) => {
                    debug!("Restarting network {} on error - {:?}", self.name, v);
                    // Go back.
                    sleep(Duration::from_millis(1000)).await;
                }
                Ok(ShouldAbort::Continue) => {
                    debug!("Restarting network {} on completion", self.name);
                    // Go back.
                    sleep(Duration::from_millis(1000)).await;
                }
                Ok(ShouldAbort::Abort(v)) => {
                    // Abort!
                    warn!("External network {} died - {}", self.name, v);
                    return Err(anyhow!("{}", v));
                }
            }
        }
    }
}
