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
use crate::uccb::message::{UCCBExternalMessage, UCCBInternalMessage};
use crate::uccb::node::UCCBNode;
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use alloy::eips::BlockNumberOrTag;
use alloy::sol_types::SolEvent;
use alloy::{
    primitives::{Address, B256},
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

pub struct ExternalNetwork {
    _parent: Arc<Mutex<UCCBNode>>,
    name: String,
    network: UCCBNetwork,
    last_block: u64,
}

pub enum ShouldAbort {
    Continue,
    Abort(String),
}
impl ExternalNetwork {
    pub fn new(parent: Arc<Mutex<UCCBNode>>, name: &str, network: UCCBNetwork) -> Result<Self> {
        let last_block = network.start_block;
        Ok(ExternalNetwork {
            _parent: parent,
            name: name.to_string(),
            network,
            last_block,
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
        info!(
            "Getting logs from block {}, chain id {}",
            self.last_block, self.network.chain_id
        );

        let relay_contract = IRELAYER_EVENTS::new(self.network.chain_gateway, provider.clone());
        let dispatch_contract = IDISPATCHER_EVENTS::new(self.network.chain_gateway, provider);
        let mut relayer_filter = relay_contract
            .Relayed_filter()
            .from_block(self.last_block)
            .watch()
            .await?
            .into_stream();
        let mut dispatcher_filter = dispatch_contract
            .Dispatched_filter()
            .from_block(self.last_block)
            .watch()
            .await?
            .into_stream();
        loop {
            select! {
                Some(result) = relayer_filter.next() => {
                    if let Ok((relay, _log)) = result {
                        info!("Relay event nonce {} to {}", relay.nonce, relay.targetChainId);
                    }
                },
                Some(result) = dispatcher_filter.next() => {
                    if let Ok((dispatch, _log)) = result {
                        info!("Dispatch event nonce {} from {}", dispatch.nonce, dispatch.sourceChainId);
                    }
                },
            }
        }

        //return Ok(ShouldAbort::Continue);
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
