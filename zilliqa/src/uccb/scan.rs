#![allow(unused_imports)]
use crate::cfg::{NodeConfig, UCCBConfig};
use crate::message::{ExternalMessage, InternalMessage};
use crate::node::Node;
use crate::p2p_node::{LocalMessageTuple, OutboundMessageTuple};
use crate::uccb::launcher::{
    UCCBLocalMessageTuple, UCCBMessageFailure, UCCBOutboundMessageTuple, UCCBRequestId,
    UCCBResponseChannel,
};
use crate::uccb::message::{UCCBExternalMessage, UCCBInternalMessage};
use crate::uccb::node::UCCBNode;
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use alloy::eips::BlockNumberOrTag;
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
    time::{self, Instant},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;

pub async fn scan_wombat(_blk: u64) -> Result<()> {
    info!("Wombat!");
    Ok(())
}

impl UCCBNode {
    pub async fn scan_local_block(&self, _blk_num: u64) -> Result<()> {
        info!("Scan!");
        Ok(())
    }
}
