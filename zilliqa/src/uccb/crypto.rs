#![allow(unused_imports)]
use crate::cfg::{NodeConfig, UCCBConfig, UCCBNetwork};
use crate::message::{ExternalMessage, InternalMessage};
use crate::node::Node;
use crate::p2p_node::{LocalMessageTuple, OutboundMessageTuple};
use crate::transaction::{EvmLog, Log, TransactionReceipt};
use crate::uccb::contracts::{IDISPATCHER_EVENTS, IRELAYER_EVENTS, SignRelayFunctionCall};
use crate::uccb::launcher::{
    UCCBLocalMessageTuple, UCCBMessageFailure, UCCBOutboundMessageTuple, UCCBRequestId,
    UCCBResponseChannel,
};
use crate::uccb::message::{RelayedMessage, SignedRelayedMessage};
use crate::uccb::message::{UCCBExternalMessage, UCCBInternalMessage};
use crate::uccb::node::UCCBNode;
use crate::{crypto::SecretKey, node_launcher::ResponseChannel, sync::SyncPeers};
use alloy::eips::BlockNumberOrTag;
use alloy::eips::eip1898::BlockId;
use alloy::network::primitives::BlockTransactionsKind;
use alloy::signers::{Signer, SignerSync, local::PrivateKeySigner};
use alloy::sol_types::SolCall;
use alloy::sol_types::SolEvent;
use alloy::{
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
};
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
    time::{self, Instant, sleep},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::*;
use url::Url;

/// Take a relayed message, encode, hash and sign it and return a signature
/// Alloy doesn't let us get at the underlying hash, annoyingly.
pub fn sign_relayed_message(relayed: &RelayedMessage, key: &SigningKey) -> Result<[u8; 65]> {
    // We ABI-encode the fields, then hash, then sign with the key.
    let encoded = SignRelayFunctionCall {
        sourceChainId: relayed.source_chain_id,
        targetChainId: relayed.target_chain_id,
        target: relayed.target,
        bytes: relayed.call.clone(),
        gasLimit: relayed.gas_limit,
        nonce: relayed.nonce,
    };
    let encoded_bytes = encoded.abi_encode();
    info!("encoded = {encoded_bytes:?}");
    let signer = PrivateKeySigner::from_signing_key(key.clone());
    let signature = signer.sign_message_sync(&encoded_bytes)?;
    Ok(signature.as_bytes())
}
