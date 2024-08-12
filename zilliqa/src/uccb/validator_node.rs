use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy::{
    contract::{ContractInstance, DynCallBuilder, Interface},
    dyn_abi::DynSolValue,
    eips::{eip2930::AccessList, BlockNumberOrTag},
    primitives::U256,
    pubsub::PubSubFrontend,
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use futures_util::StreamExt;
use libp2p::PeerId;
use tokio::{
    select,
    sync::mpsc::{self, UnboundedSender},
    task::JoinSet,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info, warn};

use crate::{
    consensus::Consensus,
    message::ExternalMessage,
    p2p_node::OutboundMessageTuple,
    schnorr::sign,
    uccb::{
        bridge_node::BridgeNode,
        cfg::Config,
        client::{ChainClient, ChainProvider /*, ContractInitializer*/},
        contracts,
        // contracts::{ChainGateway, ChainGatewayErrors},
        message::{Dispatch, InboundBridgeMessage, OutboundBridgeMessage},
        signature::SignatureTracker,
    },
};

type ChainID = U256;

#[derive(Debug)]
pub struct ValidatorNode {
    shard_id: u64,
    /// The following two message streams are used for networked messages.
    /// The sender is provided to the p2p coordinator, to forward messages to the node.
    bridge_outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
    bridge_inbound_message_sender: UnboundedSender<ExternalMessage>,
    bridge_inbound_message_receiver: UnboundedReceiverStream<ExternalMessage>,
    config: Config,
    signer: PrivateKeySigner,
    chain_clients: HashMap<ChainID, ChainClient>,
    consensus: Arc<Mutex<Consensus>>,
}

impl ValidatorNode {
    pub async fn new(
        config: &Config,
        signer: &PrivateKeySigner,
        peer_id: PeerId,
        shard_id: u64,
        bridge_outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
        consensus: Arc<Mutex<Consensus>>,
    ) -> Result<Self> {
        let (bridge_inbound_message_sender, bridge_inbound_message_receiver) =
            mpsc::unbounded_channel::<ExternalMessage>();
        let bridge_inbound_message_receiver =
            UnboundedReceiverStream::new(bridge_inbound_message_receiver);

        Ok(ValidatorNode {
            shard_id,
            bridge_outbound_message_sender,
            bridge_inbound_message_sender,
            bridge_inbound_message_receiver,
            config: config.clone(),
            signer: signer.clone(),
            chain_clients: HashMap::<ChainID, ChainClient>::new(),
            consensus,
        })
    }

    pub fn get_bridge_inbound_message_sender(&self) -> UnboundedSender<ExternalMessage> {
        self.bridge_inbound_message_sender.clone()
    }

    pub async fn start(&mut self) -> Result<()> {
        let chain_clients = crate::uccb::create_chain_clients(&self.config, &self.signer).await?;
        let chain_clients: HashMap<ChainID, ChainClient> = chain_clients
            .into_iter()
            .map(|chain_client| (chain_client.chain_id, chain_client))
            .collect();
        self.chain_clients = chain_clients;

        let (bridge_message_sender, bridge_message_receiver) =
            mpsc::unbounded_channel::<OutboundBridgeMessage>();
        let mut bridge_message_receiver = UnboundedReceiverStream::new(bridge_message_receiver);

        let mut bridge_node_threads: JoinSet<Result<()>> = JoinSet::new();

        let mut bridge_node_message_senders: HashMap<
            ChainID,
            UnboundedSender<InboundBridgeMessage>,
        > = HashMap::new();
        for (chain_id, chain_client) in &self.chain_clients {
            let mut bridge_node = BridgeNode::new(
                chain_client.clone(),
                bridge_message_sender.clone(),
                false, //config.is_leader,
            )
            .await?;

            // TODO: should this be encapsulated in BridgeNode?
            bridge_node_message_senders
                .insert(chain_id.clone(), bridge_node.get_inbound_message_sender());

            bridge_node_threads.spawn(async move {
                // Fill all historic events first
                // validator_chain_node.sync_historic_events().await
                // Then start listening to new ones
                bridge_node.listen_events().await
            });
        }

        loop {
            select! {
               Some(message) = self.bridge_inbound_message_receiver.next() => {
                    // forward messages to bridge_chain_node
                    match message {
                        ExternalMessage::BridgeEcho(echo) => {
                            // Send echo to respective source_chain_id to be verified, only if chain is supported
                            if let Some(sender) = bridge_node_message_senders.get(&echo.event.source_chain_id) {
                                sender.send(InboundBridgeMessage::Relay(echo))?;
                            }
                        },
                        _ => {
                            warn!("Unexpected message");
                        }
                    }
                }
                Some(message) = bridge_message_receiver.next() => {
                    match message {
                        OutboundBridgeMessage::Dispatch(dispatch) => {
                            // Send relay event to target chain
                            self.dispatch_message(dispatch).await?;
                        },
                        OutboundBridgeMessage::Dispatched(dispatched) => {
                            // Forward message to another chain_node
                            if let Some(sender) = bridge_node_message_senders.get(&dispatched.chain_id) {
                                sender.send(InboundBridgeMessage::Dispatched(dispatched))?;
                            }
                        },
                        OutboundBridgeMessage::Relay(relay) => {
                            // Forward message to broadcast
                            self.bridge_outbound_message_sender.send((None, self.shard_id ,ExternalMessage::BridgeEcho(relay)))?;
                        },
                    }
                }
                Some(res) = bridge_node_threads.join_next() => {
                    match res {
                        Ok(Ok(())) => unreachable!(),
                        Ok(Err(e)) => {
                            error!(%e);
                            return Err(e.into())
                        }
                        Err(e) =>{
                            error!(%e);
                            return Err(e.into())
                        }
                    }
                }
            }
        }
    }

    async fn dispatch_message(&self, dispatch: Dispatch) -> Result<()> {
        let Dispatch {
            event, signatures, ..
        } = dispatch;

        let chain_client = match self.chain_clients.get(&event.target_chain_id) {
            Some(chain_client) => chain_client,
            None => {
                warn!("Unsupported Chain ID");
                return Ok(());
            }
        };

        let chain_gateway_contract: ContractInstance<PubSubFrontend, _> =
            contracts::chain_gateway::instance(
                chain_client.chain_gateway_address,
                chain_client.provider.as_ref(),
            );

        let args = vec![
            DynSolValue::Uint(event.source_chain_id, 256),
            DynSolValue::Address(event.target),
            DynSolValue::Bytes(event.call.to_vec()),
            DynSolValue::Uint(event.gas_limit, 256),
            DynSolValue::Uint(event.nonce, 256),
            // TODO: signatures
            DynSolValue::Array(vec![]),
        ];
        let call_builder = chain_gateway_contract.function("dispatch", &args)?;
        /*
        let output = call_builder.send().await?;
        let receipt = output.get_receipt().await?;
        info!("Receipt from {}: {receipt:?}", &chain_client.rpc_url);
        */

        let call_builder = if chain_client.legacy_gas_estimation {
            call_builder.access_list(AccessList::default())
        } else {
            call_builder
        };

        for i in 1..6 {
            info!("Dispatch Attempt {:?}", i);

            let _call_builder = if chain_client.legacy_gas_estimation {
                let gas_estimate = match call_builder.estimate_gas().await {
                    Ok(estimate) => estimate,
                    Err(err) => {
                        warn!("Failed to estimate gas, {:?}", err);
                        return Ok(());
                    }
                };
                info!("Gas estimate {:?}", gas_estimate);
                call_builder.clone().gas(gas_estimate * 130 / 100) // Apply multiplier
            } else {
                let call_builder = call_builder.clone();
                // let already_dispatched_error = chain_gateway_contract.abi().error("AlreadyDispatched").unwrap().get(0).unwrap();
                if let Err(contract_err) = call_builder.call().await {
                    use alloy::{contract::Error, transports::RpcError};
                    match contract_err {
                        Error::TransportError(RpcError::ErrorResp(e)) => {
                            if let Ok(revert_code) = e.deser_data::<i64>() {
                                // TODO: how to properly decipher this specific error?
                                info!(
                                    "Already Dispatched {}.{} (error: {revert_code})",
                                    event.target_chain_id, event.nonce
                                );
                            }
                            return Ok(());
                        }
                        _ => {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    }
                }
                call_builder
            };

            // Make the actual call
            match _call_builder.send().await {
                Ok(tx) => {
                    println!(
                        "Transaction sent {}.{} {:?}",
                        event.target_chain_id,
                        event.nonce,
                        tx.tx_hash()
                    );

                    return Ok(());
                }
                Err(err) => {
                    warn!("Failed to send: {:?}", err);
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Ok(())
    }
}
