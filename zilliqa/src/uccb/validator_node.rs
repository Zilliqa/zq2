use std::{collections::HashMap, str::FromStr, time::Duration};

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
}

impl ValidatorNode {
    pub async fn new(
        config: &Config,
        signer: &PrivateKeySigner,
        peer_id: PeerId,
        shard_id: u64,
        bridge_outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
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
        let output = call_builder.send().await?;
        let receipt = output.get_receipt().await?;
        info!("Receipt from {}: {receipt:?}", &chain_client.rpc_url);

        /*
            let chain_gateway: ChainGateway<ChainProvider> = client.get_contract();

            let function_call = chain_gateway.dispatch(
                event.source_chain_id,
                event.target,
                event.call,
                event.gas_limit,
                event.nonce,
                signatures.into_ordered_signatures(),
            );
            info!(
                "Preparing to send dispatch {}.{}",
                event.target_chain_id, event.nonce
            );

            let function_call = if client.legacy_gas_estimation {
                function_call.legacy()
            } else {
                function_call
            };

            for i in 1..6 {
                info!("Dispatch Attempt {:?}", i);

                // Get gas estimate
                // TODO: refactor configs specifically for zilliqa
                let _function_call = if client.legacy_gas_estimation {
                    let gas_estimate = match function_call.estimate_gas().await {
                        Ok(estimate) => estimate,
                        Err(err) => {
                            warn!("Failed to estimate gas, {:?}", err);
                            return Ok(());
                        }
                    };
                    info!("Gas estimate {:?}", gas_estimate);
                    function_call.clone().gas(gas_estimate * 130 / 100) // Apply multiplier
                } else {
                    let function_call = function_call.clone();
                    // `eth_call` does not seem to work on ZQ so it had to be skipped
                    // Simulate call, if fails decode error and exit early
                    if let Err(contract_err) = function_call.call().await {
                        match contract_err.decode_contract_revert::<ChainGatewayErrors>() {
                            Some(ChainGatewayErrors::AlreadyDispatched(_)) => {
                                info!(
                                    "Already Dispatched {}.{}",
                                    event.target_chain_id, event.nonce
                                );
                                return Ok(());
                            }
                            Some(err) => {
                                warn!("ChainGatewayError: {:?}", err);
                                return Ok(());
                            }
                            None => {
                                warn!("Some unknown error, {:?}", contract_err);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                        }
                    }
                    function_call
                };

                // Make the actual call
                match _function_call.send().await {
                    Ok(tx) => {
                        println!(
                            "Transaction Sent {}.{} {:?}",
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
        */

        Ok(())
    }
}
