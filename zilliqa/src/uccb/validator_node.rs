use std::{collections::HashMap, str::FromStr, time::Duration};

use alloy::{primitives::U256, signers::local::PrivateKeySigner};
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
    crypto::SecretKey,
    message::ExternalMessage,
    p2p_node::OutboundMessageTuple,
    uccb::{
        bridge_node::BridgeNode,
        cfg::Config,
        client::{ChainClient, ChainProvider /*, ContractInitializer*/},
        // contracts::{ChainGateway, ChainGatewayErrors},
        message::{Dispatch, InboundBridgeMessage, OutboundBridgeMessage},
        signature::SignatureTracker,
    },
};

type ChainID = U256;

#[derive(Debug)]
pub struct ValidatorNode {
    peer_id: PeerId,
    shard_id: u64,
    /// The following two message streams are used for networked messages.
    /// The sender is provided to the p2p coordinator, to forward messages to the node.
    bridge_outbound_message_sender: UnboundedSender<OutboundMessageTuple>,
    bridge_inbound_message_sender: UnboundedSender<ExternalMessage>,
    bridge_inbound_message_receiver: UnboundedReceiverStream<ExternalMessage>,
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
        let chain_clients = crate::uccb::create_chain_clients(config, signer).await?;
        let chain_clients: HashMap<ChainID, ChainClient> = chain_clients
            .into_iter()
            .map(|chain_client| (chain_client.chain_id, chain_client))
            .collect();

        let (bridge_inbound_message_sender, bridge_inbound_message_receiver) =
            mpsc::unbounded_channel::<ExternalMessage>();
        let bridge_inbound_message_receiver =
            UnboundedReceiverStream::new(bridge_inbound_message_receiver);

        Ok(ValidatorNode {
            peer_id,
            shard_id,
            bridge_outbound_message_sender,
            bridge_inbound_message_sender,
            bridge_inbound_message_receiver,
            chain_clients,
        })
    }

    pub fn get_bridge_inbound_message_sender(&self) -> UnboundedSender<ExternalMessage> {
        self.bridge_inbound_message_sender.clone()
    }

    pub async fn start(&mut self) -> Result<()> {
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
                            /*
                            // Send echo to respective source_chain_id to be verified, only if chain is supported
                            if let Some(sender) = bridge_node_message_senders.get(&echo.event.source_chain_id) {
                                sender.send(InboundBridgeMessage::Relay(echo))?;
                            }
                            */
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
                            /*
                            self.dispatch_message(dispatch).await?;
                            */
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

    /*
    async fn dispatch_message(&self, dispatch: Dispatch) -> Result<()> {
        let Dispatch {
            event, signatures, ..
        } = dispatch;

        let client = match self.chain_clients.get(&event.target_chain_id) {
            Some(client) => client,
            None => {
                warn!("Unsupported Chain ID");
                return Ok(());
            }
        };

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

        Ok(())
    }
    */
}
