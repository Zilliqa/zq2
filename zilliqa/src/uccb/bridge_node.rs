use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use alloy::{
    contract::{ContractInstance, DynCallBuilder},
    dyn_abi::EventExt,
    eips::BlockNumberOrTag,
    primitives::{Address, U256},
    providers::Provider,
    pubsub::PubSubFrontend,
    rpc::types::Filter,
};
use anyhow::Result;
use futures_util::stream::StreamExt;
use tokio::{
    select,
    sync::mpsc::{self, UnboundedSender},
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, info, warn};

use crate::{
    consensus::Consensus,
    uccb::{
        client::ChainClient,
        contracts,
        event::{DispatchedEvent, RelayEventSignatures, RelayedEvent},
        message::{Dispatch, Dispatched, InboundBridgeMessage, OutboundBridgeMessage, Relay},
        signature::SignatureTracker,
    },
};

#[derive(Debug)]
pub struct BridgeNode {
    event_signatures: HashMap<U256, RelayEventSignatures>,
    relay_nonces: HashSet<U256>,
    outbound_message_sender: UnboundedSender<OutboundBridgeMessage>,
    inbound_message_receiver: UnboundedReceiverStream<InboundBridgeMessage>,
    inbound_message_sender: UnboundedSender<InboundBridgeMessage>,
    pub chain_client: ChainClient,
    validators: HashSet<Address>,
    consensus: Arc<Mutex<Consensus>>,
    state_info: Arc<Mutex<StateInfo>>,
}

impl BridgeNode {
    pub async fn new(
        chain_client: ChainClient,
        outbound_message_sender: UnboundedSender<OutboundBridgeMessage>,
        consensus: Arc<Mutex<Consensus>>,
        state_info: Arc<Mutex<StateInfo>>,
    ) -> Result<Self> {
        let (inbound_message_sender, inbound_message_receiver) = mpsc::unbounded_channel();
        let inbound_message_receiver = UnboundedReceiverStream::new(inbound_message_receiver);

        Ok(BridgeNode {
            event_signatures: HashMap::new(),
            chain_client,
            validators: HashSet::new(),
            outbound_message_sender,
            inbound_message_receiver,
            inbound_message_sender,
            consensus,
            relay_nonces: HashSet::new(),
            state_info,
        })
    }

    pub fn get_inbound_message_sender(&self) -> UnboundedSender<InboundBridgeMessage> {
        self.inbound_message_sender.clone()
    }

    pub async fn listen_events(&mut self) -> Result<()> {
        info!("Start Listening: {:?}", self.chain_client.chain_id);

        let chain_gateway_abi = &contracts::chain_gateway::ABI;
        let relayed_event = chain_gateway_abi.event("Relayed").unwrap().get(0).unwrap();

        let chain_gateway_address = self.chain_client.chain_gateway_address;
        let relayed_filter = Filter::new()
            .address(chain_gateway_address)
            .event(&relayed_event.signature())
            .from_block(BlockNumberOrTag::Finalized);

        let dispatched_event = chain_gateway_abi
            .event("Dispatched")
            .unwrap()
            .get(0)
            .unwrap();
        let dispatched_filter = Filter::new()
            .address(chain_gateway_address)
            .event(&dispatched_event.signature())
            .from_block(BlockNumberOrTag::Finalized);

        let chain_provider = self.chain_client.provider.clone();
        let relayed_subscription = chain_provider.subscribe_logs(&relayed_filter).await?;
        let mut relayed_stream = relayed_subscription.into_stream();

        let dispatched_subscription = chain_provider.subscribe_logs(&dispatched_filter).await?;
        let mut dispatched_stream = dispatched_subscription.into_stream();

        loop {
            select! {
                Some(log) = relayed_stream.next() => {
                    debug!("Received a log on the relay event stream: {log:?}");
                    let event = RelayedEvent::try_from(relayed_event.decode_log(log.data(), true)?, self.chain_client.chain_id)?;
                    self.handle_relayed_event(event).await?;
                },
                Some(log) = dispatched_stream.next() => {
                    let event = DispatchedEvent::try_from(dispatched_event.decode_log(log.data(), true)?)?;
                    self.handle_dispatched_event(event)?;
                },
                Some(message) = self.inbound_message_receiver.next() => {
                    self.handle_bridge_message(message).await?;
                }
            }
        }
    }

    /// Handles incoming bridge related messages, either Relay from other validators or Dispatch from another chain
    /// running on a separate thread locally
    async fn handle_bridge_message(&mut self, message: InboundBridgeMessage) -> Result<()> {
        match message {
            InboundBridgeMessage::Dispatched(dispatch) => {
                info!("{dispatch:?} done");
                match self.event_signatures.get_mut(&dispatch.nonce) {
                    Some(event_signature) => {
                        event_signature.dispatched = true;
                    }
                    None => {
                        // Create new one instance if does not yet exist
                        self.event_signatures.insert(
                            dispatch.nonce,
                            RelayEventSignatures {
                                dispatched: true,
                                ..RelayEventSignatures::default()
                            },
                        );
                    }
                };

                if let Some(event_signature) = self.event_signatures.get(&dispatch.nonce) {
                    if let Some(event) = &event_signature.event {
                        let mut state_info = self.state_info.lock().unwrap();
                        state_info.pending_relayed_events.remove(event);
                    }
                }
            }
            InboundBridgeMessage::Relay(relay) => {
                self.handle_relay(&relay).await?;
            }
        }

        Ok(())
    }

    async fn handle_relayed_event(&mut self, event: RelayedEvent) -> Result<()> {
        if self.relay_nonces.contains(&event.nonce) {
            warn!("Ignoring a duplicate relay event {event:?} with ");
            return Ok(());
        }

        if let Some(RelayEventSignatures {
            dispatched: true, ..
        }) = self.event_signatures.get(&event.nonce)
        {
            warn!(
                "Ignoring a relay event {event:?} since one was already dispatched for this nonce"
            );
            return Ok(());
        }

        info!("Received a relay event: {event:?}");
        self.relay_nonces.insert(event.nonce);

        {
            let mut state_info = self.state_info.lock().unwrap();
            state_info.pending_relayed_events.insert(event.clone());
            state_info.relayed_events.push(event.clone());
        }

        self.outbound_message_sender
            .send(OutboundBridgeMessage::Relay(Relay {
                signature: event.sign(&self.chain_client.signer).await?,
                event,
            }))?;

        Ok(())
    }

    fn handle_dispatched_event(&mut self, event: DispatchedEvent) -> Result<()> {
        info!(
            "Chain {} has received {event:?}",
            self.chain_client.chain_id
        );

        self.outbound_message_sender
            .send(OutboundBridgeMessage::Dispatched(Dispatched {
                chain_id: event.source_chain_id,
                nonce: event.nonce,
            }))?;

        Ok(())
    }

    async fn update_validators(&mut self) -> Result<()> {
        let validator_manager: ContractInstance<PubSubFrontend, _> =
            contracts::validator_manager::instance(
                self.chain_client.validator_manager_address,
                self.chain_client.provider.as_ref(),
            );
        let call_builder: DynCallBuilder<_, _, _> =
            validator_manager.function("getValidators", &[])?;
        let output = call_builder.call().await?;
        let validators: Vec<Address> = output[0]
            .as_array()
            .unwrap()
            .into_iter()
            .map(|value| value.as_address().unwrap())
            .collect();

        debug!("Validator set is: {validators:?}");
        self.validators = validators.into_iter().collect();
        Ok(())
    }

    fn has_supermajority(&self, signature_count: usize) -> bool {
        signature_count * 3 > self.validators.len() * 2
    }

    /// Handle message, verify and add to storage.
    /// If has supermajority then submit the transaction.
    async fn handle_relay(&mut self, echo: &Relay) -> Result<()> {
        let Relay { signature, event } = echo;
        let nonce = event.nonce;
        let event_hash = event.hash();

        let address = match signature.recover_address_from_prehash(&event_hash) {
            Ok(address) => {
                debug!("Recovered address is: {address}");
                address
            }
            Err(e) => {
                error!("Couldn't recover address ({e})");
                return Ok(());
            }
        };

        // update validator set in case it has changed
        self.update_validators().await?;
        if !self.validators.contains(&address) {
            warn!(
                "Ignoring {event:?} since it isn signed by {address} which isn't a UCCB validator"
            );
            return Ok(());
        }

        // TODO: handle case where validators sign different data to the same event
        let event_signatures = match self.event_signatures.get_mut(&nonce) {
            None => {
                let event_signatures =
                    RelayEventSignatures::new(event.clone(), address, *signature);
                self.event_signatures
                    .insert(nonce, event_signatures.clone());

                event_signatures
            }
            Some(event_signatures) => {
                // Only insert if it is the same event as the one stored
                let relay_event = if let Some(event) = &event_signatures.event {
                    event
                } else {
                    warn!("Found event_signature without event {:?}", event_signatures);
                    return Ok(());
                };

                if relay_event.hash() != event_hash {
                    warn!("Message bodies don't match, so reject {:?}", relay_event);
                    return Ok(());
                }

                if event_signatures.has_supermajority {
                    warn!("Ignoring a relay event that already has a supermajority {echo:?}");
                    return Ok(());
                }

                event_signatures
                    .signatures
                    .add_signature(address, *signature);

                event_signatures.clone()
            }
        };

        info!(
            "Handling relay event: {echo:?}, collected: {:?}",
            event_signatures.signatures.len()
        );

        // if leader and majority, create request to dispatch
        let consensus = self.consensus.lock().unwrap();
        let view = consensus.finalized_view();
        if let Some(block) = consensus.get_block_by_view(view)? {
            if consensus.are_we_leader_for_view(block.hash(), view)
                && self.has_supermajority(event_signatures.signatures.len())
            {
                info!("Sending out dispatch request for {:?}", &echo);

                self.event_signatures
                    .get_mut(&nonce)
                    .unwrap()
                    .has_supermajority = true;
                self.outbound_message_sender
                    .send(OutboundBridgeMessage::Dispatch(Dispatch {
                        event: event.clone(),
                        signatures: event_signatures.signatures.into_iter().collect(),
                    }))?;
            }
        }

        Ok(())
    }
}
