use std::{str::FromStr, sync::Arc};

use alloy::{
    network::AnyNetwork,
    primitives::{Address, B256, ChainId, address, b256},
    providers::{
        Identity, Provider as _, ProviderBuilder, RootProvider,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    rpc::{
        client::PollerStream,
        types::{Filter, Log},
    },
};
use anyhow::Result;
use dashmap::DashMap;
use futures::stream::SelectAll;
use jsonrpsee::client_transport::ws::Url;
use libp2p::PeerId;
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};
use tokio_stream::{
    StreamExt as _,
    wrappers::{ReceiverStream, UnboundedReceiverStream},
};

use crate::{
    cfg::NodeConfig,
    crypto::SecretKey,
    db::Db,
    message::ExternalMessage,
    node::MessageSender,
    node_launcher::ResponseChannel,
    p2p_node::{LocalMessageTuple, OutboundMessageTuple},
    uccb::{RelayUserOp, SignUserOp, relayer::Relayer, signer::Signer},
};

pub type BundlerWallet = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;
// pub type BundlerWallet = RootProvider<AnyNetwork>;

const ERC7786_GATEWAY: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
const ERC7786_MESSAGE_SENT: B256 =
    b256!("0x7e7041a74283c799a9a3b681816e897e935a8f5c9e472685714c67cd6a578663");

pub struct Uccb {
    config: NodeConfig,
    secret_key: SecretKey,
    db: Arc<Db>,
    peer_id: PeerId,
    // message_sender: MessageSender,
    /// Send responses to requests down this channel. The `ResponseChannel` passed must correspond to a
    /// `ResponseChannel` received via `handle_request`.
    // request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    chain_id: ChainId,
    signer: Signer,
    relayer: Relayer,
    message_sender: Arc<MessageSender>,
    request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
}

impl Drop for Uccb {
    fn drop(&mut self) {
        tracing::info!("UUCB-{} stopped", self.chain_id);
    }
}

impl Uccb {
    pub async fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        db: Arc<Db>,
        message_sender_channel: UnboundedSender<OutboundMessageTuple>,
        local_sender_channel: UnboundedSender<LocalMessageTuple>,
        request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    ) -> Result<Self> {
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let chain_id = ChainId::from(config.eth_chain_id);

        let message_sender = Arc::new(MessageSender {
            our_shard: chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
            local_channel: local_sender_channel,
        });

        let relayer = Relayer::new(config.clone(), secret_key.clone(), db.clone()).await?;
        let signer = Signer::new(
            config.clone(),
            secret_key.clone(),
            db.clone(),
            message_sender.clone(),
        )
        .await?;

        tracing::info!("UUCB-{} started", chain_id);

        Ok(Self {
            config,
            secret_key,
            peer_id,
            db,
            chain_id,
            signer,
            relayer,
            message_sender,
            request_responses,
        })
    }

    async fn _start_bridge_node(
        relay_rx: UnboundedReceiver<RelayUserOp>,
        sign_rx: Receiver<SignUserOp>,
        mut watch_rx: SelectAll<PollerStream<Vec<Log>>>,
    ) -> Result<()> {
        let mut relay_rx = UnboundedReceiverStream::new(relay_rx);
        let mut sign_rx = ReceiverStream::new(sign_rx);
        loop {
            select!(
                //                 message = self.broadcasts.next() => {
                uop = relay_rx.next() => {
                    let _uop = uop.expect("infinite stream");
                }
                uop = sign_rx.next() => {
                    let _uop = uop.expect("infinite stream");
                }
                logs = watch_rx.next() => {
                    let _logs = logs.expect("infinite stream");
                }
            )
        }
    }
}
