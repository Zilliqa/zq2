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
    uccb::{RelayUserOp, SignUserOp, signer::Signer},
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
}

impl Drop for Uccb {
    fn drop(&mut self) {
        tracing::info!(chain_id=%self.chain_id, "UUCB shutdown");
    }
}

impl Uccb {
    pub async fn new(config: NodeConfig, secret_key: SecretKey, db: Arc<Db>) -> Result<Self> {
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let chain_id = ChainId::from(config.eth_chain_id);

        // used for submitting UserOp
        let bundlers = Arc::new(DashMap::with_capacity(config.remote_chains.len()));
        for bundler in config.remote_chains.iter() {
            let url = Url::from_str(&bundler.bundler_url)?;
            let provider = ProviderBuilder::new().connect(url.as_str()).await?;
            match provider
                .raw_request::<(), Vec<Address>>("eth_supportedEntryPoints".into(), ())
                .await
            {
                Ok(entrypoints) => {
                    let entrypoint = bundler.entrypoint;
                    if entrypoints.contains(&entrypoint) {
                        tracing::info!(%url, "UCCB bundler");
                        bundlers.insert(bundler.chain_id, (entrypoint, provider));
                        continue;
                    }
                    tracing::error!(%url, "UCCB mismatch {} != {:?}", entrypoint, entrypoints);
                }
                Err(err) => tracing::error!(%err, "UCCB error"),
            }
        }

        // // used to call Entrypoint contract
        // let watchers = Arc::new(DashMap::with_capacity(config.remote_chains.len()));

        // // used to listen for on-chain Events
        // let mut watch_rx = futures::stream::SelectAll::new();
        // for watcher in config.remote_chains.iter() {
        //     let url = Url::from_str(&watcher.watcher_url)?;
        //     let provider = ProviderBuilder::new().connect(url.as_str()).await?;
        //     match provider.get_chain_id().await {
        //         Ok(id) => {
        //             if chain_id == id {
        //                 tracing::info!(%url, "UCCB watcher");

        //                 let filter = Filter::new()
        //                     .address(ERC7786_GATEWAY)
        //                     .event_signature(ERC7786_MESSAGE_SENT);
        //                 let stream = provider.watch_logs(&filter).await?.into_stream();
        //                 watch_rx.push(stream);

        //                 watchers.insert(id, (watcher.entrypoint, provider));
        //                 continue;
        //             }
        //             tracing::error!(%url, "UCCB mismatch {} != {:?}", id, chain_id);
        //         }
        //         Err(err) => tracing::error!(%err, "UCCB error"),
        //     }
        // }

        // let num_threads = crate::available_threads();
        // let (sign_tx, sign_rx) = tokio::sync::mpsc::channel::<SignUserOp>(num_threads * 2);
        // let (relay_tx, relay_rx) = tokio::sync::mpsc::unbounded_channel::<RelayUserOp>();

        // let handle = tokio::spawn(async move {
        //     if let Err(err) = Self::start_bridge_node(relay_rx, sign_rx, watch_rx).await {
        //         tracing::error!(%err, "UCCB error");
        //     }
        // });

        let signer = Signer::new(config.clone(), secret_key.clone(), db.clone()).await?;

        Ok(Self {
            config,
            secret_key,
            peer_id,
            db,
            chain_id,
            signer,
        })
    }

    async fn start_bridge_node(
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
                    let uop = uop.expect("infinite stream");
                }
                uop = sign_rx.next() => {
                    let uop = uop.expect("infinite stream");
                }
                logs = watch_rx.next() => {
                    let logs = logs.expect("infinite stream");
                }
            )
        }
    }
}
