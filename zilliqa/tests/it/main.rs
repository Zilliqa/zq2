mod consensus;
mod eth;

use std::{
    fmt::Debug,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ethers::{
    prelude::SignerMiddleware,
    providers::{HttpClientError, JsonRpcClient, JsonRpcError, Provider},
    signers::{LocalWallet, Signer},
};
use futures::{stream::BoxStream, Future, StreamExt};
use itertools::Itertools;
use jsonrpsee::{
    types::{Id, RequestSer, Response, ResponsePayload},
    RpcModule,
};
use k256::ecdsa::SigningKey;
use libp2p::PeerId;
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use zilliqa::{cfg::Config, crypto::SecretKey, message::Message, node::Node};

fn node() -> (
    SecretKey,
    BoxStream<'static, (PeerId, PeerId, Message)>,
    Node,
) {
    let secret_key = SecretKey::new().unwrap();

    let (message_sender, message_receiver) = mpsc::unbounded_channel();
    let message_receiver = UnboundedReceiverStream::new(message_receiver);
    // Augment the `message_receiver` stream to include the sender's `PeerId`.
    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let message_receiver = message_receiver
        .map(move |(dest, message)| (peer_id, dest, message))
        .boxed();
    let (reset_timeout_sender, reset_timeout_receiver) = mpsc::unbounded_channel();
    std::mem::forget(reset_timeout_receiver);

    (
        secret_key,
        message_receiver,
        Node::new(
            Config::default(),
            secret_key,
            message_sender,
            reset_timeout_sender,
        )
        .unwrap(),
    )
}

struct Network {
    _keys: Vec<SecretKey>,
    receivers: Vec<BoxStream<'static, (PeerId, PeerId, Message)>>,
    nodes: Vec<Arc<Mutex<Node>>>,
    rpc_modules: Vec<RpcModule<Arc<Mutex<Node>>>>,
}

impl Network {
    pub fn new(nodes: usize) -> Network {
        let (keys, receivers, mut nodes): (Vec<_>, Vec<_>, Vec<_>) =
            (0..nodes).map(|_| node()).multiunzip();

        for (i, node) in nodes.iter_mut().enumerate() {
            for (j, key) in keys.iter().enumerate() {
                if i == j {
                    continue;
                }
                node.add_peer(
                    key.to_libp2p_keypair().public().to_peer_id(),
                    key.node_public_key(),
                )
                .unwrap();
            }
        }

        let (nodes, rpc_modules) = nodes
            .into_iter()
            .map(|node| {
                let node = Arc::new(Mutex::new(node));
                let rpc_module = zilliqa::api::rpc_module(node.clone());
                (node, rpc_module)
            })
            .unzip();

        Network {
            _keys: keys,
            receivers,
            nodes,
            rpc_modules,
        }
    }

    pub async fn run_for(&mut self, ticks: usize) {
        let messages = futures::stream::select_all(&mut self.receivers);
        let mut messages = messages.take(ticks);

        while let Some((source, _destination, message)) = messages.next().await {
            // Currently, all messages are broadcast, so we replicate that behaviour here.
            for node in self.nodes.iter_mut() {
                node.lock()
                    .unwrap()
                    .handle_message(source, message.clone())
                    .unwrap();
            }
        }
    }

    pub async fn run_until(
        &mut self,
        mut condition: impl FnMut(&Network) -> bool,
        mut timeout: usize,
    ) -> Result<()> {
        while !condition(self) {
            if timeout == 0 {
                return Err(anyhow!("condition was still false after {timeout} ticks"));
            }

            self.run_for(1).await;

            timeout -= 1;
        }

        Ok(())
    }

    pub async fn run_until_async<Fut: Future<Output = bool>>(
        &mut self,
        mut condition: impl FnMut(Provider<LocalRpcClient>) -> Fut,
        mut timeout: usize,
    ) -> Result<()> {
        let provider = self.provider(0);
        while !condition(provider.clone()).await {
            if timeout == 0 {
                return Err(anyhow!("condition was still false after {timeout} ticks"));
            }

            self.run_for(1).await;

            timeout -= 1;
        }

        Ok(())
    }

    pub fn node(&self, index: usize) -> MutexGuard<Node> {
        self.nodes[index].lock().unwrap()
    }

    pub fn provider(&self, index: usize) -> Provider<LocalRpcClient> {
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: self.rpc_modules[index].clone(),
        };
        Provider::new(client)
    }
}

pub fn random_wallet(
    provider: Provider<LocalRpcClient>,
) -> SignerMiddleware<Provider<LocalRpcClient>, LocalWallet> {
    let wallet: LocalWallet = SigningKey::random(&mut rand::thread_rng()).into();
    let wallet = wallet.with_chain_id(0x8001u64);
    SignerMiddleware::new(provider, wallet)
}

/// An implementation of [JsonRpcClient] which sends requests directly to an [RpcModule], without making any network
/// calls.
#[derive(Debug, Clone)]
pub struct LocalRpcClient {
    id: Arc<AtomicU64>,
    rpc_module: RpcModule<Arc<Mutex<Node>>>,
}

#[async_trait]
impl JsonRpcClient for LocalRpcClient {
    type Error = HttpClientError;

    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let next_id = self.id.fetch_add(1, Ordering::SeqCst);
        let request = serde_json::value::to_raw_value(&params).unwrap();
        let payload = RequestSer::owned(Id::Number(next_id), method, Some(request));
        let request = serde_json::to_string(&payload).unwrap();

        let (response, _) = self.rpc_module.raw_json_request(&request, 1).await.unwrap();

        let response: Response<Rc<R>> = serde_json::from_str(&response.result).unwrap();

        let r = match response.payload {
            ResponsePayload::Result(r) => r,
            ResponsePayload::Error(e) => {
                return Err(JsonRpcError {
                    code: e.code() as i64,
                    message: e.message().to_owned(),
                    data: e.data().map(|d| serde_json::to_value(d).unwrap()),
                }
                .into());
            }
        };

        let r = Rc::try_unwrap(r.into_owned()).unwrap_or_else(|_| panic!());

        Ok(r)
    }
}
