mod consensus;
mod eth;
mod web3;

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
    TestNode,
    BoxStream<'static, (PeerId, Option<PeerId>, Message)>,
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

    let node = Node::new(
        Config::default(),
        secret_key,
        message_sender,
        reset_timeout_sender,
    )
    .unwrap();
    let node = Arc::new(Mutex::new(node));
    let rpc_module: RpcModule<Arc<Mutex<Node>>> = zilliqa::api::rpc_module(node.clone());

    (
        TestNode {
            peer_id: secret_key.to_libp2p_keypair().public().to_peer_id(),
            secret_key,
            inner: node,
            rpc_module,
        },
        message_receiver,
    )
}

/// A node within a test [Network].
struct TestNode {
    secret_key: SecretKey,
    peer_id: PeerId,
    inner: Arc<Mutex<Node>>,
    rpc_module: RpcModule<Arc<Mutex<Node>>>,
}

struct Network {
    // We keep `nodes` and `receivers` separate so we can independently borrow each half of this struct, while keeping
    // the borrow checker happy.
    nodes: Vec<TestNode>,
    /// A stream of messages from each node. The stream items are a tuple of (source, destination, message).
    /// If the destination is `None`, the message is a broadcast.
    receivers: Vec<BoxStream<'static, (PeerId, Option<PeerId>, Message)>>,
}

impl Network {
    pub fn new(nodes: usize) -> Network {
        let (nodes, receivers): (Vec<_>, Vec<_>) = (0..nodes).map(|_| node()).unzip();

        nodes
            .iter()
            .enumerate()
            .cartesian_product(nodes.iter().enumerate())
            .for_each(|((i, n1), (j, n2))| {
                if i != j {
                    let key = n2.secret_key;
                    n1.inner
                        .lock()
                        .unwrap()
                        .add_peer(
                            key.to_libp2p_keypair().public().to_peer_id(),
                            key.node_public_key(),
                        )
                        .unwrap();
                }
            });

        Network { nodes, receivers }
    }

    pub async fn run_for(&mut self, ticks: usize) {
        let messages = futures::stream::select_all(&mut self.receivers);
        let mut messages = messages.take(ticks);

        while let Some((source, destination, message)) = messages.next().await {
            // Respect the destination if it is set and only send it to one
            for node in self.nodes.iter() {
                if let Some(dest) = destination {
                    if dest == node.peer_id {
                        node.inner
                            .lock()
                            .unwrap()
                            .handle_message(source, message.clone())
                            .unwrap();
                        break;
                    }
                    continue;
                }
                // Broadcast when no destination is set
                node.inner
                    .lock()
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
        self.nodes[index].inner.lock().unwrap()
    }

    pub fn provider(&self, index: usize) -> Provider<LocalRpcClient> {
        let client = LocalRpcClient {
            id: Arc::new(AtomicU64::new(0)),
            rpc_module: self.nodes[index].rpc_module.clone(),
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

/// A helper macro to deploy a contract. Provide the relative path containing the contract, the name of the contract, a
/// wallet and the network. This will include the contract source in the test binary and compile the contract at
/// runtime.
macro_rules! deploy_contract {
    ($path:expr, $contract:expr, $wallet:ident, $network:ident) => {{
        // Include the contract source directly in the binary.
        let contract_source = include_bytes!($path);

        // Write the contract source to a file, so `solc` can compile it.
        let mut contract_file = tempfile::Builder::new().suffix(".sol").tempfile().unwrap();
        std::io::Write::write_all(&mut contract_file, contract_source).unwrap();

        //// Compile the contract.
        //let out = ethers::solc::Solc::default()
        //    .compile_source(contract_file.path())
        //    .unwrap();

        let sc = ethers::solc::Solc::default();
        //println!("sc args: {:?}", sc.args);
        //sc.args

        //let compiler_input = CompilerInput::new(contract_file.path().as_ref()).unwrap();
        let mut compiler_input = CompilerInput::new(contract_file.path()).unwrap();
        let compiler_input = compiler_input.first_mut().unwrap();
        compiler_input.settings.evm_version = Some(EvmVersion::Paris);

        let out = sc.compile::<CompilerInput>(compiler_input).unwrap();

        let contract = out
            .get(contract_file.path().to_str().unwrap(), $contract)
            .unwrap();
        let abi = contract.abi.unwrap().clone();
        let abi_ret = contract.abi.unwrap().clone();
        let bytecode = contract.bytecode().unwrap().clone();

        // Deploy the contract.
        let factory = DeploymentTxFactory::new(abi, bytecode, $wallet.clone());
        let deployment_tx = factory.deploy(()).unwrap().tx;
        let hash = $wallet
            .send_transaction(deployment_tx, None)
            .await
            .unwrap()
            .tx_hash();

        $network
            .run_until_async(
                |p| async move { p.get_transaction_receipt(hash).await.unwrap().is_some() },
                10,
            )
            .await
            .unwrap();

        (hash, abi_ret)
    }};
}

//macro_rules! contract_abi {
//    ($path:expr, $contract:expr, $wallet:ident, $network:ident) => {{
//        // Include the contract source directly in the binary.
//        let contract_source = include_bytes!($path);
//
//        // Write the contract source to a file, so `solc` can compile it.
//        let mut contract_file = tempfile::Builder::new().suffix(".sol").tempfile().unwrap();
//        std::io::Write::write_all(&mut contract_file, contract_source).unwrap();
//
//        let sc = ethers::solc::Solc::default();
//
//        //let compiler_input = CompilerInput::new(contract_file.path().as_ref()).unwrap();
//        let mut compiler_input = CompilerInput::new(contract_file.path()).unwrap();
//        let mut compiler_input = compiler_input.first_mut().unwrap();
//        compiler_input.settings.evm_version = Some(EvmVersion::Paris);
//
//        let out = sc.compile::<CompilerInput>(compiler_input).unwrap();
//
//        let contract = out
//            .get(contract_file.path().to_str().unwrap(), $contract)
//            .unwrap();
//        let abi = contract.abi.unwrap().clone();
//        let bytecode = contract.bytecode().unwrap().clone();
//
//        // Deploy the contract.
//        let factory = DeploymentTxFactory::new(abi, bytecode, $wallet.clone());
//        let deployment_tx = factory.deploy(()).unwrap().tx;
//        let hash = $wallet
//            .send_transaction(deployment_tx, None)
//            .await
//            .unwrap()
//            .tx_hash();
//
//        $network
//            .run_until_async(
//                |p| async move { p.get_transaction_receipt(hash).await.unwrap().is_some() },
//                10,
//            )
//            .await
//            .unwrap();
//
//        hash
//    }};
//}


use deploy_contract;

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
