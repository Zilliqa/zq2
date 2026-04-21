use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::{SendUserOperation, SendUserOperationResponse},
};
use anyhow::Result;
use dashmap::DashMap;
use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};

use crate::{
    cfg::NodeConfig,
    crypto::{BlsSignature, Hash, SecretKey},
    uccb::{BlsUserOp, RelayUserOp},
};

#[derive(Debug)]
pub struct Relayer {
    config: NodeConfig,
    address: Address,
    secret_key: SecretKey,
    relay_tx: UnboundedSender<RelayUserOp>,
    relay_rx: UnboundedReceiver<RelayUserOp>,
    // providers: Arc<DashMap<ChainId, BundlerProvider>>,
    // temporarily cache signatures
    signatures: RwLock<lru::LruCache<Hash, BlsUserOp>>,
}

impl Relayer {
    /// Constructs a RELAYER node.
    ///
    pub fn new(config: NodeConfig, secret_key: SecretKey) -> Self {
        let num_threads = crate::available_threads();
        let (relay_tx, relay_rx) = tokio::sync::mpsc::unbounded_channel::<RelayUserOp>();

        let address = secret_key.to_evm_address();
        Self {
            config,
            secret_key,
            address,
            relay_tx,
            relay_rx,
            signatures: RwLock::new(lru::LruCache::new(NonZeroUsize::new(1000).unwrap())),
        }
    }

    /// Start the RELAYER threads.
    ///
    /// Spins up one connection for each chain/bundler; and stores them for later use.
    /// Spawns a number of worker threads to concurrently submit UserOps.
    pub async fn start_relayer(&mut self) -> Result<()> {
        // Spin up keep-alive connections to each BUNDLER
        let providers = Arc::new(DashMap::with_capacity(self.config.bundlers.len()));
        tracing::info!("Spawn {} RELAYER bundlers", self.config.bundlers.len());
        for bundler in self.config.bundlers.iter() {
            let provider = ProviderBuilder::new().connect_hyper_http(bundler.rpc_url.clone());
            let chain_id = bundler.chain_id;
            providers.insert(chain_id, provider);
        }

        // Spawn worker threads to concurrently process messages.
        while let Some(op) = self.relay_rx.recv().await {
            let Some(provider) = providers.get(&op.chain) else {
                tracing::warn!(chain_id = %op.chain, "UserOp missing bundler");
                continue;
            };

            let send_op = SendUserOperation::EntryPointV07(op.userop.clone());
            match provider
                .raw_request::<_, SendUserOperationResponse>(
                    "eth_sendUserOperation".into(),
                    (send_op, super::ENTRYPOINT_V08),
                )
                .await
            {
                Ok(SendUserOperationResponse { user_op_hash }) => {
                    let userophash = Hash::from_bytes(user_op_hash)?;
                    anyhow::ensure!(op.hash == userophash, "UserOp hash mismatch");
                    tracing::debug!(hash=%op.hash, chain_id=%op.chain, "UserOp submitted");
                    break;
                }
                Err(err) => {
                    tracing::error!(%err, "UserOp error");
                    self.relay_tx.send(op)?;
                }
            };
        }
        Ok(())
    }

    /// Collect UserOpHash signature
    ///
    /// Collect signatures, until majority, then compute the final signature.
    pub fn collect_userop(&self, peer: PeerId, hash: Hash, sig: BlsSignature) -> Result<()> {
        // TODO: validate signature
        // TODO: retrieve stake

        // minority: cache
        if let Some(e) = self.signatures.write().get_mut(&hash) {
            e.signatures.push(sig);
            e.stake += 0;
        }

        // majority: promote
        Ok(())
    }

    /// Send UserOpHash
    ///
    /// Multi-sign the UserOp; and queues it for sending to the Bundler.
    pub fn relay_userop(&self, hash: Hash) -> Result<()> {
        let bls_uop = self
            .signatures
            .write()
            .pop(&hash)
            .expect("UserOp signatures missing");

        // multi sign it

        // construct final UserOp
        let final_uop = RelayUserOp {
            userop: bls_uop.userop,
            chain: 0,
            hash: bls_uop.hash,
        };

        // push UserOp to the sending queue
        self.relay_tx.send(final_uop)?;

        Ok(())
    }
}
