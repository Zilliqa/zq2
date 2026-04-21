use std::sync::Arc;

use alloy::{
    primitives::{Address, B256, address, b256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, PackedUserOperation},
};
use anyhow::Result;
use crossbeam::utils::Backoff;
use dashmap::DashMap;
use futures::StreamExt as _;
use libp2p::PeerId;
use revm::primitives::{Bytes, U256};
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinSet,
};

use crate::{
    cfg::NodeConfig,
    crypto::{Hash, SecretKey},
    uccb::{BlsUserOp, RelayUserOp, SignUserOp},
};

/// A signer polls the SOURCE_CHAIN for MessageSent events.
#[derive(Debug)]
pub struct Signer {
    config: NodeConfig,
    secret_key: SecretKey,
    sign_tx: Sender<SignUserOp>,
    sign_rx: Receiver<SignUserOp>,
}

impl Signer {
    /// Construct a SIGNER node.
    ///
    /// Spins up one connection for each chain/bundler; and stores them in a Map for later use.
    /// Spawns a number of worker threads to concurrently create and process UserOps.
    pub fn new(config: NodeConfig, secret_key: SecretKey) -> Self {
        let num_threads = crate::available_threads();
        let (sign_tx, sign_rx) = tokio::sync::mpsc::channel::<SignUserOp>(num_threads * 2);
        Self {
            secret_key,
            config,
            sign_tx,
            sign_rx,
        }
    }

    pub async fn start_signer(&mut self) -> Result<()> {
        // Spin up keep-alive connections to each ENTRYPOINT
        let providers = Arc::new(DashMap::with_capacity(self.config.bundlers.len()));
        tracing::info!("Spawn {} SIGNER bundlers", self.config.bundlers.len());
        for bundler in self.config.bundlers.iter() {
            let provider = ProviderBuilder::new().connect_hyper_http(bundler.rpc_url.clone());
            let chain_id = bundler.chain_id;
            providers.insert(chain_id, provider);
        }

        // 1. Retrieve the nonce
        // 2. Retrieve the userophash
        // 3. Sign the UserOp
        // 4. Send it to the RELAY_SET
        let secret_key = self.secret_key.clone();
        while let Some(mut rop) = self.sign_rx.recv().await {
            let Some(_provider) = providers.get(&rop.chain) else {
                tracing::warn!(chain_id = %rop.chain, "Missing provider");
                continue;
            };

            // retrieve nonce
            // match provider.call().await
            // retrieve userophash
            let userophash = Hash::EMPTY;
            // match provider.call().await
            let sig = secret_key
                .as_bls()
                .sign(blsful::SignatureSchemes::Basic, userophash.as_bytes())
                .unwrap();
            rop.userop.signature = sig.as_raw_value().to_compressed().into();
            // sign
            let relay_set = Self::get_relay_set();
            for peer in relay_set {
                // send to peer
            }
        }
        Ok(())
    }

    /// Compute the RELAY_SET
    ///
    /// Uses the given transaction_hash and block_hash to compute a pseudo-random set of peers.
    fn get_relay_set() -> Vec<PeerId> {
        // retrieve set of peers at height
        // sort by XOR-ing keys
        // grab top 3 only
        Vec::new()
    }

    pub async fn sign_userop(&self, op: SignUserOp) -> Result<()> {
        Ok(self.sign_tx.send(op).await?)
    }
}
