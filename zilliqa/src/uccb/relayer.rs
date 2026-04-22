use std::{io::Read, num::NonZeroUsize, sync::Arc, time::Duration};

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::{PackedUserOperation, SendUserOperation, SendUserOperationResponse},
};
use anyhow::{Context, Result};
use blsful::{Bls12381G2Impl, Signature};
use dashmap::DashMap;
use itertools::Itertools as _;
use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};

use crate::{
    cfg::NodeConfig,
    crypto::{BlsSignature, Hash, NodePublicKey, SecretKey},
    db::Db,
    state::State,
    uccb::{BlsUserOp, RelayUserOp},
};

#[derive(Debug)]
pub struct Relayer {
    peer_id: PeerId,
    config: NodeConfig,
    address: Address,
    secret_key: SecretKey,
    db: Arc<Db>,
    state: State,
    relay_tx: UnboundedSender<RelayUserOp>,
    relay_rx: UnboundedReceiver<RelayUserOp>,
    // providers: Arc<DashMap<ChainId, BundlerProvider>>,
    // temporarily cache signatures
    signatures: RwLock<lru::LruCache<Hash, BlsUserOp>>,
}

impl Relayer {
    /// Constructs a RELAYER node.
    ///
    pub fn new(config: NodeConfig, secret_key: SecretKey, db: Arc<Db>) -> Result<Self> {
        let (relay_tx, relay_rx) = tokio::sync::mpsc::unbounded_channel::<RelayUserOp>();
        let address = secret_key.to_evm_address();
        let state = State::new(db.state_trie()?, &config, db.clone())?;
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        Ok(Self {
            config,
            secret_key,
            address,
            relay_tx,
            relay_rx,
            db,
            state,
            peer_id,
            signatures: RwLock::new(lru::LruCache::new(NonZeroUsize::new(1000).unwrap())),
        })
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
    pub fn collect_userop(
        &self,
        peer: PeerId,
        block_hash: Hash,
        userop_hash: Hash,
        public_key: NodePublicKey,
        signature: BlsSignature,
    ) -> Result<()> {
        self.self_collect_userop(peer, block_hash, userop_hash, public_key, signature, None)
    }

    // Used for the self-node
    pub fn self_collect_userop(
        &self,
        peer: PeerId,
        block_hash: Hash,
        userop_hash: Hash,
        public_key: NodePublicKey,
        signature: BlsSignature,
        userop: Option<PackedUserOperation>,
    ) -> Result<()> {
        // validate signature
        public_key.verify(userop_hash.as_bytes(), signature)?;

        let Some(block) = self.db.get_block(block_hash.into())? else {
            return Err(anyhow::anyhow!("Missing block"));
        };
        let state = self.state.at_root(block.state_root_hash().into());

        // retrieve stake
        let Some(stake) = state.get_stake(public_key, block.header)? else {
            return Err(anyhow::anyhow!("Missing stake"));
        };
        let Some(peer_id) = state.get_peer_id(public_key)? else {
            return Err(anyhow::anyhow!("Missing peer id"));
        };
        // check if peer_id matches
        if peer_id != peer {
            return Err(anyhow::anyhow!("Peer id mismatch"));
        }

        // cache the thing
        let bop = self
            .signatures
            .write()
            .get_or_insert_mut_ref(&userop_hash, || BlsUserOp::default());

        if userop.is_some() && peer_id == self.peer_id {
            bop.userop = userop;
        }
        bop.signatures.push(signature);
        bop.stake = bop.stake.saturating_sub(stake.get());

        // majority: promote
        if bop.userop.is_some() && bop.stake == 0 {
            self.relay_userop(userop_hash)?;
        }
        Ok(())
    }

    /// Send UserOpHash
    ///
    /// Multi-sign the UserOp; and queues it for sending to the Bundler.
    pub fn relay_userop(&self, userop_hash: Hash) -> Result<()> {
        let bls_uop = self
            .signatures
            .write()
            .pop(&userop_hash)
            .context("UserOp signature lost")?;

        // multi sign it
        let signatures = bls_uop
            .signatures
            .iter()
            .map(|s| {
                Signature::<Bls12381G2Impl>::Basic(
                    // Underlying type is compressed G2Affine
                    blsful::inner_types::G2Projective::from_compressed(
                        s.to_bytes()
                            .as_slice()
                            .try_into()
                            .expect("previously validated"),
                    )
                    .expect("previously validated"),
                )
            })
            .collect_vec();
        let multi_signature = blsful::MultiSignature::from_signatures(signatures)?;

        // construct final UserOp
        let final_uop = RelayUserOp {
            userop: bls_uop.userop.unwrap(),
            chain: 0,
            hash: userop_hash,
        };

        // push UserOp to the sending queue
        self.relay_tx.send(final_uop)?;

        Ok(())
    }
}
