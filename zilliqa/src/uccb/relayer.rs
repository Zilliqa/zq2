use std::{num::NonZeroUsize, sync::Arc};

use alloy::{
    primitives::{Address, ChainId},
    providers::Provider,
    rpc::types::{PackedUserOperation, SendUserOperation, SendUserOperationResponse},
    sol_types::SolValue,
};
use anyhow::{Context, Result};
use blsful::{Bls12381G2Impl, Signature};
use dashmap::DashMap;
use itertools::Itertools as _;
use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::{
    cfg::NodeConfig,
    crypto::{BlsSignature, Hash, NodePublicKey, SecretKey},
    db::Db,
    state::State,
    uccb::{BlsUserOp, RelayUserOp, uccb::BundlerWallet},
};

#[derive(Debug)]
pub struct Relayer {
    peer_id: PeerId,
    address: Address,
    secret_key: SecretKey,
    db: Arc<Db>,
    state: State,
    bundlers: Arc<DashMap<ChainId, (Address, BundlerWallet)>>,
    relay_tx: UnboundedSender<RelayUserOp>,
    relay_rx: UnboundedReceiver<RelayUserOp>,
    // providers: Arc<DashMap<ChainId, BundlerProvider>>,
    // temporarily cache signatures
    signatures: RwLock<lru::LruCache<Hash, BlsUserOp>>,
}

impl Relayer {
    /// Constructs a RELAYER node.
    ///
    pub async fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        db: Arc<Db>,
        bundlers: Arc<DashMap<ChainId, (Address, BundlerWallet)>>,
    ) -> Result<Self> {
        let (relay_tx, relay_rx) = tokio::sync::mpsc::unbounded_channel::<RelayUserOp>();
        let address = secret_key.to_evm_address();
        let state = State::new(db.state_trie()?, &config, db.clone())?;
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();

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
                        tracing::info!(%url, "Bundler");
                        bundlers.insert(bundler.chain_id, (entrypoint, provider));
                        continue;
                    }
                    tracing::error!(%url, "Bundler mismatch {} != {:?}", entrypoint, entrypoints);
                }
                Err(err) => tracing::error!(%err, "Bundler error"),
            }
        }

        Ok(Self {
            secret_key,
            address,
            relay_tx,
            relay_rx,
            db,
            state,
            peer_id,
            bundlers,
            signatures: RwLock::new(lru::LruCache::new(NonZeroUsize::new(1000).unwrap())),
        })
    }

    /// Start the RELAYER threads.
    ///
    /// Spins up one connection for each chain/bundler; and stores them for later use.
    /// Spawns a number of worker threads to concurrently submit UserOps.
    async fn start_relayer(&mut self) -> Result<()> {
        // TODO: Spawn worker threads to concurrently process messages.
        while let Some(op) = self.relay_rx.recv().await {
            let Some(bundler) = self.bundlers.get(&op.chain) else {
                tracing::warn!(chain_id = %op.chain, "UserOp missing bundler");
                continue;
            };
            let (_, (entrypoint, bundler)) = bundler.pair();

            let send_op = SendUserOperation::EntryPointV07(op.userop.clone());
            match bundler
                .raw_request::<_, SendUserOperationResponse>(
                    "eth_sendUserOperation".into(),
                    (send_op, entrypoint),
                )
                .await
            {
                Ok(SendUserOperationResponse { user_op_hash }) => {
                    let userophash = Hash::from_bytes(user_op_hash)?;
                    anyhow::ensure!(op.hash == userophash, "UserOp hash mismatch");
                    tracing::debug!(hash=%op.hash, chain_id=%op.chain, "UserOp submitted");
                    continue; // next userop
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

        // cache the userops
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
        let bop = self
            .signatures
            .write()
            .pop(&userop_hash)
            .context("UserOp signature lost")?;

        // multi sign it
        let signatures = bop
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

        let multi_signature = blsful::MultiSignature::from_signatures(signatures)?
            .as_raw_value()
            .to_compressed();

        // collect signers vector

        let message = (multi_signature.as_slice(), self.address).abi_encode();
        let signature = self.secret_key.sign(message.as_slice());

        let userop_sig = (message, signature.to_bytes()).abi_encode();

        // construct final UserOp
        let bop = bop.userop.unwrap();
        let final_uop = RelayUserOp {
            userop: PackedUserOperation {
                signature: userop_sig.into(), // replace the signature with multi-sig
                ..bop
            },
            chain: 0,
            hash: userop_hash,
        };

        // push UserOp to the sending queue
        self.relay_tx.send(final_uop)?;

        Ok(())
    }
}
