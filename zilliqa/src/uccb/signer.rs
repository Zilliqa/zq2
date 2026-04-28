use std::sync::Arc;

// use super::AlloyUserOperation;
use alloy::{
    primitives::{
        Address, Bytes, ChainId, U256,
        aliases::{B32, U192},
    },
    providers::Provider as _,
    rpc::types::{Filter, PackedUserOperation as AlloyUserOperation},
    sol_types::{SolEvent, SolValue},
};
use anyhow::{Context, Result};
use itertools::Itertools as _;
use libp2p::PeerId;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};
use tokio_stream::StreamExt as _;

use crate::{
    cfg::NodeConfig,
    crypto::{Hash, SecretKey},
    db::Db,
    message::{ExternalMessage, UccbUserOp},
    node::MessageSender,
    state::State,
    uccb::{SignUserOp, utils::get_user_op_hash},
};

/// A signer polls the SOURCE_CHAIN for MessageSent events.
#[derive(Debug)]
pub struct Signer {
    workers: JoinSet<()>,
}

impl Drop for Signer {
    fn drop(&mut self) {
        self.workers.abort_all();
    }
}

impl Signer {
    /// Construct a SIGNER node.
    ///
    /// Spins up one connection for each chain/bundler; and stores them in a Map for later use.
    /// Spawns a number of worker threads to concurrently create and process UserOps.
    pub async fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        db: Arc<Db>,
        message_sender: Arc<MessageSender>,
        watchers: Arc<super::Providers>,
    ) -> Result<Self> {
        let chain_id = ChainId::from(config.eth_chain_id);
        let state = Arc::new(State::new(db.state_trie()?, &config, db.clone())?);
        let mut workers = JoinSet::new();
        let (sign_tx, sign_rx) = tokio::sync::mpsc::unbounded_channel::<SignUserOp>();

        {
            let state = state.clone();
            let db = db.clone();
            let watchers = watchers.clone();
            let sign_tx = sign_tx.clone();
            workers.spawn(async move {
                if let Err(err) = Self::start_signer(
                    chain_id,
                    state,
                    db,
                    secret_key,
                    message_sender,
                    watchers,
                    sign_rx,
                    sign_tx,
                )
                .await
                {
                    tracing::error!(%err, "SIGNER error");
                }
            });
        }

        {
            let config = config.clone();
            let watchers = watchers.clone();
            workers.spawn(async move {
                if let Err(err) = Self::start_watcher(chain_id, config, watchers, sign_tx).await {
                    tracing::error!(%err, "SIGNER error");
                }
            });
        }

        Ok(Self { workers })
    }

    /// Watch for Events
    ///
    /// Opens persistent connections to each remote chain; and monitors the logs for MessageSent events.
    async fn start_watcher(
        chain_id: ChainId,
        config: NodeConfig,
        watchers: Arc<super::Providers>,
        sign_tx: UnboundedSender<SignUserOp>,
    ) -> Result<()> {
        tracing::info!(chains=%watchers.len(), "Watcher-{}", chain_id);
        if watchers.is_empty() {
            tracing::warn!("Watcher-{} terminated", chain_id);
            return Ok(());
        }

        // Listen for events
        let mut watch_rx = futures::stream::SelectAll::new();
        for remote in config.remote_chains.iter() {
            if let Some(watcher) = watchers.get(&remote.chain_id) {
                let (_, (_, gateway, _, watcher)) = watcher.pair();
                let filter = Filter::new()
                    .address(*gateway)
                    .event_signature(super::IERC7786GatewaySource::MessageSent::SIGNATURE_HASH);
                let stream = watcher.watch_logs(&filter).await?.into_stream();
                watch_rx.push(stream);
            }
        }

        while let Some(logs) = watch_rx.next().await {
            for log in logs {
                if log.removed {
                    continue;
                }
                // construct partial UserOp
                let userop = Self::new_user_op();

                let blk_hash = log.block_hash.expect("block_hash != none").into();
                let txn_hash = log.transaction_hash.expect("txn_hash != none").into();
                let chain = ChainId::from(0u64);
                let op = SignUserOp {
                    blk_hash,
                    txn_hash,
                    chain,
                    userop,
                };
                sign_tx.send(op)?;
            }
        }
        Ok(())
    }

    /// Sign the UserOps
    ///
    /// Calls the Entrypoint contracts to fill in the `nonce` field, and computes the UserOp hash.
    /// Signs the UserOp hash and transmits the signed UserOp to the selected Relayer.
    async fn start_signer(
        chain_id: ChainId,
        state: Arc<State>,
        db: Arc<Db>,
        secret_key: SecretKey,
        message_sender: Arc<MessageSender>,
        watchers: Arc<super::Providers>,
        mut sign_rx: UnboundedReceiver<SignUserOp>,
        sign_tx: UnboundedSender<SignUserOp>,
    ) -> Result<()> {
        tracing::info!(chains=%watchers.len(), "Signer-{}", chain_id);
        if watchers.is_empty() {
            tracing::warn!("Signer-{} terminated", chain_id);
            return Ok(());
        }

        // process user ops
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        while let Ok(SignUserOp {
            mut userop,
            chain,
            txn_hash,
            blk_hash,
        }) = sign_rx.try_recv()
        {
            let Some(watcher) = watchers.get(&chain) else {
                tracing::warn!(chain_id = %chain, "Missing provider");
                continue;
            };
            let (chain_id, (entrypoint, sender, gateway, provider)) = watcher.pair();

            // 1. Retrieve the nonce
            // TODO: Tackle parallel nonce limits e.g. https://www.alchemy.com/docs/wallets/reference/bundler-faqs#parallel-nonces
            let key = Self::pack_nonce_key(gateway, &txn_hash);
            let Ok(nonce) = super::IEntryPointNonces::new(*entrypoint, provider)
                .getNonce(*sender, key)
                .call()
                .await
            else {
                tracing::error!("getNonce()");
                // retry
                sign_tx.send(SignUserOp::new(userop, chain, txn_hash, blk_hash))?;
                continue;
            };
            userop.nonce = nonce;

            // 2. Compute the UserOp hash
            let uop_hash = Hash::from_bytes(
                get_user_op_hash(&userop.clone().into(), *entrypoint, *chain_id)?.as_slice(),
            )?;

            // 3. Sign the UserOp hash;
            let sig = secret_key
                .as_bls()
                .sign(blsful::SignatureSchemes::Basic, uop_hash.as_bytes())
                .unwrap();
            userop.signature = sig.as_raw_value().to_compressed().into();

            // 4. Send it to the RELAY_SET
            let relay_set = Self::get_relay_set(blk_hash, txn_hash, state.clone(), db.clone())?;
            for peer in relay_set {
                let uop = if peer == peer_id {
                    // Only send userop to self - userop_hash assures integrity
                    Some(userop.clone())
                } else {
                    None
                };
                let msg = ExternalMessage::UccbUserOp(UccbUserOp {
                    userop_hash: uop_hash,
                    block_hash: blk_hash,
                    public_key: secret_key.node_public_key(),
                    userop: uop,
                    signature: sig.into(),
                });
                message_sender.send_external_message(peer, msg)?;
            }
        }
        Ok(())
    }

    /// Compute a nonce key
    ///
    /// The upper 192-bits of the nonce are user-defined; with the lower 64-bits as a sequence.
    /// This function packs the gateway address and a pseudo-random value into these bits.
    ///
    /// NOTE: Some bundlers impose a limit on parallel nonces e.g. https://www.alchemy.com/docs/wallets/reference/bundler-faqs#parallel-nonces
    pub fn pack_nonce_key(gateway: &Address, txn_hash: &Hash) -> U192 {
        // U192 expects big-endian bytes
        let hash = B32::from_slice(&txn_hash.0[..4]);
        let bytes = (*gateway, hash).abi_encode_packed();
        U192::from_be_slice(bytes.as_slice())
    }

    /// Compute the RELAY_SET
    ///
    /// Uses the given transaction_hash and block_hash to compute a deterministic pseudo-random set of peers.
    fn get_relay_set(
        blk_hash: Hash,
        txn_hash: Hash,
        state: Arc<State>,
        db: Arc<Db>,
    ) -> Result<Vec<PeerId>> {
        // retrieve set of peers at height
        let block = db
            .get_transactionless_block(blk_hash.into())
            .transpose()
            .context("missing block")
            .flatten()?;
        let state = state.at_root(block.state_root_hash().into());

        // sort by XOR-ing keys
        // this produces a deterministic pseudo-random order.
        let mut stakers = state.get_stakers(block.header)?;
        let sort_key = U256::from_be_bytes(blk_hash.0).bitxor(U256::from_be_bytes(txn_hash.0));
        stakers.sort_by(|a, b| {
            let a = U256::from_be_slice(a.as_bytes().as_slice()).bitxor(sort_key);
            let b = U256::from_be_slice(b.as_bytes().as_slice()).bitxor(sort_key);
            a.cmp(&b)
        });

        // grab top 3 only
        let stakers = stakers
            .into_iter()
            .take(3) // the network must have > 3 stakers
            .map(|k| state.get_peer_id(k).unwrap().unwrap())
            .collect_vec();

        Ok(stakers)
    }

    /// Construct a partial UserOp
    ///
    /// Constructs a partial UserOp during the Watching stage; to be completed during the Signing stage.
    pub fn new_user_op() -> AlloyUserOperation {
        AlloyUserOperation {
            sender: Address::random(),
            nonce: U256::ZERO,
            factory: Some(Address::random()),
            factory_data: Some(Bytes::copy_from_slice(U256::random().as_le_slice())),
            call_data: Bytes::copy_from_slice(U256::random().as_le_slice()),
            call_gas_limit: U256::ZERO,
            verification_gas_limit: U256::ZERO,
            pre_verification_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            max_priority_fee_per_gas: U256::ZERO,
            paymaster: Some(Address::random()),
            paymaster_verification_gas_limit: Some(U256::ZERO),
            paymaster_post_op_gas_limit: Some(U256::ZERO),
            paymaster_data: Some(Bytes::copy_from_slice(U256::random().as_le_slice())),
            signature: Bytes::copy_from_slice(U256::random().as_le_slice()),
        }
    }
}
