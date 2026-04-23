use std::{str::FromStr as _, sync::Arc};

use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256, address, b256},
    providers::{Provider as _, ProviderBuilder},
    rpc::types::{Filter, PackedUserOperation},
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use itertools::Itertools as _;
use jsonrpsee::client_transport::ws::Url;
use libp2p::PeerId;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinSet,
};
use tokio_stream::StreamExt as _;

use crate::{
    cfg::NodeConfig,
    crypto::{Hash, SecretKey},
    db::Db,
    state::State,
    uccb::{SignUserOp, uccb::BundlerWallet},
};

const ERC7786_GATEWAY: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
const ERC7786_MESSAGE_SENT: B256 =
    b256!("0x7e7041a74283c799a9a3b681816e897e935a8f5c9e472685714c67cd6a578663");

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
    pub async fn new(config: NodeConfig, secret_key: SecretKey, db: Arc<Db>) -> Result<Self> {
        let state = Arc::new(State::new(db.state_trie()?, &config, db.clone())?);
        let num_threads = crate::available_threads();
        let (sign_tx, sign_rx) = tokio::sync::mpsc::channel::<SignUserOp>(num_threads * 2);

        let mut workers = JoinSet::new();

        let sign_key = secret_key.clone();
        let sign_config = config.clone();
        workers.spawn(async move {
            if let Err(err) = Self::start_signer(state, db, sign_config, sign_key, sign_rx).await {
                tracing::error!(%err, "SIGNER error");
            }
        });

        let watch_config = config.clone();
        workers.spawn(async move {
            if let Err(err) = Self::start_watcher(watch_config, sign_tx).await {
                tracing::error!(%err, "WATCHER error");
            }
        });

        Ok(Self { workers })
    }

    async fn start_watcher(config: NodeConfig, sign_tx: Sender<SignUserOp>) -> Result<()> {
        let chain_id = ChainId::from(config.eth_chain_id);

        let mut watch_rx = futures::stream::SelectAll::new();
        for watcher in config.remote_chains.iter() {
            let url = Url::from_str(&watcher.watcher_url)?;
            let provider = ProviderBuilder::new().connect(url.as_str()).await?;
            match provider.get_chain_id().await {
                Ok(id) => {
                    if chain_id == id {
                        tracing::info!(%url, "Watcher");
                        let filter = Filter::new()
                            .address(ERC7786_GATEWAY)
                            .event_signature(ERC7786_MESSAGE_SENT);
                        let stream = provider.watch_logs(&filter).await?.into_stream();
                        watch_rx.push(stream);
                        continue;
                    }
                    tracing::error!(%url, "Watcher mismatch {} != {:?}", id, chain_id);
                }
                Err(err) => tracing::error!(%err, "Watcher error"),
            }
        }

        while let Some(logs) = watch_rx.next().await {
            for log in logs {
                if log.removed {
                    continue;
                }
                // construct partial UserOp
                let userop = Self::new_user_op();
                let op = SignUserOp {
                    blk_hash: log.block_hash.expect("block_hash != none").into(),
                    txn_hash: log.transaction_hash.expect("txn_hash != none").into(),
                    chain: 0,
                    userop: userop,
                };
                tracing::trace!(hash=%op.txn_hash,"MessageSent");
                sign_tx.send(op).await?
            }
        }
        Ok(())
    }

    async fn start_signer(
        state: Arc<State>,
        db: Arc<Db>,
        config: NodeConfig,
        secret_key: SecretKey,
        mut sign_rx: Receiver<SignUserOp>,
    ) -> Result<()> {
        let chain_id = ChainId::from(config.eth_chain_id);
        // used to call Entrypoint contract
        let watchers = DashMap::with_capacity(config.remote_chains.len());
        for watcher in config.remote_chains.iter() {
            let url = Url::from_str(&watcher.watcher_url)?;
            let provider = ProviderBuilder::new().connect(url.as_str()).await?;
            match provider.get_chain_id().await {
                Ok(id) => {
                    if chain_id == id {
                        tracing::info!(%url, "Signer");
                        watchers.insert(id, (watcher.entrypoint, provider));
                        continue;
                    }
                    tracing::error!(%url, "Signer mismatch {} != {:?}", id, chain_id);
                }
                Err(err) => tracing::error!(%err, "Signer error"),
            }
        }

        while let Some(mut rop) = sign_rx.recv().await {
            let Some(watcher) = watchers.get(&rop.chain) else {
                tracing::warn!(chain_id = %rop.chain, "Missing provider");
                continue;
            };
            let (_, (_entrypoint, _bundler)) = watcher.pair();

            // 1. Retrieve the nonce
            // 2. Retrieve the userophash
            let userophash = Hash::ZERO;

            // 3. Sign the UserOp
            let sig = secret_key
                .as_bls()
                .sign(blsful::SignatureSchemes::Basic, userophash.as_bytes())
                .unwrap();
            rop.userop.signature = sig.as_raw_value().to_compressed().into();

            // 4. Send it to the RELAY_SET
            let relay_set =
                Self::get_relay_set(rop.blk_hash, rop.txn_hash, state.clone(), db.clone())?;
            for _peer in relay_set {
                // send to peer
            }
        }
        Ok(())
    }

    /// Compute the RELAY_SET
    ///
    /// Uses the given transaction_hash and block_hash to compute a pseudo-random set of peers.
    fn get_relay_set(
        blk_hash: Hash,
        txn_hash: Hash,
        state: Arc<State>,
        db: Arc<Db>,
    ) -> Result<Vec<PeerId>> {
        // retrieve set of peers at height
        let block = db
            .get_block(blk_hash.into())
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

    /// Construct a UserOp
    pub fn new_user_op() -> PackedUserOperation {
        PackedUserOperation {
            sender: Address::random(),
            nonce: U256::ZERO,
            factory: Some(Address::random()),
            factory_data: Some(Bytes::new()),
            call_data: Bytes::new(),
            call_gas_limit: U256::random(),
            verification_gas_limit: U256::random(),
            pre_verification_gas: U256::random(),
            max_fee_per_gas: U256::random(),
            max_priority_fee_per_gas: U256::random(),
            paymaster: Some(Address::random()),
            paymaster_verification_gas_limit: Some(U256::random()),
            paymaster_post_op_gas_limit: Some(U256::random()),
            paymaster_data: Some(Bytes::new()),
            signature: Bytes::new(),
        }
    }
}
