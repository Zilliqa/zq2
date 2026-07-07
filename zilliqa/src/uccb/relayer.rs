use std::{num::NonZeroUsize, sync::Arc};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, B256, ChainId, U256},
    providers::{Provider, utils::eip1559_default_estimator},
    rpc::types::{Filter, PackedUserOperation as AlloyUserOperation, UserOperationGasEstimation},
    sol_types::{SolEvent, SolValue},
};
use alloy_chains::Chain;
use anyhow::{Context, Result};
use bitvec::{bitarr, order::Msb0};
use blsful::{Bls12381G2Impl, Signature};
use itertools::Itertools as _;
use libp2p::PeerId;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};
use tokio_stream::StreamExt as _;
use tokio_util::time::DelayQueue;

use crate::{
    api::to_hex::ToHex,
    cfg::NodeConfig,
    crypto::{BlsSignature, Hash, NodePublicKey, SecretKey},
    db::Db,
    message::MAX_COMMITTEE_SIZE,
    state::State,
    uccb::{BlsUserOp, EndPoint, IERC4337Extra::MessageReceived, RelayUserOp},
};

#[derive(Debug)]
pub struct Relayer {
    peer_id: PeerId,
    _address: Address,
    secret_key: SecretKey,
    db: Arc<Db>,
    state: State,
    relay_tx: UnboundedSender<RelayUserOp>,
    bls_uop: Mutex<LruCache<Hash, BlsUserOp>>,
    workers: JoinSet<()>,
    chain: Chain,
}

impl Drop for Relayer {
    fn drop(&mut self) {
        self.workers.abort_all();
    }
}

impl Relayer {
    /// Constructs a RELAYER node.
    ///
    pub async fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        db: Arc<Db>,
        providers: Arc<super::Providers>,
    ) -> Result<Self> {
        let (relay_tx, relay_rx) = tokio::sync::mpsc::unbounded_channel::<RelayUserOp>();
        let address = secret_key.to_evm_address();
        let state = State::new(db.state_trie()?, &config, db.clone())?;
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let chain = Chain::from_id(config.eth_chain_id);

        let mut workers = JoinSet::new();

        // cache recent userops
        let bls_uop = Mutex::new(LruCache::new(
            NonZeroUsize::new(providers.len() * 100).unwrap_or(NonZeroUsize::MIN),
        ));

        {
            let relay_tx = relay_tx.clone();
            let config = config.clone();
            let providers = providers.clone();
            workers.spawn(async move {
                if let Err(err) =
                    Self::start_relayer(config, secret_key, relay_tx, relay_rx, providers).await
                {
                    tracing::error!(%err, "Relayer exception");
                }
            });
        }

        // TODO: Monitor for UserOperationEvent()
        {
            workers.spawn(async move {
                if let Err(err) = Self::start_monitor(config, providers).await {
                    tracing::error!(%err, "Monitor exception");
                }
            });
        }

        Ok(Self {
            workers,
            secret_key,
            _address: address,
            relay_tx,
            db,
            state,
            peer_id,
            bls_uop,
            chain,
        })
    }

    async fn start_monitor(config: NodeConfig, watchers: Arc<super::Providers>) -> Result<()> {
        let chain = Chain::from_id(config.eth_chain_id);
        if watchers.is_empty() {
            tracing::warn!("Receiver({chain:?}): terminated");
            return Ok(());
        }
        tracing::info!(chains=%watchers.len(), "Receiver({chain:?}): started");

        // Cache last known height
        let mut heights =
            lru::LruCache::<ChainId, u64>::new(NonZeroUsize::new(watchers.len()).unwrap());

        // Schedule the polls according to average block-times.
        let mut poll_sched: DelayQueue<Chain> = DelayQueue::new();
        for remote in config.remote_chains.iter() {
            let chain = Chain::from_id(remote.chain_id);
            let period = chain
                .average_blocktime_hint()
                .unwrap_or(config.consensus.consensus_timeout);
            poll_sched.insert(chain, period);
        }

        // Subscribing to the live-stream results in 'latest' blocks that may get reorganized.
        // Manual polling is used to ensure that only finalized blocks are processed.
        while let Some(due) = poll_sched.next().await {
            // reschedule the poll
            let chain = due.into_inner();
            let period = chain
                .average_blocktime_hint()
                .unwrap_or(config.consensus.consensus_timeout);
            tracing::trace!(?period, ?chain, "Poll");
            let chain_id = chain.id();
            poll_sched.insert(chain, period);

            let logs = if let Some(watcher) = watchers.get(&chain_id) {
                let EndPoint {
                    gateway,
                    jsonrpc,
                    chain,
                    ..
                } = watcher.value();

                // 1. Check for progress
                let (cache_height, final_height) = if let Ok(Some(final_block)) = jsonrpc
                    .get_block_by_number(BlockNumberOrTag::Finalized)
                    .await
                {
                    let cache_height =
                        heights.get_or_insert_mut(chain.id(), || final_block.header.number);
                    if *cache_height >= final_block.header.number {
                        continue; // skip if stale
                    }
                    (cache_height, final_block.header.number)
                } else {
                    tracing::error!(?chain, "eth_getBlockByNumber(): transport");
                    continue; // skip on errors
                };

                // 2. Retrieve the latest set of finalized logs
                let filter = Filter::new()
                    .address(*gateway)
                    .from_block(BlockNumberOrTag::Number(cache_height.saturating_add(1)))
                    .to_block(BlockNumberOrTag::Number(final_height)) // ideally, this should be exactly one block length
                    .event_signature(super::IERC4337Extra::MessageReceived::SIGNATURE_HASH);
                let Ok(logs) = jsonrpc.get_logs(&filter).await else {
                    tracing::error!(?chain, "eth_getLogs(): transport");
                    continue; // skip on errors
                };
                tracing::trace!(
                    count=%logs.len(),
                    range=?(cache_height.saturating_add(1)..=final_height),
                    "MessageReceived({chain:?}): events",
                );
                *cache_height = final_height; // update final
                logs
            } else {
                continue;
            };

            for log in logs.into_iter() {
                if let Ok(MessageReceived { receiveId, .. }) =
                    super::IERC4337Extra::MessageReceived::decode_log_data(log.data())
                {
                    tracing::info!(send_id=%receiveId, "Receiver({chain:?}): received");
                }
            }
        }
        Ok(())
    }

    /// Submit the UserOp
    ///
    /// Handles the submission to the Bundler, skips if the UserOp has been submitted.
    async fn submit_userop(
        relay_uop: &mut RelayUserOp,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        let RelayUserOp {
            userop,
            userop_hash,
            chain,
            send_id,
            ..
        } = relay_uop;
        let d = providers.get(&chain.id()).context("{chain:?} missing")?;
        let EndPoint {
            entrypoint,
            bundler,
            ..
        } = d.value();

        // skip if the userop already exists
        tracing::trace!(%send_id, "getUserOp({chain:?}): check");
        let res = bundler
            .raw_request::<_, serde_json::Value>(
                "eth_getUserOperationByHash".into(),
                [userop_hash.0.to_hex()],
            )
            .await?;
        // responds with NULL if userop hash does not exist; else userop details.
        if !res.is_null() {
            tracing::warn!(%send_id, "sendUserOp({chain:?}): skipped");
            return Ok(());
        }

        // submit the userop
        // TODO: make sure the bundler is idempotent i.e. when the same  userop hash is submitted concurrently.
        tracing::trace!(%send_id, "sendUserOp({chain:?}): sending");
        // Each bundler uses a different response format than alloy::SendUserOperationResponse.
        // So, we just treat it as a String and check for the presence of the userop-hash.
        // https://docs.pimlico.io/references/bundler/endpoints/eth_sendUserOperation#returns
        let result = bundler
            .raw_request::<_, String>("eth_sendUserOperation".into(), (userop.clone(), entrypoint))
            .await?;
        anyhow::ensure!(
            result
                .to_uppercase()
                .contains(&userop_hash.to_string().to_uppercase()),
            "UserOp {userop_hash} mismatch"
        ); // This should never happen
        Ok(())
    }

    /// Check for sufficient gas/fees
    ///
    /// Checks whether gas/fees are sufficient.
    async fn _check_gasfees(
        _send_id: B256,
        relay_uop: &mut RelayUserOp,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        let RelayUserOp { userop, chain, .. } = relay_uop;
        let d = providers.get(&chain.id()).context("{chain} missing")?;
        let EndPoint {
            entrypoint,
            jsonrpc,
            bundler,
            ..
        } = d.value();

        // 1. Insufficient gas, delay sending.
        let (tips, header, est4337) = tokio::join!(
            jsonrpc.get_max_priority_fee_per_gas(),
            jsonrpc.get_header_by_number(BlockNumberOrTag::Latest),
            bundler.raw_request::<_, UserOperationGasEstimation>(
                "eth_estimateUserOperationGas".into(),
                (userop.clone(), *entrypoint),
            ),
        );

        let tips = tips?;
        let base_fee_per_gas = header?
            .context("header missing")?
            .base_fee_per_gas
            .context("base_fee_per_gas missing")?;
        let est4337 = est4337?;
        let eip1559 = eip1559_default_estimator(base_fee_per_gas as u128, &[vec![tips]]);

        let res = userop.max_priority_fee_per_gas >= U256::from(eip1559.max_priority_fee_per_gas)
            && userop.max_fee_per_gas >= U256::from(eip1559.max_fee_per_gas)
            && userop.call_gas_limit >= est4337.call_gas_limit
            && userop.pre_verification_gas >= est4337.pre_verification_gas
            && userop.verification_gas_limit >= est4337.verification_gas
            && userop.paymaster_verification_gas_limit.unwrap_or_default()
                >= est4337.paymaster_verification_gas
            && userop.paymaster_post_op_gas_limit.unwrap_or_default()
                >= est4337.paymaster_verification_gas;

        anyhow::ensure!(res, "insufficient gas/fees");
        Ok(())
    }

    /// Start the RELAYER threads.
    ///
    /// Spins up one connection for each chain/bundler; and stores them for later use.
    /// Spawns a number of worker threads to concurrently submit UserOps.
    async fn start_relayer(
        config: NodeConfig,
        _secret_key: SecretKey,
        relay_tx: UnboundedSender<RelayUserOp>,
        mut relay_rx: UnboundedReceiver<RelayUserOp>,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        let chain = Chain::from_id(config.eth_chain_id);
        if providers.is_empty() {
            tracing::warn!("Relayer({chain:?}): terminated");
            return Ok(());
        }
        tracing::info!(chains=%providers.len(), "Relayer({chain:?}): started");

        // for exponential-backoff-retry
        let mut delayq: DelayQueue<RelayUserOp> = DelayQueue::new();

        loop {
            select! {
                // queue processing
                Some(mut relay_uop) = relay_rx.recv() => {
                    let dest = relay_uop.chain;
                    let send_id = relay_uop.send_id;
                    // TODO: 1. Check for sufficient gas
                    // if let Err(err) = Self::check_gasfees(send_id, &mut relay_uop, providers.clone()).await
                    // {
                    //     tracing::warn!(%send_id, %err, userop=?relay_uop.userop, "Relayer#{chain_id}: gas");
                    // } else
                    // 2. Submit the UserOp
                    if let Err(err) = Self::submit_userop(&mut relay_uop, providers.clone()).await
                    {
                        tracing::warn!(%send_id, %err, userop=?relay_uop.userop, "Relayer({chain:?} => {dest:?}): transmit");
                    } else {
                        // Done
                        tracing::info!(%send_id, "Relayer({chain:?} => {dest:?}): bundled");
                        continue;
                    }

                    // X. Backoff-retry
                    let Some(backoff) = relay_uop.backoff() else {
                        // FIXME: DEAD LETTER OFFICE
                        tracing::error!(%send_id, "Relayer({chain:?} => {dest:?}): dropped");
                        continue;
                    };
                    tracing::warn!(%send_id, ?backoff, "Relayer({chain:?} => {dest:?}): backoff");
                    delayq.insert(relay_uop, backoff);
                }
                // retry processing
                Some(due) = delayq.next() => {
                    let relay_uop = due.into_inner();
                    let RelayUserOp { chain: dest, send_id, .. } = &relay_uop;
                    tracing::debug!(%send_id, "Relayer({chain:?} => {dest:?}): retry");
                    if let Err(err) = relay_tx.send(relay_uop) {
                        tracing::error!(%err, "relay_tx closed");
                        break Ok(());
                    };
                }
            }
        }
    }

    /// Collect UserOpHash signature
    ///
    /// Collect signatures, until majority, then compute the final signature.
    #[allow(clippy::too_many_arguments)]
    pub fn collect_userop(
        &self,
        send_id: B256,
        from: PeerId,
        chain: Chain,
        block_hash: Hash,
        userop_hash: Hash,
        public_key: NodePublicKey,
        signature: BlsSignature,
        userop: Option<AlloyUserOperation>,
    ) -> Result<()> {
        tracing::trace!(%from, hash=%userop_hash, "UserOp");
        // 1. Validate inputs
        public_key.verify(userop_hash.as_bytes(), signature)?;

        // fetch related block
        let block = self
            .db
            .get_transactionless_block(block_hash.into())?
            .context("must exist")?;
        let state_hash = block.state_root_hash().into();
        let state = self.state.at_root(state_hash);

        // check if peer_id matches
        let peer_id = state.get_peer_id(public_key)?.context("faux peer-id")?;
        anyhow::ensure!(peer_id == from, "peer-id {from} mismatch"); // must not happen

        // 2. Get the cache entry
        let mut cache = self.bls_uop.lock();
        let bop = cache.get_or_insert_mut_ref(&userop_hash, || {
            let stakers = state.get_stakers(block.header).expect("must exist");
            let len = stakers.len();
            let total_stake: u128 = stakers
                .into_iter()
                .map(|pub_key| {
                    state
                        .get_stake(pub_key, block.header)
                        .expect("must have stake")
                        .expect("stake != 0")
                        .get()
                })
                .sum();
            BlsUserOp {
                height: block.number(), // TODO: Set zero for foreign chain
                userop: None,
                send_id: B256::ZERO,
                threshold: 2 * total_stake / 3 + 1,
                signatures: Vec::with_capacity(len),
            }
        });

        // 3. Cache the signature entry
        let stake = state
            .get_stake(public_key, block.header)?
            .context("missing stake")?;
        bop.threshold = bop.threshold.saturating_sub(stake.get());
        bop.signatures.push((public_key, signature));

        // use only the (UserOp, send_id) we constructed ourselves.
        if from == self.peer_id {
            bop.send_id = send_id;
            bop.userop = userop;
        }

        // 4. Majority reached: promote
        if bop.userop.is_some() && bop.threshold == 0 {
            let bop = cache.pop(&userop_hash).unwrap();
            let stakers = state.get_stakers(block.header).expect("must exist");
            let send_id = bop.send_id;
            self.relay_userop(send_id, userop_hash, chain, stakers, bop)?;
        }
        Ok(())
    }

    /// Send UserOpHash
    ///
    /// Multi-sign the UserOp; and queues it for sending to the Bundler.
    pub fn relay_userop(
        &self,
        send_id: B256,
        userop_hash: Hash,
        chain: Chain,
        stakers: Vec<NodePublicKey>,
        bop: BlsUserOp,
    ) -> Result<()> {
        anyhow::ensure!(!stakers.is_empty(), "stakers cannot be empty");
        anyhow::ensure!(
            send_id != alloy::primitives::KECCAK256_EMPTY,
            "invalid send_id"
        );
        tracing::info!(%send_id, "Relayer({:?} => {chain:?}): promote", self.chain);
        let (signers, signatures): (Vec<NodePublicKey>, Vec<BlsSignature>) =
            bop.signatures.into_iter().unzip();

        // 1. Multi-sig it
        let signatures = signatures
            .into_iter()
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
        // use uncompressed format for EIP-2537 compatibility
        let pubkey = self.secret_key.as_bls().public_key().0.to_uncompressed();
        let mulsig = if signatures.len() == 1 {
            signatures.first().unwrap().as_raw_value().to_uncompressed()
        } else {
            blsful::MultiSignature::from_signatures(signatures)?
                .as_raw_value()
                .to_uncompressed()
        };
        tracing::trace!(%send_id, "Multi-sig({})", mulsig.to_hex_no_prefix());

        // 2. Count signers
        let mut cosigner = bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE];
        for (index, k) in stakers.iter().enumerate() {
            if signers.contains(k) {
                cosigner.set(index, true);
            }
        }

        let message = (
            pubkey.as_slice(),       // PublicKey(96)
            bop.height,              // u64(8)
            cosigner.as_raw_slice(), // Signers(32)
            mulsig.as_slice(),       // Signature(192)
        )
            .abi_encode_packed();
        let sig = self
            .secret_key
            .as_bls()
            .sign(blsful::SignatureSchemes::Basic, message.as_slice())?
            .as_raw_value()
            .to_uncompressed();
        tracing::trace!(%send_id, "Signature({})", sig.to_hex());

        // 3. Construct final UserOp
        let bop = bop.userop.unwrap();
        let final_uop = RelayUserOp::new(
            AlloyUserOperation {
                signature: (message.as_slice(), sig.as_slice())
                    .abi_encode_packed()
                    .into(), // replace the signature with packed struct
                ..bop
            },
            chain,
            userop_hash,
            send_id,
        );

        // 4. Push UserOp to the sending queue
        tracing::trace!(%send_id, "Relayer({:?}): queue", self.chain);
        if let Err(err) = self.relay_tx.send(final_uop) {
            tracing::error!(%err, "relay_tx closed");
        };
        Ok(())
    }
}
