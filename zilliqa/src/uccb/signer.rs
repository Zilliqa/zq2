use std::{num::NonZeroUsize, ops::Mul, sync::Arc, time::Duration};

// use super::AlloyUserOperation;
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{
        Address, B256, ChainId, U256,
        aliases::{B32, U192},
    },
    providers::Provider as _,
    rpc::types::{Filter, Log},
    sol_types::{SolCall, SolEvent, SolValue},
};
use alloy_chains::Chain;
use anyhow::{Context, Result};
use itertools::Itertools as _;
use libp2p::PeerId;
use lru::LruCache;
use revm::primitives::keccak256;
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};
use tokio_stream::StreamExt as _;
use tokio_util::time::DelayQueue;

use crate::{
    cfg::NodeConfig,
    crypto::{BlsSignature, Hash, SecretKey},
    db::{BlockFilter, Db},
    message::{ExternalMessage, UccbUserOp},
    node::MessageSender,
    state::State,
    uccb::{
        EndPoint,
        IERC7786GatewaySource::MessageSent,
        SignUserOp,
        utils::{get_erc7930_address, get_erc7930_chain, get_user_op_hash},
    },
};

/// A signer polls the SOURCE_CHAIN for MessageSent events.
#[derive(Debug)]
pub struct Signer {
    _chain: Chain,
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
        providers: Arc<super::Providers>,
    ) -> Result<Self> {
        let chain = Chain::from_id(config.eth_chain_id);
        let state = Arc::new(State::new(db.state_trie()?, &config, db.clone())?);
        let mut workers = JoinSet::new();
        let (sign_tx, sign_rx) = tokio::sync::mpsc::unbounded_channel::<SignUserOp>();

        {
            let state = state.clone();
            let db = db.clone();
            let providers = providers.clone();
            let sign_tx = sign_tx.clone();
            workers.spawn(async move {
                if let Err(err) = Self::start_signer(
                    chain,
                    state,
                    db,
                    secret_key,
                    message_sender,
                    providers,
                    sign_tx,
                    sign_rx,
                )
                .await
                {
                    tracing::error!(%err, "SIGNER error");
                }
            });
        }

        {
            let state = state.clone();
            let config = config.clone();
            let db = db.clone();
            let providers = providers.clone();
            let sign_tx = sign_tx.clone();
            workers.spawn(async move {
                if let Err(err) =
                    Self::start_watcher(chain, config, db, providers, sign_tx, state).await
                {
                    tracing::error!(%err, "SIGNER error");
                }
            });
        }

        Ok(Self {
            _chain: chain,
            workers,
        })
    }

    /// Watch for Events
    ///
    /// Opens persistent connections to each remote chain; and monitors the logs for MessageSent events.
    /// Validates and submits each event for signing.
    #[allow(clippy::too_many_arguments)]
    async fn start_watcher(
        self_chain: Chain,
        config: NodeConfig,
        db: Arc<Db>,
        watchers: Arc<super::Providers>,
        sign_tx: UnboundedSender<SignUserOp>,
        state: Arc<State>,
    ) -> Result<()> {
        let blocks_per_epoch = config.consensus.blocks_per_epoch;
        if watchers.is_empty() {
            tracing::warn!("Sender({self_chain:?}): terminated");
            return Ok(());
        }
        tracing::info!(chains=%watchers.len(), "Sender({self_chain:?}): started");

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

            //  poll the chain
            let (logs, epochs) = if let Some(watcher) = watchers.get(&chain_id) {
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
                let range = cache_height.saturating_add(1)..=final_height;
                let filter = Filter::new()
                    .address(*gateway)
                    .from_block(BlockNumberOrTag::Number(*range.start()))
                    .to_block(BlockNumberOrTag::Number(*range.end())) // ideally, this should be exactly one block length
                    .event_signature(super::IERC7786GatewaySource::MessageSent::SIGNATURE_HASH);
                let Ok(logs) = jsonrpc.get_logs(&filter).await else {
                    tracing::error!(?chain, "eth_getLogs(): transport");
                    continue; // skip on errors
                };
                *cache_height = final_height; // update final

                tracing::trace!(
                    count=%logs.len(),
                    ?range,
                    "MessageSent({chain:?}): events",
                );

                // 3. Update epochs
                let mut epochs = Vec::new();
                if chain.id() == self_chain.id() {
                    for height in range.filter(|n| n % blocks_per_epoch == 0) {
                        // jsonrpc.get_block_by_number(BlockNumberOrTag::Number(height))
                        // simple filter for small ranges
                        epochs.push(height);
                    }
                }

                (logs, epochs)
            } else {
                continue;
            };

            if let Err(err) = Self::send_updates(
                sign_tx.clone(),
                watchers.clone(),
                db.clone(),
                epochs,
                self_chain,
                state.clone(),
            )
            .await
            {
                tracing::error!(%err, "SendUpdates()");
                continue;
            }

            if let Err(err) = Self::send_messages(
                db.clone(),
                sign_tx.clone(),
                watchers.clone(),
                logs,
                self_chain,
                chain,
            )
            .await
            {
                tracing::error!(%err, "SendMessages()");
                continue;
            };
        }
        Ok(())
    }

    /// Send Epoch Updates
    ///
    /// Broadcast epoch updates to all chains.
    /// This function will collect the set of stakers, stakes, and total_stake from the local network; and encode it into the
    /// required structure that will be decoded by the UccbSender::executeUserOp() function. The same structure needs to be
    /// sent to all the remote networks.
    ///
    /// Note:
    /// - the public keys are 96-byte uncompressed G1 points; and the amounts are all u128.
    /// - the block must be signed by the previous set of signers that it seeks to replace.
    #[allow(clippy::too_many_arguments)]
    async fn send_updates(
        sign_tx: UnboundedSender<SignUserOp>,
        watchers: Arc<super::Providers>,
        db: Arc<Db>,
        epochs: Vec<u64>,
        self_chain: Chain,
        state: Arc<State>,
    ) -> Result<()> {
        for epoch in epochs {
            let epoch_block = db
                .get_transactionless_block(epoch.into())?
                .expect("must exist");
            let state = state.at_root(epoch_block.state_root_hash().into());

            // *** Ensure that co-signer list is same order as Relayer.rs ***
            let (stakers, stakes, totalstake) =
                super::utils::committee(&state, epoch_block.header)?;
            anyhow::ensure!(stakers.len() == stakes.len(), "Invalid committee");
            tracing::info!(chain=?self_chain, %epoch, len=%stakers.len(), "updateEpoch()");

            let signers = stakers
                .into_iter()
                .zip(stakes)
                .map(|(key, w)| (key.as_uncompressed(), w))
                .collect_vec();

            let threshold = 2 * totalstake.saturating_add(2) / 3; // round up

            // send update to all networks, including self.
            let payload = (signers, threshold, epoch).abi_encode_packed();
            for watcher in watchers.iter() {
                let EndPoint {
                    chain,
                    sender,
                    paymaster,
                    ..
                } = watcher.value();

                // the payloads for each network must be different, to prevent signature reuse.
                let send_id =
                    keccak256((chain.id(), payload.clone()).abi_encode_packed().as_slice());

                let userop =
                    super::new_set_staker_op(send_id, payload.clone().into(), sender, paymaster);

                // Epoch update must be signed by the previous block
                let blk_height = epoch.saturating_sub(1);
                let blk_hash = db
                    .get_transactionless_block(blk_height.into())?
                    .expect("must exist")
                    .hash();

                if let Err(err) = sign_tx.send(SignUserOp::new(
                    send_id,
                    userop,
                    *chain,
                    self_chain,
                    Hash(send_id.0), // substitute the pseudo-random txn_hash with send_id
                    blk_hash,
                    blk_height,
                )) {
                    tracing::error!(%err, "sign_rx closed");
                    break;
                };
            }
        }
        Ok(())
    }
    /// Send Messages
    ///
    /// Process the set of MessageSent() events to be put into the sending queue.
    async fn send_messages(
        db: Arc<Db>,
        sign_tx: UnboundedSender<SignUserOp>,
        watchers: Arc<super::Providers>,
        logs: Vec<Log>,
        self_chain: Chain,
        chain: Chain,
    ) -> Result<()> {
        for log in logs {
            let txn_hash = log.transaction_hash.expect("txn_hash != none").into();

            // 4. Decode the MessageSent event.
            let Ok(MessageSent {
                sendId,
                recipient,
                payload,
                value,
                sender,
                // attributes,
                ..
            }) = super::IERC7786GatewaySource::MessageSent::decode_log_data(log.data())
            else {
                tracing::warn!(%txn_hash, "MessageSent({chain:?}): invalid structure");
                continue; // skip on failure
            };
            if sendId == alloy::primitives::KECCAK256_EMPTY {
                tracing::debug!(send_id=%sendId, "MessageSent({chain:?}): skipped");
                continue; // skip local deliveries
            }
            tracing::debug!(send_id=%sendId, "MessageSent({chain:?}): seen");

            // 5. Validate payload integrity; prevent executeUserOp() calls.
            if sendId != keccak256(payload.iter().as_slice())
                && !payload.starts_with(&super::IAccountExecute::executeUserOpCall::SELECTOR)
            {
                tracing::warn!(send_id=%sendId, "MessageSent({chain:?}): invalid payload");
                continue;
            }

            // 6. Validate route
            let Ok(dst_chain) = get_erc7930_chain(recipient.iter().as_slice()) else {
                tracing::warn!(send_id=%sendId, "MessageSent({chain:?}): invalid destination");
                continue;
            };
            let Ok(src_chain) = get_erc7930_chain(sender.iter().as_slice()) else {
                tracing::warn!(send_id=%sendId, "MessageSent({chain:?}): invalid source");
                continue;
            };
            anyhow::ensure!(
                src_chain.id() == chain.id(),
                "MessageSent({chain:?}): invalid source"
            ); // MessageSent comes from source

            let Ok(origin) = get_erc7930_address(sender.iter().as_slice()) else {
                tracing::warn!(send_id=%sendId, "MessageSent({chain:?}): invalid origin");
                continue;
            };
            anyhow::ensure!(
                origin == log.address(),
                "MessageSent({chain:?}): invalid origin"
            ); // Gateway contract is sender

            // attempts to check if a chain is a 'test' or 'main' chain.
            let is_src_test = src_chain
                .named()
                .map_or_else(|| src_chain.id() == 0x814d, |c| c.is_testnet());
            let is_dst_test = dst_chain
                .named()
                .map_or_else(|| dst_chain.id() == 0x814d, |c| c.is_testnet());
            anyhow::ensure!(
                is_src_test == is_dst_test,
                "MessageSent({chain:?}): testnet != mainnet"
            ); // Prevent mixing testnet/mainnet
            tracing::info!(send_id=%sendId, "Sender({src_chain:?}): routing");

            // Warning: may dead-lock, if watchers is locked outside of this function. Ensure that it is not.
            if let Some(watcher) = watchers.get(&dst_chain.id()) {
                // Encode a receiveMessage() call
                let receive_message = super::IERC7786Recipient::receiveMessageCall {
                    receiveId: sendId,
                    sender,
                    payload, // quad-tuple
                };
                let payload = receive_message.abi_encode();

                let EndPoint {
                    allow_loopback,
                    sender,
                    paymaster,
                    gateway,
                    ..
                } = watcher.value();
                if !(dst_chain != src_chain || *allow_loopback) {
                    tracing::warn!("MessageSent({chain:?}): loop-back");
                    continue;
                }

                // 7. Construct partial UserOp; send for signing
                let userop =
                    super::new_call_op(sendId, payload.into(), sender, paymaster, gateway, value);
                tracing::trace!(send_id=%sendId, ?userop, "UserOp");

                // Outgoing: determines the effective set of signers - using the block that executed the transaction.
                // Incoming: rely on the latest set of signers.
                //
                // There is a remote possibility that an incoming message can fail if the lifetime of the message crosses an epoch; and
                // that the set of signers and/or their weights changed during that epoch; or if the node is significantly out-of-sync.
                let (blk_height, blk_hash) = if dst_chain.id() == self_chain.id() {
                    match db.get_transactionless_block(BlockFilter::Finalized) {
                        Ok(Some(b)) => (b.number(), b.hash()),
                        Err(err) => {
                            tracing::error!(%err, "Finalized error");
                            continue;
                        }
                        _ => unimplemented!("block != none"),
                    }
                } else {
                    (
                        log.block_number.expect("block_number != none"),
                        log.block_hash.expect("block_hash != none").into(),
                    )
                };

                if let Err(err) = sign_tx.send(SignUserOp::new(
                    sendId, userop, dst_chain, src_chain, txn_hash, blk_hash, blk_height,
                )) {
                    tracing::error!(%err, "sign_rx closed");
                    break;
                };
            } else {
                tracing::warn!(send_id=%sendId, "MessageSent({chain:?}): missing route");
                continue;
            };
        }
        Ok(())
    }

    /// Sign the UserOps
    ///
    /// Populates the missing UserOps fields to compute its full hash.
    /// Signs the hash and transmits the signature to the selected Relayer.
    #[allow(clippy::too_many_arguments)]
    async fn start_signer(
        chain: Chain,
        state: Arc<State>,
        db: Arc<Db>,
        secret_key: SecretKey,
        message_sender: Arc<MessageSender>,
        providers: Arc<super::Providers>,
        sign_tx: UnboundedSender<SignUserOp>,
        mut sign_rx: UnboundedReceiver<SignUserOp>,
    ) -> Result<()> {
        if providers.is_empty() {
            tracing::warn!("Signer({chain:?}): terminated");
            return Ok(());
        }
        tracing::info!(chains=%providers.len(), "Signer({chain:?}): started");

        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();

        // fee cache
        let mut cache =
            LruCache::<Hash, [u128; 6]>::new(NonZeroUsize::new(providers.len()).unwrap());

        // exponential backoff queue
        let mut delayq: DelayQueue<SignUserOp> = DelayQueue::new();
        // time-slot sending queue
        let mut sendq: DelayQueue<(PeerId, UccbUserOp)> = DelayQueue::new();

        loop {
            select! {
                Some(mut sign_uop) = sign_rx.recv() => {
                    let send_id = sign_uop.send_id;
                    // 1. Populate the nonce
                    if let Err(err) = Self::populate_nonce(send_id, &mut sign_uop, providers.clone()).await
                    {
                        tracing::warn!(%send_id, %err, userop=?sign_uop.userop, "Signer({chain:?}): nonce");
                    } else
                    // 2. Populate the gas/fees
                    if let Err(err) =
                        Self::populate_gasfees(send_id, &mut sign_uop, providers.clone(), &mut cache).await
                    {
                        tracing::warn!(%send_id, %err, userop=?sign_uop.userop, "Signer({chain:?}): gas");
                    } else
                    // 3. Compute the signature/hash
                    if let Err(err) =
                        Self::populate_signature(send_id, &mut sign_uop, providers.clone(), secret_key)
                    {
                        tracing::warn!(%send_id, %err, userop=?sign_uop.userop, "Signer({chain:?}): sign");
                    } else
                    // 4. Queue the signed UserOp for transmission
                    if let Err(err) = Self::queue_userop(
                        send_id,
                        &mut sign_uop,
                        &mut sendq,
                        state.clone(),
                        db.clone(),
                        peer_id,
                        secret_key,
                    ) {
                        tracing::warn!(%send_id, %err, userop=?sign_uop.userop, "Signer({chain:?}): txmt");
                    } else {
                        // Done
                        tracing::info!(%send_id, "Signer({chain:?}): signed");
                        continue;
                    }

                    // X. Backoff-retry
                    let Some(backoff) = sign_uop.backoff() else {
                        // FIXME: DEAD LETTER OFFICE
                        tracing::error!(%send_id, "Signer({chain:?}): dropped");
                        continue;
                    };
                    tracing::warn!(%send_id, ?backoff, "Signer({chain:?}): backoff");
                    delayq.insert(sign_uop, backoff);
                }
                // retry
                Some(due) = delayq.next() => {
                    let sign_uop = due.into_inner();
                    tracing::debug!(send_id=%sign_uop.send_id, "Signer({chain:?}): retry");
                    if let Err(err) = sign_tx.send(sign_uop) {
                        tracing::error!(%err, "sign_rx closed");
                        break Ok(());
                    };
                }
                // delay send
                Some(due) = sendq.next() => {
                    let (peer, uccb_uop) = due.into_inner();
                    tracing::debug!(send_id=%uccb_uop.send_id, "Signer({chain:?}): relayed");
                    if let Err(err) = message_sender.send_external_message(peer, ExternalMessage::UccbUserOp(uccb_uop)) {
                        tracing::error!(%err, "message_sender closed");
                        break Ok(());
                    };
                }
            }
        }
    }

    /// Queues to the RelaySet
    ///
    /// Enqueue the signed UserOp for sending to Peer with a delayed time-slot.
    #[allow(clippy::too_many_arguments)]
    fn queue_userop(
        send_id: B256,
        sign_uop: &mut SignUserOp,
        sendq: &mut DelayQueue<(PeerId, UccbUserOp)>,
        state: Arc<State>,
        db: Arc<Db>,
        peer_id: PeerId,
        secret_key: SecretKey,
    ) -> Result<()> {
        let SignUserOp {
            userop,
            blk_hash,
            txn_hash,
            dst_chain,
            uop_hash,
            blk_height,
            ..
        } = sign_uop;

        let relay_set = Self::get_relay_set(blk_hash, txn_hash, state.clone(), db.clone())?;
        tracing::trace!(%send_id, ?uop_hash, "relaySet({:?})", relay_set);

        let signature = BlsSignature::from_bytes(userop.signature.iter().as_slice())?;
        for (i, peer) in (0u32..).zip(relay_set.into_iter()) {
            let uccb_uop = UccbUserOp {
                chain: *dst_chain,
                userop_hash: uop_hash.context("uop_hash exists")?,
                block_hash: *blk_hash,
                block_height: *blk_height,
                public_key: secret_key.node_public_key(),
                // Only send userop to self - userop_hash assures integrity from other nodes
                userop: if peer == peer_id {
                    Some(userop.clone())
                } else {
                    None
                },
                signature,
                send_id,
            };
            // we use delay-slots to ensure that the first peer always has the first priority to submit the userop.
            // the two backup peers should only be able to submit it after a delay. the userop is lost if all fail.
            let delay_slot = dst_chain
                .average_blocktime_hint()
                .map_or_else(|| Duration::from_secs(60).mul(i), |d| d.mul(i));

            sendq.insert((peer, uccb_uop), delay_slot);
        }
        Ok(())
    }

    /// Populate the UserOp nonce
    ///
    /// This function retrieves the Nonce from the Destination::EntryPoint contract.
    async fn populate_nonce(
        send_id: B256,
        sign_uop: &mut SignUserOp,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        // TODO: Tackle parallel nonce limits e.g.
        // https://www.alchemy.com/docs/wallets/reference/bundler-faqs#parallel-nonces
        // https://docs.pimlico.io/guides/how-to/parallel-transactions#parallel-transactions-ordering

        if !sign_uop.userop.nonce.is_zero() {
            return Ok(());
        }

        let SignUserOp {
            userop,
            txn_hash,
            dst_chain,
            ..
        } = sign_uop;

        let p = providers
            .get(&dst_chain.id())
            .context("dst_chain missing")?;
        let EndPoint {
            entrypoint,
            sender,
            jsonrpc,
            ..
        } = p.value();

        let key = Self::pack_nonce_key(&Address::ZERO, txn_hash);
        let nonce = super::IEntryPointNonces::new(*entrypoint, jsonrpc)
            .getNonce(*sender, key)
            .call()
            .await?;
        tracing::debug!(%send_id, %nonce, "getNonce({dst_chain}): nonce");
        userop.nonce = nonce;
        Ok(())
    }

    /// Populate the UserOp nonce
    ///
    /// This function retrieves the gas/fees from the Source::Gateway contract.
    async fn populate_gasfees(
        send_id: B256,
        sign_uop: &mut SignUserOp,
        providers: Arc<super::Providers>,
        cache: &mut LruCache<Hash, [u128; 6]>,
    ) -> Result<()> {
        if sign_uop.userop.paymaster_verification_gas_limit.is_some() {
            return Ok(());
        }

        let SignUserOp {
            userop,
            dst_chain,
            src_chain,
            blk_hash,
            blk_height,
            ..
        } = sign_uop;

        let s = providers
            .get(&src_chain.id())
            .context("src_chain missing")?;
        let EndPoint {
            gateway, jsonrpc, ..
        } = s.value();

        let fees = if let Some(fees) = cache.get(blk_hash) {
            // .get_or_insert() does not work in async
            *fees
        } else {
            let chain_id = dst_chain.id();
            let fees = super::IUccbGateway::new(*gateway, jsonrpc)
                .getFees(chain_id)
                .block(BlockId::number(*blk_height))
                .call()
                .await?;
            cache.push(*blk_hash, fees);
            fees
        };

        // ERC4337 fees
        tracing::debug!(%send_id, ?fees, "getFees({src_chain:?}): fees");
        let [
            max_fee_per_gas,
            max_priority_fee_per_gas,
            paymaster_verification_gas_limit,
            verification_gas_limit,
            pre_verification_gas,
            call_gas_limit,
        ] = fees;

        userop.max_fee_per_gas = U256::from(max_fee_per_gas);
        userop.max_priority_fee_per_gas = U256::from(max_priority_fee_per_gas);

        userop.call_gas_limit = U256::from(call_gas_limit);
        userop.pre_verification_gas = U256::from(pre_verification_gas);
        userop.verification_gas_limit = U256::from(verification_gas_limit);

        userop.paymaster_verification_gas_limit =
            Some(U256::from(paymaster_verification_gas_limit));
        userop.paymaster_post_op_gas_limit = Some(U256::from(paymaster_verification_gas_limit));
        Ok(())
    }

    /// Populate the Signature
    ///
    /// Compute the signature internally instead of calling EntryPoint::getUserOpHash()
    fn populate_signature(
        send_id: B256,
        sign_uop: &mut SignUserOp,
        providers: Arc<super::Providers>,
        secret_key: SecretKey,
    ) -> Result<()> {
        if sign_uop.uop_hash.is_some() {
            return Ok(());
        }

        let SignUserOp {
            userop,
            dst_chain,
            uop_hash,
            ..
        } = sign_uop;

        let d = providers
            .get(&dst_chain.id())
            .context("dst_chain missing")?;
        let EndPoint { entrypoint, .. } = d.value();

        let hash = get_user_op_hash(&userop.clone().into(), *entrypoint, dst_chain.id())?;
        let sig = secret_key
            .as_bls()
            .sign(blsful::SignatureSchemes::Basic, hash.as_slice())
            .unwrap();
        userop.signature = sig.as_raw_value().to_compressed().into();
        uop_hash.replace(Hash(hash.0));
        tracing::trace!(%send_id, ?userop, ?uop_hash, "UserOp");
        Ok(())
    }

    /// Compute a nonce key
    ///
    /// The upper 192-bits of the nonce are user-defined; with the lower 64-bits as a sequence.
    /// This function packs the gateway address and a pseudo-random value into these bits.
    ///
    /// If the address is:
    /// - zero      : the prefix is a pseudo-random value based on the txn hash;
    /// - non-zero  : the prefix is a partial-random value based on the address || txn_hash(8).
    ///
    /// NOTE: Some bundlers impose a limit on parallel nonces e.g. https://www.alchemy.com/docs/wallets/reference/bundler-faqs#parallel-nonces
    pub fn pack_nonce_key(addr: &Address, txn_hash: &Hash) -> U192 {
        if addr.is_zero() {
            return U192::from_be_slice(&txn_hash.0[..24]);
        }
        // U192 expects big-endian bytes
        let hash32 = B32::from_slice(&txn_hash.0[..4]);
        let bytes = (*addr, hash32).abi_encode_packed();
        U192::from_be_slice(bytes.as_slice())
    }

    /// Compute the RELAY_SET
    ///
    /// Uses the given transaction_hash and block_hash to compute a deterministic pseudo-random set of peers.
    /// Given N number of peers, only 3 are selected to generate the multi-sig and submit the UserOp to the bundler.
    /// - multiple peers, redundant, to improve delivery.
    /// - sub-set of peers, to mitigate rogue nodes and reduce spam.
    fn get_relay_set(
        blk_hash: &Hash,
        txn_hash: &Hash,
        state: Arc<State>,
        db: Arc<Db>,
    ) -> Result<Vec<PeerId>> {
        // retrieve set of peers at height
        let block = db
            .get_transactionless_block(blk_hash.into())
            .transpose()
            .context("block_hash missing")
            .flatten()?;
        let state = state.at_root(block.state_root_hash().into());

        // sort by XOR-ing keys
        // this produces a deterministic pseudo-random order.
        let blk_key = blk_hash
            .0
            .chunks_exact(16)
            .map(|c| u128::from_be_bytes(c.try_into().unwrap()))
            .fold(0u128, |a, x| a ^ x);
        let txn_key = txn_hash
            .0
            .chunks_exact(16)
            .map(|c| u128::from_be_bytes(c.try_into().unwrap()))
            .fold(0u128, |a, x| a ^ x);
        let sort_key = blk_key ^ txn_key;

        let mut stakers = state
            .get_stakers(block.header)?
            .into_iter()
            .map(|k| {
                (
                    k,
                    k.as_bytes()
                        .chunks_exact(16)
                        .map(|c| u128::from_be_bytes(c.try_into().unwrap()))
                        .fold(sort_key, |a, x| a ^ x),
                )
            })
            .collect_vec();
        stakers.sort_by_key(|a| a.1);

        // grab top 3 only
        let stakers = stakers
            .into_iter()
            .take(3) // the network must have > 3 stakers
            .map(|k| state.get_peer_id(k.0).unwrap().unwrap())
            .collect_vec();

        Ok(stakers)
    }

    // pub fn default_user_op() -> AlloyUserOperation {
    //     super::new_call_op(
    //         B256::ZERO,
    //         Bytes::new(),
    //         &Address::ZERO,
    //         &Address::ZERO,
    //         &Address::ZERO,
    //         U256::ZERO,
    //     )
    // }
}
