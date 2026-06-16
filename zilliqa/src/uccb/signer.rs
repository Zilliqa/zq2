use std::{num::NonZeroUsize, ops::Mul, sync::Arc, time::Duration};

// use super::AlloyUserOperation;
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{
        Address, B256, Bytes, ChainId, U256,
        aliases::{B32, U192},
    },
    providers::Provider as _,
    rpc::types::{Filter, PackedUserOperation as AlloyUserOperation},
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
    db::Db,
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
            let config = config.clone();
            let db = db.clone();
            let providers = providers.clone();
            let sign_tx = sign_tx.clone();
            workers.spawn(async move {
                if let Err(err) = Self::start_watcher(chain, config, db, providers, sign_tx).await {
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
    async fn start_watcher(
        chain: Chain,
        config: NodeConfig,
        _db: Arc<Db>,
        watchers: Arc<super::Providers>,
        sign_tx: UnboundedSender<SignUserOp>,
    ) -> Result<()> {
        if watchers.is_empty() {
            tracing::warn!("Sender({chain:?}): terminated");
            return Ok(());
        }
        tracing::info!(chains=%watchers.len(), "Sender({chain:?}): started");

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
                    .event_signature(super::IERC7786GatewaySource::MessageSent::SIGNATURE_HASH);
                let Ok(logs) = jsonrpc.get_logs(&filter).await else {
                    tracing::error!(?chain, "eth_getLogs(): transport");
                    continue; // skip on errors
                };
                tracing::trace!(
                    count=%logs.len(),
                    range=?(cache_height.saturating_add(1)..=final_height),
                    "MessageSent({chain:?}): events",
                );
                *cache_height = final_height; // update final
                logs
            } else {
                continue;
            };

            for log in logs {
                let blk_hash = log.block_hash.expect("block_hash != none").into();
                let txn_hash = log.transaction_hash.expect("txn_hash != none").into();
                let block_height = log.block_number.expect("block_number != none");

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

                // 5. Validate payload integrity
                if sendId != keccak256(payload.iter().as_slice())
                    && payload.starts_with(&super::IAccountExecute::executeUserOpCall::SELECTOR)
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

                let Ok(sender) = get_erc7930_address(sender.iter().as_slice()) else {
                    tracing::warn!(send_id=%sendId, "MessageSent({chain:?}): invalid sender");
                    continue;
                };
                anyhow::ensure!(
                    sender == log.address(),
                    "MessageSent({chain:?}): invalid sender"
                ); // Gateway contract is sender

                let is_src_test = src_chain
                    .named()
                    .map(|c| c.is_testnet())
                    .unwrap_or_default();
                let is_dst_test = dst_chain
                    .named()
                    .map(|c| c.is_testnet())
                    .unwrap_or_default();
                anyhow::ensure!(
                    is_src_test == is_dst_test,
                    "MessageSent({chain:?}): testnet != mainnet"
                ); // Mixing testnet/mainnet
                tracing::info!(send_id=%sendId, "Sender({src_chain:?}): routing");

                // Warning: may dead-lock, if watchers is locked above
                if let Some(watcher) = watchers.get(&dst_chain.id()) {
                    let EndPoint {
                        allow_loopback,
                        sender,
                        paymaster,
                        ..
                    } = watcher.value();
                    if !(dst_chain != src_chain || *allow_loopback) {
                        tracing::warn!("MessageSent({chain:?}): loop-back");
                        continue;
                    }

                    // 7. Construct partial UserOp; send for signing
                    let userop = Self::new_user_op(payload, sender, paymaster, value, block_height);
                    tracing::trace!(send_id=%sendId, ?userop, "UserOp");
                    if let Err(err) = sign_tx.send(SignUserOp::new(
                        userop,
                        dst_chain,
                        src_chain,
                        txn_hash,
                        blk_hash,
                        block_height,
                    )) {
                        tracing::error!(%err, "sign_rx closed");
                        break;
                    };
                } else {
                    tracing::warn!(send_id=%sendId, "MessageSent({chain:?}): missing route");
                    continue;
                };
            }
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
        let mut sendq: DelayQueue<(PeerId, UccbUserOp, B256)> = DelayQueue::new();

        loop {
            select! {
                Some(mut sign_uop) = sign_rx.recv() => {
                    let send_id = keccak256(sign_uop.userop.call_data.iter().as_slice());
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
                    let send_id = keccak256(sign_uop.userop.call_data.iter().as_slice());
                    tracing::debug!(%send_id, "Signer({chain:?}): retry");
                    if let Err(err) = sign_tx.send(sign_uop) {
                        tracing::error!(%err, "sign_rx closed");
                        break Ok(());
                    };
                }
                // delay send
                Some(due) = sendq.next() => {
                    let (peer, uccb_uop, send_id) = due.into_inner();
                    tracing::debug!(%send_id, "Signer({chain:?}): relayed");
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
        sendq: &mut DelayQueue<(PeerId, UccbUserOp, B256)>,
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
                public_key: secret_key.node_public_key(),
                // Only send userop to self - userop_hash assures integrity from other nodes
                userop: if peer == peer_id {
                    Some(userop.clone())
                } else {
                    None
                },
                signature,
            };
            // we use delay-slots to ensure that the first peer always has the first priority to submit the userop.
            // the two backup peers should only be able to submit it after a delay. the userop is lost if all fail.
            let delay_slot = dst_chain
                .average_blocktime_hint()
                .map_or_else(|| Duration::from_secs(60).mul(i), |d| d.mul(i));

            sendq.insert((peer, uccb_uop, send_id), delay_slot);
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
            gateway,
            entrypoint,
            sender,
            jsonrpc,
            ..
        } = p.value();

        let key = Self::pack_nonce_key(gateway, txn_hash);
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
            let fees = super::IERC4337Extra::new(*gateway, jsonrpc)
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

    /// Construct a partial UserOp
    ///
    /// Constructs a partial UserOp during the Watching stage; to be completed during the Signing stage.
    /// Some dummy data is used to populate the UserOp initially. They *must* be replaced before submission.
    #[allow(clippy::too_many_arguments)]
    pub fn new_user_op(
        payload: Bytes,
        sender: &Address,
        paymaster: &Address,
        _value: U256,
        block_height: u64,
    ) -> AlloyUserOperation {
        // we can encode some custom things in here
        let paymaster_data = (block_height).abi_encode_packed();
        // FIXME: decode the values
        // let [a, b, c, d] = value.into_limbs();
        // let max_fee_per_gas = (b as u128) << 64 | a as u128;
        // let max_priority_fee_per_gas = (d as u128) << 64 | c as u128;
        AlloyUserOperation {
            sender: *sender,
            nonce: U256::ZERO, // unpopulated nonce/sig
            factory: None,
            // Some bundlers reject any initdata for existing senders e.g.
            // https://docs.candide.dev/wallet/technical-reference/aa10-sender-already-constructed/
            factory_data: None,
            call_data: payload,
            call_gas_limit: U256::ZERO,         // estimateUserOpGas
            verification_gas_limit: U256::ZERO, // estimateUserOpGas
            pre_verification_gas: U256::ZERO,   // estimateUserOpGas
            max_fee_per_gas: U256::MAX,
            max_priority_fee_per_gas: U256::MAX,
            paymaster: Some(*paymaster),
            paymaster_verification_gas_limit: None, // estimateUserOpGas
            paymaster_post_op_gas_limit: None,      // estimateUserOpGas
            paymaster_data: Some(Bytes::from(paymaster_data)),
            signature: Bytes::new(), // unpopulated signature
        }
    }

    pub fn default_user_op() -> AlloyUserOperation {
        Self::new_user_op(
            // B256::ZERO,
            Bytes::new(),
            &Address::ZERO,
            // &Address::ZERO,
            &Address::ZERO,
            U256::ZERO,
            0,
        )
    }
}
