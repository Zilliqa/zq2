use std::{num::NonZeroUsize, sync::Arc};

// use super::AlloyUserOperation;
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    primitives::{
        Address, B256, Bytes, ChainId, U64, U256,
        aliases::{B32, U192},
    },
    providers::Provider as _,
    rpc::types::{Filter, PackedUserOperation as AlloyUserOperation},
    sol_types::{SolEvent, SolValue},
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use itertools::Itertools as _;
use libp2p::PeerId;
use revm::primitives::keccak256;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};

use crate::{
    cfg::NodeConfig,
    crypto::{Hash, SecretKey},
    db::Db,
    message::{ExternalMessage, UccbUserOp},
    node::MessageSender,
    state::State,
    uccb::{
        IERC4337ExtraFees,
        IERC7786GatewaySource::MessageSent,
        SignUserOp,
        utils::{get_chain_id, get_user_op_hash},
    },
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
    // This needs to be the same size as the signature scheme for correct gas estimation
    const DUMMY_SIGNATURE: [u8; 148] = [255u8; 48 + 48 + 32 + 20]; // SIG || MUL-SIG || CO-SIGNER || SIGNER
    const DUMMY_GAS: U256 = U256::ZERO;

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
        let chain_id = ChainId::from(config.eth_chain_id);
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
                    chain_id,
                    state,
                    db,
                    secret_key,
                    message_sender,
                    providers,
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
            let db = db.clone();
            let providers = providers.clone();
            workers.spawn(async move {
                if let Err(err) =
                    Self::start_watcher(chain_id, config, db, providers, sign_tx).await
                {
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
        _db: Arc<Db>,
        watchers: Arc<super::Providers>,
        sign_tx: UnboundedSender<SignUserOp>,
    ) -> Result<()> {
        tracing::info!(chains=%watchers.len(), "Watcher-{chain_id}");
        if watchers.is_empty() {
            tracing::warn!("Watcher-{chain_id} terminated");
            return Ok(());
        }

        // Get last known height
        let final_number = DashMap::with_capacity(watchers.len());
        for remote in config.remote_chains.iter() {
            if let Some(watcher) = watchers.get(&remote.chain_id) {
                let (_, _, _, _, _, watcher) = watcher.value();
                let final_block = watcher
                    .get_header_by_number(BlockNumberOrTag::Finalized) // fallsback to get-block-by-number
                    .await?
                    .expect("must exist");
                final_number.insert(remote.chain_id, final_block.number);
            }
        }

        // Poll each chain, one-by-one
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await; // short polling interval
            for watcher in watchers.iter() {
                let (chain_id, (_, gateway, _, _, _, watcher)) = watcher.pair();

                // Subscribing to the live-stream results in latest blocks, which may get reorganized.
                // Manual polling is used to ensure that only finalized blocks are processed.
                // 1. Check final block number
                let final_block = watcher
                    .get_header_by_number(BlockNumberOrTag::Finalized) // fallsback to get-block-by-number
                    .await?
                    .expect("final block must exist");
                let mut last_final = final_number.get_mut(chain_id).expect("must exist");
                if final_block.number <= *last_final.value() {
                    continue; // skip if stale
                }

                // 2. Retrieve the latest set of finalized logs
                let filter = Filter::new()
                    .address(*gateway)
                    .from_block(BlockNumberOrTag::Number(
                        last_final.value().saturating_add(1),
                    ))
                    .to_block(BlockNumberOrTag::Number(final_block.number)) // ideally, this should be exactly one block length
                    .event_signature(super::IERC7786GatewaySource::MessageSent::SIGNATURE_HASH);
                let Ok(logs) = watcher.get_logs(&filter).await else {
                    tracing::error!("eth_getLogs({chain_id}): transport");
                    continue; // retry
                };
                *last_final.value_mut() = final_block.number; // update final

                // iterate thru logs
                for log in logs {
                    anyhow::ensure!(!log.removed, "finalized block reorg"); // must never happen

                    let blk_hash = log.block_hash.expect("block_hash != none").into();
                    let txn_hash = log.transaction_hash.expect("txn_hash != none").into();
                    let block_height = log.block_number.expect("block_number != none");

                    let MessageSent {
                        sendId,
                        recipient,
                        payload,
                        value,
                        sender,
                        // attributes,
                        ..
                    } = super::IERC7786GatewaySource::MessageSent::decode_log_data(log.data())?;

                    // 1. Validate payload integrity
                    if !value.is_zero() || sendId != keccak256(payload.iter().as_slice()) {
                        tracing::warn!(%sendId, "Invalid sendId");
                        continue;
                    }

                    // 2. Get route
                    let src_chain =
                        get_chain_id(std::str::from_utf8(&sender).expect("Invalid utf-8"))?;
                    anyhow::ensure!(src_chain == *chain_id, "source_chain mismatch");

                    let dst_chain =
                        get_chain_id(std::str::from_utf8(&recipient).expect("Invalid utf-8"))?;
                    // ** DO NOT ALLOW LOOP-BACK **
                    #[cfg(not(test))]
                    anyhow::ensure!(dst_chain != *chain_id, "loop-back detected");

                    let Some(p) = watchers.get(&dst_chain) else {
                        tracing::warn!(send_id=%sendId, "Missing route {src_chain} => {dst_chain}");
                        continue;
                    };
                    let (_entrypoint, sender, gateway, paymaster, _bundler, _provider) = p.value();

                    // 3. Construct partial UserOp
                    let userop = Self::new_user_op(
                        sendId,
                        payload,
                        sender,
                        gateway,
                        paymaster,
                        block_height,
                    );

                    // 4. Send it for signing
                    let op = SignUserOp::new(
                        userop,
                        dst_chain,
                        src_chain,
                        txn_hash,
                        blk_hash,
                        block_height,
                    );
                    sign_tx.send(op)?;
                }
            }
        }
        // Ok(())
    }

    /// Sign the UserOps
    ///
    /// Calls the Entrypoint contracts to fill in the `nonce` field, and computes the UserOp hash.
    /// Signs the UserOp hash and transmits the signed UserOp to the selected Relayer.
    #[allow(clippy::too_many_arguments)]
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
        tracing::info!(chains=%watchers.len(), "Signer-{chain_id}");
        if watchers.is_empty() {
            tracing::warn!("Signer-{chain_id} terminated");
            return Ok(());
        }

        let mut fee_cache = lru::LruCache::<(u64, u64), IERC4337ExtraFees>::new(
            NonZeroUsize::new(watchers.len() * 3).unwrap(),
        );

        // process user ops
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        while let Ok(SignUserOp {
            mut userop,
            dst_chain,
            src_chain,
            txn_hash,
            blk_hash,
            blk_height,
        }) = sign_rx.try_recv()
        {
            // 1. Populate UserOp fees
            if userop.max_fee_per_gas.is_zero() {
                let fees = if let Some(fees) = fee_cache.get(&(src_chain, blk_height)) {
                    fees.clone()
                } else {
                    let p = watchers.get(&src_chain).expect("must exist");
                    let (_entrypoint, _sender, gateway, _paymaster, _bundler, provider) = p.value();
                    match super::IERC4337Extra::new(*gateway, provider)
                        .getFees(dst_chain)
                        .block(BlockId::number(blk_height))
                        .call()
                        .await
                    {
                        Ok(fees) => {
                            fee_cache.push((src_chain, blk_height), fees.clone());
                            fees
                        }
                        Err(err) => {
                            let send_id = keccak256(userop.call_data.iter().as_slice());
                            tracing::error!(%send_id, %err, "getFees({src_chain}): skipped");
                            sign_tx.send(SignUserOp::new(
                                userop, dst_chain, src_chain, txn_hash, blk_hash, blk_height,
                            ))?; // retry
                            continue;
                        }
                    }
                };

                // EIP1559 fees
                userop.max_fee_per_gas = U256::from(fees.max_fee_per_gas);
                userop.max_priority_fee_per_gas = U256::from(fees.max_priority_fee_per_gas);

                // ERC4337 fees
                userop.call_gas_limit = U256::from(fees.call_gas_limit);
                userop.pre_verification_gas = U256::from(fees.pre_verification_gas);
                userop.verification_gas_limit = U256::from(fees.verification_gas_limit);
                userop.paymaster_verification_gas_limit =
                    Some(U256::from(fees.paymaster_verification_gas_limit));
                userop.paymaster_post_op_gas_limit =
                    Some(U256::from(fees.paymaster_verification_gas_limit));
            }

            // 2. Populate the nonce
            // TODO: Tackle parallel nonce limits e.g.
            // https://www.alchemy.com/docs/wallets/reference/bundler-faqs#parallel-nonces
            // https://docs.pimlico.io/guides/how-to/parallel-transactions#parallel-transactions-ordering
            let Some(p) = watchers.get(&dst_chain) else {
                tracing::warn!("Missing route {src_chain} => {dst_chain}");
                continue;
            };
            let (entrypoint, sender, gateway, _paymaster, _bundler, provider) = p.value();

            if userop.nonce.is_zero() {
                let key = Self::pack_nonce_key(gateway, &txn_hash);
                match super::IEntryPointNonces::new(*entrypoint, provider)
                    .getNonce(*sender, key)
                    .call()
                    .await
                {
                    Ok(nonce) => {
                        userop.nonce = nonce;
                    }
                    Err(err) => {
                        let send_id = keccak256(userop.call_data.iter().as_slice());
                        tracing::error!(%send_id, %err, "getNonce(dst_chain)");
                        sign_tx.send(SignUserOp::new(
                            userop, dst_chain, src_chain, txn_hash, blk_hash, blk_height,
                        ))?; // retry
                        continue;
                    }
                };
            }

            // 2. Compute + Sign the UserOp hash
            let uop_hash = get_user_op_hash(&userop.clone().into(), *entrypoint, dst_chain)?;
            let sig = secret_key
                .as_bls()
                .sign(blsful::SignatureSchemes::Basic, uop_hash.as_slice())
                .unwrap();
            userop.signature = sig.as_raw_value().to_compressed().into();

            // 3. Transmit via P2P to the RELAY_SET
            let relay_set = Self::get_relay_set(blk_hash, txn_hash, state.clone(), db.clone())?;
            for peer in relay_set {
                let msg = ExternalMessage::UccbUserOp(UccbUserOp {
                    userop_hash: Hash(uop_hash.0),
                    block_hash: blk_hash,
                    public_key: secret_key.node_public_key(),
                    // Only send userop to self - userop_hash assures integrity from other nodes
                    userop: if peer == peer_id {
                        Some(userop.clone())
                    } else {
                        None
                    },
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
        let sort_key = U64::from_be_bytes(blk_hash.0).bitxor(U64::from_be_bytes(txn_hash.0));
        stakers.sort_by(|a, b| {
            let a = U64::from_be_slice(a.as_bytes().as_slice()).bitxor(sort_key);
            let b = U64::from_be_slice(b.as_bytes().as_slice()).bitxor(sort_key);
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
    /// Some dummy data is used to populate the UserOp initially. They *must* be replaced before submission.
    #[allow(clippy::too_many_arguments)]
    pub fn new_user_op(
        send_id: B256,
        payload: Bytes,
        sender: &Address,
        gateway: &Address,
        paymaster: &Address,
        block_height: u64,
    ) -> AlloyUserOperation {
        // we can encode some custom things in here
        let paymaster_data = (block_height).abi_encode_packed();
        AlloyUserOperation {
            sender: *sender,
            nonce: U256::ZERO, // start_signer
            factory: Some(*gateway),
            factory_data: Some(Bytes::copy_from_slice(send_id.as_slice())),
            call_data: payload,
            call_gas_limit: Self::DUMMY_GAS, // estimateUserOpGas
            verification_gas_limit: Self::DUMMY_GAS, // estimateUserOpGas
            pre_verification_gas: Self::DUMMY_GAS, // estimateUserOpGas
            max_fee_per_gas: Self::DUMMY_GAS,
            max_priority_fee_per_gas: Self::DUMMY_GAS,
            paymaster: Some(*paymaster),
            paymaster_verification_gas_limit: Some(Self::DUMMY_GAS), // estimateUserOpGas
            paymaster_post_op_gas_limit: Some(Self::DUMMY_GAS),      // estimateUserOpGas
            paymaster_data: Some(Bytes::from(paymaster_data)),
            signature: Bytes::from(Self::DUMMY_SIGNATURE),
        }
    }

    pub fn default_user_op() -> AlloyUserOperation {
        Self::new_user_op(
            B256::ZERO,
            Bytes::new(),
            &Address::ZERO,
            &Address::ZERO,
            &Address::ZERO,
            0,
        )
    }
}
