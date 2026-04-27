use std::{str::FromStr as _, sync::Arc};

// use super::AlloyUserOperation;
use alloy::{
    primitives::{
        Address, Bytes, ChainId, U256,
        aliases::{B32, U192},
    },
    providers::{Provider as _, ProviderBuilder},
    rpc::types::{Filter, PackedUserOperation as AlloyUserOperation},
    sol_types::{SolEvent, SolValue},
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use itertools::Itertools as _;
use jsonrpsee::client_transport::ws::Url;
use libp2p::PeerId;
use revm::primitives::B256;
use tokio::task::JoinSet;
use tokio_stream::StreamExt as _;

use crate::{
    cfg::NodeConfig,
    crypto::{BlsSignature, Hash, SecretKey},
    db::Db,
    message::{ExternalMessage, UccbUserOp},
    node::MessageSender,
    state::State,
    uccb::SignUserOp,
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
    ) -> Result<Self> {
        let state = Arc::new(State::new(db.state_trie()?, &config, db.clone())?);
        let mut workers = JoinSet::new();

        workers.spawn(async move {
            if let Err(err) =
                Self::start_signer(state, db, config, secret_key, message_sender).await
            {
                tracing::error!(%err, "SIGNER error");
            }
        });

        Ok(Self { workers })
    }

    /// Signs the UserOp
    ///
    /// Opens persistent connections to each remote chain; and monitors the logs for MessageSent events.
    /// Calls the Entrypoint contracts to fill in the `nonce` field, and computes the UserOp hash.
    /// Signs the UserOp hash and transmits the signed UserOp to the selected Relayer.
    async fn start_signer(
        state: Arc<State>,
        db: Arc<Db>,
        config: NodeConfig,
        secret_key: SecretKey,
        message_sender: Arc<MessageSender>,
    ) -> Result<()> {
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let chain_id = ChainId::from(config.eth_chain_id);
        // used to call Entrypoint contracts
        let watchers = DashMap::with_capacity(config.remote_chains.len());
        let mut watch_rx = futures::stream::SelectAll::new();
        for watcher in config.remote_chains.iter() {
            let url = Url::from_str(&watcher.watcher_url)?;
            let provider = ProviderBuilder::new().connect(url.as_str()).await?;
            match provider.get_chain_id().await {
                Ok(id) => {
                    if chain_id == id {
                        tracing::debug!(%url, "Signer");
                        let filter = Filter::new().address(watcher.gateway).event_signature(
                            super::IERC7786GatewaySource::MessageSent::SIGNATURE_HASH,
                        );
                        let stream = provider.watch_logs(&filter).await?.into_stream();
                        watch_rx.push(stream);
                        watchers.insert(
                            id,
                            (
                                watcher.entrypoint,
                                watcher.sender,
                                watcher.gateway,
                                provider,
                            ),
                        );
                        continue;
                    }
                    tracing::error!(%url, "Signer mismatch {} != {:?}", id, chain_id);
                }
                Err(err) => tracing::error!(%err, "Signer error"),
            }
        }

        tracing::info!(chains=%watchers.len(), "Signer-{}", chain_id);
        if watchers.is_empty() {
            tracing::warn!("Signer-{} terminated", chain_id);
            return Ok(());
        }

        // TODO: Spawn multiple threads to sign messages in parallel
        let (sign_tx, mut sign_rx) = tokio::sync::mpsc::unbounded_channel::<SignUserOp>();
        while let Some(logs) = watch_rx.next().await {
            for log in logs {
                if log.removed {
                    continue;
                }
                // construct partial UserOp
                let userop = Self::new_user_op();

                let op = SignUserOp {
                    uop_hash: Hash::EMPTY,
                    blk_hash: log.block_hash.expect("block_hash != none").into(),
                    txn_hash: log.transaction_hash.expect("txn_hash != none").into(),
                    chain: ChainId::from(0u64),
                    userop: userop,
                };
                sign_tx.send(op)?;
            }

            // process user ops
            while let Ok(SignUserOp {
                mut userop,
                chain,
                txn_hash,
                blk_hash,
                mut uop_hash,
            }) = sign_rx.try_recv()
            {
                let Some(watcher) = watchers.get(&chain) else {
                    tracing::warn!(chain_id = %chain, "Missing provider");
                    continue;
                };

                let (chain_id, (entrypoint, sender, gateway, provider)) = watcher.pair();
                if chain != *chain_id {
                    tracing::error!("ChainId mistmatch");
                    continue;
                }

                // 1. Retrieve the nonce; if not yet done
                if userop.nonce.is_zero() {
                    let key = Self::pack_nonce_key(&gateway, &txn_hash);
                    let Ok(nonce) = super::INonceManager::new(entrypoint.clone(), provider)
                        .getNonce(sender.clone(), key)
                        .call()
                        .await
                    else {
                        tracing::error!("getNonce()");
                        // retry
                        sign_tx.send(SignUserOp {
                            userop,
                            chain,
                            txn_hash,
                            blk_hash,
                            uop_hash,
                        })?;
                        continue;
                    };
                    userop.nonce = nonce;
                }

                // 2. Retrieve the userophash; if not yet done
                // TODO: It is possible to compute this internally
                if uop_hash == Hash::EMPTY {
                    let uop = Self::pack_user_op(&userop);
                    let Ok(userophash) = super::IEntryPoint::new(entrypoint.clone(), provider)
                        .getUserOpHash(uop)
                        .call()
                        .await
                    else {
                        tracing::error!("getUserOpHash()");
                        // retry
                        sign_tx.send(SignUserOp {
                            userop,
                            chain,
                            txn_hash,
                            blk_hash,
                            uop_hash,
                        })?;
                        continue;
                    };
                    uop_hash = Hash::from_bytes(userophash.as_slice())?;
                };

                // 3. Sign the UserOp; if not yet done
                if userop.signature.is_empty() {
                    let sig = secret_key
                        .as_bls()
                        .sign(blsful::SignatureSchemes::Basic, uop_hash.as_bytes())
                        .unwrap();
                    userop.signature = sig.as_raw_value().to_compressed().into();
                }

                // 4. Send it to the RELAY_SET
                let relay_set = Self::get_relay_set(blk_hash, txn_hash, state.clone(), db.clone())?;
                for peer in relay_set {
                    // Send userop to Relayer(s)
                    let msg = if peer != peer_id {
                        ExternalMessage::UccbUserOp(UccbUserOp {
                            userop_hash: uop_hash,
                            block_hash: blk_hash,
                            public_key: secret_key.node_public_key(),
                            userop: None,
                            signature: BlsSignature::from_bytes(
                                &userop.signature.iter().as_slice(),
                            )?,
                        })
                    } else {
                        ExternalMessage::UccbUserOp(UccbUserOp {
                            userop_hash: uop_hash,
                            block_hash: blk_hash,
                            public_key: secret_key.node_public_key(),
                            userop: Some(userop.clone()),
                            signature: BlsSignature::from_bytes(
                                &userop.signature.iter().as_slice(),
                            )?,
                        })
                    };
                    message_sender.send_external_message(peer, msg)?;
                }
            }
        }
        Ok(())
    }

    /// Compute a nonce key
    fn pack_nonce_key(gateway: &Address, txn_hash: &Hash) -> U192 {
        // U192 expects big-endian bytes
        let hash = B32::from_slice(txn_hash.as_bytes());
        let bytes = (gateway.clone(), hash).abi_encode_packed();
        U192::from_be_slice(bytes.as_slice())
    }

    /// Convert a PackedUserOperation
    fn pack_user_op(userop: &AlloyUserOperation) -> super::PackedUserOperation {
        #[allow(non_snake_case)]
        let (verificationGasLimit, callGasLimit): (u128, u128) = (
            userop.verification_gas_limit.to(),
            userop.call_gas_limit.to(),
        );
        #[allow(non_snake_case)]
        let (maxPriorityFeePerGas, maxFeePerGas): (u128, u128) = (
            userop.max_priority_fee_per_gas.to(),
            userop.max_fee_per_gas.to(),
        );

        super::PackedUserOperation {
            sender: userop.sender,
            nonce: userop.nonce,
            initCode: Bytes::from(
                (
                    userop.factory.as_ref().unwrap().clone(),
                    userop.factory_data.as_ref().unwrap().clone(),
                )
                    .abi_encode_packed(),
            ),
            callData: userop.call_data.clone(),
            accountGasLimits: B256::from_slice(
                (verificationGasLimit, callGasLimit)
                    .abi_encode_packed()
                    .as_slice(),
            ),
            preVerificationGas: userop.pre_verification_gas,
            gasFees: B256::from_slice(
                (maxPriorityFeePerGas, maxFeePerGas)
                    .abi_encode_packed()
                    .as_slice(),
            ),
            paymasterAndData: Bytes::new(),
            signature: Bytes::from(B256::ZERO.as_slice()),
        }
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

    /// Construct a partial UserOp
    ///
    /// Constructs a partial UserOp during the Watching stage; to be completed during the Signing stage.
    pub fn new_user_op() -> AlloyUserOperation {
        AlloyUserOperation {
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
