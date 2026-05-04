use std::{num::NonZeroUsize, sync::Arc};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, Bytes, ChainId, U256},
    providers::{Provider, utils::eip1559_default_estimator},
    rpc::types::{
        PackedUserOperation as AlloyUserOperation, SendUserOperation, SendUserOperationResponse,
        UserOperationGasEstimation,
    },
    sol_types::SolValue,
};
use anyhow::{Context, Result};
use blsful::{Bls12381G2Impl, Signature};
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
    uccb::{BlsUserOp, RelayUserOp, utils::get_user_op_hash},
};

#[derive(Debug)]
pub struct Relayer {
    peer_id: PeerId,
    address: Address,
    secret_key: SecretKey,
    db: Arc<Db>,
    state: State,
    relay_tx: UnboundedSender<RelayUserOp>,
    // providers: Arc<DashMap<ChainId, BundlerProvider>>,
    // temporarily cache signatures
    signatures: RwLock<lru::LruCache<Hash, BlsUserOp>>,
    workers: JoinSet<()>,
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

        let mut workers = JoinSet::new();
        // cache the last 1_000 userops
        let signatures = RwLock::new(lru::LruCache::new(NonZeroUsize::new(1000).unwrap()));

        {
            let relay_tx = relay_tx.clone();
            workers.spawn(async move {
                if let Err(err) =
                    Self::start_relayer(config, secret_key, relay_rx, relay_tx, providers).await
                {
                    tracing::error!(%err, "Relayer exception");
                }
            });
        }

        Ok(Self {
            workers,
            secret_key,
            address,
            relay_tx,
            db,
            state,
            peer_id,
            signatures,
        })
    }

    /// Start the RELAYER threads.
    ///
    /// Spins up one connection for each chain/bundler; and stores them for later use.
    /// Spawns a number of worker threads to concurrently submit UserOps.
    async fn start_relayer(
        config: NodeConfig,
        secret_key: SecretKey,
        mut relay_rx: UnboundedReceiver<RelayUserOp>,
        relay_tx: UnboundedSender<RelayUserOp>,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        let bls_key = secret_key.as_bls();
        let chain_id = config.eth_chain_id;
        tracing::info!(chains=%providers.len(), "Relayer-{}", chain_id);
        if providers.is_empty() {
            tracing::warn!("Relayer-{} terminated", chain_id);
            return Ok(());
        }

        // TODO: Spawn worker threads to concurrently process messages.
        while let Some(RelayUserOp {
            mut userop,
            chain_id,
            send_id,
        }) = relay_rx.recv().await
        {
            let Some(provider) = providers.get(&chain_id) else {
                tracing::warn!(%chain_id, "UserOp missing bundler");
                continue;
            };
            let (_, (entrypoint, _, _, _, bundler, watcher)) = provider.pair();

            // If gas is insufficient, delay sending for a while
            let (tips, header, est4337) = tokio::join!(
                watcher.get_max_priority_fee_per_gas(),
                watcher.get_header_by_number(BlockNumberOrTag::Latest),
                bundler.raw_request::<_, UserOperationGasEstimation>(
                    "eth_estimateUserOperationGas".into(),
                    (userop.clone(), *entrypoint),
                )
            );
            if let Ok(tips) = tips
                && let Ok(Some(h)) = header
                && let Ok(est) = est4337
                && Self::validate_gas_fees(tips, h.base_fee_per_gas, est, &userop)
            {
                // do nothing
            } else {
                tracing::warn!(%send_id, %chain_id, "estimateUserOperationGas()");
                Self::retry_userop(&relay_tx, send_id, chain_id, userop, relay_rx.is_empty())
                    .await?;
                continue;
            };

            // sign the UserOp
            let userop_hash = get_user_op_hash(&userop.clone().into(), *entrypoint, chain_id)?;
            let sig = bls_key.sign(blsful::SignatureSchemes::Basic, userop_hash.0.as_slice())?;
            userop.signature = sig.as_raw_value().to_compressed().into();

            // submit the UserOp
            let send_op = SendUserOperation::EntryPointV07(userop.clone());
            let Ok(res) = bundler
                .raw_request::<_, SendUserOperationResponse>(
                    "eth_sendUserOperation".into(),
                    (send_op, entrypoint),
                )
                .await
            else {
                tracing::error!(%send_id,%chain_id,"sendUserOperation()");
                Self::retry_userop(&relay_tx, send_id, chain_id, userop, relay_rx.is_empty())
                    .await?;
                continue;
            };
            let userop_hash = Bytes::from(userop_hash);
            anyhow::ensure!(res.user_op_hash == userop_hash, "UserOp hash mismatch"); // MUST NEVER HAPPEN!
            tracing::debug!(%send_id, %chain_id, "sendUserOperation({userop:?})");
        }
        Ok(())
    }

    async fn retry_userop(
        relay_tx: &UnboundedSender<RelayUserOp>,
        send_id: Hash,
        chain_id: ChainId,
        userop: AlloyUserOperation,
        empty: bool,
    ) -> Result<()> {
        // delay
        if empty {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        Ok(relay_tx.send(RelayUserOp {
            send_id,
            chain_id,
            userop,
        })?) // retry until success
    }

    /// Checks that the hard-coded fees/limits are possible to succeed
    fn validate_gas_fees(
        max_priority_fee_per_gas: u128,
        base_fee_per_gas: Option<u64>,
        est: UserOperationGasEstimation,
        userop: &AlloyUserOperation,
    ) -> bool {
        let Some(base_fee_per_gas) = base_fee_per_gas else {
            return false;
        };
        let eip1559est =
            eip1559_default_estimator(base_fee_per_gas as u128, &[vec![max_priority_fee_per_gas]]);
        userop.max_priority_fee_per_gas >= U256::from(eip1559est.max_priority_fee_per_gas)
            && userop.max_fee_per_gas >= U256::from(eip1559est.max_fee_per_gas)
            && userop.call_gas_limit >= est.call_gas_limit
            && userop.pre_verification_gas >= est.pre_verification_gas
            && userop.verification_gas_limit >= est.verification_gas
            && userop.paymaster_verification_gas_limit.unwrap() >= est.paymaster_verification_gas
            && userop.paymaster_post_op_gas_limit.unwrap() >= est.paymaster_verification_gas
    }

    /// Collect UserOpHash signature
    ///
    /// Collect signatures, until majority, then compute the final signature.
    pub fn collect_userop(
        &self,
        from: PeerId,
        block_hash: Hash,
        userop_hash: Hash,
        public_key: NodePublicKey,
        signature: BlsSignature,
        userop: Option<AlloyUserOperation>,
    ) -> Result<()> {
        // validate signature
        public_key.verify(userop_hash.as_bytes(), signature)?;

        // fetch related block
        let Some(block) = self.db.get_transactionless_block(block_hash.into())? else {
            return Err(anyhow::anyhow!("Missing block"));
        };
        let state = self.state.at_root(block.state_root_hash().into());

        // check if peer_id matches
        let Some(peer_id) = state.get_peer_id(public_key)? else {
            return Err(anyhow::anyhow!("Missing peer id"));
        };
        if peer_id != from {
            return Err(anyhow::anyhow!("Peer id mismatch"));
        }

        // retrieve stake
        let Some(stake) = state.get_stake(public_key, block.header)? else {
            return Err(anyhow::anyhow!("Missing stake"));
        };

        // cache the userops
        let bop = self
            .signatures
            .write()
            .get_or_insert_mut_ref(&userop_hash, BlsUserOp::default);

        // use only the UserOp we constructed ourselves.
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
            userop: AlloyUserOperation {
                signature: userop_sig.into(), // replace the signature with multi-sig
                ..bop
            },
            chain_id: 0,
            send_id: userop_hash,
        };

        // push UserOp to the sending queue
        self.relay_tx.send(final_uop)?;

        Ok(())
    }
}
