use std::{num::NonZeroUsize, sync::Arc};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, B256, ChainId, U256, keccak256},
    providers::{Provider, utils::eip1559_default_estimator},
    rpc::types::{
        PackedUserOperation as AlloyUserOperation, SendUserOperationResponse,
        UserOperationGasEstimation,
    },
    sol_types::SolValue,
};
use anyhow::{Context, Result};
use bitvec::{bitarr, order::Msb0};
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
    message::MAX_COMMITTEE_SIZE,
    state::State,
    uccb::{BlsUserOp, EndPoint, RelayUserOp},
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
    // temporarily cache bls_uop
    bls_uop: RwLock<lru::LruCache<Hash, BlsUserOp>>,
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
        let bls_uop = RwLock::new(lru::LruCache::new(NonZeroUsize::new(1000).unwrap()));

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
            bls_uop,
        })
    }

    /// Submit the UserOp
    ///
    /// Handles the submission to the Bundler, skips if the UserOp has been submitted.
    async fn submit_userop(
        send_id: B256,
        relay_uop: &mut RelayUserOp,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        let RelayUserOp {
            userop,
            userop_hash,
            chain_id,
            ..
        } = relay_uop;
        let d = providers.get(chain_id).context("chain_id missing")?;
        let EndPoint {
            entrypoint,
            bundler,
            ..
        } = d.value();

        // skip if the userop already exists
        let res = bundler
            .raw_request::<_, serde_json::Value>(
                "eth_getUserOperationByHash".into(),
                [*userop_hash],
            )
            .await?;
        // responds with NULL if userop hash does not exist; else userop details.
        if !res.is_null() {
            tracing::warn!(%send_id, "sendUserOp({chain_id}): skip");
            return Ok(());
        }

        // submit the userop
        // TODO: make sure the bundler is idempotent i.e. when the same  userop hash is submitted concurrently.
        let result = bundler
            .raw_request::<_, SendUserOperationResponse>(
                "eth_sendUserOperation".into(),
                (userop.clone(), entrypoint),
            )
            .await?;

        let user_op_hash = result.user_op_hash.iter().as_slice();
        let userop_hash = userop_hash.as_bytes();
        if user_op_hash == userop_hash {
            return Ok(());
        }
        unreachable!("UserOp mismatch");
    }

    /// Check for sufficient gas/fees
    ///
    /// Checks whether gas/fees are sufficient.
    async fn _check_gasfees(
        _send_id: B256,
        relay_uop: &mut RelayUserOp,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        let RelayUserOp {
            userop, chain_id, ..
        } = relay_uop;
        let d = providers.get(chain_id).context("chain_id missing")?;
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
        mut relay_rx: UnboundedReceiver<RelayUserOp>,
        relay_tx: UnboundedSender<RelayUserOp>,
        providers: Arc<super::Providers>,
    ) -> Result<()> {
        let chain_id = config.eth_chain_id;
        tracing::info!(chains=%providers.len(), "Relayer-{chain_id}");
        if providers.is_empty() {
            tracing::warn!("Relayer-{chain_id} terminated");
            return Ok(());
        }

        // TODO: Spawn worker threads to concurrently process messages.
        while let Some(mut relay_uop) = relay_rx.recv().await {
            let send_id = keccak256(relay_uop.userop.call_data.iter().as_slice());
            // TODO: 1. Check for sufficient gas
            // if let Err(err) = Self::check_gasfees(send_id, &mut relay_uop, providers.clone()).await
            // {
            //     tracing::warn!(%send_id, %err, userop=?relay_uop.userop, "Relayer#{chain_id}: gas");
            // } else
            // 2. Submit the UserOp
            if let Err(err) = Self::submit_userop(send_id, &mut relay_uop, providers.clone()).await
            {
                tracing::warn!(%send_id, %err, userop=?relay_uop.userop, "Relayer#{chain_id}: txmt");
            } else {
                tracing::debug!(%send_id, "Relayer#{chain_id}: submitted");
                continue;
            }

            if relay_rx.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
            relay_tx.send(relay_uop)?
        }
        Ok(())
    }

    /// Collect UserOpHash signature
    ///
    /// Collect signatures, until majority, then compute the final signature.
    #[allow(clippy::too_many_arguments)]
    pub fn collect_userop(
        &self,
        from: PeerId,
        chain_id: ChainId,
        block_hash: Hash,
        userop_hash: Hash,
        public_key: NodePublicKey,
        signature: BlsSignature,
        userop: Option<AlloyUserOperation>,
    ) -> Result<()> {
        // 1. Validate inputs
        public_key.verify(userop_hash.as_bytes(), signature)?;

        // fetch related block
        let block = self
            .db
            .get_transactionless_block(block_hash.into())?
            .context("block must exist")?;
        let state_hash = block.state_root_hash().into();
        let state = self.state.at_root(state_hash);

        // check if peer_id matches
        let peer_id = state.get_peer_id(public_key)?.context("fake peer-id")?;
        anyhow::ensure!(peer_id == from, "peer-id mismatch"); // must not happen

        // 2. Get the cache entry
        let mut cache = self.bls_uop.write();
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
                userop: None,
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

        // use only the UserOp we constructed ourselves.
        if from == self.peer_id {
            bop.userop = userop;
        }

        // 4. Majority reached: promote
        if bop.userop.is_some() && bop.threshold == 0 {
            let bop = cache.pop(&userop_hash).unwrap();
            let stakers = state.get_stakers(block.header).expect("must exist");
            self.relay_userop(userop_hash, chain_id, stakers, bop)?;
        }
        Ok(())
    }

    /// Send UserOpHash
    ///
    /// Multi-sign the UserOp; and queues it for sending to the Bundler.
    pub fn relay_userop(
        &self,
        userop_hash: Hash,
        chain_id: ChainId,
        stakers: Vec<NodePublicKey>,
        bop: BlsUserOp,
    ) -> Result<()> {
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
        let multi_signature = blsful::MultiSignature::from_signatures(signatures)?
            .as_raw_value()
            .to_compressed();

        // 2. Count signers
        let mut cosigner = bitarr![u8, Msb0; 0; MAX_COMMITTEE_SIZE];
        for (index, k) in stakers.iter().enumerate() {
            if signers.contains(k) {
                cosigner.set(index, true);
            }
        }
        let message = (
            self.address,               // Address(20)
            multi_signature.as_slice(), // Signature(48)
            cosigner.as_raw_slice(),    // Signers(32)
        )
            .abi_encode_packed();
        let signature = self.secret_key.sign(message.as_slice());

        // 3. Construct final UserOp
        let bop = bop.userop.unwrap();
        let send_id = keccak256(bop.call_data.iter().as_slice()).into();
        tracing::debug!(%send_id, "relay({chain_id})");
        let final_uop = RelayUserOp {
            userop: AlloyUserOperation {
                signature: (signature.to_bytes(), message).abi_encode_packed().into(), // replace the signature with multi-sig
                ..bop
            },
            chain_id,
            userop_hash,
            send_id,
        };

        // 4. Push UserOp to the sending queue
        self.relay_tx.send(final_uop)?;
        Ok(())
    }
}
