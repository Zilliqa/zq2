use std::{str::FromStr as _, sync::Arc};

use alloy::{
    primitives::{Address, B256, Bytes, ChainId, address},
    providers::{
        Identity, Provider as _, ProviderBuilder, RootProvider,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    rpc::types::PackedUserOperation as AlloyUserOperation,
    sol,
    sol_types::SolValue as _,
};
use anyhow::Result;
use dashmap::DashMap;
use jsonrpsee::client_transport::ws::Url;
use libp2p::PeerId;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    cfg::NodeConfig,
    crypto::{BlsSignature, Hash, SecretKey},
    db::Db,
    message::{ExternalMessage, UccbUserOp},
    node::MessageSender,
    node_launcher::ResponseChannel,
    p2p_node::{LocalMessageTuple, OutboundMessageTuple},
    uccb::{relayer::Relayer, signer::Signer},
};

pub mod relayer;
pub mod signer;
pub mod utils;

pub const ENTRYPOINT_V07: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
pub const ENTRYPOINT_V08: Address = address!("0x4337084d9e255ff0702461cf8895ce9e3b5ff108");
pub const ENTRYPOINT_V09: Address = address!("0x433709009B8330FDa32311DF1C2AFA402eD8D009");

sol!(
    #[sol(rpc)]
    "../vendor/openzeppelin-contracts/contracts/interfaces/draft-IERC4337.sol"
);

sol! {
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/interfaces/draft-IERC7786.sol
    interface IERC7786GatewaySource {
        event MessageSent(
            bytes32 indexed sendId,
            bytes sender, // Binary Interoperable Address
            bytes recipient, // Binary Interoperable Address
            bytes payload,
            uint256 value,
            bytes[] attributes
        );
    }
}

pub struct SignUserOp {
    pub userop: AlloyUserOperation,
    pub chain: ChainId,
    pub txn_hash: Hash,
    pub blk_hash: Hash,
}

impl SignUserOp {
    pub fn new(userop: AlloyUserOperation, chain: ChainId, txn_hash: Hash, blk_hash: Hash) -> Self {
        Self {
            userop,
            chain,
            txn_hash,
            blk_hash,
        }
    }
}

pub struct RelayUserOp {
    pub userop: AlloyUserOperation,
    pub chain: ChainId,
    pub hash: Hash,
}

#[derive(Default)]
pub struct BlsUserOp {
    pub userop: Option<AlloyUserOperation>,
    pub signatures: Vec<BlsSignature>,
    pub stake: u128,
}

// Used to send an updated list of SIGNER keys
// pub struct EpochUpdate {
//     epoch_boundary: u64, // the future epoch (N+1) block number
//     threshold: u128,     // majority stake
//     signers: Vec<(Address, PublicKey<Bls12381G2Impl>, u128)>, // list of signers at epoch above.
// }

type Wallet = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;
type Providers = DashMap<ChainId, (Address, Address, Address, Wallet)>;

pub struct Uccb {
    // config: NodeConfig,
    // secret_key: SecretKey,
    // db: Arc<Db>,
    peer_id: PeerId,
    // message_sender: MessageSender,
    /// Send responses to requests down this channel. The `ResponseChannel` passed must correspond to a
    /// `ResponseChannel` received via `handle_request`.
    // request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    chain_id: ChainId,
    _signer: Signer,
    relayer: Relayer,
    // message_sender: Arc<MessageSender>,
    request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
}

impl Drop for Uccb {
    fn drop(&mut self) {
        tracing::info!("UUCB-{} stopped", self.chain_id);
    }
}

impl Uccb {
    pub async fn new(
        config: NodeConfig,
        secret_key: SecretKey,
        db: Arc<Db>,
        message_sender_channel: UnboundedSender<OutboundMessageTuple>,
        local_sender_channel: UnboundedSender<LocalMessageTuple>,
        request_responses: UnboundedSender<(ResponseChannel, ExternalMessage)>,
    ) -> Result<Self> {
        let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
        let chain_id = ChainId::from(config.eth_chain_id);

        let message_sender = Arc::new(MessageSender {
            our_shard: chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
            local_channel: local_sender_channel,
        });

        let bundlers = Arc::new(DashMap::with_capacity(config.remote_chains.len()));
        let watchers = Arc::new(DashMap::with_capacity(config.remote_chains.len()));
        for remote in config.remote_chains.iter() {
            let bundler = ProviderBuilder::new()
                .connect(Url::from_str(&remote.bundler_url)?.as_str())
                .await?;
            if let Ok(entrypoints) = bundler
                .raw_request::<(), Vec<Address>>("eth_supportedEntryPoints".into(), ())
                .await
                && entrypoints.contains(&remote.entrypoint)
            {
                bundlers.insert(
                    remote.chain_id,
                    (remote.entrypoint, Address::ZERO, Address::ZERO, bundler),
                );
            }
            let watcher = ProviderBuilder::new()
                .connect(Url::from_str(&remote.watcher_url)?.as_str())
                .await?;
            if let Ok(id) = watcher.get_chain_id().await
                && chain_id == id
            {
                watchers.insert(
                    remote.chain_id,
                    (remote.entrypoint, remote.sender, remote.gateway, watcher),
                );
            }
        }

        let relayer =
            Relayer::new(config.clone(), secret_key, db.clone(), bundlers.clone()).await?;
        let _signer = Signer::new(
            config.clone(),
            secret_key,
            db.clone(),
            message_sender.clone(),
            watchers.clone(),
        )
        .await?;

        tracing::info!("UUCB-{} started", chain_id);

        Ok(Self {
            // config,
            // secret_key,
            peer_id,
            // db,
            chain_id,
            _signer,
            relayer,
            // message_sender,
            request_responses,
        })
    }

    pub fn handle_request(
        &self,
        from: PeerId,
        id: &str,
        message: ExternalMessage,
        response_channel: ResponseChannel,
    ) -> Result<()> {
        tracing::debug!(%from, to = %self.peer_id, %id, %message, "handling request");
        match message {
            ExternalMessage::UccbUserOp(UccbUserOp {
                userop_hash,
                userop,
                signature,
                public_key,
                block_hash,
            }) => {
                // handle
                self.relayer.collect_userop(
                    from,
                    block_hash,
                    userop_hash,
                    public_key,
                    signature,
                    userop.filter(|_| from == self.peer_id),
                )?;
                self.request_responses
                    .send((response_channel, ExternalMessage::Acknowledgement))?;
            }
            msg => {
                tracing::warn!(%msg, "unexpected message type");
            }
        }
        Ok(())
    }
}

/// Convert a PackedUserOperation
///
/// This packs the unpacked alloy::PackedUserOperation into the packed sol::PackedUserOperation.
impl From<AlloyUserOperation> for PackedUserOperation {
    fn from(userop: AlloyUserOperation) -> Self {
        // pub fn pack_user_op(userop: &AlloyUserOperation) -> super::PackedUserOperation {
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
        #[allow(non_snake_case)]
        let (paymasterVerificationGasLimit, paymasterPostOpGasLimit): (u128, u128) = (
            userop
                .paymaster_verification_gas_limit
                .as_ref()
                .unwrap()
                .to(),
            userop.paymaster_post_op_gas_limit.as_ref().unwrap().to(),
        );

        Self {
            sender: userop.sender,
            nonce: userop.nonce,
            initCode: Bytes::from(
                (
                    *userop.factory.as_ref().unwrap(),
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
            paymasterAndData: Bytes::from(
                (
                    *userop.paymaster.as_ref().unwrap(),
                    paymasterVerificationGasLimit,
                    paymasterPostOpGasLimit,
                    userop.paymaster_data.as_ref().unwrap().clone(),
                )
                    .abi_encode_packed(),
            ),
            // FIXME: Dummy signature must have correct length
            signature: Bytes::from(B256::ZERO.as_slice()),
        }
    }
}
