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
// use serde::{Deserialize, Serialize};
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

#[cfg(not(doctest))]
sol!(
    #[sol(rpc)]
    "../vendor/openzeppelin-contracts/contracts/interfaces/draft-IERC4337.sol"
);
#[cfg(not(doctest))]
sol!(
    #[sol(rpc)]
    "../vendor/openzeppelin-contracts/contracts/interfaces/draft-IERC7786.sol"
);

sol! {
    interface IERC7786Attributes {
        function eip1559_fees(uint128 max_priority_gas_fee,uint128 max_base_gas_fee) external;
    }
}

sol! {
    struct IERC4337ExtraFees {
        uint128 max_priority_fee_per_gas;
        uint128 max_fee_per_gas;
        uint128 call_gas_limit;
        uint128 pre_verification_gas;
        uint128 verification_gas_limit;
        uint128 paymaster_verification_gas_limit;
        uint128 paymaster_post_op_gas_limit;
    }

    #[sol(rpc)]
    interface IERC4337Extra {
        function getFees(
            uint64 chain_id
        ) external view returns (IERC4337ExtraFees);
    }
}

// This is to pass doctest
#[cfg(doctest)]
sol! {
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/interfaces/draft-IERC7786.sol
    #[sol(rpc)]
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

    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode; // `abi.encodePacked(factory, factoryData)`
        bytes callData;
        bytes32 accountGasLimits; // `abi.encodePacked(verificationGasLimit, callGasLimit)` 16 bytes each
        uint256 preVerificationGas;
        bytes32 gasFees; // `abi.encodePacked(maxPriorityFeePerGas, maxFeePerGas)` 16 bytes each
        bytes paymasterAndData; // `abi.encodePacked(paymaster, paymasterVerificationGasLimit, paymasterPostOpGasLimit, paymasterData[, paymasterSignature, paymasterSignatureSize, PAYMASTER_SIG_MAGIC])` (20 bytes, 16 bytes, 16 bytes, dynamic[, dynamic, 2 bytes, 8 bytes])
        bytes signature;
    }

    #[sol(rpc)]
    interface IEntryPoint {
        function getUserOpHash(
            PackedUserOperation calldata userOp
        ) external view returns (bytes32);
        function getNonce(address sender, uint192 key) external view returns (uint256 nonce);
    }

    // https://github.com/eth-infinitism/account-abstraction/tree/develop/contracts/interfaces
    #[sol(rpc)]
    interface INonceManager {
        function getNonce(address sender, uint192 key)
        external view returns (uint256 nonce);
    }
}

pub struct SignUserOp {
    pub userop: AlloyUserOperation,
    pub txn_hash: Hash,
    pub blk_hash: Hash,
    pub dst_chain: ChainId,
    pub src_chain: ChainId,
    pub blk_height: u64,
}

impl SignUserOp {
    pub fn new(
        userop: AlloyUserOperation,
        dst_chain: ChainId,
        src_chain: ChainId,
        txn_hash: Hash,
        blk_hash: Hash,
        blk_height: u64,
    ) -> Self {
        Self {
            userop,
            dst_chain,
            src_chain,
            txn_hash,
            blk_hash,
            blk_height,
        }
    }
}

pub struct RelayUserOp {
    pub userop: AlloyUserOperation,
    pub chain_id: ChainId,
    pub send_id: Hash,
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
type Providers = DashMap<ChainId, (Address, Address, Address, Address, Wallet, Wallet)>;

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

        let providers = Arc::new(DashMap::with_capacity(config.remote_chains.len()));
        for remote in config.remote_chains.iter() {
            let bundler = ProviderBuilder::new()
                .connect(Url::from_str(&remote.bundler_url)?.as_str())
                .await?;
            let watcher = ProviderBuilder::new()
                .connect(Url::from_str(&remote.watcher_url)?.as_str())
                .await?;

            if let Ok(entrypoints) = bundler
                .raw_request::<(), Vec<Address>>("eth_supportedEntryPoints".into(), ())
                .await
                && entrypoints.contains(&remote.entrypoint)
                && let Ok(id) = watcher.get_chain_id().await
                && chain_id == id
            {
                providers.insert(
                    remote.chain_id,
                    (
                        remote.entrypoint,
                        remote.sender,
                        remote.gateway,
                        remote.paymaster,
                        watcher,
                        bundler,
                    ),
                );
            }
        }
        providers.shrink_to_fit();

        let relayer =
            Relayer::new(config.clone(), secret_key, db.clone(), providers.clone()).await?;
        let _signer = Signer::new(
            config.clone(),
            secret_key,
            db.clone(),
            message_sender.clone(),
            providers.clone(),
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
            signature: userop.signature,
        }
    }
}

// Represents the gas estimation for a user operation.
//
// alloy::UserOperationGasEstimation is v0.6, not v0.7/0.8
// #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub(crate) struct UserOperationGasEstimationV07 {
//     pub pre_verification_gas: U256,
//     pub verification_gas: U256,
//     pub paymaster_verification_gas: U256,
//     pub call_gas_limit: U256,
//     pub paymaster_post_op_gas_limit: U256,
// }
