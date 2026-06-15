use std::{str::FromStr as _, sync::Arc, time::Duration};

use alloy::{
    primitives::{Address, B256, Bytes, ChainId, address},
    providers::{
        Identity, Provider as _, ProviderBuilder, RootProvider,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    rpc::{client::RpcClient, types::PackedUserOperation as AlloyUserOperation},
    sol,
    sol_types::SolValue as _,
    transports::layers::RetryBackoffLayer,
};
use alloy_chains::Chain;
use anyhow::Result;
use dashmap::DashMap;
use jsonrpsee::client_transport::ws::Url;
use libp2p::PeerId;
use rand::Rng as _;
// use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    cfg::{NodeConfig, RemoteChain},
    crypto::{BlsSignature, Hash, NodePublicKey, SecretKey},
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
    #[sol(rpc)]
    interface IERC4337Extra {
        function feeParams(uint128[6]);
        event MessageReceived(bytes32 indexed receiveId, address relayer);
        function getFees(
            uint64 chain_id
        ) external view returns (uint128[6]);
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

#[derive(Debug)]
pub struct SignUserOp {
    pub userop: AlloyUserOperation,
    pub txn_hash: Hash,
    pub blk_hash: Hash,
    pub dst_chain: Chain,
    pub src_chain: Chain,
    pub blk_height: u64,
    pub uop_hash: Option<Hash>,
    retry_s: u16,
}
impl SignUserOp {
    pub fn new(
        userop: AlloyUserOperation,
        dst_chain: Chain,
        src_chain: Chain,
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
            uop_hash: None,
            retry_s: 0,
        }
    }

    pub fn backoff(&mut self) -> Option<Duration> {
        let elapse = self.retry_s.saturating_add(1).checked_next_power_of_two()?;
        self.retry_s = elapse;
        let run_at = Duration::from_millis(
            // jitter
            rand::thread_rng()
                .gen_range::<u64, _>(0..500)
                .saturating_add(elapse as u64 * 1_000),
        );
        Some(run_at)
    }
}

#[derive(Debug)]
pub struct RelayUserOp {
    pub userop: AlloyUserOperation,
    pub chain: Chain,
    pub userop_hash: Hash,
    pub send_id: Hash,
    retry_s: u16,
}

impl RelayUserOp {
    pub fn new(userop: AlloyUserOperation, chain: Chain, userop_hash: Hash, send_id: Hash) -> Self {
        Self {
            userop,
            chain,
            userop_hash,
            send_id,
            retry_s: 0,
        }
    }
    pub fn backoff(&mut self) -> Option<Duration> {
        let elapse = self.retry_s.saturating_add(1).checked_next_power_of_two()?;
        self.retry_s = elapse;
        let run_at = Duration::from_millis(
            // jitter
            rand::thread_rng()
                .gen_range::<u64, _>(0..500)
                .saturating_add(elapse as u64 * 1_000),
        );
        Some(run_at)
    }
}

#[derive(Default)]
pub struct BlsUserOp {
    pub userop: Option<AlloyUserOperation>,
    pub signatures: Vec<(NodePublicKey, BlsSignature)>,
    pub threshold: u128,
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

fn build_wallet(uri: &str) -> Result<Wallet> {
    let url = Url::from_str(uri)?;

    let retry_layer = RetryBackoffLayer::new(
        10,
        1_000,
        url.fragment()
            .map_or_else(|| 500u64, |s| s.parse::<u64>().unwrap()),
    );

    let client = RpcClient::builder().layer(retry_layer).hyper_http(url);
    let provider = ProviderBuilder::new().connect_client(client);
    Ok(provider)
}

pub struct EndPoint {
    pub chain: Chain,
    pub gateway: Address,
    pub sender: Address,
    pub entrypoint: Address,
    pub paymaster: Address,
    pub bundler: Wallet,
    pub jsonrpc: Wallet,
    pub allow_loopback: bool,
}
type Providers = DashMap<ChainId, EndPoint>;

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
        tracing::info!("UUCB#{} stopped", self.chain_id);
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
        let eth_chain_id = ChainId::from(config.eth_chain_id);

        let message_sender = Arc::new(MessageSender {
            our_shard: eth_chain_id,
            our_peer_id: peer_id,
            outbound_channel: message_sender_channel,
            local_channel: local_sender_channel,
        });

        let providers = Arc::new(DashMap::with_capacity(config.remote_chains.len()));
        for RemoteChain {
            chain_id,
            bundler_url,
            watcher_url,
            entrypoint,
            gateway,
            sender,
            paymaster,
            allow_loopback,
        } in config.remote_chains.clone().into_iter()
        {
            let bundler = build_wallet(&bundler_url)?;
            let jsonrpc = build_wallet(&watcher_url)?;

            let (get_entrypoints, bundler_chain_id, jsonrpc_chain_id) = tokio::join!(
                bundler.raw_request::<(), Vec<Address>>("eth_supportedEntryPoints".into(), ()),
                bundler.get_chain_id(),
                jsonrpc.get_chain_id()
            );

            if let Err(err) = get_entrypoints {
                tracing::warn!(%err, "UCCB#{eth_chain_id} {bundler_url}");
            } else if let Ok(ref entrypoints) = get_entrypoints
                && !entrypoints.contains(&entrypoint)
            {
                tracing::warn!("UCCB#{eth_chain_id}: != {entrypoints:?}");
            };

            if let Err(err) = jsonrpc_chain_id {
                tracing::warn!(%err, "UCCB#{eth_chain_id} {}", watcher_url);
            } else if let Err(err) = bundler_chain_id {
                tracing::warn!(%err, "UCCB#{eth_chain_id} {}", bundler_url);
            } else if let Ok(json_id) = jsonrpc_chain_id
                && let Ok(bundler_id) = bundler_chain_id
                && (json_id != chain_id || chain_id != bundler_id)
            {
                tracing::warn!("UCCB#{eth_chain_id} != {json_id}")
            };

            let chain = Chain::from_id(chain_id);

            tracing::info!("UCCB#{eth_chain_id} => {chain:?}");
            // insert it either way as Relayer/Signer has to handle http errors anyway.
            providers.insert(
                chain_id,
                EndPoint {
                    entrypoint,
                    gateway,
                    sender,
                    paymaster,
                    bundler,
                    jsonrpc,
                    chain,
                    allow_loopback,
                },
            );
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

        tracing::info!("UUCB#{eth_chain_id} started");

        Ok(Self {
            // config,
            // secret_key,
            peer_id,
            // db,
            chain_id: eth_chain_id,
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
                chain,
            }) => {
                // handle
                self.relayer.collect_userop(
                    from,
                    chain,
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
            initCode: if let Some(factory) = userop.factory.as_ref()
                && let Some(factory_data) = userop.factory_data.as_ref()
            {
                Bytes::from((*factory, factory_data.clone()).abi_encode_packed())
            } else {
                Bytes::new()
            },
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
            paymasterAndData: if let Some(paymaster) = userop.paymaster.as_ref()
                && let Some(paymaster_data) = userop.paymaster_data.as_ref()
            {
                Bytes::from(
                    (
                        *paymaster,
                        paymasterVerificationGasLimit,
                        paymasterPostOpGasLimit,
                        paymaster_data.clone(),
                    )
                        .abi_encode_packed(),
                )
            } else {
                Bytes::new()
            },
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
