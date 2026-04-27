use std::sync::Arc;

use alloy::{
    primitives::{Address, ChainId, address},
    rpc::types::PackedUserOperation as AlloyUserOperation,
    sol,
};
use anyhow::Result;
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

pub const ENTRYPOINT_V07: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
pub const ENTRYPOINT_V08: Address = address!("0x4337084d9e255ff0702461cf8895ce9e3b5ff108");
pub const ENTRYPOINT_V09: Address = address!("0x433709009B8330FDa32311DF1C2AFA402eD8D009");

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

    // https://github.com/eth-infinitism/account-abstraction/tree/develop/contracts/interfaces
    #[sol(rpc)]
    interface INonceManager {
        function getNonce(address sender, uint192 key)
        external view returns (uint256 nonce);
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
}

pub struct SignUserOp {
    pub userop: AlloyUserOperation,
    pub chain: ChainId,
    pub txn_hash: Hash,
    pub blk_hash: Hash,
    pub uop_hash: Hash,
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

        let relayer = Relayer::new(config.clone(), secret_key, db.clone()).await?;
        let _signer = Signer::new(
            config.clone(),
            secret_key,
            db.clone(),
            message_sender.clone(),
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
