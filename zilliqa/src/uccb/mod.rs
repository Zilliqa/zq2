use alloy::{
    primitives::{Address, B256, ChainId, address, b256},
    rpc::types::PackedUserOperation as AlloyUserOperation,
    sol,
};

use crate::crypto::{BlsSignature, Hash};

pub mod relayer;
pub mod signer;
pub mod uccb;

pub const ENTRYPOINT_V07: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
pub const ENTRYPOINT_V08: Address = address!("0x4337084d9e255ff0702461cf8895ce9e3b5ff108");
pub const ENTRYPOINT_V09: Address = address!("0x433709009B8330FDa32311DF1C2AFA402eD8D009");
pub const ERC7786_MESSAGE_SENT: B256 =
    b256!("0x7446eaa0a0dda80670b3bfe972bfbefab659bcfb67abad4e0b64dc4630a70481");

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
