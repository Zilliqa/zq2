use alloy::{
    primitives::{Address, ChainId},
    providers::{
        Identity, RootProvider,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    rpc::types::PackedUserOperation,
};
use blsful::{Bls12381G2Impl, PublicKey};
use crossbeam::utils::Backoff;
use revm::primitives::address;

use crate::crypto::{BlsSignature, Hash};

pub mod bundler;
pub mod relayer;
pub mod signer;
pub mod watcher;

pub const ENTRYPOINT_V07: Address = address!("0x0000000071727de22e5e9d8baf0edac6f37da032");
pub const ENTRYPOINT_V08: Address = address!("0x4337084d9e255ff0702461cf8895ce9e3b5ff108");
pub const ENTRYPOINT_V09: Address = address!("0x433709009B8330FDa32311DF1C2AFA402eD8D009");

pub struct SignUserOp {
    pub userop: PackedUserOperation,
    pub chain: ChainId,
    pub txn_hash: Hash,
    pub blk_hash: Hash,
}

pub struct RelayUserOp {
    pub userop: PackedUserOperation,
    pub chain: ChainId,
    pub hash: Hash,
}

pub struct BlsUserOp {
    pub hash: Hash,
    pub userop: PackedUserOperation,
    pub signatures: Vec<BlsSignature>,
    pub stake: u128,
}

/// Used to send an updated list of SIGNER keys
pub struct EpochUpdate {
    epoch_boundary: u64, // the future epoch (N+1) block number
    threshold: u128,     // majority stake
    signers: Vec<(Address, PublicKey<Bls12381G2Impl>, u128)>, // list of signers at epoch above.
}

type BundlerProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;
