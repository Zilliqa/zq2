use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, B256, ChainId, U256, keccak256},
    sol_types::SolValue,
};
use anyhow::Result;

use super::PackedUserOperation;

pub fn get_chain_id(account_id: &str) -> Result<ChainId> {
    if let [namespace, chain_id, _address] = account_id.split(':').collect::<Vec<_>>().as_slice()
        && *namespace == "eip155"
    {
        return Ok(ChainId::from_str_radix(chain_id, 10)?);
    }
    Err(anyhow::anyhow!("Invalid AccountId"))
}

/// keccak256("PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,
///            bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)")
const PACKED_TYPE_HASH: B256 =
    alloy::primitives::b256!("29a0bca4af4be3421398da00295e58e6d7de38cb492214754cb6a47507dd6f8e");

/// Compute the EIP-712 struct hash of a PackedUserOperation.
/// Optionally accepts an override for the initCode hash (used for EIP-7702 init codes).
fn user_op_hash_inner(
    user_op: &PackedUserOperation,
    override_init_code_hash: Option<B256>,
) -> B256 {
    let type_hash = PACKED_TYPE_HASH;

    let init_code_hash = override_init_code_hash.unwrap_or_else(|| keccak256(&user_op.initCode));
    let call_data_hash = keccak256(&user_op.callData);
    let paymaster_hash = keccak256(&user_op.paymasterAndData);

    let encoded = (
        type_hash,
        user_op.sender,
        user_op.nonce,
        init_code_hash,
        call_data_hash,
        user_op.accountGasLimits,
        user_op.preVerificationGas,
        user_op.gasFees,
        paymaster_hash,
    )
        .abi_encode();

    keccak256(encoded)
}

/// Legacy (v0.7) inner hash: keccak256(abi.encode(sender, nonce, hashInitCode, hashCallData, accountGasLimits, preVerificationGas, gasFees, hashPaymasterAndData))
fn user_op_hash_legacy(
    user_op: &PackedUserOperation,
    override_init_code_hash: Option<B256>,
) -> B256 {
    let init_code_hash = override_init_code_hash.unwrap_or_else(|| keccak256(&user_op.initCode));
    let call_data_hash = keccak256(&user_op.callData);
    let paymaster_hash = keccak256(&user_op.paymasterAndData);

    // Build encoded tuple exactly as solidity's abi.encode(sender, nonce, hashInitCode, hashCallData,
    // accountGasLimits, preVerificationGas, gasFees, hashPaymasterAndData)
    let encoded = (
        user_op.sender,
        user_op.nonce,
        init_code_hash,
        call_data_hash,
        user_op.accountGasLimits,
        user_op.preVerificationGas,
        user_op.gasFees,
        paymaster_hash,
    )
        .abi_encode();

    keccak256(encoded)
}

// FIXME: Keep in sync with newer Entrypoint versions.
/// EntryPoint.getUserOpHash().
///
/// Returns the final EIP-712 typed data hash. Works against v0.7/0.8/0.9 only!
pub fn get_user_op_hash(
    user_op: &PackedUserOperation,
    entry_point: Address,
    chain_id: u64,
) -> Result<B256> {
    // if entry_point equals the known v0.7 address, use legacy hashing
    match entry_point {
        super::ENTRYPOINT_V07 => {
            // inner hash is keccak256(abi.encode(...)) without the type hash
            let inner = user_op_hash_legacy(user_op, None);
            let encoded = (inner, entry_point, U256::from(chain_id)).abi_encode();
            Ok(keccak256(encoded))
        }
        super::ENTRYPOINT_V08 | super::ENTRYPOINT_V09 => {
            let domain_sep = Eip712Domain::new(
                Some("ERC4337".into()),
                Some("1".into()),
                Some(U256::from(chain_id)),
                Some(entry_point),
                None,
            )
            .hash_struct();
            let struct_hash = user_op_hash_inner(user_op, None);

            // EIP-712: "\x19\x01" ++ domainSeparator ++ structHash
            let mut digest_input = [0u8; 66];
            digest_input[0] = 0x19;
            digest_input[1] = 0x01;
            digest_input[2..34].copy_from_slice(domain_sep.as_slice());
            digest_input[34..66].copy_from_slice(struct_hash.as_slice());

            Ok(keccak256(digest_input))
        }
        _ => Err(anyhow::anyhow!("Entrypoint {entry_point:?} unsupported")),
    }
}
