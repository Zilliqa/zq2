// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

// @notice address of the EIP-198 modular exponentiation precompile
uint256 constant MODEXP_ADDRESS = 5;

// @notice address of the EIP-196 BN254 G1 point addition
uint256 constant ECADD_ADDRESS = 6;

// @notice address of the EIP-196 BN254 G1 scalar multiplication
uint256 constant ECMUL_ADDRESS = 7;

// @notice address of the EIP-197 BN254 pairing check
uint256 constant BN254_ECPAIRING_ADDRESS = 8;

// @notice address of the EIP-2537 BLS12-381 point addition precompile (G1)
uint256 constant BLS12_G1ADD = 0x0b;

// @notice address of the EIP-2537 BLS12-381 point addition precompile (G2)
uint256 constant BLS12_G2ADD = 0x0d;

// @notice address of the EIP-2537 BLS12-381 pairing check precompile
uint256 constant BLS12_PAIRING_CHECK = 0x0f;

// @notice address of the EIP-2537 BLS12-381 base field element to G1 point precompile
// @dev it uses the Simplified Shallue-van de Woestĳne-Ulas mapping (SSWU)
uint256 constant BLS12_MAP_FP_TO_G1 = 0x10;

// @notice address of the EIP-2537 BLS12-381 quadratic extension field element to G2 point precompile
// @dev it uses the Simplified Shallue-van de Woestĳne-Ulas mapping (SSWU)
uint256 constant BLS12_MAP_FP2_TO_G2 = 0x11;
