// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Thin wrapper around the EIP-2537 BLS12_G1ADD precompile at address 0x0b.
/// Used to verify that the precompile is wired up under the Pectra fork.
contract Bls12G1Add {
    function addG1(bytes calldata input) external view returns (bytes memory) {
        (bool ok, bytes memory output) = address(0x0b).staticcall(input);
        require(ok, "BLS12_G1ADD failed");
        return output;
    }
}
