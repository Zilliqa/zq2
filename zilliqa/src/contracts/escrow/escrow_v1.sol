// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Groth16Verifier} from "./verifier.sol";

contract EscrowInit is UUPSUpgradeable, Groth16Verifier {
    uint64 public constant VERSION = 1;
    /// @custom:storage-location erc7201:zilliqa.claimvault.storage
    struct ClaimVaultStorage {
        mapping(address => uint256) balances;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.claimvault.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ClaimVaultStorageLocation =
        0x8cf65e91db77c9a578cba58115eeac4928c460eeeb74dcf98908c5ffaac6b600;

    function _getClaimVaultStorage()
        private
        pure
        returns (ClaimVaultStorage storage $)
    {
        assembly {
            $.slot := ClaimVaultStorageLocation
        }
    }

    event Deposited(address indexed from, uint256 amount);
    event Released(
        address indexed oldAddress,
        address indexed newAddress,
        uint256 amount
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() public payable initializer {
        __UUPSUpgradeable_init();
    }

    /// @notice Anyone can send funds here; recorded against msg.sender.
    /// We do not implement a receive() to prevent accidental transfers.
    function lodge() external payable {
        ClaimVaultStorage storage $ = _getClaimVaultStorage();
        $.balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function balanceOf(address addr) public view returns (uint256) {
        return _getClaimVaultStorage().balances[addr];
    }

    /// @dev Required by UUPSUpgradeable — gates who can call upgradeToAndCall
    function _authorizeUpgrade(
        // solhint-disable-next-line no-unused-vars
        address newImplementation
    ) internal virtual override {
        require(
            msg.sender == address(0),
            "system contract must be upgraded by the system"
        );
    }

    /// @param pA Groth16 proof component A
    /// @param pB Groth16 proof component B
    /// @param pC Groth16 proof component C
    /// @param pubSignals [old_address, new_address, chain_id]
    function claim(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) public {
        require(pubSignals[2] == block.chainid, "Invalid domain");
        ClaimVaultStorage storage $ = _getClaimVaultStorage();

        address srcAddress = address(uint160(pubSignals[0]));
        uint256 amount = $.balances[srcAddress];
        // require(amount > 0, "No balance lodged");

        // Verify ZKP
        bool verify = verifyProof(pA, pB, pC, pubSignals);
        require(verify, "Zk-proof failed");

        // Effects before interaction (reentrancy guard pattern)
        $.balances[srcAddress] = 0;
        address dstAddress = address(uint160(pubSignals[1]));
        (bool sent, ) = payable(dstAddress).call{value: amount}("");
        require(sent, "Transfer failed");

        emit Released(srcAddress, dstAddress, amount);
    }
}
