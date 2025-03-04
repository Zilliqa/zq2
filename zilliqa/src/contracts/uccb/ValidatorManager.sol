// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable, Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ISignatureValidatorErrors, SignatureValidator} from "./SignatureValidator.sol";

interface IValidatorManager is ISignatureValidatorErrors {
    function addValidator(address user) external returns (bool);

    function removeValidator(address user) external returns (bool);

    function getValidators() external view returns (address[] memory);

    function isValidator(address user) external view returns (bool);

    function validatorsSize() external view returns (uint256);

    function validateMessageWithSupermajority(
        bytes32 ethSignedMessageHash,
        bytes[] calldata signatures
    ) external view;
}

/**
 * @title ValidatorManager
 * @notice Manages the validators for the UCCB network
 * It can be used by `ChainGateway` contract to verify the signatures of the validators
 * on incoming dispatch requests
 */
contract ValidatorManager is
    IValidatorManager,
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using SignatureValidator for EnumerableSet.AddressSet;

    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:zilliqa.storage.ValidatorManager
     */
    struct ValidatorManagerStorage {
        EnumerableSet.AddressSet validators;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.ValidatorManager")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VALIDATOR_MANAGER_STORAGE_POSITION =
        0x7accde04f7b3831ef9580fa40c18d71adaa2564f23664e60f2464dcc899c5400;

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    function _getValidatorManagerStorage()
        private
        pure
        returns (ValidatorManagerStorage storage $)
    {
        assembly {
            $.slot := VALIDATOR_MANAGER_STORAGE_POSITION
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the contract with the owner and the initial validators
     */
    function initialize(
        address _owner,
        address[] calldata validators
    ) external initializer {
        __Ownable_init(_owner);

        uint256 validatorsLength = validators.length;
        for (uint256 i = 0; i < validatorsLength; ++i) {
            _addValidator(validators[i]);
        }
    }

    /**
     * @dev Restricts update to only the owner
     */
    function _authorizeUpgrade(address) internal virtual override onlyOwner {}

    /**
     * @dev Internal getter for validators
     */
    function _validators()
        internal
        view
        returns (EnumerableSet.AddressSet storage)
    {
        ValidatorManagerStorage storage $ = _getValidatorManagerStorage();
        return $.validators;
    }

    /**
     * @dev internal setter to add new validator
     */
    function _addValidator(address user) internal returns (bool) {
        return _validators().add(user);
    }

    /**
     * @dev external function to add new validator restricted to owner
     */
    function addValidator(address user) public onlyOwner returns (bool) {
        return _addValidator(user);
    }

    /**
     * @dev external function to remove validator restricted to owner
     */
    function removeValidator(address user) external onlyOwner returns (bool) {
        return _validators().remove(user);
    }

    /**
     * @dev external function to get all validators
     * Expensive function, avoid calling on-chain.
     * Should be used off-chain only.
     */
    function getValidators() external view returns (address[] memory) {
        return _validators().values();
    }

    /**
     * @dev getter to check if the user is part of the validator set
     */
    function isValidator(address user) external view returns (bool) {
        return _validators().contains(user);
    }

    /**
     * @dev getter to get the size of the validator set
     */
    function validatorsSize() external view returns (uint256) {
        return _validators().length();
    }

    /**
     * @dev validators the signatures against the input hash
     * Ensuring that all the signatures are from the validators
     * and satisfies supermajority of the validators
     * Signatures also have to be passed in ascending order of address
     * No repeated signatures are allowed
     * Function reverts if the signatures are not valid
     */
    function validateMessageWithSupermajority(
        bytes32 ethSignedMessageHash,
        bytes[] calldata signatures
    ) external view {
        _validators().validateSignaturesWithSupermajority(
            ethSignedMessageHash,
            signatures
        );
    }
}
