// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
// import {SignatureValidator} from "contracts/core/SignatureValidator.sol";

interface IValidatorManager {
    function addValidator(address user) external returns (bool);

    function removeValidator(address user) external returns (bool);

    function getValidators() external view returns (address[] memory);

    function isValidator(address user) external view returns (bool);

    function validatorsSize() external view returns (uint);

    /*
    function validateMessageWithSupermajority(
        bytes32 ethSignedMessageHash,
        bytes[] calldata signatures
    ) external view;
    */
}

contract ValidatorManager is Ownable2Step {
    using EnumerableSet for EnumerableSet.AddressSet;
    // using SignatureValidator for EnumerableSet.AddressSet;
    bool initialized = false;

    EnumerableSet.AddressSet private _validators;

    constructor(address _owner) Ownable(_owner) {}

    modifier initializer() {
        require(!initialized, "ValidatorManager: already initialized");
        initialized = true;
        _;
    }

    function initialize(
        address[] calldata validators
    ) external onlyOwner initializer {
        uint validatorsLength = validators.length;
        for (uint i = 0; i < validatorsLength; ++i) {
            addValidator(validators[i]);
        }
    }

    // Ownership should then be transferred to the relayer
    function addValidator(address user) public onlyOwner returns (bool) {
        return _validators.add(user);
    }

    // Ownership should then be transferred to the relayer
    function removeValidator(address user) external onlyOwner returns (bool) {
        return _validators.remove(user);
    }

    function setValidators(address[] calldata users) external onlyOwner {
      clearValidators();

      uint256 length = users.length;
      for (uint256 i = 0; i < length; ++i) {
        _validators.add(users[i]);
      }
    }

    // Expensive function, avoid calling on-chain
    function getValidators() external view returns (address[] memory) {
        return _validators.values();
    }

    function isValidator(address user) external view returns (bool) {
        return _validators.contains(user);
    }

    function validatorsSize() external view returns (uint) {
        return _validators.length();
    }

    function clearValidators() private {
        uint256 length = _validators.length();
        for (uint256 i = length; i > 0; i--) {
            _validators.remove(_validators.at(i - 1));
        }
    }
      /*
    function validateMessageWithSupermajority(
        bytes32 ethSignedMessageHash,
        bytes[] calldata signatures
    ) external view {
        _validators.validateSignaturesWithSupermajority(
            ethSignedMessageHash,
            signatures
        );
    }
      */
}
