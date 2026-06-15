// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ISignatureValidatorErrors, SignatureValidator} from "../../uccb/SignatureValidator.sol";
import {Tester, Vm} from "../../test/Tester.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract SignatureValidatorHarness is Tester {
    using EnumerableSet for EnumerableSet.AddressSet;
    using SignatureValidator for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private _validators;

    constructor(address[] memory validators) {
        uint256 validatorsLength = validators.length;
        for (uint256 i = 0; i < validatorsLength; ++i) {
            _validators.add(validators[i]);
        }
    }

    function exposed_validateMessageWithSupermajority(
        bytes32 ethSignedMessageHash,
        bytes[] calldata signatures
    ) external view {
        _validators.validateSignaturesWithSupermajority(
            ethSignedMessageHash,
            signatures
        );
    }
}

abstract contract SignatureValidatorFixture is Tester {
    using MessageHashUtils for bytes;
    using EnumerableSet for EnumerableSet.AddressSet;
    using SignatureValidator for EnumerableSet.AddressSet;

    uint256 constant validatorSize = 10;
    SignatureValidatorHarness internal signatureValidator;

    Vm.Wallet[] validatorsWallets = new Vm.Wallet[](validatorSize);

    constructor() {
        // Setup validator manager
        (
            Vm.Wallet[] memory _validatorWallets,
            SignatureValidatorHarness _signatureValidator
        ) = generateValidators(validatorSize);
        validatorsWallets = _validatorWallets;
        signatureValidator = _signatureValidator;
    }

    function generateValidators(
        uint256 size
    ) internal returns (Vm.Wallet[] memory, SignatureValidatorHarness) {
        Vm.Wallet[] memory validatorWallets = new Vm.Wallet[](size);
        address[] memory validatorAddresses = new address[](size);
        for (uint256 i = 0; i < size; ++i) {
            validatorWallets[i] = vm.createWallet(i + 1);
            validatorAddresses[i] = validatorWallets[i].addr;
        }

        return (
            validatorWallets,
            new SignatureValidatorHarness(validatorAddresses)
        );
    }

    function exactSupermajority(
        uint256 size
    ) internal pure returns (uint256 supermajority) {
        supermajority = (size * 2) / 3 + 1;
    }

    function getValidatorSubset(
        Vm.Wallet[] memory _validators,
        uint256 size
    ) internal pure returns (Vm.Wallet[] memory subset) {
        subset = new Vm.Wallet[](size);
        for (uint256 i = 0; i < size; ++i) {
            subset[i] = _validators[i];
        }
    }
}

contract SignatureValidatorTests is SignatureValidatorFixture {
    using MessageHashUtils for bytes;

    function test_allValidatorsSign() external {
        bytes32 messageHash = bytes("Hello world").toEthSignedMessageHash();
        bytes[] memory signatures = multiSign(
            sort(validatorsWallets),
            messageHash
        );
        // If it works does not do anything
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function test_exactMajoritySign() external {
        bytes32 messageHash = bytes("Hello world").toEthSignedMessageHash();
        uint256 exactSupermajoritySize = exactSupermajority(validatorSize);
        Vm.Wallet[] memory exactSupermajorityValidators = getValidatorSubset(
            validatorsWallets,
            exactSupermajoritySize
        );
        bytes[] memory signatures = multiSign(
            sort(exactSupermajorityValidators),
            messageHash
        );
        // If it works does not do anything
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function testRevert_lessThanSupermajoritySign() external {
        bytes32 messageHash = bytes("Hello world").toEthSignedMessageHash();
        uint256 exactSupermajoritySize = exactSupermajority(validatorSize) - 1;
        Vm.Wallet[] memory exactSupermajorityValidators = getValidatorSubset(
            validatorsWallets,
            exactSupermajoritySize
        );
        bytes[] memory signatures = multiSign(
            sort(exactSupermajorityValidators),
            messageHash
        );
        // If it works does not do anything
        vm.expectRevert(ISignatureValidatorErrors.NoSupermajority.selector);
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function testRevert_noSignatures() external {
        bytes32 messageHash = bytes("Hello world").toEthSignedMessageHash();
        bytes[] memory signatures = new bytes[](0);
        vm.expectRevert(ISignatureValidatorErrors.NoSupermajority.selector);
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function test_emptyMessage() external {
        bytes32 messageHash;
        bytes[] memory signatures = multiSign(
            sort(validatorsWallets),
            messageHash
        );
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function testRevert_invalidSignature() external {
        bytes32 messageHash = bytes("Hello world").toEthSignedMessageHash();
        bytes[] memory signatures = multiSign(
            sort(validatorsWallets),
            messageHash
        );
        // Manipulate one of the bytes in the first signature
        signatures[0][0] = 0;
        vm.expectRevert(
            ISignatureValidatorErrors.InvalidValidatorOrSignatures.selector
        );
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function testRevert_unorderedSignatures() external {
        bytes32 messageHash = bytes("Hello world").toEthSignedMessageHash();
        // Don't sort the validators by address
        bytes[] memory signatures = multiSign(validatorsWallets, messageHash);
        vm.expectRevert(
            ISignatureValidatorErrors.NonUniqueOrUnorderedSignatures.selector
        );
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function testRevert_repeatedSigners() external {
        bytes32 messageHash = bytes("Hello world").toEthSignedMessageHash();
        // Don't sort the validators by address
        bytes[] memory signatures = multiSign(
            sort(validatorsWallets),
            messageHash
        );
        // Repeat first and second validator
        signatures[0] = signatures[1];
        vm.expectRevert(
            ISignatureValidatorErrors.NonUniqueOrUnorderedSignatures.selector
        );
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function testFuzz_message(bytes memory message) external {
        bytes32 messageHash = message.toEthSignedMessageHash();
        bytes[] memory signatures = multiSign(
            sort(validatorsWallets),
            messageHash
        );

        // Should work regardless of validators
        signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    function test_largeValidatorSet() external {
        uint256 _validatorSize = 25_000;

        (
            Vm.Wallet[] memory _validatorWallet,
            SignatureValidatorHarness _signatureValidator
        ) = generateValidators(_validatorSize);

        bytes32 messageHash = bytes("Hello World").toEthSignedMessageHash();
        bytes[] memory signatures = multiSign(
            sort(_validatorWallet),
            messageHash
        );

        // Should work regardless of validators
        _signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }

    /// forge-config: default.fuzz.runs = 100
    function testFuzz_signatureCount(uint256 input) external {
        uint256 size = 200;
        uint256 exactSupermajoritySize = exactSupermajority(size);
        uint256 signaturesCount = exactSupermajoritySize +
            (input % (size - exactSupermajoritySize));

        (
            Vm.Wallet[] memory _validatorWallet,
            SignatureValidatorHarness _signatureValidator
        ) = generateValidators(size);
        Vm.Wallet[] memory validatorSubset = getValidatorSubset(
            _validatorWallet,
            signaturesCount
        );
        bytes32 messageHash = bytes("Hello World").toEthSignedMessageHash();

        bytes[] memory signatures = multiSign(
            sort(validatorSubset),
            messageHash
        );

        // Should work regardless of validators
        _signatureValidator.exposed_validateMessageWithSupermajority(
            messageHash,
            signatures
        );
    }
}
