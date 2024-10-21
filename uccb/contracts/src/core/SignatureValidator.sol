// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

interface ISignatureValidatorErrors {
    /**
     * @dev Triggers when the signatures provided are either out of order or repeated
     */
    error NonUniqueOrUnorderedSignatures();
    /**
     * @dev Triggers when the signature does not match any validator
     * It could be due to either the signature being wrong or validator invalid
     */
    error InvalidValidatorOrSignatures();
    /**
     * @dev not enough signatures are provided to reach supermajority
     */
    error NoSupermajority();
}

/**
 * @title SignatureValidator
 * @notice Library used on enumerable set of validators to validate signatures
 * It checks if the signatures are unique, ordered and valid against the provided message hash
 */
library SignatureValidator {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;

    /**
     * @dev Checks for strict supermajority
     */
    function isSupermajority(
        EnumerableSet.AddressSet storage self,
        uint count
    ) internal view returns (bool) {
        return count * 3 > self.length() * 2;
    }

    /**
     * @dev Checks signatures are unique, ordered and valid against message hash
     * and forms a supermajority
     * errors [NonUniqueOrUnorderedSignatures, InvalidValidatorOrSignatures, NoSupermajority]
     * NOTE: The signatures provided must be ordered by address ascendingly otherwise validation will fail
     */
    function validateSignaturesWithSupermajority(
        EnumerableSet.AddressSet storage self,
        bytes32 ethSignedMessageHash,
        bytes[] calldata signatures
    ) internal view {
        address lastSigner = address(0);
        uint signaturesLength = signatures.length;

        for (uint i = 0; i < signaturesLength; ) {
            address signer = ethSignedMessageHash.recover(signatures[i]);
            if (signer <= lastSigner) {
                revert ISignatureValidatorErrors
                    .NonUniqueOrUnorderedSignatures();
            }
            if (!self.contains(signer)) {
                revert ISignatureValidatorErrors.InvalidValidatorOrSignatures();
            }
            lastSigner = signer;
            unchecked {
                ++i;
            }
        }

        if (!isSupermajority(self, signaturesLength)) {
            revert ISignatureValidatorErrors.NoSupermajority();
        }
    }
}
