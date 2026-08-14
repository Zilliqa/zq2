// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS} from "solady/src/utils/ext/ithaca/BLS.sol";

abstract contract BLS12381 {
    bytes32 private constant NEG_G1_GEN_X_A = bytes32(
        uint256(31827880280837800241567138048534752271)
    );
    bytes32 private constant NEG_G1_GEN_X_B = bytes32(
        uint256(
            88385725958748408079899006800036250932223001591707578097800747617502997169851
        )
    );
    bytes32 private constant NEG_G1_GEN_Y_A = bytes32(
        uint256(22997279242622214937712647648895181298)
    );
    bytes32 private constant NEG_G1_GEN_Y_B = bytes32(
        uint256(
            46816884707101390882112958134453447585552332943769894357249934112654335001290
        )
    );

    function _g1Decode(
        bytes memory m
    ) private pure returns (BLS.G1Point memory) {
        require(m.length == 96, "Invalid G1 bytes length");

        bytes32 xHi;
        bytes32 xLo;
        bytes32 yHi;
        bytes32 yLo;

        assembly {
            xHi := shr(128, mload(add(m, 0x20)))
            xLo := mload(add(m, 0x30))
            yHi := shr(128, mload(add(m, 0x50)))
            yLo := mload(add(m, 0x60))
        }

        return BLS.G1Point(xHi, xLo, yHi, yLo);
    }

    function _g2Decode(
        bytes memory m
    ) private pure returns (BLS.G2Point memory) {
        require(m.length == 192, "Invalid G2 bytes length");

        bytes32 x1Hi;
        bytes32 x1Lo;
        bytes32 x0Hi;
        bytes32 x0Lo;
        bytes32 y1Hi;
        bytes32 y1Lo;
        bytes32 y0Hi;
        bytes32 y0Lo;

        assembly {
            x1Hi := shr(128, mload(add(m, 0x20)))
            x1Lo := mload(add(m, 0x30))
            x0Hi := shr(128, mload(add(m, 0x50)))
            x0Lo := mload(add(m, 0x60))
            y1Hi := shr(128, mload(add(m, 0x80)))
            y1Lo := mload(add(m, 0x90))
            y0Hi := shr(128, mload(add(m, 0xb0)))
            y0Lo := mload(add(m, 0xc0))
        }

        return BLS.G2Point(x0Hi, x0Lo, x1Hi, x1Lo, y0Hi, y0Lo, y1Hi, y1Lo);
    }

    /**
     * Verifies a BLS12-381 signature.
     *
     * @param payload The raw byte array message that was signed.
     * @param pubkeyG1 The public key, encoded as a 96-byte G1 point.
     * @param signatureG2 The signature, encoded as a 192-byte G2 point.
     * @return bool True if the signature is valid, false otherwise.
     */
    function _validateSignature(
        bytes memory pubkeyG1,
        bytes memory payload,
        bytes memory signatureG2
    ) internal view returns (bool) {
        BLS.G2Point memory hmsg = BLS.hashToG2(payload);

        BLS.G1Point[] memory g1points = new BLS.G1Point[](2);
        BLS.G2Point[] memory g2points = new BLS.G2Point[](2);

        g1points[0] = BLS.G1Point(
            NEG_G1_GEN_X_A,
            NEG_G1_GEN_X_B,
            NEG_G1_GEN_Y_A,
            NEG_G1_GEN_Y_B
        );
        g1points[1] = _g1Decode(pubkeyG1);
        g2points[0] = _g2Decode(signatureG2);
        g2points[1] = hmsg;

        return BLS.pairing(g1points, g2points);
    }

    /// @dev See `MultiSignerERC7913._validateSignatures`. Sorting signers by their `keccak256`
    /// hash improves gas efficiency, as with the non-checkpointed version.
    function _validateSignatures(
        bytes32 hash,
        bytes[] memory signers,
        bytes memory aggSig
    ) internal view returns (bool valid) {
        require(signers.length > 0, "no public keys provided");
        // aggregate public keys
        BLS.G1Point memory aggPubkey;
        aggPubkey = _g1Decode(signers[0]);
        for (uint256 i = 1; i < signers.length; i++) {
            aggPubkey = BLS.add(aggPubkey, _g1Decode(signers[i]));
        }

        BLS.G2Point memory hmsg = BLS.hashToG2(bytes.concat(hash));

        BLS.G1Point[] memory g1points = new BLS.G1Point[](2);
        BLS.G2Point[] memory g2points = new BLS.G2Point[](2);

        g1points[0] = BLS.G1Point(
            NEG_G1_GEN_X_A,
            NEG_G1_GEN_X_B,
            NEG_G1_GEN_Y_A,
            NEG_G1_GEN_Y_B
        );
        g1points[1] = aggPubkey;
        g2points[0] = _g2Decode(aggSig);
        g2points[1] = hmsg;

        return BLS.pairing(g1points, g2points);
    }

    /**
     * Verifies a Cross-Message Multi-Signature
     *
     * @param xSig      the (Multi-sig + Sender-sig) cross-message signature.
     * @param hash      the Message payload
     * @param signers   the Set of G1 public keys used in Multi-sig
     * @param payload   the Sender payload
     * @param signer    the Sender G1 public key used in Sender-sig.
     */
    function _validateCrossSignatures(
        bytes memory xSig, // 192-bytes
        bytes32 hash, // 32-bytes
        bytes[] memory signers,
        bytes memory payload, // 328-bytes
        bytes memory signer // 96-bytes
    ) internal view returns (bool valid) {
        require(signers.length > 0, "no public keys provided");

        // sender public key
        BLS.G1Point memory senderKey = _g1Decode(signer);
        // aggregate public keys
        BLS.G1Point memory aggPubkey;
        aggPubkey = _g1Decode(signers[0]);
        for (uint256 i = 1; i < signers.length; i++) {
            aggPubkey = BLS.add(aggPubkey, _g1Decode(signers[i]));
        }

        // hash of messages
        BLS.G2Point memory hdata = BLS.hashToG2(bytes.concat(hash));
        BLS.G2Point memory hsender = BLS.hashToG2(payload);

        BLS.G1Point[] memory g1Points = new BLS.G1Point[](3);
        BLS.G2Point[] memory g2Points = new BLS.G2Point[](3);

        // construct e(P1, Q1) * e(P2, Q2) * ... * e(Pk, Qk) == 1; where k = 3.
        g1Points[0] = senderKey;
        g1Points[1] = aggPubkey;
        g1Points[2] = BLS.G1Point(
            NEG_G1_GEN_X_A,
            NEG_G1_GEN_X_B,
            NEG_G1_GEN_Y_A,
            NEG_G1_GEN_Y_B
        );

        g2Points[0] = hsender;
        g2Points[1] = hdata;
        g2Points[2] = _g2Decode(xSig);

        return BLS.pairing(g1Points, g2Points);
    }
}
