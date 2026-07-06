// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "./Precompiles.sol";

/// @title  Boneh–Lynn–Shacham (BLS) signature scheme on Barreto-Lynn-Scott 381-bit curve (BLS12-381) used to verify BLS signatures
/// @notice We use BLS signature aggregation to reduce the size of signature data to store on chain.
/// @dev We support both BLS conventions:
///        - "min-sig": messages/signatures on G1 (96 bytes), public keys on G2 (192 bytes) -- see `verifySingle`.
///        - "min-pubkey-size": public keys on G1 (96 bytes), messages/signatures on G2 (192 bytes) -- see the
///          `verifySingle` overload taking a `PointG2 signature` and `PointG1 pubkey`, and `hashToPointG2`.
/// @dev base field elements are 48-bytes, and are represented as an uint128 followed by and uint256.
/// @dev G1 is 96 bytes and G2 is 192 bytes. Compression is not currently available.
library BLS2 {
    struct PointG1 {
        uint128 x_hi;
        uint256 x_lo;
        uint128 y_hi;
        uint256 y_lo;
    }

    struct PointG2 {
        uint128 x1_hi;
        uint256 x1_lo;
        uint128 x0_hi;
        uint256 x0_lo;
        uint128 y1_hi;
        uint256 y1_lo;
        uint128 y0_hi;
        uint256 y0_lo;
    }

    uint128 private constant N_G2_X0_HI = 0x024aa2b2f08f0a91260805272dc51051;
    uint256 private constant N_G2_X0_LO =
        0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
    uint128 private constant N_G2_X1_HI = 0x13e02b6052719f607dacd3a088274f65;
    uint256 private constant N_G2_X1_LO =
        0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
    uint128 private constant N_G2_Y0_HI = 0x0d1b3cc2c7027888be51d9ef691d77bc;
    uint256 private constant N_G2_Y0_LO =
        0xb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa;
    uint128 private constant N_G2_Y1_HI = 0x13fa4d4a0ad8b1ce186ed5061789213d;
    uint256 private constant N_G2_Y1_LO =
        0x993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed;

    // Field order
    uint128 private constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO =
        0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    uint128 private constant P_PLUS_ONE_SLASH_2_HI =
        0x0680447a8e5ff9a692c6e9ed90d2eb35;
    uint256 private constant P_PLUS_ONE_SLASH_2_LO =
        0xd91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab;

    // Negated generator of G1, used to verify a signature/message pair that lives on G2 against a
    // public key that lives on G1: e(-g1, signature) * e(pubkey, H(m)) == 1  <=>  e(g1, signature) == e(pubkey, H(m))
    uint128 private constant N_G1_X_HI = 0x17f1d3a73197d7942695638c4fa9ac0f;
    uint256 private constant N_G1_X_LO =
        0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    uint128 private constant N_G1_Y_HI = 0x114d1d6855d545a8aa7d76c8cf2e21f2;
    uint256 private constant N_G1_Y_LO =
        0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca;

    error InvalidDSTLength(bytes dst);

    /// @notice Unmarshals a point on G1 from bytes in an uncompressed form.
    function g1Unmarshal(
        bytes memory m
    ) internal pure returns (PointG1 memory) {
        require(m.length == 96, "Invalid G1 bytes length");

        uint128 x_hi;
        uint256 x_lo;
        uint128 y_hi;
        uint256 y_lo;

        assembly {
            x_hi := shr(128, mload(add(m, 0x20)))
            x_lo := mload(add(m, 0x30))
            y_hi := shr(128, mload(add(m, 0x50)))
            y_lo := mload(add(m, 0x60))
        }

        return PointG1(x_hi, x_lo, y_hi, y_lo);
    }

    // @notice Unmarshal a G1 point in compressed form.
    function g1UnmarshalCompressed(
        bytes memory m
    ) internal view returns (PointG1 memory) {
        require(m.length == 48, "Invalid G1 bytes length");

        uint128 x_hi;
        uint256 x_lo;
        uint128 y_hi;
        uint256 y_lo;

        bytes memory buf = new bytes(288);

        uint8 flags;
        bool larger = false;

        assembly {
            x_hi := shr(128, mload(add(m, 0x20)))
            x_lo := mload(add(m, 0x30))
            flags := byte(16, x_hi)
            x_hi := and(x_hi, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        }

        if (flags & 0x80 == 0) {
            revert("Invalid G1 point: not compressed");
        }
        if (flags & 0x40 != 0) {
            revert("unsupported: point at infinity");
        }
        if (flags & 0x20 == 0) {
            larger = true;
        }

        // compute x**3 mod p
        bool ok;
        assembly {
            let p := add(buf, 32)
            mstore(p, 64) // length of base
            p := add(p, 32)
            mstore(p, 1) // length of exponent 3
            p := add(p, 32)
            mstore(p, 64) // length of modulus
            p := add(p, 32)
            mstore(p, x_hi)
            p := add(p, 32)
            mstore(p, x_lo)
            p := add(p, 32)
            mstore8(p, 3) // exponent
            p := add(p, 1)
            mstore(p, P_HI)
            p := add(p, 32)
            mstore(p, P_LO)
            ok := staticcall(
                gas(),
                MODEXP_ADDRESS,
                add(32, buf),
                225,
                add(32, buf),
                64
            )
            y_hi := mload(add(buf, 32))
            y_lo := mload(add(buf, 64))
        }
        assert(ok);
        unchecked {
            y_lo += 4;
        }
        if (y_lo < 4) {
            // overflow -> carry
            y_hi += 1;
        }

        // compute y = sqrt(x**3 + 4) mod p = (x**3 + 4)^(p+1)/2 mod p
        assembly {
            let p := add(buf, 32)
            mstore(p, 64) // length of base
            p := add(p, 32)
            mstore(p, 64) // length of exponent
            p := add(p, 32)
            mstore(p, 64) // length of modulus
            p := add(p, 32)
            mstore(p, y_hi)
            p := add(p, 32)
            mstore(p, y_lo)
            p := add(p, 32)
            mstore(p, P_PLUS_ONE_SLASH_2_HI)
            p := add(p, 32)
            mstore(p, P_PLUS_ONE_SLASH_2_LO)
            p := add(p, 32)
            mstore(p, P_HI)
            p := add(p, 32)
            mstore(p, P_LO)
            ok := staticcall(
                gas(),
                MODEXP_ADDRESS,
                add(32, buf),
                288,
                add(32, buf),
                64
            )
            y_hi := mload(add(buf, 32))
            y_lo := mload(add(buf, 64))
        }
        assert(ok);

        uint128 alt_y_hi = P_HI - y_hi;
        uint256 alt_y_lo;
        unchecked {
            alt_y_lo = P_LO - y_lo;
        }
        if (alt_y_lo > P_LO) {
            // underflow -> carry
            alt_y_hi -= 1;
        }

        bool do_swap = y_hi > alt_y_hi || (y_hi == alt_y_hi && y_lo > alt_y_lo);
        do_swap = larger == do_swap;
        if (do_swap) {
            y_hi = alt_y_hi;
            y_lo = alt_y_lo;
        }

        return PointG1(x_hi, x_lo, y_hi, y_lo);
    }

    /// @notice Marshals a point on G1 to bytes form.
    function g1Marshal(
        PointG1 memory point
    ) internal pure returns (bytes memory) {
        bytes memory m = new bytes(96);
        uint256 x_hi = point.x_hi;
        uint256 x_lo = point.x_lo;
        uint256 y_hi = point.y_hi;
        uint256 y_lo = point.y_lo;

        assembly {
            mstore(add(m, 0x20), shl(128, x_hi))
            mstore(add(m, 0x30), x_lo)
            mstore(add(m, 0x50), shl(128, y_hi))
            mstore(add(m, 0x60), y_lo)
        }

        return m;
    }

    function g2Unmarshal(
        bytes memory m
    ) internal pure returns (PointG2 memory) {
        require(m.length == 192, "Invalid G2 bytes length");

        uint128 x1_hi;
        uint256 x1_lo;
        uint128 x0_hi;
        uint256 x0_lo;
        uint128 y1_hi;
        uint256 y1_lo;
        uint128 y0_hi;
        uint256 y0_lo;

        assembly {
            x1_hi := shr(128, mload(add(m, 0x20)))
            x1_lo := mload(add(m, 0x30))
            x0_hi := shr(128, mload(add(m, 0x50)))
            x0_lo := mload(add(m, 0x60))
            y1_hi := shr(128, mload(add(m, 0x80)))
            y1_lo := mload(add(m, 0x90))
            y0_hi := shr(128, mload(add(m, 0xb0)))
            y0_lo := mload(add(m, 0xc0))
        }

        return PointG2(x1_hi, x1_lo, x0_hi, x0_lo, y1_hi, y1_lo, y0_hi, y0_lo);
    }

    function g2Marshal(
        PointG2 memory point
    ) internal pure returns (bytes memory) {
        bytes memory m = new bytes(192);
        uint256 x1_hi = point.x1_hi;
        uint256 x1_lo = point.x1_lo;
        uint256 x0_hi = point.x0_hi;
        uint256 x0_lo = point.x0_lo;
        uint256 y1_hi = point.y1_hi;
        uint256 y1_lo = point.y1_lo;
        uint256 y0_hi = point.y0_hi;
        uint256 y0_lo = point.y0_lo;

        assembly {
            mstore(add(m, 0x20), shl(128, x1_hi))
            mstore(add(m, 0x30), x1_lo)
            mstore(add(m, 0x50), shl(128, x0_hi))
            mstore(add(m, 0x60), x0_lo)
            mstore(add(m, 0x80), shl(128, y1_hi))
            mstore(add(m, 0x90), y1_lo)
            mstore(add(m, 0xb0), shl(128, y0_hi))
            mstore(add(m, 0xc0), y0_lo)
        }

        return m;
    }

    // follows RFC9380 §5
    function hashToPoint(
        bytes memory dst,
        bytes memory message
    ) internal view returns (PointG1 memory out) {
        bytes memory uniform_bytes = expandMsg(dst, message, 128);
        bytes memory buf = new bytes(225);
        bytes memory buf2 = new bytes(256);
        bool ok;
        for (uint256 i = 0; i < 2; i++) {
            assembly {
                // inplace mod in uniform_bytes[64*i]
                let p := add(32, uniform_bytes)
                let q := add(32, buf)

                p := add(p, mul(64, i))
                mstore(q, 64) // length of base
                q := add(q, 32)
                mstore(q, 1) // length of exponent 1
                q := add(q, 32)
                mstore(q, 64) // length of modulus
                q := add(q, 32)
                mcopy(q, p, 64) // copy base
                q := add(q, 64)
                mstore8(q, 1) // exponent
                q := add(q, 1)
                mstore(q, P_HI)
                q := add(q, 32)
                mstore(q, P_LO)
                ok := staticcall(
                    gas(),
                    MODEXP_ADDRESS,
                    add(32, buf),
                    225,
                    p,
                    64
                )

                // EIP-2537 map_fp_to_g1
                let r := add(32, buf2)
                r := add(r, mul(128, i))
                ok := and(
                    ok,
                    staticcall(gas(), BLS12_MAP_FP_TO_G1, p, 64, r, 128)
                )
            }
            require(ok);
        }
        assembly {
            ok := staticcall(gas(), BLS12_G1ADD, add(buf2, 32), 256, out, 128)
        }
        require(ok, "g1add failed");
    }

    /// @notice Hash a message onto a point on G2, following RFC9380 §5 (suite BLS12381G2_XMD:SHA-256_SSWU_RO_).
    /// @dev Used for the "min-pubkey-size" convention: 96-byte G1 public keys and 192-byte G2 signatures/messages.
    /// @dev Fp2 elements are encoded c0 || c1 (64 bytes each), matching the EIP-2537 precompile encoding, so the
    ///      x0/y0 (c0) and x1/y1 (c1) fields of the returned PointG2 can be fed straight into `verifySingle` or
    ///      `BLS12_PAIRING_CHECK` without any further reshuffling.
    /// @param dst Domain separation tag
    /// @param message The message to hash
    /// @return out The resulting point on G2
    function hashToPointG2(
        bytes memory dst,
        bytes memory message
    ) internal view returns (PointG2 memory out) {
        // 2 field elements (u0, u1) in Fp2, each made of 2 Fp components (c0, c1), each L = 64 bytes -> 256 bytes.
        bytes memory uniform_bytes = expandMsg(dst, message, 256);
        bytes memory buf = new bytes(225);
        bytes memory buf2 = new bytes(512); // two intermediate G2 points (256 bytes each)

        bool ok;
        for (uint256 i = 0; i < 2; i++) {
            assembly {
                // reduce c0 (uniform_bytes[128*i : 128*i+64]) mod p in place
                let p := add(32, uniform_bytes)
                p := add(p, mul(128, i))
                let q := add(32, buf)
                mstore(q, 64) // length of base
                q := add(q, 32)
                mstore(q, 1) // length of exponent 1
                q := add(q, 32)
                mstore(q, 64) // length of modulus
                q := add(q, 32)
                mcopy(q, p, 64) // copy base (c0)
                q := add(q, 64)
                mstore8(q, 1) // exponent
                q := add(q, 1)
                mstore(q, P_HI)
                q := add(q, 32)
                mstore(q, P_LO)
                ok := staticcall(
                    gas(),
                    MODEXP_ADDRESS,
                    add(32, buf),
                    225,
                    p,
                    64
                )

                // reduce c1 (uniform_bytes[128*i+64 : 128*i+128]) mod p in place
                let p1 := add(p, 64)
                q := add(32, buf)
                mstore(q, 64)
                q := add(q, 32)
                mstore(q, 1)
                q := add(q, 32)
                mstore(q, 64)
                q := add(q, 32)
                mcopy(q, p1, 64) // copy base (c1)
                q := add(q, 64)
                mstore8(q, 1)
                q := add(q, 1)
                mstore(q, P_HI)
                q := add(q, 32)
                mstore(q, P_LO)
                ok := and(
                    ok,
                    staticcall(gas(), MODEXP_ADDRESS, add(32, buf), 225, p1, 64)
                )

                // EIP-2537 map_fp2_to_g2 on the reduced Fp2 element (c0 || c1, 128 bytes at p)
                let r := add(32, buf2)
                r := add(r, mul(256, i))
                ok := and(
                    ok,
                    staticcall(gas(), BLS12_MAP_FP2_TO_G2, p, 128, r, 256)
                )
            }
            require(ok, "map to G2 failed");
        }

        bytes memory res = new bytes(256);
        assembly {
            ok := staticcall(
                gas(),
                BLS12_G2ADD,
                add(buf2, 32),
                512,
                add(res, 32),
                256
            )
        }
        require(ok, "g2add failed");

        // res is laid out as EIP-2537 G2 point: x_c0 || x_c1 || y_c0 || y_c1 (64 bytes each, already
        // zero-padded), which maps onto our x0/x1/y0/y1 fields (c0 -> x0/y0, c1 -> x1/y1).
        uint128 x0_hi;
        uint256 x0_lo;
        uint128 x1_hi;
        uint256 x1_lo;
        uint128 y0_hi;
        uint256 y0_lo;
        uint128 y1_hi;
        uint256 y1_lo;
        assembly {
            x0_hi := mload(add(res, 0x20))
            x0_lo := mload(add(res, 0x40))
            x1_hi := mload(add(res, 0x60))
            x1_lo := mload(add(res, 0x80))
            y0_hi := mload(add(res, 0xa0))
            y0_lo := mload(add(res, 0xc0))
            y1_hi := mload(add(res, 0xe0))
            y1_lo := mload(add(res, 0x100))
        }
        out = PointG2(x1_hi, x1_lo, x0_hi, x0_lo, y1_hi, y1_lo, y0_hi, y0_lo);
    }

    /// @notice Expand arbitrary message to n bytes, as described
    ///     in rfc9380 section 5.3.1, using H = sha256.
    /// @param DST Domain separation tag
    /// @param message The message to expand
    /// @param n_bytes The number of bytes to extend to (encoded as a 2-byte big-endian length, per rfc9380)
    function expandMsg(
        bytes memory DST,
        bytes memory message,
        uint16 n_bytes
    ) internal pure returns (bytes memory) {
        uint256 domainLen = DST.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(DST);
        }
        bytes memory zpad = new bytes(64);
        bytes memory b_0 = abi.encodePacked(
            zpad,
            message,
            uint8(n_bytes >> 8),
            uint8(n_bytes),
            uint8(0),
            DST,
            uint8(domainLen)
        );
        bytes32 b0 = sha256(b_0);

        bytes memory b_i = abi.encodePacked(
            b0,
            uint8(1),
            DST,
            uint8(domainLen)
        );
        bytes32 bi = sha256(b_i);
        bytes memory out = new bytes(n_bytes);
        uint256 ell = (uint256(n_bytes) + uint256(31)) >> 5;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(
                b0 ^ bi,
                uint8(1 + i),
                DST,
                uint8(domainLen)
            );
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = sha256(b_i);
        }
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Verify signed message on g1 against signature on g1 and public key on g2
    /// @param signature Signature to check
    /// @param pubkey Public key of signer
    /// @param message Message to check
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifySingle(
        PointG1 memory signature,
        PointG2 memory pubkey,
        PointG1 memory message
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        uint256[24] memory input = [
            signature.x_hi,
            signature.x_lo,
            signature.y_hi,
            signature.y_lo,
            N_G2_X0_HI,
            N_G2_X0_LO,
            N_G2_X1_HI,
            N_G2_X1_LO,
            N_G2_Y0_HI,
            N_G2_Y0_LO,
            N_G2_Y1_HI,
            N_G2_Y1_LO,
            message.x_hi,
            message.x_lo,
            message.y_hi,
            message.y_lo,
            pubkey.x0_hi,
            pubkey.x0_lo,
            pubkey.x1_hi,
            pubkey.x1_lo,
            pubkey.y0_hi,
            pubkey.y0_lo,
            pubkey.y1_hi,
            pubkey.y1_lo
        ];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(
                gas(),
                BLS12_PAIRING_CHECK,
                input,
                768,
                out,
                0x20
            )
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Verify signed message on G2 against a signature on G2 and a public key on G1
    /// @dev "min-pubkey-size" convention: 96-byte G1 public keys, 192-byte G2 signatures/messages.
    ///      Checks e(-g1, signature) * e(pubkey, message) == 1, which holds iff
    ///      e(g1, signature) == e(pubkey, message), i.e. e(g1, sk*H(m)) == e(sk*g1, H(m)).
    /// @param signature Signature to check, on G2
    /// @param pubkey Public key of signer, on G1
    /// @param message Message to check (typically the output of `hashToPointG2`), on G2
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifySingle(
        PointG2 memory signature,
        PointG1 memory pubkey,
        PointG2 memory message
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        uint256[24] memory input = [
            N_G1_X_HI,
            N_G1_X_LO,
            N_G1_Y_HI,
            N_G1_Y_LO,
            signature.x0_hi,
            signature.x0_lo,
            signature.x1_hi,
            signature.x1_lo,
            signature.y0_hi,
            signature.y0_lo,
            signature.y1_hi,
            signature.y1_lo,
            pubkey.x_hi,
            pubkey.x_lo,
            pubkey.y_hi,
            pubkey.y_lo,
            message.x0_hi,
            message.x0_lo,
            message.x1_hi,
            message.x1_lo,
            message.y0_hi,
            message.y0_lo,
            message.y1_hi,
            message.y1_lo
        ];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(
                gas(),
                BLS12_PAIRING_CHECK,
                input,
                768,
                out,
                0x20
            )
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Adds two points on G1, using the EIP-2537 G1 point addition precompile.
    /// @param p1 The first point on the G1 curve.
    /// @param p2 The second point on the G1 curve.
    /// @return sum The resulting point p1 + p2 on G1.
    function addG1Points(
        PointG1 memory p1,
        PointG1 memory p2
    ) internal view returns (PointG1 memory sum) {
        uint256[8] memory input = [
            uint256(p1.x_hi),
            p1.x_lo,
            uint256(p1.y_hi),
            p1.y_lo,
            uint256(p2.x_hi),
            p2.x_lo,
            uint256(p2.y_hi),
            p2.y_lo
        ];
        uint256[4] memory out;
        bool ok;
        assembly {
            ok := staticcall(gas(), BLS12_G1ADD, input, 256, out, 128)
        }
        require(ok, "g1add failed");
        sum = PointG1(uint128(out[0]), out[1], uint128(out[2]), out[3]);
    }

    /// @notice Aggregates an array of 96-byte G1 public keys into a single multi/aggregated public key.
    /// @dev Aggregation is a simple sum on G1: pkAgg = pubkeys[0] + pubkeys[1] + ... + pubkeys[n-1].
    ///      This matches the corresponding multi-signature aggregation, sigAgg = sig_0 + sig_1 + ... + sig_(n-1)
    ///      on G2, so that verifySingle(sigAgg, pkAgg, H(m)) succeeds iff every signer signed the same message.
    /// @param pubkeys Array of signer public keys, each 96 bytes (uncompressed, on G1). Must be non-empty.
    /// @return aggPubkey The aggregated public key, on G1
    function aggregatePublicKeys(
        bytes[] memory pubkeys
    ) internal view returns (PointG1 memory aggPubkey) {
        require(pubkeys.length > 0, "no public keys provided");
        aggPubkey = g1Unmarshal(pubkeys[0]);
        for (uint256 i = 1; i < pubkeys.length; i++) {
            aggPubkey = addG1Points(aggPubkey, g1Unmarshal(pubkeys[i]));
        }
    }

    /// @notice Verify a payload against a BLS multi-signature and the individual signers' public keys.
    /// @dev "min-pubkey-size" convention: 96-byte G1 public keys, 192-byte G2 multi-signature.
    ///      Computes the aggregated public key (sum of the individual G1 public keys) and checks it against
    ///      the (already aggregated) multi-signature using the same pairing equation as
    ///      `verifySingle(PointG2 signature, PointG1 pubkey, PointG2 message)`, i.e.
    ///      e(-g1, sigAgg) * e(pkAgg, H(m)) == 1.
    /// @dev Every signer is assumed to have signed the exact same `message` with the same `dst`. This does not
    ///      perform subgroup-membership checks on the supplied public keys/signature.
    /// @param dst Domain separation tag used to hash `message` onto G2
    /// @param signature The 192-byte aggregated multi-signature, on G2
    /// @param pubkeys Array of signer public keys, each 96 bytes, on G1
    /// @param message The signed payload (raw bytes; this function hashes it onto G2 internally)
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifyMulti(
        bytes memory dst,
        bytes memory signature,
        bytes[] memory pubkeys,
        bytes memory message
    ) internal view returns (bool pairingSuccess, bool callSuccess) {
        require(signature.length == 192, "Invalid G2 signature bytes length");

        PointG1 memory aggPubkey = aggregatePublicKeys(pubkeys);
        PointG2 memory sig = g2Unmarshal(signature);
        PointG2 memory hashedMessage = hashToPointG2(dst, message);

        return verifySingle(sig, aggPubkey, hashedMessage);
    }
}
