// SPDX-License-Identifier: MIT
// Adapted from https://github.com/randa-mu/bls-solidity
pragma solidity ^0.8.28;

// @notice address of the EIP-198 modular exponentiation precompile
uint256 constant MODEXP_ADDRESS = 5;
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
        uint128 xHi;
        uint256 xLo;
        uint128 yHi;
        uint256 yLo;
    }

    struct PointG2 {
        uint128 x1Hi;
        uint256 x1Lo;
        uint128 x0Hi;
        uint256 x0Lo;
        uint128 y1Hi;
        uint256 y1Lo;
        uint128 y0Hi;
        uint256 y0Lo;
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

        uint128 xHi;
        uint256 xLo;
        uint128 yHi;
        uint256 yLo;

        assembly {
            xHi := shr(128, mload(add(m, 0x20)))
            xLo := mload(add(m, 0x30))
            yHi := shr(128, mload(add(m, 0x50)))
            yLo := mload(add(m, 0x60))
        }

        return PointG1(xHi, xLo, yHi, yLo);
    }

    // @notice Unmarshal a G1 point in compressed form.
    function g1UnmarshalCompressed(
        bytes memory m
    ) internal view returns (PointG1 memory) {
        require(m.length == 48, "Invalid G1 bytes length");

        uint128 xHi;
        uint256 xLo;
        uint128 yHi;
        uint256 yLo;

        bytes memory buf = new bytes(288);

        uint8 flags;
        bool larger = false;

        assembly {
            xHi := shr(128, mload(add(m, 0x20)))
            xLo := mload(add(m, 0x30))
            flags := byte(16, xHi)
            xHi := and(xHi, 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
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
            mstore(p, xHi)
            p := add(p, 32)
            mstore(p, xLo)
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
            yHi := mload(add(buf, 32))
            yLo := mload(add(buf, 64))
        }
        assert(ok);
        unchecked {
            yLo += 4;
        }
        if (yLo < 4) {
            // overflow -> carry
            yHi += 1;
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
            mstore(p, yHi)
            p := add(p, 32)
            mstore(p, yLo)
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
            yHi := mload(add(buf, 32))
            yLo := mload(add(buf, 64))
        }
        assert(ok);

        uint128 alt_yHi = P_HI - yHi;
        uint256 alt_yLo;
        unchecked {
            alt_yLo = P_LO - yLo;
        }
        if (alt_yLo > P_LO) {
            // underflow -> carry
            alt_yHi -= 1;
        }

        bool do_swap = yHi > alt_yHi || (yHi == alt_yHi && yLo > alt_yLo);
        do_swap = larger == do_swap;
        if (do_swap) {
            yHi = alt_yHi;
            yLo = alt_yLo;
        }

        return PointG1(xHi, xLo, yHi, yLo);
    }

    /// @notice Marshals a point on G1 to uncompressed bytes form.
    function g1Marshal(
        PointG1 memory point
    ) internal pure returns (bytes memory) {
        bytes memory m = new bytes(96);
        uint256 xHi = point.xHi;
        uint256 xLo = point.xLo;
        uint256 yHi = point.yHi;
        uint256 yLo = point.yLo;

        assembly {
            mstore(add(m, 0x20), shl(128, xHi))
            mstore(add(m, 0x30), xLo)
            mstore(add(m, 0x50), shl(128, yHi))
            mstore(add(m, 0x60), yLo)
        }

        return m;
    }

    function g2Unmarshal(
        bytes memory m
    ) internal pure returns (PointG2 memory) {
        require(m.length == 192, "Invalid G2 bytes length");

        uint128 x1Hi;
        uint256 x1Lo;
        uint128 x0Hi;
        uint256 x0Lo;
        uint128 y1Hi;
        uint256 y1Lo;
        uint128 y0Hi;
        uint256 y0Lo;

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

        return PointG2(x1Hi, x1Lo, x0Hi, x0Lo, y1Hi, y1Lo, y0Hi, y0Lo);
    }

    function g2Marshal(
        PointG2 memory point
    ) internal pure returns (bytes memory) {
        bytes memory m = new bytes(192);
        uint256 x1Hi = point.x1Hi;
        uint256 x1Lo = point.x1Lo;
        uint256 x0Hi = point.x0Hi;
        uint256 x0Lo = point.x0Lo;
        uint256 y1Hi = point.y1Hi;
        uint256 y1Lo = point.y1Lo;
        uint256 y0Hi = point.y0Hi;
        uint256 y0Lo = point.y0Lo;

        assembly {
            mstore(add(m, 0x20), shl(128, x1Hi))
            mstore(add(m, 0x30), x1Lo)
            mstore(add(m, 0x50), shl(128, x0Hi))
            mstore(add(m, 0x60), x0Lo)
            mstore(add(m, 0x80), shl(128, y1Hi))
            mstore(add(m, 0x90), y1Lo)
            mstore(add(m, 0xb0), shl(128, y0Hi))
            mstore(add(m, 0xc0), y0Lo)
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
        uint128 x0Hi;
        uint256 x0Lo;
        uint128 x1Hi;
        uint256 x1Lo;
        uint128 y0Hi;
        uint256 y0Lo;
        uint128 y1Hi;
        uint256 y1Lo;
        assembly {
            x0Hi := mload(add(res, 0x20))
            x0Lo := mload(add(res, 0x40))
            x1Hi := mload(add(res, 0x60))
            x1Lo := mload(add(res, 0x80))
            y0Hi := mload(add(res, 0xa0))
            y0Lo := mload(add(res, 0xc0))
            y1Hi := mload(add(res, 0xe0))
            y1Lo := mload(add(res, 0x100))
        }
        out = PointG2(x1Hi, x1Lo, x0Hi, x0Lo, y1Hi, y1Lo, y0Hi, y0Lo);
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
            signature.xHi,
            signature.xLo,
            signature.yHi,
            signature.yLo,
            N_G2_X0_HI,
            N_G2_X0_LO,
            N_G2_X1_HI,
            N_G2_X1_LO,
            N_G2_Y0_HI,
            N_G2_Y0_LO,
            N_G2_Y1_HI,
            N_G2_Y1_LO,
            message.xHi,
            message.xLo,
            message.yHi,
            message.yLo,
            pubkey.x0Hi,
            pubkey.x0Lo,
            pubkey.x1Hi,
            pubkey.x1Lo,
            pubkey.y0Hi,
            pubkey.y0Lo,
            pubkey.y1Hi,
            pubkey.y1Lo
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
            signature.x0Hi,
            signature.x0Lo,
            signature.x1Hi,
            signature.x1Lo,
            signature.y0Hi,
            signature.y0Lo,
            signature.y1Hi,
            signature.y1Lo,
            pubkey.xHi,
            pubkey.xLo,
            pubkey.yHi,
            pubkey.yLo,
            message.x0Hi,
            message.x0Lo,
            message.x1Hi,
            message.x1Lo,
            message.y0Hi,
            message.y0Lo,
            message.y1Hi,
            message.y1Lo
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
            uint256(p1.xHi),
            p1.xLo,
            uint256(p1.yHi),
            p1.yLo,
            uint256(p2.xHi),
            p2.xLo,
            uint256(p2.yHi),
            p2.yLo
        ];
        uint256[4] memory out;
        bool ok;
        assembly {
            ok := staticcall(gas(), BLS12_G1ADD, input, 256, out, 128)
        }
        require(ok, "g1add failed");
        sum = PointG1(uint128(out[0]), out[1], uint128(out[2]), out[3]);
    }

    /// @notice Aggregates an array of 48-byte G1 public keys into a single multi/aggregated public key.
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
}
