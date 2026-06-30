// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {AbstractSigner} from "@openzeppelin/contracts/utils/cryptography/signers/AbstractSigner.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {IEntryPoint, IAccount, IAccountExecute, PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {MultiSignerERC7913Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/MultiSignerERC7913Upgradeable.sol";
import {MultiSignerERC7913WeightedUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/MultiSignerERC7913WeightedUpgradeable.sol";

/**
 * @title  UccbSender
 * @notice ERC-4337 Sender contract built entirely on OpenZeppelin v5.6.x.
 *
 * @custom:oz-upgrades-unsafe-allow constructor
 */
contract UccbSender is
    Initializable,
    MultiSignerERC7913WeightedUpgradeable,
    ERC165Upgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardTransient,
    EIP712Upgradeable,
    IAccountExecute,
    Account
{
    using Address for address;

    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice One-time initializer called by the factory immediately after
     *         deploying the proxy.
     */
    function initialize(address admin_) external initializer {
        __EIP712_init("UccbSender", "1");
        __AccessControl_init();
        __ERC165_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(WITHDRAWER_ROLE, admin_);
    }

    // This is needed to allow UccbGateway::setLink() to work.
    function supportsAttribute(bytes4) external pure returns (bool) {
        // does not need to do anything
        return false;
    }

    /// ***** External execution *****

    /**
     * @notice Execute a single arbitrary call.
     *         Called by the EntryPoint after successful validateUserOp.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPointOrSelf nonReentrant {
        _execute(target, value, data);
    }

    /**
     * @dev Low-level call with revert bubbling.
     *      Uses Address.functionCallWithValue so reverts propagate correctly
     *      even when returndata is empty.
     */
    function _execute(
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        // Address.functionCallWithValue reverts with the upstream reason on failure.
        // We catch it here to emit ExecutionFailure before re-reverting.
        try this._callExternal(target, value, data) {
            // emit ExecutionSuccess(target, value, data);
        } catch (bytes memory reason) {
            // emit ExecutionFailure(target, value, data, reason);
            // Re-revert with the original reason.
            assembly {
                revert(add(reason, 32), mload(reason))
            }
        }
    }

    /**
     * @dev External shim so try/catch can wrap a low-level call.
     *      Only callable by this contract itself (via _execute's try/catch).
     */
    function _callExternal(
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        assert(msg.sender == address(this));
        Address.functionCallWithValue(target, data, value);
    }

    /*
     * Configuration Messages
     * ======================
     * Used by the Rust pipeline to send updates to the Sender/Paymaster contracts e.g.
     * - Updated stakers list
     * - Updated stakes
     */
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external onlyEntryPoint {
        // TODO: Update stakers/stakes
    }

    /*
     * Overrides internal signature verification function
     */

    // EIP-2537 Pairing Check Precompile Address
    address constant BLS12_PAIRING_CHECK = address(0x0f);

    /**
     * @notice High-level verification of a BLS12-381 signature
     * @param publicKeyThe G1 public key point (128 bytes: x, y padded to 64 bytes each)
     * @param messageG2   The message mapped to a G2 point (256 bytes: x0, x1, y0, y1 padded)
     * @param signature   The G2 signature point (256 bytes: x0, x1, y0, y1 padded)
     */
    function verify(
        bytes calldata publicKey,
        bytes calldata messageG2,
        bytes calldata signature
    ) external view returns (bool) {
        // Validation: Verify standard EVM EIP-2537 input sizes
        require(publicKey.length == 128, "Invalid G1 Public Key size");
        require(messageG2.length == 256, "Invalid G2 Message size");
        require(signature.length == 256, "Invalid G2 Signature size");

        // According to EIP-2537, the pairing precompile accepts an array of pairs.
        // It returns 1 if: e(P1, Q1) * e(P2, Q2) * ... * e(Pk, Qk) == 1
        // We verify the BLS relation: e(G1_Generator, Signature) == e(PublicKey, Message)
        // Which translates mathematically to: e(-G1_Generator, Signature) * e(PublicKey, Message) == 1

        bytes memory pairingInput = abi.encodePacked(
            getNegativeG1Generator(), // 128 bytes (G1)
            signature, // 256 bytes (G2)
            publicKey, // 128 bytes (G1)
            messageG2 // 256 bytes (G2)
        );

        // Execute staticcall to EIP-2537 pairing precompile
        (bool success, bytes memory result) = BLS12_PAIRING_CHECK.staticcall(
            pairingInput
        );

        if (!success || result.length == 0) {
            return false;
        }

        // Returns 1 if pairing condition holds true, 0 otherwise
        return abi.decode(result, (uint256)) == 1;
    }

    /**
     * @dev Returns the standard negated G1 generator point for BLS12-381
     * encoded as two 64-byte padded elements (EIP-2537 format).
     */
    function getNegativeG1Generator() internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                uint256(
                    0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
                ),
                uint256(
                    0x08b3f481e3aaa6a3ec3133761014e59c1b76617054b01750a630659c00de45b1b51b8e83162c118e8609531193300a2a
                )
            );
    }

    function _decodeSignature(
        bytes calldata packedSig
    )
        private
        pure
        returns (
            address addr,
            bytes memory msig,
            bytes memory cosig,
            bytes memory sig
        )
    {
        // Sanity check to prevent out-of-bounds errors
        require(packedSig.length == 244, "Invalid signature length");

        // Slice out each segment and cast manually
        addr = address(bytes20(packedSig[0:20]));
        msig = bytes(packedSig[20:116]);
        cosig = bytes(packedSig[116:148]);
        sig = bytes(packedSig[148:244]);
    }

    function _rawSignatureValidation(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        pure
        override(AbstractSigner, MultiSignerERC7913Upgradeable)
        returns (bool)
    {
        if (signature.length == 0) return false; // For ERC-7739 compatibility
        (
            address signer,
            bytes memory msig,
            bytes memory cosig,
            bytes memory sig
        ) = _decodeSignature(signature);
        bytes memory message = signature[0:148];

        // verify sig(message)

        // verify msig(hash)

        // TODO: verify all signatures signature
        return hash != 0 && signature.length != 0;
    }

    // ***** SIGNERS MANAGEMENT *****

    function addSigners(
        bytes[] memory signers
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addSigners(signers);
    }

    function removeSigners(
        bytes[] memory signers
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _removeSigners(signers);
    }

    function setThreshold(
        uint64 threshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setThreshold(threshold);
    }

    function setSignerWeights(
        bytes[] memory signers,
        uint64[] memory weights
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _setSignerWeights(signers, weights);
    }

    /**
     * @notice Top-up this account's gas deposit in the EntryPoint.
     */
    function depositTo() external payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice View current EntryPoint deposit balance.
     */
    function balanceOf() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * @notice Withdraw ETH from the EntryPoint deposit.
     */
    function withdrawTo(
        address payable to,
        uint256 amount
    ) external onlyRole(WITHDRAWER_ROLE) {
        entryPoint().withdrawTo(to, amount);
    }

    // ***** BOILER-PLATE *****

    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return
            interfaceId == type(IAccountExecute).interfaceId ||
            interfaceId == type(IAccount).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev Account.receive() already exists and emits nothing.
     *      Override to emit an event so indexers can track deposits.
     */
    receive() external payable virtual override {}
}
