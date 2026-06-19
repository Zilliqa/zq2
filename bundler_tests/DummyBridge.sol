// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IEntryPointNonces, IPaymaster, IEntryPoint, PackedUserOperation, IAccount, IAccountExecute} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {NoncesKeyed} from "@openzeppelin/contracts/utils/NoncesKeyed.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

contract DummyBridge is
    Pausable,
    IERC7786GatewaySource,
    IERC7786Recipient,
    IEntryPointNonces,
    IPaymaster,
    IAccount,
    NoncesKeyed
{
    event MessageReceived(bytes32 indexed receiveId, address gateway);
    IEntryPoint entryPoint;

    bytes32 private immutable LOCAL_CHAIN_K256;
    address private EP_ADDRESS;

    mapping(uint64 => uint128[6]) private destinationFees;

    constructor(address _ep) payable {
        entryPoint = IEntryPoint(_ep);
        LOCAL_CHAIN_K256 = keccak256(
            InteroperableAddress.formatEvmV1(block.chainid)
        );
        EP_ADDRESS = _ep;

        // pre-populate
        destinationFees[uint64(block.chainid)] = [
            uint128(0x100001),
            uint128(0x100002),
            uint128(0x100003),
            uint128(0x100004),
            uint128(0x100005),
            uint128(0x100006)
        ];
    }

    /// @dev Restrict calls to the EntryPoint or the owner themselves
    modifier onlyEntryPointOrOwner() {
        require(
            msg.sender == EP_ADDRESS, // || msg.sender == owner,
            "SimpleAccount: not entryPoint or owner"
        );
        _;
    }

    /// Called in the execution phase of UserOp handling.
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyEntryPointOrOwner {
        uint256 len = targets.length;
        require(len == values.length && len == datas.length);
        for (uint256 i; i < len; ++i) {
            _execute(targets[i], values[i], datas[i]);
        }
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

    /// IAccountExecute::executeUserOp()
    /// Called in the execution phase of UserOp handling.
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 _userOpHash
    ) external onlyEntryPointOrOwner {
        // return success
    }

    /// IAccount::validateUserOp()
    /// Validates the signature.
    function validateUserOp(
        PackedUserOperation calldata,
        bytes32,
        uint256 missingWalletFunds
    ) public view override returns (uint256 validationData) {
        require(msg.sender == EP_ADDRESS, "Invalid entrypoint");
        require(missingWalletFunds == 0, "Missing paymaster");

        // TODO: Check relayer signature
        validationData = 0;
    }

    /// IPaymaster::validatePaymasterUserOp()
    /// Validates the multi-signature.
    function validatePaymasterUserOp(
        PackedUserOperation calldata,
        bytes32,
        uint256 maxCost
    ) external pure returns (bytes memory context, uint256 validationData) {
        require(maxCost > 0, "maxCost == 0");
        // address relayer = address(bytes20(userOp.paymasterAndData[:20]));

        // TODO: Check bls12-381 multi-signature
        context = ""; // abi.encode(relayer); // trigger post-op
        validationData = 0;
    }

    /// IPaymaster::postOp()
    /// Records the relayer and co-signers.
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint
    ) external onlyEntryPointOrOwner {
        // TODO: Record relayer/signers for rewards
    }

    receive() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    function getNonce(
        address sender,
        uint192 key
    ) external view returns (uint256) {
        return nonces(sender, key);
    }

    function getFees(
        uint64 chain_id
    ) public view virtual returns (uint128[6] memory) {
        return destinationFees[chain_id];
    }

    function supportsAttribute(
        bytes4 /*selector*/
    ) public view virtual returns (bool) {
        return false;
    }

    /// IERC7786Recipient::receiveMessage()
    /// Deconstruct the quad-tuple payload and send the original payload to its destination.
    function receiveMessage(
        bytes32 receiveId,
        bytes calldata _relayer, // CAIP10 - relayer address
        bytes calldata _payload
    ) external payable returns (bytes4) {
        // 1. Validate caller
        // TODO: require(msg.sender == XXX)

        // 2. Record relayer
        address relayer = address(bytes20(_relayer));
        emit MessageReceived(receiveId, relayer);

        // 3. Deconstruct the quad-tuple payload
        (
            bytes memory sender,
            bytes memory recipient,
            bytes memory payload,
            uint256 _nonce
        ) = abi.decode(_payload, (bytes, bytes, bytes, uint256));
        // 4. Nonce replay check

        // 5. Send to destination
        (uint256 dst_chain, address dst_addr) = InteroperableAddress.parseEvmV1(
            recipient
        );
        require(
            keccak256(InteroperableAddress.formatEvmV1(dst_chain)) ==
                LOCAL_CHAIN_K256,
            "Foreign destination"
        );
        (uint256 src_chain, address src_addr) = InteroperableAddress.parseEvmV1(
            sender
        );

        // require(
        //     IERC7786Recipient(Strings.parseAddress(dst_addr)).receiveMessage(
        //         receiveId,
        //         bytes(src_addr),
        //         payload
        //     ) == IERC7786Recipient.receiveMessage.selector,
        //     "Target failed"
        // );
        return IERC7786Recipient.receiveMessage.selector;
    }

    /// IERC7786GatewaySource::sendMessage()
    /// Constructs the cross-chain quad-tuple payload to be relayed.
    function sendMessage(
        bytes calldata recipient, // ERC7930
        bytes calldata payload,
        bytes[] calldata attributes // Stick pricing in here?
    ) public payable virtual whenNotPaused returns (bytes32 sendId) {
        // wrapping the payload
        bytes memory sender = InteroperableAddress.formatEvmV1(
            block.chainid,
            msg.sender
        );
        uint256 nonce = _useNonce(address(this), uint192(0));

        bytes memory wrappedPayload = abi.encode(
            sender,
            recipient,
            payload,
            nonce
        );

        // compute sendId
        sendId = keccak256(wrappedPayload);

        bytes memory gateway = InteroperableAddress.formatEvmV1(
            block.chainid,
            address(this)
        );

        emit MessageSent(
            sendId,
            gateway,
            recipient,
            wrappedPayload,
            0,
            attributes
        );
    }
}
