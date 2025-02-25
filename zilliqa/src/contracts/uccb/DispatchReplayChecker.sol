// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

interface IDispatchReplayCheckerErrors {
    /**
     * @dev Triggered to when a repeated nonce is detected on dispatch request
     */
    error AlreadyDispatched();
}

interface IDispatchReplayChecker is IDispatchReplayCheckerErrors {
    function dispatched(
        uint sourceChainId,
        uint nonce
    ) external view returns (bool);
}

/**
 * @title DispatchReplayChecker
 * @notice Prevents dispatch replay attacks by keeping track of dispatched nonces
 * @dev The contract has a modifier that can be used to protect functions from replay attacks
 * essentially prevent the same message from being dispatched twice
 * The combination of `(sourceChainId, nonce)` form a unique key pair.
 */
abstract contract DispatchReplayCheckerUpgradeable is IDispatchReplayChecker {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:zilliqa.storage.DispatchReplayChecker
     */
    struct DispatchReplayCheckerStorage {
        // sourceChainId => nonce => isDispatched
        mapping(uint => mapping(uint => bool)) dispatched;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.DispatchReplayChecker")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant DISPATCH_REPLAY_CHECKER_STORAGE_POSITION =
        0xf0d7858cd36fafa025d5af5f0a6a6196668a9b0994a77eee7583c69fc18dfb00;

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    function _getDispatchReplayCheckerStorage()
        private
        pure
        returns (DispatchReplayCheckerStorage storage $)
    {
        assembly {
            $.slot := DISPATCH_REPLAY_CHECKER_STORAGE_POSITION
        }
    }

    /**
     * @dev view function to verify if a message has been dispatched
     */
    function dispatched(
        uint sourceChainId,
        uint nonce
    ) external view returns (bool) {
        DispatchReplayCheckerStorage
            storage $ = _getDispatchReplayCheckerStorage();
        return $.dispatched[sourceChainId][nonce];
    }

    /**
     * @dev Internal function handling the replay check and reverts if the message has been dispatched
     */
    function _replayDispatchCheck(uint sourceChainId, uint nonce) internal {
        DispatchReplayCheckerStorage
            storage $ = _getDispatchReplayCheckerStorage();

        if ($.dispatched[sourceChainId][nonce]) {
            revert AlreadyDispatched();
        }
        $.dispatched[sourceChainId][nonce] = true;
    }

    /**
     * @dev Modifier to protect functions from replay attacks and used by child contracts
     */
    modifier replayDispatchGuard(uint sourceShardId, uint nonce) {
        _replayDispatchCheck(sourceShardId, nonce);
        _;
    }
}
