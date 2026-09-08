// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable, Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {IValidatorManager} from "./ValidatorManager.sol";
import {IDispatchReplayChecker, DispatchReplayChecker} from "./DispatchReplayChecker.sol";

interface IChainDispatcherEvents {
    /**
     * @dev Triggered when an event enters this chain
     */
    event Dispatched(
        uint256 indexed sourceChainId,
        address indexed target,
        bool success,
        bytes response,
        uint256 indexed nonce
    );
}

interface IChainDispatcherErrors {
    /**
     * @dev The target address being called must be a contract or the call will fall through
     */
    error NonContractCaller(address target);
}

interface IChainDispatcher is
    IChainDispatcherEvents,
    IChainDispatcherErrors,
    IDispatchReplayChecker
{
    function validatorManager() external view returns (address);

    function setValidatorManager(address validatorManager) external;

    function dispatch(
        uint256 sourceChainId,
        address target,
        bytes calldata call,
        uint256 gasLimit,
        uint256 nonce,
        bytes[] calldata signatures
    ) external;
}

/**
 * @title ChainDispatcher
 * @notice Handles everything related to receiving messages from other chains to be dispatched
 * @dev This contract should be used by inherited for cross-chain messaging. It is also made upgradeable.
 *
 * The `dispatch` function will dispatch a message sourcing from a different chain
 * It is able to relay message to any arbitrary chain that is part of the UCCB network
 */
abstract contract ChainDispatcher is
    IChainDispatcher,
    Initializable,
    Ownable2StepUpgradeable,
    DispatchReplayChecker
{
    using MessageHashUtils for bytes;

    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:zilliqa.storage.ChainDispatcher
     */
    struct ChainDispatcherStorage {
        IValidatorManager validatorManager;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.ChainDispatcher")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant CHAIN_DISPATCHER_STORAGE_POSITION =
        0x8cff60b14f9f959be48079fe56fd2ddb283fd144e381f4bd805400fbf1d0d600;

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    function _getChainDispatcherStorage()
        private
        pure
        returns (ChainDispatcherStorage storage $)
    {
        assembly {
            $.slot := CHAIN_DISPATCHER_STORAGE_POSITION
        }
    }

    /**
     * @dev Initializes the contracts with all the inherited contracts
     */
    function __ChainDispatcher_init(
        address _owner,
        address _validatorManager
    ) internal onlyInitializing {
        __Ownable_init(_owner);
        __ChainDispatcher_init_unchained(_validatorManager);
    }

    /**
     * @dev The unchained version is used to avoid repeated initializations down the inheritance path
     */
    function __ChainDispatcher_init_unchained(
        address _validatorManager
    ) internal onlyInitializing {
        _setValidatorManager(_validatorManager);
    }

    /**
     * @dev Returns the address of the validator manager used to validator messages
     */
    function validatorManager() external view returns (address) {
        ChainDispatcherStorage storage $ = _getChainDispatcherStorage();
        return address($.validatorManager);
    }

    /**
     * @dev Sets the validator manager
     */
    function _setValidatorManager(address _validatorManager) internal {
        ChainDispatcherStorage storage $ = _getChainDispatcherStorage();
        $.validatorManager = IValidatorManager(_validatorManager);
    }

    /**
     * @dev External function to set validator manager and permissioned by owner
     */
    function setValidatorManager(address _validatorManager) external onlyOwner {
        _setValidatorManager(_validatorManager);
    }

    /**
     * @dev Dispatches a message from another chain, it also verifies the signatures from the dispatchers
     *
     * The function will should not revert on the underlying call instruction made to the target contract
     * and should catch all cases the it would fail.
     *
     * All other sources of transaction failure would come from the validation of the signatures of the call
     * or due to cross-chain message replay, where the same nonce is being used repeatedly
     *
     * NOTE: The exception to reverting due to underlying call can be caused if the call is made to a scilla interoperability precompile
     * where if this fails, it will revert the whole transaction
     *
     * @param sourceChainId the chainid where the message originated
     * @param target the address of the contract to be called
     * @param call the call data to be used in the call
     * @param gasLimit the gas limit to be used in the call
     * @param nonce the nonce from the relayer on the source chain
     * @param signatures the signatures of the messages of the validator
     */
    function dispatch(
        uint256 sourceChainId,
        address target,
        bytes calldata call,
        uint256 gasLimit,
        uint256 nonce,
        bytes[] calldata signatures
    ) external replayDispatchGuard(sourceChainId, nonce) {
        ChainDispatcherStorage storage $ = _getChainDispatcherStorage();

        $.validatorManager.validateMessageWithSupermajority(
            abi
                .encode(
                    sourceChainId,
                    block.chainid,
                    target,
                    call,
                    gasLimit,
                    nonce
                )
                .toEthSignedMessageHash(),
            signatures
        );

        // If it is not a contract the call itself should not revert
        if (target.code.length == 0) {
            emit Dispatched(
                sourceChainId,
                target,
                false,
                abi.encodeWithSelector(NonContractCaller.selector, target),
                nonce
            );
            return;
        }

        // This call will not revert the transaction
        (bool success, bytes memory response) = (target).call{gas: gasLimit}(
            call
        );

        emit Dispatched(sourceChainId, target, success, response, nonce);
    }
}
