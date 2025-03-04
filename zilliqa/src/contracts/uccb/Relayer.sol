// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {OwnableUpgradeable, Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {Registry, IRegistry} from "./Registry.sol";

interface IRelayerEvents {
    /**
     * @dev Triggered when a outgoing message is relayed to another chain
     */
    event Relayed(
        uint256 indexed targetChainId,
        address target,
        bytes call,
        uint256 gasLimit,
        uint256 nonce
    );
}

struct CallMetadata {
    uint256 sourceChainId;
    address sender;
}

interface IRelayer is IRelayerEvents, IRegistry {
    /**
     * @dev Incorporates the extra metadata to add on relay
     */
    struct CallMetadata {
        uint256 sourceChainId;
        address sender;
    }

    function nonce(uint256 chainId) external view returns (uint256);

    function relayWithMetadata(
        uint256 targetChainId,
        address target,
        bytes4 callSelector,
        bytes calldata callData,
        uint256 gasLimit
    ) external returns (uint256);

    function relay(
        uint256 targetChainId,
        address target,
        bytes calldata call,
        uint256 gasLimit
    ) external returns (uint256);
}

/**
 * @title Relayer
 * @notice Handles everything related to outgoing messages to be dispatched on other chains
 * @dev This contract should be used by inherited for cross-chain messaging. It is also made upgradeable.
 *
 * It is able to relay message to any arbitrary chain that is part of the UCCB network
 */
abstract contract Relayer is
    IRelayer,
    Initializable,
    Ownable2StepUpgradeable,
    Registry
{
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:zilliqa.storage.Relayer
     */
    struct RelayerStorage {
        // TargetChainId => Nonce
        mapping(uint256 => uint256) nonce;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.Relayer")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant RELAYER_STORAGE_POSITION =
        0x814fccf6b0465c7c83d1a86cf4c4cdd0d8463969cbd4702358f5ae439f30a000;

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    function _getRelayerStorage()
        private
        pure
        returns (RelayerStorage storage $)
    {
        assembly {
            $.slot := RELAYER_STORAGE_POSITION
        }
    }

    /**
     * @dev Initializes the contracts with all the inherited contracts
     */
    function __Relayer_init(address _owner) internal onlyInitializing {
        __Ownable_init(_owner);
        __Relayer_init_unchained();
    }

    /**
     * @dev The unchained version is used to avoid repeated initializations down the inheritance path
     */
    function __Relayer_init_unchained() internal onlyInitializing {}

    /**
     * @dev Returns the nonce for a given chain
     */
    function nonce(uint256 chainId) external view returns (uint256) {
        RelayerStorage storage $ = _getRelayerStorage();
        return $.nonce[chainId];
    }

    /**
     * @dev internal relay function shared by the different implementations
     *
     * Nonces start counting from 1
     * It is also secured by the registry set. So only approved addresses can call relay
     * Eventually we can remove `isRegistered` and allow it for public use.
     * This requires a proper fee system to prevent abuse.

     */
    function _relay(
        uint256 targetChainId,
        address target,
        bytes memory call,
        uint256 gasLimit
    ) internal isRegistered(_msgSender()) returns (uint256) {
        RelayerStorage storage $ = _getRelayerStorage();
        uint256 _nonce = ++$.nonce[targetChainId];

        emit Relayed(targetChainId, target, call, gasLimit, _nonce);
        return _nonce;
    }

    /**
     * @dev Basic relay called by contracts on the source chain to send message to target chain
     * The sender needs to encode the call data and the target chain id with abi of the callee function
     *
     * @param targetChainId the chain id the message is intended to be sent to
     * @param target the address of the contract on the target chain to execute the call
     * @param call the encoded call data to be executed on the target address on the target chain
     * @param gasLimit the gas limit for the call executed on the target chain
     */
    function relay(
        uint256 targetChainId,
        address target,
        bytes calldata call,
        uint256 gasLimit
    ) external returns (uint256) {
        return _relay(targetChainId, target, call, gasLimit);
    }

    /**
     * @dev Use this function to relay a call with metadata. This is useful when the dispatched function on the target chain requires the metadata
     * For example they may need to verify the sender or the nonce of the transaction on the source chain.
     * When packed here, we can ensure that the metadata is not tampered with
     *
     * NOTE: Ensure the target function conforms to the required abi format `function(CallMetadata, bytes)`
     *
     * @param targetChainId the chain id the message is intended to be sent to
     * @param target the address of the contract on the target chain to execute the call
     * @param callSelector the selector of the function to be called on target
     * @param callData the calldata to be appended on the call selector
     * @param gasLimit the gas limit for the call executed on the target chain
     */
    function relayWithMetadata(
        uint256 targetChainId,
        address target,
        bytes4 callSelector,
        bytes calldata callData,
        uint256 gasLimit
    ) external returns (uint256) {
        return
            _relay(
                targetChainId,
                target,
                abi.encodeWithSelector(
                    callSelector,
                    CallMetadata(block.chainid, _msgSender()),
                    callData
                ),
                gasLimit
            );
    }

    /**
     * @dev Able to register new addresses that can call the relayer
     */
    function register(address newTarget) external override onlyOwner {
        _register(newTarget);
    }

    /**
     * @dev Removes an address from the registry. Thus preventing them to call relayer
     */
    function unregister(address removeTarget) external override onlyOwner {
        _unregister(removeTarget);
    }
}
