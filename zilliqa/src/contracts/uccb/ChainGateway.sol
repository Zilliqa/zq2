// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {IChainDispatcher, ChainDispatcher} from "./ChainDispatcher.sol";
import {IRelayer, RelayerUpgradeable} from "./Relayer.sol";

interface IChainGateway is IRelayer, IChainDispatcher {}

/**
 * @title ChainGateway
 * @notice The main core contract that is deployed on everychain to handle cross-chain messaging
 * It inherits 2 important contracts Relayer and ChainDispatcher:
 * The Relayer handles outbound messages with `relay` and `relayWithMetadata` functions.
 * The ChainDispatcher serves for inbound messages.
 * The contract is also UUPS upgradeable.
 * For future upgrades of the contract refer to: https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable
 */
contract ChainGateway is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    RelayerUpgradeable,
    ChainDispatcherUpgradeable
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializer for the contract
     */
    function initialize(
        address _validatorManager,
        address _owner
    ) external initializer {
        __Ownable_init(_owner);
        __Relayer_init_unchained();
        __ChainDispatcher_init_unchained(_validatorManager);
    }

    /**
     * @dev Override used to secure the upgrade call to the contract owner
     */
    function _authorizeUpgrade(address) internal virtual override onlyOwner {}
}
