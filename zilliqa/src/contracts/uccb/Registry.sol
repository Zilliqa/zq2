// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

interface IRegistryErrors {
    /**
     * @dev error thrown when modifier detects a unregistered address
     */
    error NotRegistered(address targetAddress);
}

interface IRegistryEvents {
    /**
     * @dev Triggered when a new address is registered
     */
    event ContractRegistered(address target);
    /**
     * @dev Triggered when a address is removed
     */
    event ContractUnregistered(address target);
}

interface IRegistry is IRegistryErrors, IRegistryEvents {
    function registered(address target) external view returns (bool);

    function register(address newTarget) external;

    function unregister(address removeTarget) external;
}

/**
 * @title Registry
 * @notice Holds registered contracts that are allowed to be used by the
 * contract that inherits this one
 * Includes the `isRegistered` modifier that other contracts can leverage
 */
abstract contract RegistryUpgradeable is IRegistry {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:zilliqa.storage.Registry
     */
    struct RegistryStorage {
        mapping(address => bool) registered;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.Registry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REGISTRY_STORAGE_POSITION =
        0x4432bdf0e567007e5ad3c8ad839a7f885ef69723eaa659dd9f06e98a97274300;

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    function _getRegistryStorage()
        private
        pure
        returns (RegistryStorage storage $)
    {
        assembly {
            $.slot := REGISTRY_STORAGE_POSITION
        }
    }

    /**
     * @dev modifier used by contracts that inherit from this one to check if
     * the given `target` is part of the registry
     */
    modifier isRegistered(address target) {
        RegistryStorage storage $ = _getRegistryStorage();
        if (!registered(target)) {
            revert NotRegistered(target);
        }
        _;
    }

    /**
     * @dev public function returns whether `target` is part of the registry
     */
    function registered(address target) public view returns (bool) {
        RegistryStorage storage $ = _getRegistryStorage();
        return $.registered[target];
    }

    /**
     * @dev Internal function to register a new address
     * Can be exposed through child contract
     */
    function _register(address newTarget) internal {
        RegistryStorage storage $ = _getRegistryStorage();
        $.registered[newTarget] = true;
        emit ContractRegistered(newTarget);
    }

    /**
     * @dev Internal function to unregister an address
     * Can be exposed through child contract
     */
    function _unregister(address removeTarget) internal {
        RegistryStorage storage $ = _getRegistryStorage();
        $.registered[removeTarget] = false;
        emit ContractUnregistered(removeTarget);
    }
}
