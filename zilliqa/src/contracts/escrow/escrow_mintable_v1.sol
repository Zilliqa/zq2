// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Groth16Verifier} from "./verifier.sol";

/// @dev Every token registered here must expose this, and must let only the escrow call it.
interface IEscrowMintable {
    function mint(address to, uint256 amount) external;
}

/// @title Mintable escrow: per-token lodged balances, released by ZK claim as a mint.
/// @notice Anyone may CREATE2-deploy a token through `deploy`, so its address is derivable
/// off-chain before the lodge lists referencing it are built; only the admin may `register` a
/// deployed token for lodging.
contract EscrowMintableInit is UUPSUpgradeable, Groth16Verifier {
    uint64 public constant VERSION = 1;

    /// @custom:storage-location erc7201:zilliqa.escrowmintable.storage
    struct EscrowMintableStorage {
        // token => user => lodged amount
        mapping(address => mapping(address => uint256)) balances;
        address[] tokens;
        mapping(address => bool) registered;
        // The only account allowed to extend `tokens` via `register`.
        address admin;
        // Everything `deploy` has created; `register` accepts nothing else.
        mapping(address => bool) deployed;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.escrowmintable.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant EscrowMintableStorageLocation =
        0x8d7fbe7a9e49393af3808764ca535f89a692062e9f6bbc53a8565fc767928300;

    function _getEscrowMintableStorage()
        private
        pure
        returns (EscrowMintableStorage storage $)
    {
        assembly {
            $.slot := EscrowMintableStorageLocation
        }
    }

    event TokenDeployed(
        address indexed deployer,
        address indexed token,
        bytes32 salt
    );
    event TokenRegistered(address indexed token);
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);
    event Lodged(address indexed user, address indexed token, uint256 amount);
    event Released(
        address indexed oldAddress,
        address indexed newAddress,
        address indexed token,
        uint256 amount
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param admin_ May call `register`. Zero leaves the registry closed until the system
    /// calls `setAdmin`.
    function initialize(address admin_) public initializer {
        __UUPSUpgradeable_init();
        _getEscrowMintableStorage().admin = admin_;
    }

    modifier onlySystem() {
        require(msg.sender == address(0), "system only");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == _getEscrowMintableStorage().admin, "admin only");
        _;
    }

    /// @dev Required by UUPSUpgradeable — gates who can call upgradeToAndCall
    function _authorizeUpgrade(
        // solhint-disable-next-line no-unused-vars
        address newImplementation
    ) internal virtual override onlySystem {}

    /// @notice Deploys `initCode` with CREATE2. Anyone may call; the token is not lodgeable
    /// until the admin registers it.
    function deploy(
        bytes32 salt,
        bytes calldata initCode
    ) external returns (address token) {
        require(initCode.length > 0, "Empty init code");
        bytes memory code = initCode;
        assembly {
            token := create2(0, add(code, 0x20), mload(code), salt)
        }
        require(token != address(0), "CREATE2 failed");

        _getEscrowMintableStorage().deployed[token] = true;
        emit TokenDeployed(msg.sender, token, salt);
    }

    /// @notice Makes a token created by `deploy` lodgeable. The escrow does not check that the
    /// token restricts `mint` to it.
    function register(address token) external onlyAdmin {
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        require($.deployed[token], "Not deployed here");
        require(!$.registered[token], "Already registered");
        $.tokens.push(token);
        $.registered[token] = true;
        emit TokenRegistered(token);
    }

    /// @notice Replaces the admin. System only, so the chain can recover a lost or wrong admin.
    function setAdmin(address newAdmin) external onlySystem {
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        emit AdminChanged($.admin, newAdmin);
        $.admin = newAdmin;
    }

    /// @notice Records `amounts[i]` of `token` for `users[i]`. Lodge lists carry each
    /// (user, token) pair at most once, so this assigns rather than accumulates.
    function lodge(
        address token,
        address[] calldata users,
        uint256[] calldata amounts
    ) external onlySystem {
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        require($.registered[token], "Unknown token");
        require(users.length == amounts.length, "Length mismatch");
        for (uint256 i = 0; i < users.length; i++) {
            $.balances[token][users[i]] = amounts[i];
            emit Lodged(users[i], token, amounts[i]);
        }
    }

    function admin() public view returns (address) {
        return _getEscrowMintableStorage().admin;
    }

    function isDeployed(address token) public view returns (bool) {
        return _getEscrowMintableStorage().deployed[token];
    }

    function balanceOf(
        address token,
        address user
    ) public view returns (uint256) {
        return _getEscrowMintableStorage().balances[token][user];
    }

    function isRegistered(address token) public view returns (bool) {
        return _getEscrowMintableStorage().registered[token];
    }

    function tokens() public view returns (address[] memory) {
        return _getEscrowMintableStorage().tokens;
    }

    function tokenCount() public view returns (uint256) {
        return _getEscrowMintableStorage().tokens.length;
    }

    /// @param pubSignals [old_address, new_address, chain_id, ...]
    function _verifyClaim(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) private view returns (address srcAddress, address dstAddress) {
        require(pubSignals[2] == block.chainid, "Invalid domain");
        dstAddress = address(uint160(pubSignals[1]));
        require(dstAddress != address(0), "Invalid destination");
        srcAddress = address(uint160(pubSignals[0]));
        require(srcAddress != address(0), "Invalid source");
        require(verifyProof(pA, pB, pC, pubSignals), "Zk-proof failed");
    }

    function _release(
        EscrowMintableStorage storage $,
        address token,
        address srcAddress,
        address dstAddress
    ) private returns (uint256 amount) {
        amount = $.balances[token][srcAddress];
        if (amount == 0) {
            return 0;
        }
        // Effects before interaction: `mint` is an external call into a user-deployed token.
        $.balances[token][srcAddress] = 0;
        IEscrowMintable(token).mint(dstAddress, amount);
        emit Released(srcAddress, dstAddress, token, amount);
    }

    /// @notice Mints the lodged `token` balance of the proven old address to the new one.
    function claim(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals,
        address token
    ) public {
        (address srcAddress, address dstAddress) = _verifyClaim(
            pA,
            pB,
            pC,
            pubSignals
        );
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        require($.balances[token][srcAddress] > 0, "No balance lodged");
        _release($, token, srcAddress, dstAddress);
    }

    /// @notice `claim` for every registered token the old address has a balance in.
    function claimAll(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata pubSignals
    ) public {
        (address srcAddress, address dstAddress) = _verifyClaim(
            pA,
            pB,
            pC,
            pubSignals
        );
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        uint256 released = 0;
        uint256 count = $.tokens.length;
        for (uint256 i = 0; i < count; i++) {
            if (_release($, $.tokens[i], srcAddress, dstAddress) > 0) {
                released++;
            }
        }
        require(released > 0, "No balance lodged");
    }
}
