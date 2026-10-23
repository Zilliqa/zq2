// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Groth16Verifier} from "./verifier.sol";

interface IEscrowMintable {
    function mint(address to, uint256 amount) external;
}

contract EscrowMintableInit is UUPSUpgradeable, Groth16Verifier {
    uint64 public constant VERSION = 1;

    /// @custom:storage-location erc7201:zilliqa.escrowmintable.storage
    struct EscrowMintableStorage {
        mapping(address => mapping(address => uint256)) balances;
        address[] sources;
        mapping(address => address) targets;
        address admin;
        mapping(address => bool) whitelisted;
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

    event Whitelisted(address indexed source, address indexed target);
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);
    event Lodged(address indexed user, address indexed source, uint256 amount);
    event Released(
        address indexed oldAddress,
        address indexed newAddress,
        address indexed source,
        address target,
        uint256 amount
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

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

    function _authorizeUpgrade(
        // solhint-disable-next-line no-unused-vars
        address newImplementation
    ) internal virtual override onlySystem {}

    function whitelist(address source, address target) external onlyAdmin {
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        require(source != address(0), "Zero source");
        require(
            target == address(0) || target.code.length > 0,
            "Target is not a contract"
        );
        require(!$.whitelisted[source], "Already whitelisted");
        $.whitelisted[source] = true;
        $.sources.push(source);
        $.targets[source] = target;
        emit Whitelisted(source, target);
    }

    function setAdmin(address newAdmin) external onlySystem {
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        emit AdminChanged($.admin, newAdmin);
        $.admin = newAdmin;
    }

    function lodge(
        address source,
        address[] calldata users,
        uint256[] calldata amounts
    ) external onlySystem {
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        require(users.length == amounts.length, "Length mismatch");
        for (uint256 i = 0; i < users.length; i++) {
            $.balances[source][users[i]] = amounts[i];
            emit Lodged(users[i], source, amounts[i]);
        }
    }

    function admin() public view returns (address) {
        return _getEscrowMintableStorage().admin;
    }

    function balanceOf(
        address source,
        address user
    ) public view returns (uint256) {
        return _getEscrowMintableStorage().balances[source][user];
    }

    function targetOf(address source) public view returns (address) {
        return _getEscrowMintableStorage().targets[source];
    }

    function isWhitelisted(address source) public view returns (bool) {
        return _getEscrowMintableStorage().whitelisted[source];
    }

    function sources() public view returns (address[] memory) {
        return _getEscrowMintableStorage().sources;
    }

    function sourceCount() public view returns (uint256) {
        return _getEscrowMintableStorage().sources.length;
    }

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
        address source,
        address srcAddress,
        address dstAddress
    ) private returns (uint256 amount) {
        amount = $.balances[source][srcAddress];
        if (amount == 0) {
            return 0;
        }
        $.balances[source][srcAddress] = 0;
        address target = $.targets[source];
        if (target != address(0)) {
            IEscrowMintable(target).mint(dstAddress, amount);
        }
        emit Released(srcAddress, dstAddress, source, target, amount);
    }

    function claim(
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
        _releaseAll(srcAddress, dstAddress);
    }

    function migrate() public {
        _releaseAll(msg.sender, msg.sender);
    }

    function _releaseAll(address srcAddress, address dstAddress) private {
        EscrowMintableStorage storage $ = _getEscrowMintableStorage();
        uint256 released = 0;
        uint256 count = $.sources.length;
        for (uint256 i = 0; i < count; i++) {
            if (_release($, $.sources[i], srcAddress, dstAddress) > 0) {
                released++;
            }
        }
        require(released > 0, "Nothing to claim");
    }
}
