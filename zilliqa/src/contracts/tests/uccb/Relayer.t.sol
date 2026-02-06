// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Tester} from "../../test/Tester.sol";
import {Relayer, IRelayerEvents, IRelayer, CallMetadata} from "../../uccb/Relayer.sol";
import {IRegistryErrors} from "../../uccb/Registry.sol";

import {OwnableUpgradeable, Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract RelayerHarness is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    Relayer
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
        __Relayer_init_unchained();
    }

    function _authorizeUpgrade(address) internal virtual override onlyOwner {}
}

interface ITest {
    struct Args {
        uint256 num;
    }

    function foo() external;

    function fooWithMetadata(
        CallMetadata calldata call,
        Args calldata data
    ) external;
}

contract RelayerTests is Tester, IRelayerEvents {
    RelayerHarness relayer;
    address owner = vm.createWallet("Owner").addr;
    address registered = vm.createWallet("Registered").addr;

    function setUp() external {
        // Make deployment
        address implementation = address(new RelayerHarness());
        address proxy = address(
            new ERC1967Proxy(
                implementation,
                abi.encodeWithSelector(
                    RelayerHarness.initialize.selector,
                    owner
                )
            )
        );
        relayer = RelayerHarness(proxy);

        // Preregister
        vm.prank(owner);
        relayer.register(registered);

        assertEq(relayer.registered(registered), true);
    }

    function test_relay_happyPath() external {
        uint256 nonce = 1;
        uint256 targetChainId = 1;
        address target = address(0x1);
        bytes memory call = abi.encodeWithSelector(ITest.foo.selector);
        uint256 gasLimit = 100_000;

        vm.expectEmit(address(relayer));
        vm.prank(registered);
        emit IRelayerEvents.Relayed(
            targetChainId,
            target,
            call,
            gasLimit,
            nonce
        );
        uint256 result = relayer.relay(targetChainId, target, call, gasLimit);

        assertEq(result, nonce);
        assertEq(relayer.nonce(targetChainId), nonce);
    }

    function test_relay_identicalConsecutiveCallsHaveDifferentNonce() external {
        uint256 nonce = 1;
        uint256 targetChainId = 1;
        address target = address(0x1);
        bytes memory call = abi.encodeWithSelector(ITest.foo.selector);
        uint256 gasLimit = 100_000;

        vm.expectEmit(address(relayer));
        vm.prank(registered);
        emit IRelayerEvents.Relayed(
            targetChainId,
            target,
            call,
            gasLimit,
            nonce
        );
        uint256 result = relayer.relay(targetChainId, target, call, gasLimit);

        assertEq(result, nonce);
        assertEq(relayer.nonce(targetChainId), nonce);

        nonce++;

        vm.expectEmit(address(relayer));
        emit IRelayerEvents.Relayed(
            targetChainId,
            target,
            call,
            gasLimit,
            nonce
        );
        vm.prank(registered);
        result = relayer.relay(targetChainId, target, call, gasLimit);
        assertEq(result, nonce);
        assertEq(relayer.nonce(targetChainId), nonce);
    }

    function test_relay_identicalConsecutiveCallsHaveDifferenceTargetChainId()
        external
    {
        uint256 nonce = 1;
        uint256 targetChainId = 1;
        uint256 targetChainId2 = 2;
        address target = address(0x1);
        bytes memory call = abi.encodeWithSelector(ITest.foo.selector);
        uint256 gasLimit = 100_000;

        vm.expectEmit(address(relayer));
        vm.prank(registered);
        emit IRelayerEvents.Relayed(
            targetChainId,
            target,
            call,
            gasLimit,
            nonce
        );
        uint256 result = relayer.relay(targetChainId, target, call, gasLimit);

        assertEq(result, nonce);
        assertEq(relayer.nonce(targetChainId), nonce);

        vm.expectEmit(address(relayer));
        emit IRelayerEvents.Relayed(
            targetChainId2,
            target,
            call,
            gasLimit,
            nonce
        );
        vm.prank(registered);
        result = relayer.relay(targetChainId2, target, call, gasLimit);

        assertEq(result, nonce);
        assertEq(relayer.nonce(targetChainId), nonce);
        assertEq(relayer.nonce(targetChainId2), nonce);
    }

    function test_relayWithMetadata_happyPath() external {
        uint256 nonce = 1;
        uint256 targetChainId = 1;
        address target = address(0x1);
        bytes4 callSelector = ITest.foo.selector;
        bytes memory callData = abi.encode(ITest.Args(1));
        uint256 gasLimit = 100_000;

        bytes memory expectedCall = abi.encodeWithSelector(
            callSelector,
            CallMetadata(block.chainid, registered),
            callData
        );

        vm.expectEmit(address(relayer));
        emit IRelayerEvents.Relayed(
            targetChainId,
            target,
            expectedCall,
            gasLimit,
            nonce
        );
        vm.prank(registered);
        uint256 result = relayer.relayWithMetadata(
            targetChainId,
            target,
            callSelector,
            callData,
            gasLimit
        );

        assertEq(result, nonce);
        assertEq(relayer.nonce(targetChainId), nonce);
    }

    function test_RevertNonRegisteredSender() external {
        uint256 targetChainId = 1;
        address target = address(0x1);
        bytes memory call = abi.encodeWithSelector(ITest.foo.selector);
        uint256 gasLimit = 100_000;
        address notRegisteredSender = vm.addr(10);

        vm.prank(notRegisteredSender);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRegistryErrors.NotRegistered.selector,
                notRegisteredSender
            )
        );
        relayer.relay(targetChainId, target, call, gasLimit);
    }

    function test_removeRegisteredSender() external {
        uint256 targetChainId = 1;
        address target = address(0x1);
        bytes memory call = abi.encodeWithSelector(ITest.foo.selector);
        uint256 gasLimit = 100_000;

        vm.prank(owner);
        relayer.unregister(registered);
        assertEq(relayer.registered(registered), false);

        vm.prank(registered);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRegistryErrors.NotRegistered.selector,
                registered
            )
        );
        relayer.relay(targetChainId, target, call, gasLimit);
    }

    function test_RevertUnauthorizedRegister() external {
        address notOwner = vm.createWallet("notOwner").addr;
        address newRegistrant = vm.createWallet("newRegistrant").addr;

        vm.prank(notOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                notOwner
            )
        );
        relayer.register(newRegistrant);
    }

    function test_RevertUnauthorizedUnregister() external {
        address notOwner = vm.createWallet("notOwner").addr;

        vm.prank(notOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                notOwner
            )
        );
        relayer.unregister(registered);
    }

    function test_transferOwnership() external {
        address newOwner = vm.createWallet("newOwner").addr;

        vm.prank(owner);
        relayer.transferOwnership(newOwner);
        // Ownership should only be transferred after newOwner accepts
        assertEq(relayer.owner(), owner);

        vm.prank(newOwner);
        relayer.acceptOwnership();
        assertEq(relayer.owner(), newOwner);
    }
}
