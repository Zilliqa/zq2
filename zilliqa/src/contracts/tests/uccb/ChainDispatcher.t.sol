// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Target, ValidatorManagerFixture, IReentrancy} from "./Helpers.sol";

import {ChainDispatcher, IChainDispatcherEvents, IChainDispatcherErrors} from "../../uccb/ChainDispatcher.sol";

import {ISignatureValidatorErrors} from "../../uccb/SignatureValidator.sol";
import {IDispatchReplayCheckerErrors} from "../../uccb/DispatchReplayChecker.sol";

import {OwnableUpgradeable, Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

library DispatchArgsBuilder {
    struct DispatchArgs {
        uint256 sourceChainId;
        address target;
        bytes call;
        uint256 gasLimit;
        uint256 nonce;
    }

    function instance(
        address target
    ) external pure returns (DispatchArgs memory args) {
        args.sourceChainId = 1;
        args.target = target;
        args.call = abi.encodeWithSelector(Target.work.selector, uint256(1));
        args.gasLimit = 1_000_000;
        args.nonce = 1;
    }

    function withCall(
        DispatchArgs memory args,
        bytes calldata call
    ) external pure returns (DispatchArgs memory) {
        args.call = call;
        return args;
    }
}

contract ChainDispatcherHarness is
    Initializable,
    UUPSUpgradeable,
    ChainDispatcher
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _validatorManager
    ) external initializer {
        __ChainDispatcher_init(_owner, _validatorManager);
    }

    function _authorizeUpgrade(address) internal virtual override onlyOwner {}
}

contract DispatcherFixture is IChainDispatcherEvents, ValidatorManagerFixture {
    using MessageHashUtils for bytes;
    using DispatchArgsBuilder for DispatchArgsBuilder.DispatchArgs;

    address owner = vm.createWallet("Owner").addr;

    Target internal immutable target = new Target();
    ChainDispatcherHarness dispatcher;

    constructor() ValidatorManagerFixture() {}

    function setUp() external {
        address implementation = address(new ChainDispatcherHarness());
        address proxy = address(
            new ERC1967Proxy(
                implementation,
                abi.encodeWithSelector(
                    ChainDispatcherHarness.initialize.selector,
                    owner,
                    address(validatorManager)
                )
            )
        );
        dispatcher = ChainDispatcherHarness(proxy);
    }

    function signDispatch(
        DispatchArgsBuilder.DispatchArgs memory args
    ) public returns (bytes[] memory signatures) {
        bytes32 hashedMessage = abi
            .encode(
                args.sourceChainId,
                block.chainid,
                args.target,
                args.call,
                args.gasLimit,
                args.nonce
            )
            .toEthSignedMessageHash();

        signatures = multiSign(sort(validators), hashedMessage);
    }
}

contract ChainDispatcherTests is DispatcherFixture {
    using DispatchArgsBuilder for DispatchArgsBuilder.DispatchArgs;

    function test_happyPath() external {
        DispatchArgsBuilder.DispatchArgs memory args = DispatchArgsBuilder
            .instance(address(target));
        bytes[] memory signatures = signDispatch(args);

        vm.expectCall(address(target), args.call);
        vm.expectEmit(address(dispatcher));
        emit Dispatched(
            args.sourceChainId,
            args.target,
            true,
            abi.encode(uint(2)),
            args.nonce
        );
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            args.nonce,
            signatures
        );
        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), true);
    }

    function testRevert_badSignature() external {
        // Prepare call
        DispatchArgsBuilder.DispatchArgs memory args = DispatchArgsBuilder
            .instance(address(target));
        bytes[] memory signatures = signDispatch(args);
        uint256 badNonce = args.nonce + 1;

        vm.expectRevert(
            ISignatureValidatorErrors.InvalidValidatorOrSignatures.selector
        );
        // Dispatch
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            badNonce,
            signatures
        );
        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), false);
    }

    function testRevert_replay() external {
        // Prepare call
        DispatchArgsBuilder.DispatchArgs memory args = DispatchArgsBuilder
            .instance(address(target));
        bytes[] memory signatures = signDispatch(args);

        // Dispatch
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            args.nonce,
            signatures
        );
        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), true);
        // Replay
        vm.expectRevert(
            IDispatchReplayCheckerErrors.AlreadyDispatched.selector
        );
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            args.nonce,
            signatures
        );
        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), true);
    }

    function test_failedCall() external {
        uint256 num = 1000;
        bytes memory failedCall = abi.encodeWithSelector(
            target.work.selector,
            num
        );
        DispatchArgsBuilder.DispatchArgs memory args = DispatchArgsBuilder
            .instance(address(target))
            .withCall(failedCall);
        bytes[] memory signatures = signDispatch(args);

        // Dispatch
        vm.expectCall(address(target), failedCall);

        bytes memory expectedError = abi.encodeWithSignature(
            "Error(string)",
            "Too large"
        );
        vm.expectEmit(address(dispatcher));
        emit Dispatched(
            args.sourceChainId,
            args.target,
            false,
            expectedError,
            args.nonce
        );
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            args.nonce,
            signatures
        );
        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), true);
    }

    function test_nonContractCallerWithFailedCall() external {
        DispatchArgsBuilder.DispatchArgs memory args = DispatchArgsBuilder
            .instance(vm.addr(1001));
        bytes[] memory signatures = signDispatch(args);

        // Dispatch
        bytes memory expectedError = abi.encodeWithSelector(
            IChainDispatcherErrors.NonContractCaller.selector,
            args.target
        );
        vm.expectEmit(address(dispatcher));
        emit Dispatched(
            args.sourceChainId,
            args.target,
            false,
            expectedError,
            args.nonce
        );
        // Dispatch
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            args.nonce,
            signatures
        );

        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), true);
    }

    function test_outOfGasCall() external {
        bytes memory call = abi.encodeWithSelector(
            target.infiniteLoop.selector
        );
        DispatchArgsBuilder.DispatchArgs memory args = DispatchArgsBuilder
            .instance(address(target))
            .withCall(call);
        bytes[] memory signatures = signDispatch(args);

        // Dispatch
        vm.expectCall(address(target), args.call);
        vm.expectEmit(address(dispatcher));
        emit Dispatched(
            args.sourceChainId,
            args.target,
            false,
            hex"", // denotes out of gas
            args.nonce
        );
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            args.nonce,
            signatures
        );

        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), true);
        assertEq(target.c(), uint256(0));
    }

    function test_reentrancy() external {
        bytes memory call = abi.encodeWithSelector(target.reentrancy.selector);
        DispatchArgsBuilder.DispatchArgs memory args = DispatchArgsBuilder
            .instance(address(target))
            .withCall(call);
        bytes[] memory signatures = signDispatch(args);

        target.setReentrancyConfig(
            address(dispatcher),
            abi.encodeWithSelector(
                dispatcher.dispatch.selector,
                args.sourceChainId,
                args.target,
                args.call,
                args.gasLimit,
                args.nonce,
                signatures
            )
        );

        // Dispatch
        bytes memory expectedError = abi.encodeWithSelector(
            IReentrancy.ReentrancySafe.selector
        );
        vm.expectEmit(address(dispatcher));
        emit Dispatched(
            args.sourceChainId,
            args.target,
            false,
            expectedError,
            args.nonce
        );
        dispatcher.dispatch(
            args.sourceChainId,
            args.target,
            args.call,
            args.gasLimit,
            args.nonce,
            signatures
        );
        assertEq(dispatcher.dispatched(args.sourceChainId, args.nonce), true);
    }

    function test_updateValidatorManager() external {
        address newValidatorManager = vm
            .createWallet("NewValidatorManager")
            .addr;

        assertEq(dispatcher.validatorManager(), address(validatorManager));
        vm.prank(owner);
        dispatcher.setValidatorManager(newValidatorManager);
        assertEq(dispatcher.validatorManager(), newValidatorManager);
    }

    function testRevert_updateValidatorManagerWhenNotOwner() external {
        address newValidatorManager = vm
            .createWallet("NewValidatorManager")
            .addr;
        address notOwner = vm.createWallet("notOwner").addr;

        assertEq(dispatcher.validatorManager(), address(validatorManager));
        vm.prank(notOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector,
                notOwner
            )
        );
        dispatcher.setValidatorManager(newValidatorManager);
        assertEq(dispatcher.validatorManager(), address(validatorManager));
    }
}
