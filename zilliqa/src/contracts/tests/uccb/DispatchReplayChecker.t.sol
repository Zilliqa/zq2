// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Tester} from "../../test/Tester.sol";
import {DispatchReplayChecker, IDispatchReplayCheckerErrors} from "../../uccb/DispatchReplayChecker.sol";

contract DispatchReplayCheckerHarness is
    UUPSUpgradeable,
    DispatchReplayChecker
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function _authorizeUpgrade(address) internal virtual override {}

    function exposed_replayDispatchCheck(
        uint256 sourceShardId,
        uint256 nonce
    ) external {
        _replayDispatchCheck(sourceShardId, nonce);
    }
}

contract DispatchReplayCheckerTests is Tester {
    DispatchReplayCheckerHarness dispatchReplayChecker =
        new DispatchReplayCheckerHarness();

    function setUp() external {
        address implementation = address(new DispatchReplayCheckerHarness());
        address proxy = address(new ERC1967Proxy(implementation, ""));
        dispatchReplayChecker = DispatchReplayCheckerHarness(proxy);
    }

    function test_happyPath() external {
        uint256 sourceShardId = 0;
        uint256 nonce = 0;

        dispatchReplayChecker.exposed_replayDispatchCheck(sourceShardId, nonce);

        assertEq(
            dispatchReplayChecker.dispatched(sourceShardId, nonce),
            true,
            "should have marked dispatched"
        );
    }

    function testRevert_whenAlreadyDispatched() external {
        uint256 sourceShardId = 0;
        uint256 nonce = 0;

        dispatchReplayChecker.exposed_replayDispatchCheck(sourceShardId, nonce);
        assertEq(
            dispatchReplayChecker.dispatched(sourceShardId, nonce),
            true,
            "should have marked dispatched"
        );

        vm.expectRevert(
            IDispatchReplayCheckerErrors.AlreadyDispatched.selector
        );
        dispatchReplayChecker.exposed_replayDispatchCheck(sourceShardId, nonce);
    }

    function test_sameNonceDifferentSourceShard() external {
        uint256 chain1 = 0;
        uint256 chain2 = 1;
        uint256 nonce = 0;

        dispatchReplayChecker.exposed_replayDispatchCheck(chain1, nonce);
        assertEq(
            dispatchReplayChecker.dispatched(chain1, nonce),
            true,
            "should have marked dispatched"
        );

        dispatchReplayChecker.exposed_replayDispatchCheck(chain2, nonce);
        assertEq(
            dispatchReplayChecker.dispatched(chain2, nonce),
            true,
            "should have marked dispatched"
        );
    }
}
