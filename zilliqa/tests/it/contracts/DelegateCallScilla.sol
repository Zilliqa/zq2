// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Experiment: which address does the `scilla_call` precompile observe as its caller when
// the precompile CALL is issued by B's code that is running inside A's context via
// DELEGATECALL?
//
//   EOA --CALL--> A.run() --DELEGATECALL--> B.invoke() --CALL--> scilla_call precompile
//
// DELEGATECALL runs B's code in A's context, so inside B: address(this) == A and
// msg.sender == EOA. The subsequent *regular* CALL to the precompile therefore originates
// from address A, so the precompile's caller is A (not B, and not the EOA).

// Contract A: entry point. Records its own address + caller, then DELEGATECALLs into B.
contract A {
    event AContext(address self, address caller);

    function run(address b, address scillaTarget, string calldata transition) external {
        emit AContext(address(this), msg.sender);

        (bool ok, bytes memory ret) =
            b.delegatecall(abi.encodeWithSignature("invoke(address,string)", scillaTarget, transition));
        if (!ok) {
            // Bubble up B's revert reason verbatim.
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

// Contract B: reached via DELEGATECALL, so this body executes in A's context.
// Records the caller B observes, then makes a *regular* CALL (not delegatecall) to the
// scilla_call precompile with keep_origin = 0, i.e. the precompile uses its direct EVM
// caller as the Scilla `_sender`.
contract B {
    address constant SCILLA_CALL = 0x000000000000000000000000000000005a494c53;

    event BContext(address self, address caller);

    function invoke(address scillaTarget, string calldata transition) external {
        emit BContext(address(this), msg.sender);

        bytes memory args = abi.encode(scillaTarget, transition, uint256(0));
        (bool ok, ) = SCILLA_CALL.call(args);
        require(ok, "scilla call failed");
    }
}
