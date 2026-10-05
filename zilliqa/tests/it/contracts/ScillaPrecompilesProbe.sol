pragma solidity ^0.8.20;

contract ScillaPrecompilesProbe {
    address private constant SCILLA_CALL_PRECOMPILE = address(0x5a494c53);
    address private constant SCILLA_READ_PRECOMPILE = address(0x5a494c92);

    bool public probed;
    bool public scillaCallOk;
    bool public scillaReadOk;

    function probe(address target) external {
        (scillaCallOk, ) = SCILLA_CALL_PRECOMPILE.call{gas: 100_000}(
            abi.encode(target, "Foo", uint256(0))
        );
        (scillaReadOk, ) = SCILLA_READ_PRECOMPILE.staticcall{gas: 100_000}(
            abi.encode(target, "field")
        );
        probed = true;
    }
}
