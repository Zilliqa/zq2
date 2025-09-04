pragma solidity ^0.8.0;

contract BytesArrayContract {
    // global storage variable (persists on chain)
    bytes[] public data;

    // view function returning number of elements
    function getLength() external view returns (uint256) {
        return data.length;
    }
}