pragma solidity ^0.8.0;

struct Opaque {
    bytes[] data;
}

contract BytesArrayContract {
    Opaque[3] myArray;

    // view function returning number of elements
    function getLength() external view returns (uint256) {
        uint256 result = 0;
        uint256 length = myArray[1].data.length;
        for (uint256 j = 0; j < length; ++j) {
            length++;
        }
        return length;
    }
}