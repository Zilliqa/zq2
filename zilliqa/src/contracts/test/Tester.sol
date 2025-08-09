// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";

abstract contract Tester is Test {
    modifier TODO() {
        vm.skip(true);
        _;
    }

    function quickSort(
        Vm.Wallet[] memory arr,
        int256 left,
        int256 right
    ) private pure {
        int256 i = left;
        int256 j = right;
        if (i == j) return;
        Vm.Wallet memory pivot = arr[uint256(left + (right - left) / 2)];
        while (i <= j) {
            while (arr[uint(i)].addr < pivot.addr) i++;
            while (pivot.addr < arr[uint(j)].addr) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256uint256uint256(j)]) = (
                    arr[uint256(j)],
                    arr[uint256(i)]
                );
                i++;
                j--;
            }
        }
        if (left < j) quickSort(arr, left, j);
        if (i < right) quickSort(arr, i, right);
    }

    function sign(
        Vm.Wallet memory wallet,
        bytes32 hashedMessage
    ) public returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wallet, hashedMessage);
        return abi.encodePacked(r, s, v);
    }

    function multiSign(
        Vm.Wallet[] memory wallet,
        bytes32 hashedMessage
    ) public returns (bytes[] memory) {
        bytes[] memory signatures = new bytes[](wallet.length);

        for (uint256 i = 0; i < wallet.length; ++i) {
            signatures[i] = sign(wallet[i], hashedMessage);
        }
        return signatures;
    }

    function sort(
        Vm.Wallet[] memory data
    ) public pure returns (Vm.Wallet[] memory) {
        quickSort(data, int256(0), int256(data.length - 1));
        return data;
    }
}
