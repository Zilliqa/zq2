// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;

struct Withdrawal {
    uint256 startedAt;
    uint256 amount;
}

// A non-broken implementation of a double-ended queue of `Withdrawal`s. `deque.sol` doesn't work, don't use it.
library Deque {
    struct Withdrawals {
        mapping(uint256 index => Withdrawal) values;
        // The index of the first element.
        uint256 head;
        // The index where the next element will be inserted at the end of the queue.
        uint256 tail;
    }

    function length(Withdrawals storage deque) internal view returns (uint256) {
        return deque.tail - deque.head;
    }

    // Get the element at the given logical index. Reverts if `idx >= queue.length()`.
    function get(
        Withdrawals storage deque,
        uint256 idx
    ) internal view returns (Withdrawal storage) {
        require(deque.head + idx < deque.tail, "element does not exist");
        return deque.values[deque.head + idx];
    }

    // Push an empty element to the back of the queue. Returns a reference to the new element.
    function pushBack(
        Withdrawals storage deque
    ) internal returns (Withdrawal storage) {
        uint256 idx = deque.tail;
        deque.tail++;
        return deque.values[idx];
    }

    // Pop an element from the front of the queue.
    function popFront(
        Withdrawals storage deque
    ) internal returns (Withdrawal memory) {
        require(deque.head < deque.tail, "queue is empty");

        Withdrawal memory frontElement = deque.values[deque.head];

        delete deque.values[deque.head];
        deque.head++;

        return frontElement;
    }

    // Peeks the element at the back of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function back(
        Withdrawals storage deque
    ) internal view returns (Withdrawal storage) {
        require(deque.head < deque.tail, "queue is empty");
        return deque.values[deque.tail - 1];
    }

    // Peeks the element at the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function front(
        Withdrawals storage deque
    ) internal view returns (Withdrawal storage) {
        require(deque.head < deque.tail, "queue is empty");
        return deque.values[deque.head];
    }
}
