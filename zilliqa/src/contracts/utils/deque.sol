// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

struct Withdrawal {
    uint256 startedAt;
    uint256 amount;
}

// Implementation of a double-ended queue of `Withdrawal`s, backed by a circular buffer.
library Deque {
    struct Withdrawals {
        Withdrawal[] values;
        // The physical index of the first element, if it exists. If `len == 0`, the value of `head` is unimportant.
        uint256 head;
        // The number of elements in the queue.
        uint256 len;
    }

    // Returns the physical index of an element, given its logical index.
    function physicalIdx(
        Withdrawals storage deque,
        uint256 idx
    ) internal view returns (uint256) {
        uint256 physical = deque.head + idx;
        // Wrap the physical index in case it is out-of-bounds of the buffer.
        if (physical >= deque.values.length) {
            return physical - deque.values.length;
        } else {
            return physical;
        }
    }

    function length(Withdrawals storage deque) internal view returns (uint256) {
        return deque.len;
    }

    // Get the element at the given logical index. Reverts if `idx >= queue.length()`.
    function get(
        Withdrawals storage deque,
        uint256 idx
    ) internal view returns (Withdrawal storage) {
        if (idx >= deque.len) {
            revert("element does not exist");
        }

        uint256 pIdx = physicalIdx(deque, idx);
        return deque.values[pIdx];
    }

    // Push an empty element to the back of the queue. Returns a reference to the new element.
    function pushBack(
        Withdrawals storage deque
    ) internal returns (Withdrawal storage) {
        // Add more space in the buffer if it is full.
        if (deque.len == deque.values.length) {
            deque.values.push();
        }

        uint256 idx = physicalIdx(deque, deque.len);
        deque.len += 1;

        return deque.values[idx];
    }

    // Pop an element from the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function popFront(
        Withdrawals storage deque
    ) internal returns (Withdrawal storage) {
        if (deque.len == 0) {
            revert("queue is empty");
        }

        uint256 oldHead = deque.head;
        deque.head = physicalIdx(deque, 1);
        deque.len -= 1;
        return deque.values[oldHead];
    }

    // Peeks the element at the back of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function back(
        Withdrawals storage deque
    ) internal view returns (Withdrawal storage) {
        if (deque.len == 0) {
            revert("queue is empty");
        }

        return get(deque, deque.len - 1);
    }

    // Peeks the element at the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function front(
        Withdrawals storage deque
    ) internal view returns (Withdrawal storage) {
        if (deque.len == 0) {
            revert("queue is empty");
        }

        return get(deque, 0);
    }
}
