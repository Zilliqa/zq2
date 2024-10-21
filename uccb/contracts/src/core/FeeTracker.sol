// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

interface IFeeTrackerErrors {
    /**
     * @dev Triggers when the fee deposit is insufficient to pay for the offset
     */
    error InsufficientMinFeeDeposit();
}

/**
 * @title FeeTracker
 * @notice Contract to track and manage fees for the relay calls
 * This is inteded to be used by the dispatcher to meter the fees on `dispatch` of `ChainDispatcher`
 * It forces the user to deposit the fee before the call on the remote chain
 * The user experience might not be optimal. But ensures that the validator that submits the message gets refunded
 * The validator is then able to retrieve the fees from the contract on the txns submitted successfully
 */
abstract contract FeeTracker is IFeeTrackerErrors {
    mapping(address => uint) public feeDeposit;
    mapping(address => uint) public feeRefund;

    /**
     * @dev Modifier to meter the fee for the transaction
     * It can be used on the `dispatch` function of `ChainDispatcher`
     * NOTE: this should be the outermost modifier to ensure that the gas is measured correctly
     */
    modifier meterFee(address patron) {
        uint feeStart = gasleft() * tx.gasprice;
        // The following is an estimate of gas cost for "measuring the gas"
        // 44703 = 21000 + 3 + 6600 + 17100
        // 17100 = init storage cost (worst case)
        // 6600 = operations related to gas tracking
        // 21000 = fixed cost of transaction
        uint feeOffset = (44703 + 16 * (msg.data.length - 4)) * tx.gasprice;
        // Should reject if insuficient to pay for the offset
        if (feeDeposit[patron] < feeOffset) {
            revert InsufficientMinFeeDeposit();
        }
        feeStart += feeOffset;
        // It will still take fees even if insufficient fee deposit is provided
        if (feeDeposit[patron] >= feeStart) {
            _;
        }
        uint spent = feeStart - gasleft() * tx.gasprice;
        feeDeposit[patron] -= spent;
        feeRefund[msg.sender] += spent;
    }

    /**
     * @dev depoits fees to the sender. This can be used to handle fees later
     */
    function depositFee() external payable {
        feeDeposit[msg.sender] += msg.value;
    }

    /**
     * @dev withdraw fees if any available to the sender
     */
    function withdrawFee(uint amount) external {
        feeDeposit[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    /**
     * @dev refunds the fee to the validator that submitted the transactions
     */
    function refundFee() external {
        uint amount = feeRefund[msg.sender];
        // TODO: keep it 1 for saving gas
        feeRefund[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
