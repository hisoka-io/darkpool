// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

contract MockTarget {
    event MockCalled(uint256 value, string message);

    function successFn(
        string memory message
    ) external payable returns (string memory) {
        emit MockCalled(msg.value, message);
        return message;
    }

    function failFn(string memory message) external payable {
        revert(message);
    }

    function failNoReason() external payable {
        revert();
    }
}
