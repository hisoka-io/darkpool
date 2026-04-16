// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

contract RelayerMulticall {
    error CriticalCallFailed();
    error ETHRefundFailed();

    struct Call {
        address target;
        bytes data;
        uint256 value;
        bool requireSuccess;
    }

    event CallExecuted(uint256 indexed index, bool success, bytes returnData);
    event CallFailed(uint256 indexed index, bytes reason);

    /**
     * @notice Executes a batch of calls.
     * @param calls The array of calls to execute.
     */
    function multicall(Call[] calldata calls) external payable {
        for (uint256 i = 0; i < calls.length; i++) {
            Call calldata call = calls[i];

            (bool success, bytes memory returnData) = call.target.call{
                value: call.value
            }(call.data);

            if (success) {
                emit CallExecuted(i, true, returnData);
            } else {
                if (call.requireSuccess) {
                    if (returnData.length > 0) {
                        assembly {
                            let returndata_size := mload(returnData)
                            revert(add(32, returnData), returndata_size)
                        }
                    } else {
                        revert CriticalCallFailed();
                    }
                } else {
                    emit CallFailed(i, returnData);
                    emit CallExecuted(i, false, returnData);
                }
            }
        }

        uint256 remaining = address(this).balance;
        if (remaining > 0) {
            (bool refundSuccess, ) = payable(msg.sender).call{value: remaining}("");
            if (!refundSuccess) revert ETHRefundFailed();
        }
    }
}
