// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title RelayerMulticall
 * @notice Stateless, permissionless batch-call forwarder. Any ETH or tokens left here can be swept by the
 *         next caller, so callers MUST NOT approve this contract or leave a balance between calls.
 */
contract RelayerMulticall is ReentrancyGuard {
    error CriticalCallFailed();
    error ETHRefundFailed();
    error ValueMismatch();

    struct Call {
        address target;
        bytes data;
        uint256 value;
        bool requireSuccess;
    }

    event CallExecuted(uint256 indexed index, bool success, bytes returnData);
    event CallFailed(uint256 indexed index, bytes reason);

    /// @notice Executes a batch of calls. Reverts unless msg.value equals the sum of calls[i].value;
    ///         residual ETH is refunded to msg.sender.
    function multicall(Call[] calldata calls) external payable nonReentrant {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < calls.length; i++) {
            totalValue += calls[i].value;
        }
        if (msg.value != totalValue) revert ValueMismatch();

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
            (bool refundSuccess, ) = payable(msg.sender).call{value: remaining}(
                ""
            );
            if (!refundSuccess) revert ETHRefundFailed();
        }
    }
}
