// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

interface IDarkPool {
    /**
     * @notice Withdraws funds from the shielded pool.
     * Used by Adaptors to "pull" funds synchronously.
     */
    function withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external;

    /**
     * @notice Deposits funds back into the shielded pool as a Public Memo.
     */
    function publicTransfer(
        uint256 _ownerX,
        uint256 _ownerY,
        address _asset,
        uint256 _value,
        uint256 _timelock,
        uint256 _salt
    ) external;
}
