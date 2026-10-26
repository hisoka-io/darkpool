// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/// @notice The one registry read `KageSettlement` makes per settlement.
interface IKageRegistry {
    /// @notice The key allowed to approve settlements for `solverId` right now, or `address(0)` when the solver is
    ///         unknown, exiting, exited, frozen or staked below the current minimum.
    function settlementSigner(uint256 solverId) external view returns (address);
}
