// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/// @dev A settlement module's timestamp bound set to this value is not enforced.
uint32 constant NO_BOUND = type(uint32).max;

/// @notice The settlement entrypoint a registered module contract calls on DarkPool.
interface IDarkPoolSettlement {
    /// @notice Verify `proof` with the caller's registered verifier, spend its nullifiers and insert its
    ///         output notes. Reverts unless `msg.sender` is a registered, active module.
    function settle(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external;
}
