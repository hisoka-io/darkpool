// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/**
 * @title IWithdrawRecipient
 * @notice Implemented by any CONTRACT named as the recipient of a shielded withdraw.
 * @dev Replaces the older `msg.sender == recipient` gate, which proved "this contract is the caller" rather
 *      than "this contract asked for THIS pull". A contract that is itself a withdraw recipient and can be
 *      induced to call the pool with attacker-supplied calldata would satisfy the old gate while pulling a
 *      withdraw it never requested. Affirming the specific nullifier and intent hash closes that for every
 *      present and future recipient, instead of requiring each one to re-implement its own screen.
 *
 *      An EOA recipient is unaffected: the pool only calls this when the recipient has code.
 */
interface IWithdrawRecipient {
    /// @notice Affirm that this contract requested the withdraw identified by `nullifier` and `intentHash`.
    /// @dev MUST revert, or return anything other than the magic value, to reject an unrequested pull.
    ///      Called by the pool after the proof verifies and the nullifier is spent, before any token moves.
    /// @return The function selector of this method, as the magic acceptance value.
    function acceptWithdraw(
        bytes32 nullifier,
        uint256 intentHash
    ) external returns (bytes4);
}
