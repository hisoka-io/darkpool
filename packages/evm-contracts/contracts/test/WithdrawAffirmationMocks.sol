// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IWithdrawRecipient} from "../interfaces/IWithdrawRecipient.sol";

// Test-only: implements the interface but answers with a value that is not the magic selector.
contract WrongMagicRecipient is IWithdrawRecipient {
    function acceptWithdraw(bytes32, uint256) external pure returns (bytes4) {
        return bytes4(keccak256("notTheMagicValue()"));
    }
}

// Test-only: implements the interface and refuses every pull by reverting.
contract RejectingRecipient is IWithdrawRecipient {
    error NotMyWithdraw();

    function acceptWithdraw(bytes32, uint256) external pure returns (bytes4) {
        revert NotMyWithdraw();
    }
}

/**
 * @notice Test-only DarkPool stand-in that drives the affirmation callback with caller-chosen arguments.
 * @dev A recipient's intent binding is only reachable while a pull is in flight, and the real pool's
 *      nonReentrant makes a second pull unreachable through it. Standing in for the pool is what puts a
 *      mismatched second affirmation inside the window the recipient holds open.
 */
contract PullProbeDarkPool {
    bytes32 public probeNullifier;
    uint256 public probeIntent;

    function setProbe(bytes32 nullifier, uint256 intentHash) external {
        probeNullifier = nullifier;
        probeIntent = intentHash;
    }

    function withdraw(bytes calldata, bytes32[] calldata) external {
        IWithdrawRecipient(msg.sender).acceptWithdraw(
            probeNullifier,
            probeIntent
        );
    }
}
