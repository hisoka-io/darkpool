// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/// @notice Test-only stand-in for NoxRegistry's relayer-membership view.
contract MockNoxRegistry {
    mapping(address => bool) private active;

    function setActive(address relayer, bool status) external {
        active[relayer] = status;
    }

    function isActiveRelayer(address relayer) external view returns (bool) {
        return active[relayer];
    }
}
