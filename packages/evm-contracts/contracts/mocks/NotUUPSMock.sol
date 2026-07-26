// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/// @notice No proxiableUUID, so upgrading to it must revert ERC1967InvalidImplementation rather than brick
/// upgradeability.
contract NotUUPSMock {
    function version() external pure returns (uint256) {
        return 999;
    }
}
