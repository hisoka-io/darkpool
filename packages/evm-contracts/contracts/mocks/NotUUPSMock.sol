// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/// @notice A non-UUPS implementation (no proxiableUUID) used to prove the proxy's anti-brick cross-check:
/// upgrading to it reverts ERC1967InvalidImplementation instead of bricking upgradeability.
contract NotUUPSMock {
    function version() external pure returns (uint256) {
        return 999;
    }
}
