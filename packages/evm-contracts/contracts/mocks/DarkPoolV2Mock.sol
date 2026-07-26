// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {DarkPool} from "../DarkPool.sol";

/// @notice Test-only storage-preserving upgrade target: adds only a pure view, so an upgrade is observable
/// while the ERC-7201 namespaces stay byte-identical. The annotation silences an initializer-presence false
/// positive (it inherits DarkPool's initializer and adds none).
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract DarkPoolV2Mock is DarkPool {
    function version() external pure returns (uint256) {
        return 2;
    }
}
