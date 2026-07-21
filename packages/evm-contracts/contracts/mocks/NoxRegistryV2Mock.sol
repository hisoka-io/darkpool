// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {NoxRegistry} from "../nox/NoxRegistry.sol";

/// @notice Storage-preserving upgrade target: adds only a pure view so an upgrade is observable while the
/// ERC-7201 registry namespace stays byte-identical.
/// @dev Test-only; annotation silences an initializer-presence false positive. Storage layout still validated
/// against NoxRegistry.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract NoxRegistryV2Mock is NoxRegistry {
    function version() external pure returns (uint256) {
        return 2;
    }
}
