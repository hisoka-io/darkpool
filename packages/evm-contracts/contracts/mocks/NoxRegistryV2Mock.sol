// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {NoxRegistry} from "../nox/NoxRegistry.sol";

/// @notice Storage-preserving upgrade target: adds only a pure view so an upgrade is observable while the
/// ERC-7201 registry namespace stays byte-identical.
/// @dev Test-only. Inherits NoxRegistry's initializer and declares none of its own; the annotation silences
/// the initializer-PRESENCE false positive (a self-added initializer would trip missing-initializer-call for
/// the parent chain). Storage-layout safety is unaffected and still validated against NoxRegistry.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract NoxRegistryV2Mock is NoxRegistry {
    function version() external pure returns (uint256) {
        return 2;
    }
}
