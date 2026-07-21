// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {DarkPool} from "../DarkPool.sol";

/// @notice Storage-preserving upgrade target: adds only a pure view so an upgrade is observable while the
/// ERC-7201 anonymity-set namespaces stay byte-identical. Still links Poseidon2.
/// @dev Test-only; the annotation silences an initializer-presence false positive (inherits DarkPool's
/// initializer, adds none). Storage-layout safety still validated against DarkPool.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract DarkPoolV2Mock is DarkPool {
    function version() external pure returns (uint256) {
        return 2;
    }
}
