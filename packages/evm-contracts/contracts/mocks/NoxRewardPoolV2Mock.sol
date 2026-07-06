// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {NoxRewardPool} from "../nox/NoxRewardPool.sol";

/// @notice Storage-preserving upgrade target: adds only a pure view so an upgrade is observable while the
/// ERC-7201 reward-pool namespace stays byte-identical.
/// @dev Test-only. Inherits NoxRewardPool's initializer and declares none of its own; the annotation silences
/// the initializer-PRESENCE false positive. Storage-layout safety is unaffected and still validated against
/// NoxRewardPool.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract NoxRewardPoolV2Mock is NoxRewardPool {
    function version() external pure returns (uint256) {
        return 2;
    }
}
