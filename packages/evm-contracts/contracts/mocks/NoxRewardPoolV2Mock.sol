// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {NoxRewardPool} from "../nox/NoxRewardPool.sol";

/// @notice Storage-preserving upgrade target: adds only a pure view so an upgrade is observable while the
/// ERC-7201 reward-pool namespace stays byte-identical.
/// @dev Test-only; annotation silences an initializer-presence false positive. Storage layout still validated
/// against NoxRewardPool.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract NoxRewardPoolV2Mock is NoxRewardPool {
    function version() external pure returns (uint256) {
        return 2;
    }
}
