// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {NoxRewardPool} from "../nox/NoxRewardPool.sol";

/// @notice Test-only storage-preserving upgrade target: adds only a pure view, so an upgrade is observable
/// while the ERC-7201 reward-pool namespace stays byte-identical.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract NoxRewardPoolV2Mock is NoxRewardPool {
    function version() external pure returns (uint256) {
        return 2;
    }
}
