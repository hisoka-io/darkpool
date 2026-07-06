// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {DarkPool} from "../DarkPool.sol";

/// @notice Storage-preserving upgrade target: adds only a pure view so an upgrade is observable while the
/// ERC-7201 anonymity-set namespaces stay byte-identical. Still links Poseidon2.
/// @dev Test-only. The annotation silences an initializer-PRESENCE false positive: this mock inherits
/// DarkPool's full initializer and, since the proxy is already initialized, correctly declares no new one
/// (a self-added initializer would then trip missing-initializer-call for the parent chain). Storage-layout
/// safety is unaffected and still validated against DarkPool.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract DarkPoolV2Mock is DarkPool {
    function version() external pure returns (uint256) {
        return 2;
    }
}
