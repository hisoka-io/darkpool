// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {BundleExecutor} from "../adaptors/BundleExecutor.sol";

// Test-only: re-enters BundleExecutor.execute to prove the nonReentrant guard blocks reentrancy through the
// arbitrary-call surface.
contract ReentrantBundleAttacker {
    BundleExecutor public immutable executor;

    constructor(address _executor) {
        executor = BundleExecutor(_executor);
    }

    // Re-enter execute with throwaway args: nonReentrant reverts at function entry, before any arg validation.
    function attack() external {
        bytes memory proof = "";
        bytes32[] memory publicInputs = new bytes32[](18);
        BundleExecutor.BundleCall[]
            memory calls = new BundleExecutor.BundleCall[](0);
        address[] memory assetsToClear = new address[](0);
        executor.execute(
            proof,
            publicInputs,
            calls,
            type(uint256).max,
            assetsToClear
        );
    }
}
