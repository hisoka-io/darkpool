// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {UniswapAdaptor} from "../adaptors/uniswap/UniswapAdaptor.sol";

// Test-only: exposes the internal pure intent hash so a committed golden can lock TS<->Solidity parity in CI.
// The adaptor's production path only compares the hash against a proof-supplied intentHash, which is exercised
// solely in the fork-only integration suite; this harness makes the hash itself assertable in test:fast.
contract UniswapIntentHarness is UniswapAdaptor {
    constructor(
        address darkPool,
        address router
    ) UniswapAdaptor(darkPool, router) {}

    function calcIntentHash(
        SwapType sType,
        bytes calldata encoded
    ) external pure returns (bytes32) {
        return _calculateIntentHash(sType, encoded);
    }
}
