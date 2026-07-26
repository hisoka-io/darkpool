// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {UniswapAdaptor} from "../adaptors/uniswap/UniswapAdaptor.sol";

// Test-only: exposes the internal intent hash so a golden vector can lock TS/Solidity parity outside the
// fork suite.
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

    // The deadline-bound hash executeSwap writes into publicInputs[2]. Covered separately from the base hash
    // so a drift in either fold is caught.
    function calcBoundIntentHash(
        SwapType sType,
        bytes calldata encoded,
        uint256 deadline
    ) external pure returns (bytes32) {
        return _bindDeadline(_calculateIntentHash(sType, encoded), deadline);
    }
}
