// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISwapRouter} from "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";

// Test-only deterministic Uniswap V3 router: pays out tokenOut at a fixed 1:1 rate so the UniswapAdaptor swap
// path can be exercised in CI (test:fast) without a mainnet fork. Must be pre-funded with tokenOut liquidity.
contract MockSwapRouter {
    function exactInputSingle(
        ISwapRouter.ExactInputSingleParams calldata params
    ) external returns (uint256 amountOut) {
        IERC20(params.tokenIn).transferFrom(
            msg.sender,
            address(this),
            params.amountIn
        );
        amountOut = params.amountIn;
        require(amountOut >= params.amountOutMinimum, "insufficient output");
        IERC20(params.tokenOut).transfer(params.recipient, amountOut);
    }
}
