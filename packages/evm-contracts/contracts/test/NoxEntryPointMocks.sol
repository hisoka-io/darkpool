// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MockNoxPaymentAdapter {
    using SafeERC20 for IERC20;

    address public immutable ENTRY_POINT;
    address public immutable FEE_ASSET;
    uint256 public shortfall;

    error NotEntryPoint();

    constructor(address entryPoint, address feeAsset) {
        ENTRY_POINT = entryPoint;
        FEE_ASSET = feeAsset;
    }

    function setShortfall(uint256 amount) external {
        shortfall = amount;
    }

    function pay(
        bytes32,
        bytes32,
        address feeAsset,
        uint256 amount,
        bytes calldata
    ) external {
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint();
        if (feeAsset != FEE_ASSET) revert NotEntryPoint();
        IERC20(feeAsset).safeTransfer(msg.sender, amount - shortfall);
    }
}

contract NoxActionTarget {
    uint256 public value;

    function setValue(uint256 nextValue) external returns (uint256) {
        value = nextValue;
        return nextValue;
    }

    function fail(string calldata reason) external pure {
        revert(reason);
    }
}
