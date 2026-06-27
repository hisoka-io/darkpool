// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockFeeOnTransferERC20 is ERC20 {
    uint8 private immutable _decimals;
    uint256 public immutable feeBps;

    constructor(
        string memory name,
        string memory symbol,
        uint8 decimals_,
        uint256 feeBps_
    ) ERC20(name, symbol) {
        _decimals = decimals_;
        feeBps = feeBps_;
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function _update(
        address from,
        address to,
        uint256 value
    ) internal virtual override {
        if (from != address(0) && to != address(0) && feeBps > 0) {
            uint256 fee = (value * feeBps) / 10_000;
            super._update(from, to, value - fee);
            super._update(from, address(0), fee);
        } else {
            super._update(from, to, value);
        }
    }
}
