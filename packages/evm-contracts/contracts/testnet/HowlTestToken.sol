// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title HowlTestToken
 * @notice A test token for the Howl pre-freeze testnet build; it carries no value.
 * @dev Issuance is owner-only so a test deployment's balances stay under the deployer's control.
 */
contract HowlTestToken is ERC20, Ownable {
    uint8 private immutable _tokenDecimals;

    constructor(
        string memory tokenName,
        string memory tokenSymbol,
        uint8 tokenDecimals,
        address initialOwner
    ) ERC20(tokenName, tokenSymbol) Ownable(initialOwner) {
        _tokenDecimals = tokenDecimals;
    }

    function decimals() public view override returns (uint8) {
        return _tokenDecimals;
    }

    /// @notice Issue test tokens. Reverts for everyone but the owner.
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
