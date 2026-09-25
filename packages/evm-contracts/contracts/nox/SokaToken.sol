// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SokaToken
 * @notice SOKA, the Nox staking and execution-fee token.
 * @dev The whole initial supply goes to a treasury at construction. Further issuance is owner-only, and
 *      renouncing ownership fixes the supply for good. NoxRegistry binds its staking token once at
 *      initialize, so there is deliberately no permissionless mint.
 */
contract SokaToken is ERC20, Ownable {
    constructor(
        address treasury,
        uint256 initialSupply,
        address initialOwner
    ) ERC20("Soka", "SOKA") Ownable(initialOwner) {
        _mint(treasury, initialSupply);
    }

    /// @notice Issue new SOKA. Reverts for everyone but the owner.
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
