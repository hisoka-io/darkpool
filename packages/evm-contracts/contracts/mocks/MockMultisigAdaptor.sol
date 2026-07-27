// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IWithdrawRecipient} from "../interfaces/IWithdrawRecipient.sol";

interface IMultisigDarkPool {
    function withdrawMultisig(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external;

    function publicTransfer(
        uint256 ownerX,
        uint256 ownerY,
        address asset,
        uint256 value,
        uint256 timelock,
        uint256 salt
    ) external;
}

/**
 * @title MockMultisigAdaptor
 * @notice Test adaptor: self-submits a `withdrawMultisig` naming itself as recipient (the DarkPool affirmation
 *         callback forces a contract recipient to have asked for its own withdraw), then re-shields it as a memo.
 */
contract MockMultisigAdaptor is ReentrancyGuard, IWithdrawRecipient {
    using SafeERC20 for IERC20;

    /// @dev Withdraw public-input layout: [0] value, [1] recipient, [5] nullifier, [7] asset. See DarkPool._withdraw.
    uint256 internal constant WITHDRAW_INPUTS = 17;
    uint256 internal constant VALUE_IDX = 0;
    uint256 internal constant RECIPIENT_IDX = 1;
    uint256 internal constant NULLIFIER_IDX = 5;
    uint256 internal constant ASSET_IDX = 7;

    address public immutable DARK_POOL;

    /// @dev Set only across the one pull `pullAndForward` initiates. This adaptor forwards a caller-supplied
    ///      intent hash rather than computing one, so the nullifier is what identifies its own pull.
    bytes32 private _pullNullifier;
    bool private _pulling;

    error ZeroAddress();
    error InvalidInputsLength();
    error RecipientNotAdaptor();
    error NotTheDarkPool();
    error NoPullInProgress();
    error NullifierMismatch();

    event MultisigWithdrawForwarded(
        address indexed asset,
        uint256 value,
        uint256 ownerX,
        uint256 ownerY,
        uint256 salt
    );

    constructor(address _darkPool) {
        if (_darkPool == address(0)) revert ZeroAddress();
        DARK_POOL = _darkPool;
    }

    /// @notice Affirm to the pool that this contract requested the withdraw now being settled.
    function acceptWithdraw(
        bytes32 nullifier,
        uint256
    ) external view returns (bytes4) {
        if (msg.sender != DARK_POOL) revert NotTheDarkPool();
        if (!_pulling) revert NoPullInProgress();
        if (nullifier != _pullNullifier) revert NullifierMismatch();
        return IWithdrawRecipient.acceptWithdraw.selector;
    }

    function pullAndForward(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        uint256 ownerX,
        uint256 ownerY,
        uint256 salt
    ) external nonReentrant {
        if (publicInputs.length != WITHDRAW_INPUTS)
            revert InvalidInputsLength();
        if (
            address(uint160(uint256(publicInputs[RECIPIENT_IDX]))) !=
            address(this)
        ) revert RecipientNotAdaptor();

        uint256 value = uint256(publicInputs[VALUE_IDX]);
        address asset = address(uint160(uint256(publicInputs[ASSET_IDX])));

        _pulling = true;
        _pullNullifier = publicInputs[NULLIFIER_IDX];
        IMultisigDarkPool(DARK_POOL).withdrawMultisig(proof, publicInputs);
        _pulling = false;
        _pullNullifier = bytes32(0);

        IERC20(asset).forceApprove(DARK_POOL, value);
        IMultisigDarkPool(DARK_POOL).publicTransfer(
            ownerX,
            ownerY,
            asset,
            value,
            0,
            salt
        );

        emit MultisigWithdrawForwarded(asset, value, ownerX, ownerY, salt);
    }
}
