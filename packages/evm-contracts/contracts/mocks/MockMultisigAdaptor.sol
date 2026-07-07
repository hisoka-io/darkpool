// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @dev The DarkPool surface a multisig adaptor pulls through: a FROST-multisig withdraw that pays this
///      contract, plus the public-memo repay leg. Declared here so the shipped IDarkPool stays untouched.
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
 * @notice Exercises the FROST-multisig withdraw path through an adaptor. It self-submits a `withdrawMultisig`
 *         naming itself as recipient (the DarkPool code-gate forces a contract recipient to pull its own
 *         withdraw), receives the exact public funds, then re-shields them via a `publicTransfer` memo.
 *         Mirrors the standard adaptor pull->repay shape; the multisig withdraw layout is byte-identical to
 *         the single-signer withdraw. Real swap wiring is deferred, so the repay leg is a public memo rather
 *         than a Uniswap trade.
 */
contract MockMultisigAdaptor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @dev Withdraw public-input layout: [0] value, [1] recipient, [7] asset. See DarkPool._withdraw.
    uint256 internal constant WITHDRAW_INPUTS = 18;
    uint256 internal constant VALUE_IDX = 0;
    uint256 internal constant RECIPIENT_IDX = 1;
    uint256 internal constant ASSET_IDX = 7;

    address public immutable DARK_POOL;

    error ZeroAddress();
    error InvalidInputsLength();
    error RecipientNotAdaptor();

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

    /**
     * @notice Pull a FROST-multisig withdraw to this contract, then re-shield the funds to `owner` as a memo.
     * @param proof The withdraw_multisig proof.
     * @param publicInputs Withdraw public inputs; [1] recipient must be this contract, [0] value, [7] asset.
     * @param ownerX Recipient owner point x for the repay memo.
     * @param ownerY Recipient owner point y for the repay memo.
     * @param salt Memo salt.
     */
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

        IMultisigDarkPool(DARK_POOL).withdrawMultisig(proof, publicInputs);

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
