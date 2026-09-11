// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IDarkPool} from "../interfaces/IDarkPool.sol";
import {IWithdrawRecipient} from "../interfaces/IWithdrawRecipient.sol";

/**
 * @title HowlPaymentAdapter
 * @notice Acquires one exact Nox fee from an independently authorized standard Howl withdraw.
 */
contract HowlPaymentAdapter is IWithdrawRecipient, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant BN254_P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant WITHDRAW_INPUTS = 17;

    address public immutable DARK_POOL;
    address public immutable ENTRY_POINT;

    bytes32 public expectedNullifier;
    uint256 public expectedIntent;
    bool public pulling;

    error ZeroAddress();
    error DependencyHasNoCode(address dependency);
    error NotEntryPoint();
    error NotDarkPool();
    error InvalidInputsLength();
    error PaymentIdMismatch();
    error RecipientMismatch();
    error IntentMismatch();
    error FeeAssetMismatch();
    error FeeAmountMismatch();
    error NoPullInProgress();
    error IncorrectWithdrawalAmount(uint256 expected, uint256 received);
    error ResidualBalance();

    constructor(address darkPool, address entryPoint) {
        if (darkPool == address(0) || entryPoint == address(0))
            revert ZeroAddress();
        if (darkPool.code.length == 0) revert DependencyHasNoCode(darkPool);
        if (entryPoint.code.length == 0) revert DependencyHasNoCode(entryPoint);
        DARK_POOL = darkPool;
        ENTRY_POINT = entryPoint;
    }

    /// @notice Domain-separated reduction carried by withdraw public input 2.
    function paymentIntent(bytes32 executionId) public pure returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encodePacked("hisoka.nox.howl-payment.v1", executionId)
                )
            ) % BN254_P;
    }

    /// @notice Pull the exact quoted fee from a standard withdraw and forward it to EntryPoint.
    function pay(
        bytes32 executionId,
        bytes32 paymentId,
        address feeAsset,
        uint256 amount,
        bytes calldata paymentData
    ) external nonReentrant {
        if (msg.sender != ENTRY_POINT) revert NotEntryPoint();
        (bytes memory proof, bytes32[] memory publicInputs) = abi.decode(
            paymentData,
            (bytes, bytes32[])
        );
        if (publicInputs.length != WITHDRAW_INPUTS)
            revert InvalidInputsLength();
        if (publicInputs[5] != paymentId) revert PaymentIdMismatch();
        if (uint256(publicInputs[1]) != uint256(uint160(address(this))))
            revert RecipientMismatch();

        uint256 intent = paymentIntent(executionId);
        if (uint256(publicInputs[2]) != intent) revert IntentMismatch();
        if (uint256(publicInputs[7]) != uint256(uint160(feeAsset)))
            revert FeeAssetMismatch();
        if (uint256(publicInputs[0]) != amount) revert FeeAmountMismatch();

        IERC20 token = IERC20(feeAsset);
        uint256 startingBalance = token.balanceOf(address(this));
        pulling = true;
        expectedNullifier = paymentId;
        expectedIntent = intent;
        IDarkPool(DARK_POOL).withdraw(proof, publicInputs);
        pulling = false;
        expectedNullifier = bytes32(0);
        expectedIntent = 0;

        uint256 endingBalance = token.balanceOf(address(this));
        if (endingBalance < startingBalance)
            revert IncorrectWithdrawalAmount(amount, 0);
        uint256 received = endingBalance - startingBalance;
        if (received != amount)
            revert IncorrectWithdrawalAmount(amount, received);
        token.safeTransfer(ENTRY_POINT, amount);
        if (token.balanceOf(address(this)) != startingBalance)
            revert ResidualBalance();
    }

    /// @notice Affirm only the exact fee withdrawal currently initiated by EntryPoint.
    function acceptWithdraw(
        bytes32 nullifier,
        uint256 intentHash
    ) external view returns (bytes4) {
        if (msg.sender != DARK_POOL) revert NotDarkPool();
        if (!pulling) revert NoPullInProgress();
        if (nullifier != expectedNullifier) revert PaymentIdMismatch();
        if (intentHash != expectedIntent) revert IntentMismatch();
        return IWithdrawRecipient.acceptWithdraw.selector;
    }
}
