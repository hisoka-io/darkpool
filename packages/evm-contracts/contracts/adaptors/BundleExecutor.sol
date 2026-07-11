// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IDarkPool} from "../interfaces/IDarkPool.sol";

/**
 * @title BundleExecutor
 * @notice Permissionless atomic executor: pulls one shielded withdraw to itself, runs a caller-bound call
 *         bundle (treasury fee, swap, distribution), and asserts it holds zero residual over the union of the
 *         withdrawn asset, every bound call's approve token, and the declared assetsToClear when it returns.
 *         Holds funds only within `execute`; grants no standing allowances.
 * @dev The bundle is bound to the proof through the withdraw layout's free public input [2] (intent hash):
 *      `execute` recomputes the hash from the exact `boundCalls/deadline/assetsToClear` and overwrites [2],
 *      so a relayer that alters any call makes the proof fail verification. A raw withdraw to this contract
 *      from outside `execute` reverts via the DarkPool code gate (msg.sender != recipient).
 */
contract BundleExecutor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @dev BN254 scalar field modulus; the intent hash is reduced into it since it lands in a Field input.
    uint256 internal constant BN254_P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Withdraw public-input layout: [0] value, [1] recipient, [2] intent hash, [7] asset. See DarkPool.
    uint256 internal constant WITHDRAW_INPUTS = 18;
    uint256 internal constant RECIPIENT_IDX = 1;
    uint256 internal constant INTENT_IDX = 2;
    uint256 internal constant NULLIFIER_IDX = 5;
    uint256 internal constant ASSET_IDX = 7;

    struct BundleCall {
        address target;
        bytes data;
        uint256 value;
        bool requireSuccess;
        address approveToken;
        uint256 approveAmount;
    }

    address public immutable DARK_POOL;

    error ZeroAddress();
    error ExpiredDeadline();
    error InvalidInputsLength();
    error RecipientNotExecutor();
    error NonZeroCallValue(uint256 index);
    error RequiredCallFailed(uint256 index);
    error ResidualBalance(address asset);

    event BundleExecuted(
        bytes32 indexed nullifier,
        uint256 intentHash,
        uint256 callCount
    );
    event CallExecuted(uint256 indexed index, bytes returnData);
    event CallFailed(uint256 indexed index, bytes reason);

    constructor(address _darkPool) {
        if (_darkPool == address(0)) revert ZeroAddress();
        DARK_POOL = _darkPool;
    }

    /**
     * @notice Recompute the intent hash that binds a bundle to its withdraw proof.
     * @dev Byte-identical to the SDK builder: keccak256(abi.encode(...)) reduced into the BN254 field.
     */
    function intentHashOf(
        BundleCall[] calldata boundCalls,
        uint256 deadline,
        address[] calldata assetsToClear
    ) public pure returns (uint256) {
        return
            uint256(
                keccak256(abi.encode(boundCalls, deadline, assetsToClear))
            ) % BN254_P;
    }

    /**
     * @notice Atomically withdraw one shielded note to this contract and run the bound call bundle.
     * @param proof The withdraw proof.
     * @param publicInputs The withdraw public inputs; index [2] is overwritten with the bundle intent hash.
     * @param boundCalls The calls to run after the withdraw, in order.
     * @param deadline Unix seconds after which `execute` reverts.
     * @param assetsToClear ERC20s (besides the withdrawn asset) that must end at zero balance here.
     */
    function execute(
        bytes calldata proof,
        bytes32[] memory publicInputs,
        BundleCall[] calldata boundCalls,
        uint256 deadline,
        address[] calldata assetsToClear
    ) external nonReentrant {
        if (block.timestamp > deadline) revert ExpiredDeadline();
        if (publicInputs.length != WITHDRAW_INPUTS)
            revert InvalidInputsLength();

        uint256 intentHash = intentHashOf(boundCalls, deadline, assetsToClear);
        publicInputs[INTENT_IDX] = bytes32(intentHash);

        if (
            address(uint160(uint256(publicInputs[RECIPIENT_IDX]))) !=
            address(this)
        ) revert RecipientNotExecutor();

        IDarkPool(DARK_POOL).withdraw(proof, publicInputs);

        for (uint256 i; i < boundCalls.length; ++i) {
            BundleCall calldata c = boundCalls[i];
            if (c.value != 0) revert NonZeroCallValue(i);

            if (c.approveToken != address(0) && c.approveAmount != 0)
                IERC20(c.approveToken).forceApprove(c.target, c.approveAmount);

            (bool ok, bytes memory ret) = c.target.call(c.data);

            if (c.approveToken != address(0))
                IERC20(c.approveToken).forceApprove(c.target, 0);

            if (ok) {
                emit CallExecuted(i, ret);
            } else {
                if (c.requireSuccess) {
                    if (ret.length > 0) {
                        assembly {
                            revert(add(32, ret), mload(ret))
                        }
                    }
                    revert RequiredCallFailed(i);
                }
                emit CallFailed(i, ret);
            }
        }

        address withdrawnAsset = address(
            uint160(uint256(publicInputs[ASSET_IDX]))
        );
        address[] memory checked = new address[](
            1 + boundCalls.length + assetsToClear.length
        );
        uint256 checkedCount = _assertZeroResidual(withdrawnAsset, checked, 0);
        for (uint256 i; i < boundCalls.length; ++i)
            checkedCount = _assertZeroResidual(
                boundCalls[i].approveToken,
                checked,
                checkedCount
            );
        for (uint256 i; i < assetsToClear.length; ++i)
            checkedCount = _assertZeroResidual(
                assetsToClear[i],
                checked,
                checkedCount
            );

        emit BundleExecuted(
            publicInputs[NULLIFIER_IDX],
            intentHash,
            boundCalls.length
        );
    }

    /// @dev Reverts ResidualBalance if `asset` holds a nonzero balance here; skips the zero address and
    ///      assets already checked, so the withdrawn-asset / approve-token / assetsToClear union is verified
    ///      once each. `checked` accumulates the distinct assets seen; the new count is returned.
    function _assertZeroResidual(
        address asset,
        address[] memory checked,
        uint256 checkedCount
    ) private view returns (uint256) {
        if (asset == address(0)) return checkedCount;
        for (uint256 i; i < checkedCount; ++i)
            if (checked[i] == asset) return checkedCount;
        if (IERC20(asset).balanceOf(address(this)) != 0)
            revert ResidualBalance(asset);
        checked[checkedCount] = asset;
        return checkedCount + 1;
    }
}
