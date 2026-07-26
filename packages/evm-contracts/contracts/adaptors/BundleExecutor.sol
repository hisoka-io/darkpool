// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IDarkPool} from "../interfaces/IDarkPool.sol";

/**
 * @title BundleExecutor
 * @notice Permissionless atomic executor: pulls one shielded withdraw to itself, runs a caller-bound call
 *         bundle, and asserts zero residual balance on return. Holds funds only within `execute` and grants
 *         no standing allowances.
 * @dev The bundle is bound to the proof through the withdraw layout's free public input [2] (intent hash):
 *      `execute` recomputes the hash from the exact `boundCalls/deadline/assetsToClear` and overwrites [2],
 *      so a relayer that alters any call makes the proof fail verification. That binding covers only the one
 *      proof passed to `execute`; the pool's recipient gate (msg.sender != recipient) is satisfied by
 *      anything this contract calls, so a bound call reaching the pool is screened separately and may never
 *      pull a withdraw naming this contract.
 */
contract BundleExecutor is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @dev BN254 scalar field modulus; the intent hash is reduced into it to land in a Field input.
    uint256 internal constant BN254_P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Withdraw public-input layout: [0] value, [1] recipient, [2] intent hash, [7] asset. See DarkPool.
    uint256 internal constant WITHDRAW_INPUTS = 17;
    uint256 internal constant RECIPIENT_IDX = 1;
    uint256 internal constant INTENT_IDX = 2;
    uint256 internal constant NULLIFIER_IDX = 5;
    uint256 internal constant ASSET_IDX = 7;

    /// @dev Pool entrypoints a bound call may reach. Allowlisted rather than denylisted because the pool is
    ///      upgradeable behind an immutable address here: an entrypoint added later must revert, not be
    ///      assumed harmless. Both listed non-withdraw calls only pull tokens in from msg.sender.
    bytes4 internal constant SEL_DEPOSIT =
        bytes4(keccak256("deposit(bytes,bytes32[])"));
    bytes4 internal constant SEL_PUBLIC_TRANSFER =
        bytes4(
            keccak256(
                "publicTransfer(uint256,uint256,address,uint256,uint256,uint256)"
            )
        );
    bytes4 internal constant SEL_WITHDRAW =
        bytes4(keccak256("withdraw(bytes,bytes32[])"));
    bytes4 internal constant SEL_WITHDRAW_MULTISIG =
        bytes4(keccak256("withdrawMultisig(bytes,bytes32[])"));

    /// @dev Allowance grants are reachable only through `approveToken`, which is revoked after each call;
    ///      a bound call issuing its own grant would outlive `execute`.
    bytes4 internal constant SEL_APPROVE =
        bytes4(keccak256("approve(address,uint256)"));
    bytes4 internal constant SEL_INCREASE_ALLOWANCE =
        bytes4(keccak256("increaseAllowance(address,uint256)"));

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
    error UnsupportedDarkPoolCall(uint256 index, bytes4 selector);
    error NestedWithdrawToSelf(uint256 index);
    error ApproveTargetIsDarkPool(uint256 index);
    error AllowanceCallForbidden(uint256 index);
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

    /// @notice Recompute the intent hash that binds a bundle to its withdraw proof.
    /// @dev Byte-identical to the SDK builder.
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

    /// @notice Atomically withdraw one shielded note to this contract and run the bound call bundle.
    /// @param proof The withdraw proof.
    /// @param publicInputs The withdraw public inputs; index [2] is overwritten with the bundle intent hash.
    /// @param boundCalls The calls to run after the withdraw, in order.
    /// @param deadline Unix seconds after which `execute` reverts.
    /// @param assetsToClear ERC20s (besides the withdrawn asset) that must end at zero balance here.
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
            if (c.approveToken == DARK_POOL) revert ApproveTargetIsDarkPool(i);
            _screenBoundCall(i, c.target, c.data);

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

    /// @dev `execute` binds exactly one pull, and the pool's recipient gate is satisfied by anything this
    ///      contract calls, so a second withdraw naming this contract is unbound by construction. The nested
    ///      arguments are read with `abi.decode` over the forwarded slice, never a fixed offset: the caller
    ///      controls the argument-region head pointers, so a peek at the canonical position can be aimed at a
    ///      different word than the pool's own decoder consumes.
    function _screenBoundCall(
        uint256 index,
        address target,
        bytes calldata data
    ) private view {
        if (data.length < 4) {
            if (target == DARK_POOL)
                revert UnsupportedDarkPoolCall(index, bytes4(0));
            return;
        }

        bytes4 selector = bytes4(data[:4]);
        if (selector == SEL_APPROVE || selector == SEL_INCREASE_ALLOWANCE)
            revert AllowanceCallForbidden(index);

        if (target != DARK_POOL) return;
        if (selector == SEL_DEPOSIT || selector == SEL_PUBLIC_TRANSFER) return;
        if (selector != SEL_WITHDRAW && selector != SEL_WITHDRAW_MULTISIG)
            revert UnsupportedDarkPoolCall(index, selector);

        (, bytes32[] memory nestedInputs) = abi.decode(
            data[4:],
            (bytes, bytes32[])
        );
        if (nestedInputs.length != WITHDRAW_INPUTS)
            revert InvalidInputsLength();
        if (
            address(uint160(uint256(nestedInputs[RECIPIENT_IDX]))) ==
            address(this)
        ) revert NestedWithdrawToSelf(index);
    }

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
