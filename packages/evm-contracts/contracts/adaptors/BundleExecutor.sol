// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IDarkPool} from "../interfaces/IDarkPool.sol";
import {IWithdrawRecipient} from "../interfaces/IWithdrawRecipient.sol";

/**
 * @title BundleExecutor
 * @notice Permissionless atomic executor: pulls one shielded withdraw to itself, runs a caller-bound call
 *         bundle, and restores every declared token balance on return. Grants
 *         no standing allowances.
 * @dev The bundle is bound to the proof through the withdraw layout's free public input [2] (intent hash):
 *      `execute` recomputes the domain-bound hash from the exact calls, deadline, tracked assets, and recipients,
 *      so a relayer that alters any call makes the proof fail verification. That binding covers only the one
 *      proof passed to `execute`, so a bound call reaching the pool is screened separately and may never pull
 *      a withdraw naming this contract: by then the pool's affirmation callback finds no pull in progress, and
 *      the screen is the defence in depth in front of it.
 */
contract BundleExecutor is ReentrancyGuard, IWithdrawRecipient {
    using SafeERC20 for IERC20;

    /// @dev Set only across the one pull `execute` initiates. Any other pull naming this contract, including
    ///      one a bound call tries to trigger, finds this zero and is refused at the pool.
    uint256 private _pullIntent;
    bool private _pulling;

    /// @dev BN254 scalar field modulus; the intent hash is reduced into it to land in a Field input.
    uint256 internal constant BN254_P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant BUNDLE_VERSION = 2;
    uint256 public constant MAX_BUNDLE_CALLS = 32;
    uint256 public constant MAX_TRACKED_ASSETS = 32;
    uint256 public constant MAX_RECIPIENTS = 32;
    uint256 public constant MAX_RETURN_PREFIX_BYTES = 4096;
    uint256 public constant POST_CALL_RESERVE_GAS = 60_000;

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
    bytes4 internal constant SEL_TRANSFER =
        bytes4(keccak256("transfer(address,uint256)"));
    bytes4 internal constant SEL_TRANSFER_FROM =
        bytes4(keccak256("transferFrom(address,address,uint256)"));

    struct BundleCall {
        address target;
        bytes data;
        uint256 value;
        bool requireSuccess;
        address approveToken;
        uint256 approveAmount;
        uint256 gasLimit;
        uint256 returnDataLimit;
    }

    address public immutable DARK_POOL;

    error ZeroAddress();
    error ExpiredDeadline();
    error InvalidInputsLength();
    error RecipientNotExecutor();
    error NonZeroCallValue(uint256 index);
    error RequiredCallFailed(
        uint256 index,
        uint256 returnDataLength,
        bytes32 returnPrefixHash
    );
    error UnsupportedDarkPoolCall(uint256 index, bytes4 selector);
    error NotTheDarkPool();
    error NoPullInProgress();
    error IntentMismatch();
    error NestedWithdrawToSelf(uint256 index);
    error ApproveTargetIsDarkPool(uint256 index);
    error AllowanceCallForbidden(uint256 index);
    error TooManyBundleCalls();
    error TooManyTrackedAssets();
    error TooManyRecipients();
    error InvalidTrackedAsset();
    error DuplicateTrackedAsset(address asset);
    error InvalidRecipient();
    error DuplicateRecipient(address recipient);
    error WithdrawnAssetNotTracked(address asset);
    error UntrackedApprovalAsset(address asset);
    error InvalidApproval(uint256 index);
    error ZeroCallTarget(uint256 index);
    error BalanceChanged(
        address asset,
        uint256 beforeBalance,
        uint256 afterBalance
    );
    error DarkPoolHasNoCode();
    error InvalidCallGas(uint256 index);
    error ReturnDataLimitTooLarge(uint256 index);
    error InsufficientCallGas(uint256 index);
    error UntrackedTokenCall(address token);
    error UnboundTokenRecipient(address recipient);
    error TransferSourceNotExecutor(address source);
    error MalformedTokenCall(uint256 index);

    event BundleExecuted(
        bytes32 indexed nullifier,
        uint256 intentHash,
        uint256 callCount
    );
    event CallExecuted(
        uint256 indexed index,
        uint256 returnDataLength,
        bytes32 returnPrefixHash
    );
    event CallFailed(
        uint256 indexed index,
        uint256 returnDataLength,
        bytes32 returnPrefixHash
    );

    constructor(address _darkPool) {
        if (_darkPool == address(0)) revert ZeroAddress();
        if (_darkPool.code.length == 0) revert DarkPoolHasNoCode();
        DARK_POOL = _darkPool;
    }

    /// @notice Affirm to the pool that this contract requested the withdraw now being settled.
    /// @dev The intent hash is what makes this specific rather than a blanket yes: it is recomputed by
    ///      `execute` from the exact bundle, so a pull carrying any other bundle's binding is refused even
    ///      while a legitimate pull is in flight.
    function acceptWithdraw(
        bytes32,
        uint256 intentHash
    ) external view returns (bytes4) {
        if (msg.sender != DARK_POOL) revert NotTheDarkPool();
        if (!_pulling) revert NoPullInProgress();
        if (intentHash != _pullIntent) revert IntentMismatch();
        return IWithdrawRecipient.acceptWithdraw.selector;
    }

    /// @notice Recompute the intent hash that binds a bundle to its withdraw proof.
    /// @dev Byte-identical to the SDK builder.
    function intentHashOf(
        BundleCall[] calldata boundCalls,
        uint256 deadline,
        address[] calldata trackedAssets,
        address[] calldata recipients
    ) public view returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encode(
                        BUNDLE_VERSION,
                        block.chainid,
                        address(this),
                        DARK_POOL,
                        boundCalls,
                        deadline,
                        trackedAssets,
                        recipients
                    )
                )
            ) % BN254_P;
    }

    /// @notice Atomically withdraw one shielded note to this contract and run the bound call bundle.
    /// @param proof The withdraw proof.
    /// @param publicInputs The withdraw public inputs; index [2] is overwritten with the bundle intent hash.
    /// @param boundCalls The calls to run after the withdraw, in order.
    /// @param deadline Unix seconds after which `execute` reverts.
    /// @param trackedAssets ERC20s whose balances must return to their pre-execution values.
    /// @param recipients Explicit action recipients bound into the intent for user review.
    function execute(
        bytes calldata proof,
        bytes32[] memory publicInputs,
        BundleCall[] calldata boundCalls,
        uint256 deadline,
        address[] calldata trackedAssets,
        address[] calldata recipients
    ) external nonReentrant {
        if (block.timestamp > deadline) revert ExpiredDeadline();
        if (publicInputs.length != WITHDRAW_INPUTS)
            revert InvalidInputsLength();
        if (boundCalls.length > MAX_BUNDLE_CALLS) revert TooManyBundleCalls();
        if (trackedAssets.length > MAX_TRACKED_ASSETS)
            revert TooManyTrackedAssets();
        if (recipients.length > MAX_RECIPIENTS) revert TooManyRecipients();

        uint256 intentHash = intentHashOf(
            boundCalls,
            deadline,
            trackedAssets,
            recipients
        );
        publicInputs[INTENT_IDX] = bytes32(intentHash);

        if (
            address(uint160(uint256(publicInputs[RECIPIENT_IDX]))) !=
            address(this)
        ) revert RecipientNotExecutor();

        address withdrawnAsset = address(
            uint160(uint256(publicInputs[ASSET_IDX]))
        );
        uint256[] memory startingBalances = _validateAndSnapshot(
            withdrawnAsset,
            boundCalls,
            trackedAssets,
            recipients
        );

        _pulling = true;
        _pullIntent = intentHash;
        IDarkPool(DARK_POOL).withdraw(proof, publicInputs);
        _pulling = false;
        _pullIntent = 0;

        for (uint256 i; i < boundCalls.length; ++i) {
            BundleCall calldata c = boundCalls[i];
            if (c.value != 0) revert NonZeroCallValue(i);
            if (c.target == address(0)) revert ZeroCallTarget(i);
            if ((c.approveToken == address(0)) != (c.approveAmount == 0))
                revert InvalidApproval(i);
            if (c.gasLimit == 0) revert InvalidCallGas(i);
            if (c.returnDataLimit > MAX_RETURN_PREFIX_BYTES)
                revert ReturnDataLimitTooLarge(i);
            if (c.approveToken == DARK_POOL) revert ApproveTargetIsDarkPool(i);
            _screenBoundCall(i, c.target, c.data, trackedAssets, recipients);

            if (c.approveToken != address(0) && c.approveAmount != 0)
                IERC20(c.approveToken).forceApprove(c.target, c.approveAmount);

            (
                bool ok,
                uint256 returnDataLength,
                bytes32 returnPrefixHash
            ) = _callBound(i, c);

            if (c.approveToken != address(0))
                IERC20(c.approveToken).forceApprove(c.target, 0);

            if (ok) {
                emit CallExecuted(i, returnDataLength, returnPrefixHash);
            } else {
                if (c.requireSuccess) {
                    revert RequiredCallFailed(
                        i,
                        returnDataLength,
                        returnPrefixHash
                    );
                }
                emit CallFailed(i, returnDataLength, returnPrefixHash);
            }
        }

        for (uint256 i; i < trackedAssets.length; ++i) {
            uint256 endingBalance = IERC20(trackedAssets[i]).balanceOf(
                address(this)
            );
            if (endingBalance != startingBalances[i])
                revert BalanceChanged(
                    trackedAssets[i],
                    startingBalances[i],
                    endingBalance
                );
        }

        emit BundleExecuted(
            publicInputs[NULLIFIER_IDX],
            intentHash,
            boundCalls.length
        );
    }

    /// @dev `execute` binds exactly one pull, so a second withdraw naming this contract is unbound by
    ///      construction. The nested arguments are read with `abi.decode` over the forwarded slice, never a
    ///      fixed offset: the caller controls the argument-region head pointers, so a peek at the canonical
    ///      position can be aimed at a different word than the pool's own decoder consumes.
    function _screenBoundCall(
        uint256 index,
        address target,
        bytes calldata data,
        address[] calldata trackedAssets,
        address[] calldata recipients
    ) private view {
        if (data.length < 4) {
            if (target == DARK_POOL)
                revert UnsupportedDarkPoolCall(index, bytes4(0));
            return;
        }

        bytes4 selector = bytes4(data[:4]);
        if (selector == SEL_APPROVE || selector == SEL_INCREASE_ALLOWANCE)
            revert AllowanceCallForbidden(index);

        if (selector == SEL_TRANSFER) {
            if (data.length != 68) revert MalformedTokenCall(index);
            (address recipient, ) = abi.decode(data[4:], (address, uint256));
            _requireTrackedTransfer(
                target,
                recipient,
                trackedAssets,
                recipients
            );
        } else if (selector == SEL_TRANSFER_FROM) {
            if (data.length != 100) revert MalformedTokenCall(index);
            (address source, address recipient, ) = abi.decode(
                data[4:],
                (address, address, uint256)
            );
            if (source != address(this))
                revert TransferSourceNotExecutor(source);
            _requireTrackedTransfer(
                target,
                recipient,
                trackedAssets,
                recipients
            );
        }

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

    function _requireTrackedTransfer(
        address token,
        address recipient,
        address[] calldata trackedAssets,
        address[] calldata recipients
    ) private pure {
        if (!_contains(trackedAssets, token)) revert UntrackedTokenCall(token);
        if (!_contains(recipients, recipient))
            revert UnboundTokenRecipient(recipient);
    }

    function _callBound(
        uint256 index,
        BundleCall calldata callSpec
    )
        private
        returns (bool success, uint256 returnDataLength, bytes32 prefixHash)
    {
        uint256 available = gasleft();
        if (available <= POST_CALL_RESERVE_GAS)
            revert InsufficientCallGas(index);
        unchecked {
            available -= POST_CALL_RESERVE_GAS;
        }
        if ((available * 63) / 64 < callSpec.gasLimit)
            revert InsufficientCallGas(index);

        bytes memory callData = callSpec.data;
        uint256 callGas = callSpec.gasLimit;
        address target = callSpec.target;
        assembly {
            success := call(
                callGas,
                target,
                0,
                add(callData, 0x20),
                mload(callData),
                0,
                0
            )
            returnDataLength := returndatasize()
        }
        uint256 copiedLength = returnDataLength < callSpec.returnDataLimit
            ? returnDataLength
            : callSpec.returnDataLimit;
        bytes memory prefix = new bytes(copiedLength);
        assembly {
            returndatacopy(add(prefix, 0x20), 0, copiedLength)
        }
        prefixHash = keccak256(prefix);
    }

    function _validateAndSnapshot(
        address withdrawnAsset,
        BundleCall[] calldata boundCalls,
        address[] calldata trackedAssets,
        address[] calldata recipients
    ) private view returns (uint256[] memory balances) {
        bool withdrawnTracked;
        balances = new uint256[](trackedAssets.length);
        for (uint256 i; i < trackedAssets.length; ++i) {
            address asset = trackedAssets[i];
            if (asset == address(0)) revert InvalidTrackedAsset();
            for (uint256 j; j < i; ++j) {
                if (trackedAssets[j] == asset)
                    revert DuplicateTrackedAsset(asset);
            }
            if (asset == withdrawnAsset) withdrawnTracked = true;
            balances[i] = IERC20(asset).balanceOf(address(this));
        }
        if (!withdrawnTracked) revert WithdrawnAssetNotTracked(withdrawnAsset);

        for (uint256 i; i < boundCalls.length; ++i) {
            address approvalAsset = boundCalls[i].approveToken;
            if (
                approvalAsset != address(0) &&
                !_contains(trackedAssets, approvalAsset)
            ) revert UntrackedApprovalAsset(approvalAsset);
        }
        for (uint256 i; i < recipients.length; ++i) {
            address recipient = recipients[i];
            if (recipient == address(0)) revert InvalidRecipient();
            for (uint256 j; j < i; ++j) {
                if (recipients[j] == recipient)
                    revert DuplicateRecipient(recipient);
            }
        }
    }

    function _contains(
        address[] calldata values,
        address expected
    ) private pure returns (bool) {
        for (uint256 i; i < values.length; ++i) {
            if (values[i] == expected) return true;
        }
        return false;
    }
}
