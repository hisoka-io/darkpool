// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/**
 * @title NoxExecutionSandbox
 * @notice One-shot isolated caller for a single zero-native-value Nox action.
 */
contract NoxExecutionSandbox {
    uint256 public constant MAX_TRACKED_ASSETS = 16;
    uint256 public constant MAX_RETURN_PREFIX_BYTES = 4096;
    uint256 public constant CALL_OVERHEAD_GAS = 8_000;
    uint256 public constant POST_ACTION_BASE_GAS = 35_000;
    uint256 public constant POST_ACTION_ASSET_GAS = 18_000;

    address public entryPoint;
    bytes32 public clientIntentId;
    bool public initialized;
    bool public finalized;

    error AlreadyInitialized();
    error InvalidClientIntent();
    error NotEntryPoint();
    error NotInitialized();
    error AlreadyFinalized();
    error InvalidTarget();
    error TooManyTrackedAssets();
    error DuplicateTrackedAsset(address asset);
    error InvalidTrackedAsset();
    error ReturnDataLimitTooLarge();
    error InsufficientActionGas();
    error NativeBalanceChanged();
    error TokenBalanceReadFailed(address asset);
    error TokenBalanceChanged(address asset);

    constructor() {
        initialized = true;
        finalized = true;
    }

    /// @notice Initialize a newly created minimal proxy. The creator becomes its sole controller.
    function initialize(bytes32 intentId) external {
        if (initialized) revert AlreadyInitialized();
        if (intentId == bytes32(0)) revert InvalidClientIntent();
        initialized = true;
        entryPoint = msg.sender;
        clientIntentId = intentId;
    }

    /// @notice Execute exactly one action and permanently finalize this sandbox.
    function execute(
        address target,
        bytes calldata actionData,
        uint256 actionGasLimit,
        address[] calldata trackedAssets,
        uint256 returnDataLimit,
        address implementation
    )
        external
        returns (
            bool success,
            uint256 returnDataLength,
            bytes32 returnPrefixHash
        )
    {
        if (!initialized) revert NotInitialized();
        if (msg.sender != entryPoint) revert NotEntryPoint();
        if (finalized) revert AlreadyFinalized();
        if (
            target == address(0) ||
            target == address(this) ||
            target == entryPoint ||
            target == implementation
        ) revert InvalidTarget();
        if (trackedAssets.length > MAX_TRACKED_ASSETS)
            revert TooManyTrackedAssets();
        if (returnDataLimit > MAX_RETURN_PREFIX_BYTES)
            revert ReturnDataLimitTooLarge();

        uint256 nativeBalance = address(this).balance;
        uint256[] memory balances = new uint256[](trackedAssets.length);
        for (uint256 i; i < trackedAssets.length; ++i) {
            address asset = trackedAssets[i];
            if (asset == address(0)) revert InvalidTrackedAsset();
            for (uint256 j; j < i; ++j) {
                if (trackedAssets[j] == asset)
                    revert DuplicateTrackedAsset(asset);
            }
            balances[i] = _balanceOf(asset);
        }

        finalized = true;
        (success, returnDataLength, returnPrefixHash) = _performAction(
            target,
            actionData,
            actionGasLimit,
            returnDataLimit,
            trackedAssets.length
        );

        if (address(this).balance != nativeBalance)
            revert NativeBalanceChanged();
        for (uint256 i; i < trackedAssets.length; ++i) {
            if (_balanceOf(trackedAssets[i]) != balances[i])
                revert TokenBalanceChanged(trackedAssets[i]);
        }
    }

    function _performAction(
        address target,
        bytes memory actionData,
        uint256 actionGasLimit,
        uint256 returnDataLimit,
        uint256 trackedAssetCount
    )
        private
        returns (bool success, uint256 returnDataLength, bytes32 prefixHash)
    {
        uint256 reserve = CALL_OVERHEAD_GAS +
            POST_ACTION_BASE_GAS +
            trackedAssetCount *
            POST_ACTION_ASSET_GAS;
        uint256 available = gasleft();
        if (available <= reserve) revert InsufficientActionGas();
        unchecked {
            available -= reserve;
        }
        if ((available * 63) / 64 < actionGasLimit)
            revert InsufficientActionGas();

        assembly {
            success := call(
                actionGasLimit,
                target,
                0,
                add(actionData, 0x20),
                mload(actionData),
                0,
                0
            )
            returnDataLength := returndatasize()
        }
        uint256 copiedLength = returnDataLength < returnDataLimit
            ? returnDataLength
            : returnDataLimit;
        bytes memory returnPrefix = new bytes(copiedLength);
        assembly {
            returndatacopy(add(returnPrefix, 0x20), 0, copiedLength)
        }
        prefixHash = keccak256(returnPrefix);
    }

    function _balanceOf(
        address asset
    ) private view returns (uint256 tokenBalance) {
        bytes4 selector = 0x70a08231;
        bool ok;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, shl(224, selector))
            mstore(add(ptr, 4), address())
            ok := staticcall(20000, asset, ptr, 36, ptr, 32)
            if and(ok, lt(returndatasize(), 32)) {
                ok := 0
            }
            tokenBalance := mload(ptr)
        }
        if (!ok) revert TokenBalanceReadFailed(asset);
    }
}
