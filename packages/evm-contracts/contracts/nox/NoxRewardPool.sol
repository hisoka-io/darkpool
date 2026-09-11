// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
// solhint-disable-next-line max-line-length
import {AccessControlDefaultAdminRulesUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface INoxRegistry {
    function isActiveRelayer(address relayer) external view returns (bool);
}

/**
 * @title NoxRewardPool
 * @notice Treasury for the NOX Relayer Network: collects ERC20 gas fees and pays them out to relayers.
 * @dev The split is computed off-chain by the Distributor. UUPS proxy over an ERC-7201 namespace; the
 *      registry link is set in initialize, so it is never zero under the proxy.
 */
contract NoxRewardPool is
    Initializable,
    UUPSUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;

    bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    bytes32 public constant ENTRYPOINT_ROLE = keccak256("ENTRYPOINT_ROLE");

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /// @custom:storage-location erc7201:hisoka.nox.rewardpool
    struct RewardPoolStorage {
        INoxRegistry noxRegistry;
        mapping(address => bool) isSupportedAsset;
        mapping(address => uint256) totalCollected;
        mapping(address => uint256) totalDistributed;
        mapping(address => uint256) legacyNetworkLiability;
        mapping(address => bool) legacyClassified;
        mapping(address => uint256) newNetworkCollected;
        mapping(address => uint256) newNetworkDistributed;
        mapping(address => uint256) totalExitCredited;
        mapping(address => uint256) totalExitClaimed;
        mapping(address => mapping(address => uint256)) claimableExit;
        mapping(bytes32 => bool) settledExecution;
    }

    /// @dev Inlined on OZ's canonical namespace; contracts-upgradeable 5.6.1 dropped ReentrancyGuardUpgradeable.
    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyStorage {
        uint256 status;
    }

    // keccak256(abi.encode(uint256(keccak256("hisoka.nox.rewardpool")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REWARDPOOL_LOCATION =
        0x54fc6109d79aa70b8d075edff760cc58b2a4f172bcefb22efc43c410f648fa00;
    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REENTRANCY_LOCATION =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    function _rewardPool() private pure returns (RewardPoolStorage storage $) {
        assembly {
            $.slot := REWARDPOOL_LOCATION
        }
    }

    function _reentrancyStorage()
        private
        pure
        returns (ReentrancyStorage storage $)
    {
        assembly {
            $.slot := REENTRANCY_LOCATION
        }
    }

    modifier nonReentrant() {
        ReentrancyStorage storage $ = _reentrancyStorage();
        if ($.status == ENTERED) revert ReentrancyGuardReentrantCall();
        $.status = ENTERED;
        _;
        $.status = NOT_ENTERED;
    }

    event AssetStatusChanged(address indexed asset, bool isSupported);
    event RewardsDeposited(
        address indexed asset,
        address indexed from,
        uint256 amount
    );
    event RewardsDistributed(
        address indexed asset,
        uint256 totalAmount,
        uint256 recipientCount
    );
    event FundsRescued(
        address indexed asset,
        address indexed to,
        uint256 amount
    );
    event AssetClassified(address indexed asset, uint256 legacyLiability);
    event ExecutionFeeRecorded(
        bytes32 indexed executionId,
        bytes32 indexed paymentId,
        address indexed exit,
        address asset,
        uint256 exitAmount,
        uint256 networkAmount
    );
    event ExitCreditClaimed(
        address indexed exit,
        address indexed recipient,
        address indexed asset,
        uint256 amount
    );

    error InvalidAsset();
    error AssetNotSupported();
    error ArrayLengthMismatch();
    error ZeroAddress();
    error ZeroAmount();
    error InsufficientCollected();
    error RecipientNotRegistered();
    error ExceedsRescuableBalance();
    error FeeOnTransferUnsupported();
    error ReentrancyGuardReentrantCall();
    error AssetAlreadyClassified();
    error AssetNotClassified();
    error ExecutionAlreadySettled();
    error InsufficientExitCredit();
    error AccountingOverflow();
    error InvalidIdentifier();

    struct InitParams {
        uint48 initialAdminDelay;
        address initialAdmin;
        address noxRegistry;
        address admin;
        address distributor;
        address upgrader;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice One-time proxy init. Roles go to the passed-in governance addresses, never msg.sender.
    function initialize(InitParams calldata p) external initializer {
        if (p.initialAdmin == address(0)) revert ZeroAddress();
        if (p.noxRegistry == address(0)) revert ZeroAddress();
        if (p.admin == address(0)) revert ZeroAddress();
        if (p.distributor == address(0)) revert ZeroAddress();
        if (p.upgrader == address(0)) revert ZeroAddress();

        __AccessControlDefaultAdminRules_init(
            p.initialAdminDelay,
            p.initialAdmin
        );
        __Pausable_init();
        _reentrancyStorage().status = NOT_ENTERED;

        _grantRole(ADMIN_ROLE, p.admin);
        _grantRole(DISTRIBUTOR_ROLE, p.distributor);
        _grantRole(UPGRADER_ROLE, p.upgrader);
        _setRoleAdmin(ENTRYPOINT_ROLE, ADMIN_ROLE);

        _rewardPool().noxRegistry = INoxRegistry(p.noxRegistry);
    }

    // solhint-disable no-empty-blocks
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
    // solhint-enable no-empty-blocks

    /// @notice Toggle support for a gas token. ERC20 only, no raw ETH.
    function setAssetStatus(
        address _asset,
        bool _status
    ) external onlyRole(ADMIN_ROLE) {
        if (_asset == address(0)) revert ZeroAddress();
        _rewardPool().isSupportedAsset[_asset] = _status;
        emit AssetStatusChanged(_asset, _status);
    }

    /// @notice Atomically hand the operational admin role to a replacement account.
    function transferOperationalAdmin(
        address newAdmin
    ) external onlyRole(ADMIN_ROLE) {
        if (newAdmin == address(0)) revert ZeroAddress();
        _grantRole(ADMIN_ROLE, newAdmin);
        _revokeRole(ADMIN_ROLE, msg.sender);
    }

    /// @notice Snapshot an asset's outstanding legacy network liability before EntryPoint accounting begins.
    function classifyAsset(address _asset) external onlyRole(ADMIN_ROLE) {
        if (_asset == address(0)) revert ZeroAddress();
        RewardPoolStorage storage $ = _rewardPool();
        if ($.legacyClassified[_asset]) revert AssetAlreadyClassified();
        uint256 legacyLiability = $.totalCollected[_asset] -
            $.totalDistributed[_asset];
        $.legacyNetworkLiability[_asset] = legacyLiability;
        $.legacyClassified[_asset] = true;
        emit AssetClassified(_asset, legacyLiability);
    }

    /// @notice Emergency pause for deposits and distributions.
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /// @notice Resume deposits and distributions.
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Accept gas payments from the DarkPool or from users.
    /// @param _asset Whitelisted ERC20 to deposit; fee-on-transfer tokens are rejected.
    /// @param _amount Amount to pull from the caller.
    function depositRewards(
        address _asset,
        uint256 _amount
    ) external nonReentrant whenNotPaused {
        if (_amount == 0) revert ZeroAmount();
        RewardPoolStorage storage $ = _rewardPool();
        if (!$.isSupportedAsset[_asset]) revert AssetNotSupported();

        uint256 bal0 = IERC20(_asset).balanceOf(address(this));
        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _amount);
        if (IERC20(_asset).balanceOf(address(this)) - bal0 != _amount)
            revert FeeOnTransferUnsupported();

        $.totalCollected[_asset] = _checkedAdd(
            $.totalCollected[_asset],
            _amount
        );
        if ($.legacyClassified[_asset]) {
            $.newNetworkCollected[_asset] = _checkedAdd(
                $.newNetworkCollected[_asset],
                _amount
            );
        }

        emit RewardsDeposited(_asset, msg.sender, _amount);
    }

    /// @notice Distribute accumulated fees to registered relayers.
    /// @dev Checks-effects-interactions: solvency is verified and accounting updated before any transfer.
    function distributeRewards(
        address _asset,
        address[] calldata _recipients,
        uint256[] calldata _amounts
    ) external nonReentrant whenNotPaused onlyRole(DISTRIBUTOR_ROLE) {
        RewardPoolStorage storage $ = _rewardPool();
        if (!$.isSupportedAsset[_asset]) revert AssetNotSupported();
        if (_recipients.length != _amounts.length) revert ArrayLengthMismatch();
        if (_recipients.length == 0) revert ArrayLengthMismatch();

        uint256 batchTotal = 0;
        for (uint256 i = 0; i < _recipients.length; i++) {
            address to = _recipients[i];
            if (to == address(0)) revert ZeroAddress();
            if (!$.noxRegistry.isActiveRelayer(to))
                revert RecipientNotRegistered();
            batchTotal = _checkedAdd(batchTotal, _amounts[i]);
        }

        if (batchTotal > _networkOutstanding($, _asset))
            revert InsufficientCollected();
        $.totalDistributed[_asset] = _checkedAdd(
            $.totalDistributed[_asset],
            batchTotal
        );
        if ($.legacyClassified[_asset]) {
            $.newNetworkDistributed[_asset] = _checkedAdd(
                $.newNetworkDistributed[_asset],
                batchTotal
            );
        }

        for (uint256 i = 0; i < _recipients.length; i++) {
            if (_amounts[i] > 0) {
                IERC20(_asset).safeTransfer(_recipients[i], _amounts[i]);
            }
        }

        emit RewardsDistributed(_asset, batchTotal, _recipients.length);
    }

    /// @notice Rescue only the free surplus. Committed rewards (collected minus distributed) are never
    ///         rescuable, regardless of the whitelist flag.
    function rescueFunds(
        address _asset,
        address _to,
        uint256 _amount
    ) external nonReentrant onlyRole(ADMIN_ROLE) {
        if (_to == address(0)) revert ZeroAddress();
        if (_amount == 0) revert ZeroAmount();

        RewardPoolStorage storage $ = _rewardPool();
        uint256 committed = _networkOutstanding($, _asset) +
            ($.totalExitCredited[_asset] - $.totalExitClaimed[_asset]);
        uint256 liveBalance = IERC20(_asset).balanceOf(address(this));
        uint256 free = liveBalance > committed ? liveBalance - committed : 0;
        if (_amount > free) revert ExceedsRescuableBalance();

        IERC20(_asset).safeTransfer(_to, _amount);
        emit FundsRescued(_asset, _to, _amount);
    }

    /// @notice Record one EntryPoint settlement and reserve the selected exit's credit.
    function recordExecutionFee(
        bytes32 executionId,
        bytes32 paymentId,
        address exit,
        address asset,
        uint256 exitAmount,
        uint256 networkAmount
    ) external nonReentrant whenNotPaused onlyRole(ENTRYPOINT_ROLE) {
        if (executionId == bytes32(0) || paymentId == bytes32(0))
            revert InvalidIdentifier();
        if (exit == address(0) || asset == address(0)) revert ZeroAddress();
        uint256 total = _checkedAdd(exitAmount, networkAmount);
        if (total == 0) revert ZeroAmount();

        RewardPoolStorage storage $ = _rewardPool();
        if (!$.isSupportedAsset[asset]) revert AssetNotSupported();
        if (!$.legacyClassified[asset]) revert AssetNotClassified();
        if ($.settledExecution[executionId]) revert ExecutionAlreadySettled();

        uint256 balanceBefore = IERC20(asset).balanceOf(address(this));
        IERC20(asset).safeTransferFrom(msg.sender, address(this), total);
        if (IERC20(asset).balanceOf(address(this)) - balanceBefore != total)
            revert FeeOnTransferUnsupported();

        $.settledExecution[executionId] = true;
        $.totalCollected[asset] = _checkedAdd($.totalCollected[asset], total);
        $.newNetworkCollected[asset] = _checkedAdd(
            $.newNetworkCollected[asset],
            networkAmount
        );
        $.totalExitCredited[asset] = _checkedAdd(
            $.totalExitCredited[asset],
            exitAmount
        );
        $.claimableExit[exit][asset] = _checkedAdd(
            $.claimableExit[exit][asset],
            exitAmount
        );

        emit ExecutionFeeRecorded(
            executionId,
            paymentId,
            exit,
            asset,
            exitAmount,
            networkAmount
        );
    }

    /// @notice Claim credit earned by the caller while it served as the selected exit.
    function claimExitCredit(
        address asset,
        address recipient,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        RewardPoolStorage storage $ = _rewardPool();
        uint256 credit = $.claimableExit[msg.sender][asset];
        if (amount > credit) revert InsufficientExitCredit();
        $.claimableExit[msg.sender][asset] = credit - amount;
        $.totalExitClaimed[asset] = _checkedAdd(
            $.totalExitClaimed[asset],
            amount
        );
        $.totalDistributed[asset] = _checkedAdd(
            $.totalDistributed[asset],
            amount
        );
        IERC20(asset).safeTransfer(recipient, amount);
        emit ExitCreditClaimed(msg.sender, recipient, asset, amount);
    }

    function _networkOutstanding(
        RewardPoolStorage storage $,
        address asset
    ) private view returns (uint256) {
        if (!$.legacyClassified[asset]) {
            return $.totalCollected[asset] - $.totalDistributed[asset];
        }
        return
            $.legacyNetworkLiability[asset] +
            $.newNetworkCollected[asset] -
            $.newNetworkDistributed[asset];
    }

    function _checkedAdd(
        uint256 left,
        uint256 right
    ) private pure returns (uint256 sum) {
        unchecked {
            sum = left + right;
        }
        if (sum < left) revert AccountingOverflow();
    }

    /// @notice Registry used to confirm reward recipients are network relayers.
    function noxRegistry() external view returns (INoxRegistry) {
        return _rewardPool().noxRegistry;
    }

    /// @notice Assets whitelisted for gas payments, blocking griefing/spam tokens.
    function isSupportedAsset(address _asset) external view returns (bool) {
        return _rewardPool().isSupportedAsset[_asset];
    }

    /// @notice Lifetime deposits of an asset; minus totalDistributed this is the committed reward balance.
    function totalCollected(address _asset) external view returns (uint256) {
        return _rewardPool().totalCollected[_asset];
    }

    /// @notice Lifetime payouts of an asset to relayers.
    function totalDistributed(address _asset) external view returns (uint256) {
        return _rewardPool().totalDistributed[_asset];
    }

    function isAssetClassified(address asset) external view returns (bool) {
        return _rewardPool().legacyClassified[asset];
    }

    function networkOutstanding(address asset) external view returns (uint256) {
        RewardPoolStorage storage $ = _rewardPool();
        return _networkOutstanding($, asset);
    }

    function exitOutstanding(address asset) external view returns (uint256) {
        RewardPoolStorage storage $ = _rewardPool();
        return $.totalExitCredited[asset] - $.totalExitClaimed[asset];
    }

    function claimableExit(
        address exit,
        address asset
    ) external view returns (uint256) {
        return _rewardPool().claimableExit[exit][asset];
    }

    function isExecutionSettled(
        bytes32 executionId
    ) external view returns (bool) {
        return _rewardPool().settledExecution[executionId];
    }
}
