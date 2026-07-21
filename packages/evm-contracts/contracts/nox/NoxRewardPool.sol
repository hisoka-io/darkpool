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
 * @author Hisoka Protocol
 * @notice The centralized treasury for the NOX Relayer Network.
 * @dev Escrow that collects ERC20 gas fees and distributes them to relayers; the split is
 *      computed off-chain by the Distributor. UUPS proxy: all mutable state lives in an ERC-7201
 *      namespace; the registry link is set in initialize (never zero under the proxy). Upgrades
 *      gated by UPGRADER_ROLE.
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

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /// @custom:storage-location erc7201:hisoka.nox.rewardpool
    struct RewardPoolStorage {
        INoxRegistry noxRegistry;
        mapping(address => bool) isSupportedAsset;
        mapping(address => uint256) totalCollected;
        mapping(address => uint256) totalDistributed;
    }

    /// @dev Inlined upgradeable reentrancy guard against OZ's canonical namespace; contracts-upgradeable
    /// 5.6.1 dropped ReentrancyGuardUpgradeable once the base became stateless.
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

    /**
     * @notice One-time proxy initialization. Grants roles to the passed-in governance addresses
     *         (never msg.sender) and links the relayer registry. Callable exactly once.
     */
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

        _rewardPool().noxRegistry = INoxRegistry(p.noxRegistry);
    }

    // solhint-disable no-empty-blocks
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
    // solhint-enable no-empty-blocks

    /**
     * @notice Toggle support for a gas token (e.g., USDC, WETH).
     * @dev Only ERC20s allowed. No raw ETH.
     * @param _asset The ERC20 token address.
     * @param _status True to enable, False to disable.
     */
    function setAssetStatus(
        address _asset,
        bool _status
    ) external onlyRole(ADMIN_ROLE) {
        if (_asset == address(0)) revert ZeroAddress();
        _rewardPool().isSupportedAsset[_asset] = _status;
        emit AssetStatusChanged(_asset, _status);
    }

    /**
     * @notice Emergency pause for distributions/deposits.
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause operations.
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Accepts gas payments from DarkPool or Users.
     * @param _asset The ERC20 token address.
     * @param _amount The amount to deposit.
     */
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

        $.totalCollected[_asset] += _amount;

        emit RewardsDeposited(_asset, msg.sender, _amount);
    }

    /**
     * @notice Distributes accumulated fees to a list of relayers.
     * @dev Recipients must be registered relayers. Checks-effects-interactions: solvency is verified and
     *      accounting updated before any transfer.
     * @param _asset The ERC20 token to distribute (must be whitelisted).
     * @param _recipients Array of relayer addresses.
     * @param _amounts Array of amounts to send.
     */
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
            batchTotal += _amounts[i];
        }

        if (batchTotal > $.totalCollected[_asset] - $.totalDistributed[_asset])
            revert InsufficientCollected();
        $.totalDistributed[_asset] += batchTotal;

        for (uint256 i = 0; i < _recipients.length; i++) {
            if (_amounts[i] > 0) {
                IERC20(_asset).safeTransfer(_recipients[i], _amounts[i]);
            }
        }

        emit RewardsDistributed(_asset, batchTotal, _recipients.length);
    }

    /// @notice Rescue tokens that are not owed to relayers. Committed rewards (collected minus
    ///         distributed) are never rescuable regardless of the whitelist flag; only the free surplus is.
    function rescueFunds(
        address _asset,
        address _to,
        uint256 _amount
    ) external nonReentrant onlyRole(ADMIN_ROLE) {
        if (_to == address(0)) revert ZeroAddress();
        if (_amount == 0) revert ZeroAmount();

        RewardPoolStorage storage $ = _rewardPool();
        uint256 committed = $.totalCollected[_asset] -
            $.totalDistributed[_asset];
        uint256 liveBalance = IERC20(_asset).balanceOf(address(this));
        uint256 free = liveBalance > committed ? liveBalance - committed : 0;
        if (_amount > free) revert ExceedsRescuableBalance();

        IERC20(_asset).safeTransfer(_to, _amount);
        emit FundsRescued(_asset, _to, _amount);
    }

    /// @notice Registry used to confirm reward recipients are network relayers.
    function noxRegistry() external view returns (INoxRegistry) {
        return _rewardPool().noxRegistry;
    }

    /// @notice Assets whitelisted for gas payments, blocking griefing/spam tokens.
    function isSupportedAsset(address _asset) external view returns (bool) {
        return _rewardPool().isSupportedAsset[_asset];
    }

    function totalCollected(address _asset) external view returns (uint256) {
        return _rewardPool().totalCollected[_asset];
    }

    function totalDistributed(address _asset) external view returns (uint256) {
        return _rewardPool().totalDistributed[_asset];
    }
}
