// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
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
 *      computed off-chain by the Distributor.
 */
contract NoxRewardPool is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Registry used to confirm reward recipients are network relayers.
    INoxRegistry public immutable noxRegistry;

    /// @notice Assets whitelisted for gas payments, blocking griefing/spam tokens.
    mapping(address => bool) public isSupportedAsset;

    mapping(address => uint256) public totalCollected;

    mapping(address => uint256) public totalDistributed;

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
    error TransferFailed();
    error InsufficientCollected();
    error RecipientNotRegistered();
    error ExceedsRescuableBalance();
    error FeeOnTransferUnsupported();

    /**
     * @param _admin The initial admin and distributor.
     * @param _noxRegistry The relayer registry; recipients must be registered relayers.
     */
    constructor(address _admin, address _noxRegistry) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_noxRegistry == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(DISTRIBUTOR_ROLE, _admin);

        noxRegistry = INoxRegistry(_noxRegistry);
    }

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
        isSupportedAsset[_asset] = _status;
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
        if (!isSupportedAsset[_asset]) revert AssetNotSupported();

        uint256 bal0 = IERC20(_asset).balanceOf(address(this));
        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _amount);
        if (IERC20(_asset).balanceOf(address(this)) - bal0 != _amount)
            revert FeeOnTransferUnsupported();

        totalCollected[_asset] += _amount;

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
        if (!isSupportedAsset[_asset]) revert AssetNotSupported();
        if (_recipients.length != _amounts.length) revert ArrayLengthMismatch();
        if (_recipients.length == 0) revert ArrayLengthMismatch();

        uint256 batchTotal = 0;
        for (uint256 i = 0; i < _recipients.length; i++) {
            address to = _recipients[i];
            if (to == address(0)) revert ZeroAddress();
            if (!noxRegistry.isActiveRelayer(to))
                revert RecipientNotRegistered();
            batchTotal += _amounts[i];
        }

        if (batchTotal > totalCollected[_asset] - totalDistributed[_asset])
            revert InsufficientCollected();
        totalDistributed[_asset] += batchTotal;

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

        uint256 committed = totalCollected[_asset] - totalDistributed[_asset];
        uint256 liveBalance = IERC20(_asset).balanceOf(address(this));
        uint256 free = liveBalance > committed ? liveBalance - committed : 0;
        if (_amount > free) revert ExceedsRescuableBalance();

        IERC20(_asset).safeTransfer(_to, _amount);
        emit FundsRescued(_asset, _to, _amount);
    }
}
