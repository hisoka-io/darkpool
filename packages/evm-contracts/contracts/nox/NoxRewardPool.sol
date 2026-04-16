// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {
    ReentrancyGuard
} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title NoxRewardPool
 * @author Hisoka Protocol
 * @notice The centralized treasury for the NOX Relayer Network (v0).
 * @dev Collects gas fees (ERC20) and distributes them to Relayers based on work performed.
 *      This contract acts as a stateless escrow: it collects, holds, and distributes.
 *      Distribution logic is determined off-chain by the Distributor.
 */
contract NoxRewardPool is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // --- ROLES ---

    /// @notice Role allowed to trigger reward distributions
    bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");

    /// @notice Role for asset whitelist and emergency controls
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    // --- STATE ---

    /// @notice Whitelisted assets (e.g., WETH, USDC) allowed for gas payments.
    /// @dev Prevents users from paying in griefing/spam tokens.
    mapping(address => bool) public isSupportedAsset;

    /// @notice Total amount collected per asset (Accounting).
    mapping(address => uint256) public totalCollected;

    /// @notice Total amount distributed per asset (Historical accounting).
    mapping(address => uint256) public totalDistributed;

    // --- EVENTS ---

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

    // --- ERRORS ---

    error InvalidAsset();
    error AssetNotSupported();
    error ArrayLengthMismatch();
    error ZeroAddress();
    error ZeroAmount();
    error TransferFailed();

    /**
     * @param _admin The initial admin and distributor.
     */
    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(DISTRIBUTOR_ROLE, _admin);
    }

    // --- CONFIGURATION ---

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

    // --- INFLOW (DEPOSIT) ---

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

        totalCollected[_asset] += _amount;
        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _amount);

        emit RewardsDeposited(_asset, msg.sender, _amount);
    }

    // --- OUTFLOW (DISTRIBUTION) ---

    /**
     * @notice Distributes accumulated fees to a list of relayers.
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
            uint256 amount = _amounts[i];

            if (to == address(0)) revert ZeroAddress();
            if (amount > 0) {
                IERC20(_asset).safeTransfer(to, amount);
                batchTotal += amount;
            }
        }

        totalDistributed[_asset] += batchTotal;

        emit RewardsDistributed(_asset, batchTotal, _recipients.length);
    }

    // --- EMERGENCY ---

    /**
     * @notice Rescues tokens sent to this contract by mistake, or drains pool in emergency.
     * @dev Can act on any asset, whitelisted or not. Bypass Paused state.
     */
    function rescueFunds(
        address _asset,
        address _to,
        uint256 _amount
    ) external nonReentrant onlyRole(ADMIN_ROLE) {
        if (_to == address(0)) revert ZeroAddress();
        if (_amount == 0) revert ZeroAmount();

        IERC20(_asset).safeTransfer(_to, _amount);
        emit FundsRescued(_asset, _to, _amount);
    }
}
