// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title KageRegistry
 * @notice Staked registry of kage solver nodes: the orderbook only routes orders to solvers listed here.
 **/
contract KageRegistry is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /// @notice Delay between deregister and unstake; leaving solvers stay slashable.
    uint256 public constant UNSTAKE_COOLDOWN = 1 days;

    enum SolverStatus {
        None,
        Registered,
        InCooldown,
        Deregistered
    }

    struct SolverProfile {
        bytes32 noiseKey;
        uint256 stakedAmount;
        uint256 unlockTime;
        SolverStatus status;
        bool frozen;
    }

    IERC20 public immutable STAKING_TOKEN;
    uint256 public immutable MIN_STAKE;

    mapping(address => SolverProfile) public solvers;
    uint256 public solverCount;

    event SolverRegistered(
        address indexed solver,
        bytes32 noiseKey,
        uint256 stake
    );
    event NoiseKeyUpdated(address indexed solver, bytes32 newNoiseKey);
    event StakeAdded(address indexed solver, uint256 amount);
    event SolverDeregistered(address indexed solver, uint256 unlockTime);
    event CooldownReset(address indexed solver, uint256 unlockTime);
    event Unstaked(address indexed solver, uint256 amount);
    event Slashed(
        address indexed solver,
        uint256 amount,
        address indexed slasher
    );
    event SolverFrozen(address indexed solver, address indexed by);
    event SolverUnfrozen(address indexed solver, address indexed by);

    error ZeroAddress();
    error InvalidKey();
    error InvalidAmount();
    error AlreadyRegistered();
    error NotRegistered();
    error NotInCooldown();
    error InsufficientStake();
    error CooldownNotOver();
    error NothingToSlash();
    error NodeFrozen();
    error AlreadyFrozen();
    error NotFrozen();

    /// @dev Blocks the action while `_solver` is frozen by the slasher.
    modifier notFrozen(address _solver) {
        if (solvers[_solver].frozen) revert NodeFrozen();
        _;
    }

    /// @dev Restricts the action to callers currently registered as solvers.
    modifier onlyRegistered() {
        if (solvers[msg.sender].status != SolverStatus.Registered)
            revert NotRegistered();
        _;
    }

    /// @dev Rejects the zero value as a Noise pubkey.
    modifier validKey(bytes32 _key) {
        if (_key == bytes32(0)) revert InvalidKey();
        _;
    }

    constructor(
        address _stakingToken,
        uint256 _minStake,
        address _admin,
        address _slasher
    ) {
        if (_stakingToken == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();
        if (_slasher == address(0)) revert ZeroAddress();
        if (_minStake == 0) revert InvalidAmount();

        STAKING_TOKEN = IERC20(_stakingToken);
        MIN_STAKE = _minStake;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(SLASHER_ROLE, _slasher);
    }

    /// @dev Pulls _amount from the caller, returning what the contract actually received
    ///      so fee-on-transfer tokens can never make recorded stake exceed the balance.
    function _pullStake(uint256 _amount) private returns (uint256 received) {
        if (_amount == 0) return 0;
        uint256 balanceBefore = STAKING_TOKEN.balanceOf(address(this));
        STAKING_TOKEN.safeTransferFrom(msg.sender, address(this), _amount);
        return STAKING_TOKEN.balanceOf(address(this)) - balanceBefore;
    }

    /// @notice Join instantly with MIN_STAKE total; InCooldown stake counts, cancelling the cooldown.
    function register(
        bytes32 _noiseKey,
        uint256 _stakeAmount
    ) external nonReentrant notFrozen(msg.sender) validKey(_noiseKey) {
        SolverProfile storage profile = solvers[msg.sender];
        if (profile.status == SolverStatus.Registered)
            revert AlreadyRegistered();

        uint256 totalStake = profile.stakedAmount + _pullStake(_stakeAmount);
        if (totalStake < MIN_STAKE) revert InsufficientStake();

        profile.noiseKey = _noiseKey;
        profile.stakedAmount = totalStake;
        profile.unlockTime = 0;
        profile.status = SolverStatus.Registered;
        solverCount++;
        emit SolverRegistered(msg.sender, _noiseKey, totalStake);
    }

    /// @notice Rotate the caller's Noise pubkey.
    function updateNoiseKey(
        bytes32 _newNoiseKey
    ) external onlyRegistered notFrozen(msg.sender) validKey(_newNoiseKey) {
        solvers[msg.sender].noiseKey = _newNoiseKey;
        emit NoiseKeyUpdated(msg.sender, _newNoiseKey);
    }

    /// @notice Top up the caller's stake while registered.
    function addStake(
        uint256 _amount
    ) external nonReentrant onlyRegistered notFrozen(msg.sender) {
        if (_amount == 0) revert InvalidAmount();

        uint256 received = _pullStake(_amount);
        solvers[msg.sender].stakedAmount += received;
        emit StakeAdded(msg.sender, received);
    }

    /// @notice Leave the network immediately; stake stays locked and slashable for the cooldown.
    function deregister() external onlyRegistered notFrozen(msg.sender) {
        SolverProfile storage profile = solvers[msg.sender];
        profile.status = SolverStatus.InCooldown;
        profile.unlockTime = block.timestamp + UNSTAKE_COOLDOWN;
        solverCount--;
        emit SolverDeregistered(msg.sender, profile.unlockTime);
    }

    /// @notice After the cooldown, anyone may release the stake — always to the solver's own address.
    function unstake(address _solver) external nonReentrant notFrozen(_solver) {
        SolverProfile storage profile = solvers[_solver];
        if (profile.status != SolverStatus.InCooldown) revert NotInCooldown();
        if (block.timestamp < profile.unlockTime) revert CooldownNotOver();

        uint256 amount = profile.stakedAmount;
        profile.stakedAmount = 0;
        profile.unlockTime = 0;
        profile.status = SolverStatus.Deregistered;

        if (amount > 0) {
            STAKING_TOKEN.safeTransfer(_solver, amount);
        }
        emit Unstaked(_solver, amount);
    }

    /// @notice Slash stake (registered or in cooldown); dropping below MIN_STAKE forces the cooldown.
    function slash(
        address _solver,
        uint256 _amount
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        SolverProfile storage profile = solvers[_solver];
        if (profile.status == SolverStatus.None) revert NotRegistered();

        uint256 currentStake = profile.stakedAmount;
        uint256 slashAmount = _amount > currentStake ? currentStake : _amount;
        if (slashAmount == 0) revert NothingToSlash();

        uint256 remaining = currentStake - slashAmount;
        profile.stakedAmount = remaining;

        if (
            profile.status == SolverStatus.Registered && remaining < MIN_STAKE
        ) {
            profile.status = SolverStatus.InCooldown;
            profile.unlockTime = block.timestamp + UNSTAKE_COOLDOWN;
            solverCount--;
            emit SolverDeregistered(_solver, profile.unlockTime);
        } else if (profile.status == SolverStatus.InCooldown) {
            profile.unlockTime = block.timestamp + UNSTAKE_COOLDOWN;
            emit CooldownReset(_solver, profile.unlockTime);
        }

        STAKING_TOKEN.safeTransfer(msg.sender, slashAmount);
        emit Slashed(_solver, slashAmount, msg.sender);
    }

    /// @notice Suspend a solver while a slash is pending: not routable, cannot act or unstake. Slasher-only.
    function freeze(address _solver) external onlyRole(SLASHER_ROLE) {
        SolverProfile storage profile = solvers[_solver];
        if (
            profile.status != SolverStatus.Registered &&
            profile.status != SolverStatus.InCooldown
        ) revert NotRegistered();
        if (profile.frozen) revert AlreadyFrozen();
        profile.frozen = true;
        emit SolverFrozen(_solver, msg.sender);
    }

    /// @notice Lift a freeze, restoring the solver's ability to act and unstake. Slasher-only.
    function unfreeze(address _solver) external onlyRole(SLASHER_ROLE) {
        SolverProfile storage profile = solvers[_solver];
        if (!profile.frozen) revert NotFrozen();
        profile.frozen = false;
        emit SolverUnfrozen(_solver, msg.sender);
    }

    /// @notice True only for a solver currently in the network and not frozen.
    function isActiveSolver(address _solver) external view returns (bool) {
        SolverProfile storage profile = solvers[_solver];
        return profile.status == SolverStatus.Registered && !profile.frozen;
    }
}
