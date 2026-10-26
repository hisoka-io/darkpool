// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
// solhint-disable-next-line max-line-length
import {AccessControlDefaultAdminRulesUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IKageRegistry} from "./IKageRegistry.sol";

/**
 * @title KageRegistry
 * @notice Staked Kage solvers. Each solver id has a cold owner (stake, exit, key rotation) and a hot signer that
 *         approves settlements. Stake is one ERC20 fixed at initialize, in that token's base units.
 * @dev UUPS proxy over an ERC-7201 namespace. Every settlement reads `settlementSigner` at execution time, so
 *      rotation, exit, freeze and slashing take effect from the block they land; nothing is grandfathered.
 */
contract KageRegistry is
    IKageRegistry,
    Initializable,
    UUPSUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;

    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 public constant MIN_EXIT_DELAY = 1 days;

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    enum SolverStatus {
        None,
        Active,
        Exiting,
        Exited
    }

    /// @dev Two slots: owner, status, frozen, unlockTime | signer, stake.
    struct Solver {
        address owner;
        SolverStatus status;
        bool frozen;
        uint64 unlockTime;
        address signer;
        uint96 stake;
    }

    /// @custom:storage-location erc7201:hisoka.kage.registry
    struct RegistryStorage {
        IERC20 stakingToken;
        // Fixed at initialize: a dust minimum stake would make solver ids free to mint.
        uint256 minStakeFloor;
        uint256 minStake;
        uint256 exitDelay;
        uint256 solverCount;
        mapping(uint256 => Solver) solvers;
    }

    /// @dev Inlined on OZ's canonical namespace; contracts-upgradeable 5.6.1 dropped ReentrancyGuardUpgradeable.
    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyStorage {
        uint256 status;
    }

    // keccak256(abi.encode(uint256(keccak256("hisoka.kage.registry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REGISTRY_LOCATION =
        0x102b9fa007d4c73faa68f63651f6c057c7e7cb4c5454c9575e84d8c78e4a1b00;
    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REENTRANCY_LOCATION =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    struct InitParams {
        uint48 initialAdminDelay;
        address initialAdmin;
        address stakingToken;
        uint256 minStake;
        uint256 minStakeFloor;
        uint256 exitDelay;
        address slasher;
        address configManager;
        address upgrader;
    }

    event SolverRegistered(
        uint256 indexed solverId,
        address indexed owner,
        address indexed signer,
        uint256 stake
    );
    event SignerRotated(
        uint256 indexed solverId,
        address indexed oldSigner,
        address indexed newSigner
    );
    event StakeAdded(uint256 indexed solverId, uint256 amount);
    event ExitRequested(uint256 indexed solverId, uint256 unlockTime);
    event ExitCancelled(uint256 indexed solverId);
    event Unstaked(
        uint256 indexed solverId,
        address indexed owner,
        uint256 amount
    );
    event Slashed(uint256 indexed solverId, uint256 amount, address slasher);
    event SolverFrozen(uint256 indexed solverId, address by);
    event SolverUnfrozen(uint256 indexed solverId, address by);
    event ConfigUpdated(uint256 minStake, uint256 exitDelay);

    error ZeroAddress();
    error InvalidAmount();
    error InvalidDelay();
    error MinStakeBelowFloor();
    error InsufficientStake();
    error FeeOnTransferUnsupported();
    error NotSolverOwner(uint256 solverId);
    error SolverNotActive(uint256 solverId);
    error SolverNotExiting(uint256 solverId);
    error SolverNotRegistered(uint256 solverId);
    error SolverIsFrozen(uint256 solverId);
    error SolverNotFrozen(uint256 solverId);
    error SignerUnchanged();
    error ExitTooEarly(uint256 unlockTime);
    error NothingToSlash();
    error ReentrancyGuardReentrantCall();

    modifier nonReentrant() {
        ReentrancyStorage storage $ = _reentrancyStorage();
        if ($.status == ENTERED) revert ReentrancyGuardReentrantCall();
        $.status = ENTERED;
        _;
        $.status = NOT_ENTERED;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice One-time proxy init. Roles go to the passed-in governance addresses, never msg.sender. Stake
    ///         amounts are in the staking token's base units (6 decimals for USDC, 18 for WETH).
    function initialize(InitParams calldata p) external initializer {
        if (
            p.initialAdmin == address(0) ||
            p.stakingToken == address(0) ||
            p.slasher == address(0) ||
            p.configManager == address(0) ||
            p.upgrader == address(0)
        ) revert ZeroAddress();
        if (p.minStakeFloor == 0) revert InvalidAmount();
        if (p.minStake < p.minStakeFloor) revert MinStakeBelowFloor();
        if (p.exitDelay < MIN_EXIT_DELAY) revert InvalidDelay();

        __AccessControlDefaultAdminRules_init(
            p.initialAdminDelay,
            p.initialAdmin
        );
        __Pausable_init();
        _reentrancyStorage().status = NOT_ENTERED;

        _grantRole(CONFIG_ROLE, p.configManager);
        _grantRole(SLASHER_ROLE, p.slasher);
        _grantRole(UPGRADER_ROLE, p.upgrader);

        RegistryStorage storage $ = _registry();
        $.stakingToken = IERC20(p.stakingToken);
        $.minStakeFloor = p.minStakeFloor;
        $.minStake = p.minStake;
        $.exitDelay = p.exitDelay;
    }

    // solhint-disable no-empty-blocks
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
    // solhint-enable no-empty-blocks

    /// @notice Stake `amount` and open a new solver id owned by the caller, settling through `signer`.
    function register(
        address signer,
        uint256 amount
    ) external nonReentrant whenNotPaused returns (uint256 solverId) {
        RegistryStorage storage $ = _registry();
        if (signer == address(0)) revert ZeroAddress();
        if (amount < $.minStake) revert InsufficientStake();
        uint96 stake = SafeCast.toUint96(amount);
        _pullExact($.stakingToken, amount);

        solverId = ++$.solverCount;
        $.solvers[solverId] = Solver({
            owner: msg.sender,
            status: SolverStatus.Active,
            frozen: false,
            unlockTime: 0,
            signer: signer,
            stake: stake
        });
        emit SolverRegistered(solverId, msg.sender, signer, amount);
    }

    /// @notice Replace the settlement key. Pause-exempt and allowed while frozen or exiting: it is how a leaked
    ///         hot key is revoked. Approvals by the old key stop working in the same block.
    function rotateSigner(uint256 solverId, address newSigner) external {
        Solver storage s = _ownedSolver(solverId);
        if (s.status != SolverStatus.Active && s.status != SolverStatus.Exiting)
            revert SolverNotRegistered(solverId);
        if (newSigner == address(0)) revert ZeroAddress();
        address oldSigner = s.signer;
        if (newSigner == oldSigner) revert SignerUnchanged();
        s.signer = newSigner;
        emit SignerRotated(solverId, oldSigner, newSigner);
    }

    /// @notice Top up an active, unfrozen solver's stake.
    function addStake(
        uint256 solverId,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        Solver storage s = _ownedSolver(solverId);
        if (s.status != SolverStatus.Active) revert SolverNotActive(solverId);
        if (s.frozen) revert SolverIsFrozen(solverId);
        if (amount == 0) revert InvalidAmount();
        uint96 stake = SafeCast.toUint96(uint256(s.stake) + amount);
        _pullExact(_registry().stakingToken, amount);
        s.stake = stake;
        emit StakeAdded(solverId, amount);
    }

    /// @notice Stop settling and start the exit delay. The stake stays slashable until `withdrawStake`.
    function requestExit(uint256 solverId) external whenNotPaused {
        Solver storage s = _ownedSolver(solverId);
        if (s.status != SolverStatus.Active) revert SolverNotActive(solverId);
        if (s.frozen) revert SolverIsFrozen(solverId);
        uint64 unlockTime = SafeCast.toUint64(
            block.timestamp + _registry().exitDelay
        );
        s.status = SolverStatus.Exiting;
        s.unlockTime = unlockTime;
        emit ExitRequested(solverId, unlockTime);
    }

    /// @notice Abort a pending exit; the solver can settle again from this block.
    function cancelExit(uint256 solverId) external whenNotPaused {
        Solver storage s = _ownedSolver(solverId);
        if (s.status != SolverStatus.Exiting) revert SolverNotExiting(solverId);
        if (s.frozen) revert SolverIsFrozen(solverId);
        s.status = SolverStatus.Active;
        s.unlockTime = 0;
        emit ExitCancelled(solverId);
    }

    /// @notice Pay a matured exit's stake to the owner. Anyone may call; pause-exempt so honest stake is never
    ///         trapped by a halt.
    function withdrawStake(uint256 solverId) external nonReentrant {
        Solver storage s = _registry().solvers[solverId];
        if (s.status != SolverStatus.Exiting) revert SolverNotExiting(solverId);
        if (s.frozen) revert SolverIsFrozen(solverId);
        if (block.timestamp < s.unlockTime) revert ExitTooEarly(s.unlockTime);

        uint256 amount = s.stake;
        address solverOwner = s.owner;
        s.status = SolverStatus.Exited;
        s.stake = 0;
        if (amount > 0)
            _registry().stakingToken.safeTransfer(solverOwner, amount);
        emit Unstaked(solverId, solverOwner, amount);
    }

    /// @notice Block a solver from settling, exiting or withdrawing while evidence is reviewed.
    function freeze(uint256 solverId) external onlyRole(SLASHER_ROLE) {
        Solver storage s = _registeredSolver(solverId);
        if (s.frozen) revert SolverIsFrozen(solverId);
        s.frozen = true;
        emit SolverFrozen(solverId, msg.sender);
    }

    /// @notice Lift a freeze.
    function unfreeze(uint256 solverId) external onlyRole(SLASHER_ROLE) {
        Solver storage s = _registeredSolver(solverId);
        if (!s.frozen) revert SolverNotFrozen(solverId);
        s.frozen = false;
        emit SolverUnfrozen(solverId, msg.sender);
    }

    /// @notice Take up to `amount` of a solver's stake to the slasher. An exiting solver's delay restarts, so
    ///         a slash cannot be raced by a withdrawal. A solver left below `minStake` cannot settle until it
    ///         tops up.
    function slash(
        uint256 solverId,
        uint256 amount
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        Solver storage s = _registeredSolver(solverId);
        uint256 current = s.stake;
        uint256 taken = amount > current ? current : amount;
        if (taken == 0) revert NothingToSlash();
        s.stake = SafeCast.toUint96(current - taken);
        if (s.status == SolverStatus.Exiting) {
            s.unlockTime = SafeCast.toUint64(
                block.timestamp + _registry().exitDelay
            );
        }
        _registry().stakingToken.safeTransfer(msg.sender, taken);
        emit Slashed(solverId, taken, msg.sender);
    }

    /// @notice Change the minimum stake and exit delay; existing stakes are not touched, and a solver below a
    ///         raised minimum stops settling until it tops up.
    function updateConfig(
        uint256 newMinStake,
        uint256 newExitDelay
    ) external onlyRole(CONFIG_ROLE) {
        RegistryStorage storage $ = _registry();
        if (newMinStake < $.minStakeFloor) revert MinStakeBelowFloor();
        if (newExitDelay < MIN_EXIT_DELAY) revert InvalidDelay();
        $.minStake = newMinStake;
        $.exitDelay = newExitDelay;
        emit ConfigUpdated(newMinStake, newExitDelay);
    }

    /// @notice Halt registration, top-ups and exit requests. Rotation, withdrawal, freeze and slash stay open.
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Resume the paused lifecycle calls.
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @inheritdoc IKageRegistry
    function settlementSigner(
        uint256 solverId
    ) external view returns (address) {
        RegistryStorage storage $ = _registry();
        Solver storage s = $.solvers[solverId];
        if (s.status != SolverStatus.Active || s.frozen || s.stake < $.minStake)
            return address(0);
        return s.signer;
    }

    /// @notice The full record of `solverId` (all zero for an unissued id).
    function solver(uint256 solverId) external view returns (Solver memory) {
        return _registry().solvers[solverId];
    }

    function stakingToken() external view returns (IERC20) {
        return _registry().stakingToken;
    }

    function minStakeFloor() external view returns (uint256) {
        return _registry().minStakeFloor;
    }

    function minStake() external view returns (uint256) {
        return _registry().minStake;
    }

    function exitDelay() external view returns (uint256) {
        return _registry().exitDelay;
    }

    /// @notice Number of solver ids issued; ids run from 1 to this value.
    function solverCount() external view returns (uint256) {
        return _registry().solverCount;
    }

    /// @dev Credits exactly `amount` or reverts, so a fee-on-transfer token can never overstate a stake.
    function _pullExact(IERC20 token, uint256 amount) private {
        uint256 before = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        if (token.balanceOf(address(this)) - before != amount)
            revert FeeOnTransferUnsupported();
    }

    function _ownedSolver(
        uint256 solverId
    ) private view returns (Solver storage s) {
        s = _registry().solvers[solverId];
        if (s.owner != msg.sender) revert NotSolverOwner(solverId);
    }

    function _registeredSolver(
        uint256 solverId
    ) private view returns (Solver storage s) {
        s = _registry().solvers[solverId];
        if (s.status != SolverStatus.Active && s.status != SolverStatus.Exiting)
            revert SolverNotRegistered(solverId);
    }

    function _registry() private pure returns (RegistryStorage storage $) {
        assembly {
            $.slot := REGISTRY_LOCATION
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
}
