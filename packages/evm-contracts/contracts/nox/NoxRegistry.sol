// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title NoxRegistry
 * @author Hisoka Protocol
 * @notice The "Phonebook" for the NOX Mixnet: staked community relayers plus an admin whitelist
 *         for bootstrap, with admin removal of bad actors.
 * @dev UUPS proxy: all mutable state lives in an ERC-7201 namespace so a config field can be appended
 *      without shifting existing slots. Config (stakingToken, minStake, unstakeDelay, minStakeFloor)
 *      is set in initialize, so under the proxy it is never zero. Upgrades gated by UPGRADER_ROLE.
 */
contract NoxRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;

    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Lifecycle phase of a registered node. None == not registered.
    enum RelayerStatus {
        None,
        Registered,
        Unstaking
    }

    struct RelayerProfile {
        bytes32 sphinxKey;
        string url;
        string ingressUrl;
        string metadataUrl;
        uint256 stakedAmount;
        uint256 unlockTime;
        bool isRegistered;
        RelayerStatus status;
        bool frozen;
    }

    uint8 public constant ROLE_RELAY = 1;
    uint8 public constant ROLE_EXIT = 2;
    uint8 public constant ROLE_FULL = 3;

    uint256 public constant MIN_UNSTAKE_DELAY = 1 days;

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /// @custom:storage-location erc7201:hisoka.nox.registry
    struct RegistryStorage {
        IERC20 stakingToken;
        uint256 minStakeFloor;
        uint256 minStakeAmount;
        uint256 unstakeDelay;
        uint256 relayerCount;
        bytes32 topologyFingerprint;
        mapping(address => RelayerProfile) relayers;
        mapping(address => uint8) nodeRoles;
        mapping(bytes32 => address) sphinxKeyOwner;
    }

    /// @dev Inlined upgradeable reentrancy guard against OZ's canonical namespace; contracts-upgradeable
    /// 5.6.1 dropped ReentrancyGuardUpgradeable once the base became stateless.
    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyStorage {
        uint256 status;
    }

    // keccak256(abi.encode(uint256(keccak256("hisoka.nox.registry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REGISTRY_LOCATION =
        0xe2348d1bc3620e4f532594e661dc0600650faeb9b23105efb1d75c3e0e027400;
    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REENTRANCY_LOCATION =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

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

    modifier nonReentrant() {
        ReentrancyStorage storage $ = _reentrancyStorage();
        if ($.status == ENTERED) revert ReentrancyGuardReentrantCall();
        $.status = ENTERED;
        _;
        $.status = NOT_ENTERED;
    }

    event RelayerRegistered(
        address indexed relayer,
        bytes32 sphinxKey,
        string url,
        string ingressUrl,
        string metadataUrl,
        uint256 stake,
        uint8 nodeRole
    );
    event PrivilegedRelayerRegistered(
        address indexed relayer,
        bytes32 sphinxKey,
        string url,
        string ingressUrl,
        string metadataUrl,
        uint8 nodeRole
    );
    event RelayerUpdated(address indexed relayer, string newUrl);
    event IngressUrlUpdated(address indexed relayer, string newIngressUrl);
    event MetadataUrlUpdated(address indexed relayer, string newMetadataUrl);
    event KeyRotated(address indexed relayer, bytes32 newSphinxKey);
    event StakeAdded(address indexed relayer, uint256 amount);
    event UnstakeRequested(address indexed relayer, uint256 unlockTime);
    event UnstakeCancelled(address indexed relayer);
    event Unstaked(address indexed relayer, uint256 amount);
    event Slashed(
        address indexed relayer,
        uint256 amount,
        address indexed slasher
    );
    event RelayerFrozen(address indexed relayer, address indexed by);
    event RelayerUnfrozen(address indexed relayer, address indexed by);
    event RelayerRemoved(address indexed relayer, address indexed by);
    event RoleUpdated(address indexed relayer, uint8 newRole);
    event ConfigUpdated(uint256 newMinStake, uint256 newUnstakeDelay);
    event TopologyFingerprintUpdated(
        bytes32 indexed newFingerprint,
        bytes32 indexed prevFingerprint
    );

    error ZeroAddress();
    error InvalidKey();
    error DuplicateKey();
    error InvalidAmount();
    error InvalidDelay();
    error AlreadyRegistered();
    error NotRegistered();
    error InsufficientStake();
    error MinStakeBelowFloor();
    error UnstakeAlreadyRequested();
    error NotUnstaking();
    error UnstakeTooEarly();
    error NodeFrozen();
    error AlreadyFrozen();
    error NotFrozen();
    error NothingToSlash();
    error NotUnderCollateralized();
    error EmptyString();
    error InvalidRole();
    error ReentrancyGuardReentrantCall();

    struct InitParams {
        uint48 initialAdminDelay;
        address initialAdmin;
        address stakingToken;
        uint256 minStake;
        uint256 unstakeDelay;
        uint256 minStakeFloor;
        address slasher;
        address configManager;
        address upgrader;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice One-time proxy initialization. Grants roles to the passed-in governance addresses
     *         (never msg.sender) and sets the staking config. Callable exactly once.
     */
    function initialize(InitParams calldata p) external initializer {
        if (p.initialAdmin == address(0)) revert ZeroAddress();
        if (p.stakingToken == address(0)) revert ZeroAddress();
        if (p.slasher == address(0)) revert ZeroAddress();
        if (p.configManager == address(0)) revert ZeroAddress();
        if (p.upgrader == address(0)) revert ZeroAddress();
        if (p.unstakeDelay < MIN_UNSTAKE_DELAY) revert InvalidDelay();
        if (p.minStakeFloor == 0) revert InvalidAmount();
        if (p.minStake < p.minStakeFloor) revert MinStakeBelowFloor();

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
        $.minStakeAmount = p.minStake;
        $.unstakeDelay = p.unstakeDelay;

        // XOR identity: empty set = bytes32(0). No genesis hash needed.
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /// @dev Self-inverse: XOR to add a node, XOR again to remove it.
    function _xorAddressIntoFingerprint(address nodeAddress) private {
        RegistryStorage storage $ = _registry();
        bytes32 prevFingerprint = $.topologyFingerprint;
        $.topologyFingerprint =
            prevFingerprint ^
            keccak256(abi.encodePacked(nodeAddress));
        emit TopologyFingerprintUpdated($.topologyFingerprint, prevFingerprint);
    }

    /// @dev Clears all node state; stake handling (return vs burn) is the caller's responsibility.
    function _removeRelayer(address _relayer, bytes32 _sphinxKey) private {
        RegistryStorage storage $ = _registry();
        delete $.sphinxKeyOwner[_sphinxKey];
        delete $.relayers[_relayer];
        delete $.nodeRoles[_relayer];
        $.relayerCount--;
        _xorAddressIntoFingerprint(_relayer);
    }

    function register(
        bytes32 _sphinxKey,
        string calldata _url,
        string calldata _ingressUrl,
        string calldata _metadataUrl,
        uint256 _stakeAmount,
        uint8 _nodeRole
    ) external nonReentrant whenNotPaused {
        RegistryStorage storage $ = _registry();
        if ($.relayers[msg.sender].isRegistered) revert AlreadyRegistered();
        if (_stakeAmount < $.minStakeAmount) revert InsufficientStake();
        if (bytes(_url).length == 0) revert EmptyString();
        if (_sphinxKey == bytes32(0)) revert InvalidKey();
        if ($.sphinxKeyOwner[_sphinxKey] != address(0)) revert DuplicateKey();
        if (_nodeRole < ROLE_RELAY || _nodeRole > ROLE_FULL)
            revert InvalidRole();

        $.stakingToken.safeTransferFrom(
            msg.sender,
            address(this),
            _stakeAmount
        );

        $.relayers[msg.sender] = RelayerProfile({
            sphinxKey: _sphinxKey,
            url: _url,
            ingressUrl: _ingressUrl,
            metadataUrl: _metadataUrl,
            stakedAmount: _stakeAmount,
            unlockTime: 0,
            isRegistered: true,
            status: RelayerStatus.Registered,
            frozen: false
        });
        $.sphinxKeyOwner[_sphinxKey] = msg.sender;
        $.nodeRoles[msg.sender] = _nodeRole;

        $.relayerCount++;
        _xorAddressIntoFingerprint(msg.sender);
        emit RelayerRegistered(
            msg.sender,
            _sphinxKey,
            _url,
            _ingressUrl,
            _metadataUrl,
            _stakeAmount,
            _nodeRole
        );
    }

    /**
     * @notice Bootstrap the network with trusted nodes (no stake required).
     * @dev Zero-stake nodes cannot be financially slashed; remove them with forceUnregister().
     */
    function registerPrivileged(
        address _relayer,
        bytes32 _sphinxKey,
        string calldata _url,
        string calldata _ingressUrl,
        string calldata _metadataUrl,
        uint8 _nodeRole
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        RegistryStorage storage $ = _registry();
        if ($.relayers[_relayer].isRegistered) revert AlreadyRegistered();
        if (_relayer == address(0)) revert ZeroAddress();
        if (bytes(_url).length == 0) revert EmptyString();
        if (_sphinxKey == bytes32(0)) revert InvalidKey();
        if ($.sphinxKeyOwner[_sphinxKey] != address(0)) revert DuplicateKey();
        if (_nodeRole < ROLE_RELAY || _nodeRole > ROLE_FULL)
            revert InvalidRole();

        $.relayers[_relayer] = RelayerProfile({
            sphinxKey: _sphinxKey,
            url: _url,
            ingressUrl: _ingressUrl,
            metadataUrl: _metadataUrl,
            stakedAmount: 0,
            unlockTime: 0,
            isRegistered: true,
            status: RelayerStatus.Registered,
            frozen: false
        });
        $.sphinxKeyOwner[_sphinxKey] = _relayer;
        $.nodeRoles[_relayer] = _nodeRole;

        $.relayerCount++;
        _xorAddressIntoFingerprint(_relayer);
        emit PrivilegedRelayerRegistered(
            _relayer,
            _sphinxKey,
            _url,
            _ingressUrl,
            _metadataUrl,
            _nodeRole
        );
    }

    function updateUrl(string calldata _newUrl) external {
        RegistryStorage storage $ = _registry();
        if (!$.relayers[msg.sender].isRegistered) revert NotRegistered();
        if (bytes(_newUrl).length == 0) revert EmptyString();
        $.relayers[msg.sender].url = _newUrl;
        emit RelayerUpdated(msg.sender, _newUrl);
    }

    function updateIngressUrl(string calldata _newIngressUrl) external {
        RegistryStorage storage $ = _registry();
        if (!$.relayers[msg.sender].isRegistered) revert NotRegistered();
        $.relayers[msg.sender].ingressUrl = _newIngressUrl;
        emit IngressUrlUpdated(msg.sender, _newIngressUrl);
    }

    function updateMetadataUrl(string calldata _newMetadataUrl) external {
        RegistryStorage storage $ = _registry();
        if (!$.relayers[msg.sender].isRegistered) revert NotRegistered();
        $.relayers[msg.sender].metadataUrl = _newMetadataUrl;
        emit MetadataUrlUpdated(msg.sender, _newMetadataUrl);
    }

    function updateRole(uint8 _newRole) external whenNotPaused {
        RegistryStorage storage $ = _registry();
        if (!$.relayers[msg.sender].isRegistered) revert NotRegistered();
        if (_newRole < ROLE_RELAY || _newRole > ROLE_FULL) revert InvalidRole();
        $.nodeRoles[msg.sender] = _newRole;
        emit RoleUpdated(msg.sender, _newRole);
    }

    function rotateKey(bytes32 _newSphinxKey) external whenNotPaused {
        RegistryStorage storage $ = _registry();
        if (!$.relayers[msg.sender].isRegistered) revert NotRegistered();
        if (_newSphinxKey == bytes32(0)) revert InvalidKey();
        if ($.sphinxKeyOwner[_newSphinxKey] != address(0))
            revert DuplicateKey();

        delete $.sphinxKeyOwner[$.relayers[msg.sender].sphinxKey];
        $.sphinxKeyOwner[_newSphinxKey] = msg.sender;
        $.relayers[msg.sender].sphinxKey = _newSphinxKey;
        emit KeyRotated(msg.sender, _newSphinxKey);
    }

    function addStake(uint256 _amount) external nonReentrant whenNotPaused {
        RegistryStorage storage $ = _registry();
        RelayerProfile storage profile = $.relayers[msg.sender];
        if (!profile.isRegistered) revert NotRegistered();
        if (_amount == 0) revert InvalidAmount();
        if (profile.status != RelayerStatus.Registered)
            revert UnstakeAlreadyRequested();

        $.stakingToken.safeTransferFrom(msg.sender, address(this), _amount);
        profile.stakedAmount += _amount;
        emit StakeAdded(msg.sender, _amount);
    }

    /// @notice Begin the unstake cooldown. The node STAYS registered and slashable until it exits;
    ///         routing may stop off-chain, but its stake remains locked and slashable for the whole delay.
    function requestUnstake() external whenNotPaused {
        RegistryStorage storage $ = _registry();
        RelayerProfile storage profile = $.relayers[msg.sender];
        if (!profile.isRegistered) revert NotRegistered();
        if (profile.status != RelayerStatus.Registered)
            revert UnstakeAlreadyRequested();

        profile.status = RelayerStatus.Unstaking;
        profile.unlockTime = block.timestamp + $.unstakeDelay;
        emit UnstakeRequested(msg.sender, profile.unlockTime);
    }

    /// @notice Abort a pending unstake and return to active. Blocked while a slasher freeze is in effect.
    function cancelUnstake() external whenNotPaused {
        RegistryStorage storage $ = _registry();
        RelayerProfile storage profile = $.relayers[msg.sender];
        if (!profile.isRegistered) revert NotRegistered();
        if (profile.status != RelayerStatus.Unstaking) revert NotUnstaking();
        if (profile.frozen) revert NodeFrozen();

        profile.status = RelayerStatus.Registered;
        profile.unlockTime = 0;
        emit UnstakeCancelled(msg.sender);
    }

    /// @notice Complete a matured unstake and reclaim stake. A slasher freeze blocks this so a flagged
    ///         node cannot exit past a live investigation. Pause-exempt so honest stake is never trapped.
    function executeUnstake() external nonReentrant {
        RegistryStorage storage $ = _registry();
        RelayerProfile storage profile = $.relayers[msg.sender];
        if (!profile.isRegistered) revert NotRegistered();
        if (profile.status != RelayerStatus.Unstaking) revert NotUnstaking();
        if (profile.frozen) revert NodeFrozen();
        if (block.timestamp < profile.unlockTime) revert UnstakeTooEarly();

        uint256 amount = profile.stakedAmount;
        _removeRelayer(msg.sender, profile.sphinxKey);

        if (amount > 0) {
            $.stakingToken.safeTransfer(msg.sender, amount);
        }
        emit Unstaked(msg.sender, amount);
    }

    /// @notice Freeze a node: it cannot cancel its unstake or exit until the slasher resolves it.
    /// @dev Incident-response lever; intentionally pause-exempt.
    function freeze(address _relayer) external onlyRole(SLASHER_ROLE) {
        RelayerProfile storage profile = _registry().relayers[_relayer];
        if (!profile.isRegistered) revert NotRegistered();
        if (profile.frozen) revert AlreadyFrozen();
        profile.frozen = true;
        emit RelayerFrozen(_relayer, msg.sender);
    }

    /// @notice Lift a freeze.
    function unfreeze(address _relayer) external onlyRole(SLASHER_ROLE) {
        RelayerProfile storage profile = _registry().relayers[_relayer];
        if (!profile.isRegistered) revert NotRegistered();
        if (!profile.frozen) revert NotFrozen();
        profile.frozen = false;
        emit RelayerUnfrozen(_relayer, msg.sender);
    }

    /// @notice Slash a relayer's stake. A slash that empties or drops the stake below minStakeAmount
    ///         deregisters the node so no under-collateralized node keeps routing; any sub-floor remainder
    ///         is returned to the node. Reverts if there is nothing to slash (e.g. a zero-stake node).
    /// @dev Incident-response lever; intentionally pause-exempt.
    function slash(
        address _relayer,
        uint256 _amount
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        RegistryStorage storage $ = _registry();
        RelayerProfile storage profile = $.relayers[_relayer];
        if (!profile.isRegistered) revert NotRegistered();

        uint256 currentStake = profile.stakedAmount;
        uint256 slashAmount = _amount > currentStake ? currentStake : _amount;
        if (slashAmount == 0) revert NothingToSlash();

        uint256 remaining = currentStake - slashAmount;
        bool deregister = remaining < $.minStakeAmount;

        if (deregister) {
            _removeRelayer(_relayer, profile.sphinxKey);
        } else {
            profile.stakedAmount = remaining;
        }

        $.stakingToken.safeTransfer(msg.sender, slashAmount);
        emit Slashed(_relayer, slashAmount, msg.sender);

        if (deregister) {
            emit RelayerRemoved(_relayer, msg.sender);
            if (remaining > 0) {
                $.stakingToken.safeTransfer(_relayer, remaining);
            }
        }
    }

    /// @notice Permissionlessly remove a formerly-staked node stranded below the floor (e.g. after a
    ///         minStakeAmount raise), returning its remaining stake. Trusted zero-stake nodes are exempt.
    function removeUnderCollateralized(address _relayer) external nonReentrant {
        RegistryStorage storage $ = _registry();
        RelayerProfile storage profile = $.relayers[_relayer];
        if (!profile.isRegistered) revert NotRegistered();
        // A frozen node must not exit any path while the slasher holds it.
        if (profile.frozen) revert NodeFrozen();
        uint256 staked = profile.stakedAmount;
        if (staked == 0 || staked >= $.minStakeAmount)
            revert NotUnderCollateralized();

        _removeRelayer(_relayer, profile.sphinxKey);
        $.stakingToken.safeTransfer(_relayer, staked);
        emit RelayerRemoved(_relayer, msg.sender);
    }

    /**
     * @notice Admin removal of a node; remaining stake is returned to the owner (call `slash()`
     *         first to burn it instead).
     */
    function forceUnregister(
        address _relayer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        RegistryStorage storage $ = _registry();
        RelayerProfile storage profile = $.relayers[_relayer];
        if (!profile.isRegistered) revert NotRegistered();

        uint256 remainingStake = profile.stakedAmount;
        _removeRelayer(_relayer, profile.sphinxKey);

        if (remainingStake > 0) {
            $.stakingToken.safeTransfer(_relayer, remainingStake);
        }

        emit RelayerRemoved(_relayer, msg.sender);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Whether an address is a registered relayer (staked or trusted, active or unstaking).
    function isActiveRelayer(address _relayer) external view returns (bool) {
        return _registry().relayers[_relayer].isRegistered;
    }

    /// @notice Node role for a registered relayer; unset (0) reads as ROLE_FULL.
    function getNodeRole(address _relayer) external view returns (uint8) {
        uint8 role = _registry().nodeRoles[_relayer];
        return role == 0 ? ROLE_FULL : role;
    }

    function updateConfig(
        uint256 _minStake,
        uint256 _unstakeDelay
    ) external onlyRole(CONFIG_ROLE) {
        if (_unstakeDelay < MIN_UNSTAKE_DELAY) revert InvalidDelay();
        RegistryStorage storage $ = _registry();
        if (_minStake < $.minStakeFloor) revert MinStakeBelowFloor();
        $.minStakeAmount = _minStake;
        $.unstakeDelay = _unstakeDelay;
        emit ConfigUpdated(_minStake, _unstakeDelay);
    }

    /// @notice ERC20 staked by relayers as slashable collateral.
    function stakingToken() external view returns (IERC20) {
        return _registry().stakingToken;
    }

    /// @notice Hard lower bound on minStakeAmount; a zero or dust minStake would allow unslashable Sybils.
    function minStakeFloor() external view returns (uint256) {
        return _registry().minStakeFloor;
    }

    function minStakeAmount() external view returns (uint256) {
        return _registry().minStakeAmount;
    }

    function unstakeDelay() external view returns (uint256) {
        return _registry().unstakeDelay;
    }

    function relayerCount() external view returns (uint256) {
        return _registry().relayerCount;
    }

    /// @notice XOR-based topology fingerprint: XOR(keccak256(addr) for each registered node); empty set
    ///         = bytes32(0). Self-inverse, so add and remove are the same operation.
    function topologyFingerprint() external view returns (bytes32) {
        return _registry().topologyFingerprint;
    }

    function relayers(
        address _relayer
    )
        external
        view
        returns (
            bytes32 sphinxKey,
            string memory url,
            string memory ingressUrl,
            string memory metadataUrl,
            uint256 stakedAmount,
            uint256 unlockTime,
            bool isRegistered,
            RelayerStatus status,
            bool frozen
        )
    {
        RelayerProfile storage profile = _registry().relayers[_relayer];
        return (
            profile.sphinxKey,
            profile.url,
            profile.ingressUrl,
            profile.metadataUrl,
            profile.stakedAmount,
            profile.unlockTime,
            profile.isRegistered,
            profile.status,
            profile.frozen
        );
    }

    /// @notice Node role for each registered relayer (1=Relay, 2=Exit, 3=Full); unset (0) reads as Full.
    function nodeRoles(address _relayer) external view returns (uint8) {
        return _registry().nodeRoles[_relayer];
    }

    /// @notice sphinxKey -> owner, enforcing key uniqueness across nodes.
    function sphinxKeyOwner(
        bytes32 _sphinxKey
    ) external view returns (address) {
        return _registry().sphinxKeyOwner[_sphinxKey];
    }
}
