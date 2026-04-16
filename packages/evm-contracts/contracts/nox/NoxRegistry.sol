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
 * @title NoxRegistry
 * @author Hisoka Protocol
 * @notice The "Phonebook" for the NOX Mixnet.
 * @dev V0 Features:
 *      - Sybil resistance via Staking (Community).
 *      - Bootstrapping via Admin Whitelist (Privileged).
 *      - Admin "God Mode" to remove bad actors during Beta.
 */
contract NoxRegistry is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // --- ROLES ---
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant CONFIG_ROLE = keccak256("CONFIG_ROLE");

    // --- STRUCTS ---
    struct RelayerProfile {
        bytes32 sphinxKey;
        string url;
        string ingressUrl;
        string metadataUrl;
        uint256 stakedAmount;
        uint256 unstakeRequestTime;
        bool isRegistered;
    }

    // --- NODE ROLE CONSTANTS ---
    uint8 public constant ROLE_RELAY = 1;
    uint8 public constant ROLE_EXIT = 2;
    uint8 public constant ROLE_FULL = 3;

    // --- CONSTANTS ---
    uint256 public constant MIN_UNSTAKE_DELAY = 1 days;

    // --- STATE ---
    IERC20 public immutable stakingToken;
    uint256 public minStakeAmount;
    uint256 public unstakeDelay;
    uint256 public relayerCount;

    /// @notice XOR-based topology fingerprint: XOR(keccak256(addr) for each registered node)
    /// @dev Client recomputes from nodes list and verifies against this value.
    ///      Empty set = bytes32(0). Self-inverse: same operation for add and remove.
    bytes32 public topologyFingerprint;

    mapping(address => RelayerProfile) public relayers;

    /// @notice Node role for each registered relayer (1=Relay, 2=Exit, 3=Full).
    /// @dev Unset (0) treated as Full for backward compatibility.
    mapping(address => uint8) public nodeRoles;

    /// @notice Enforces sphinxKey uniqueness — prevents two nodes from sharing a key.
    mapping(bytes32 => address) public sphinxKeyOwner;

    // --- EVENTS ---
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
    event Unstaked(address indexed relayer, uint256 amount);
    event Slashed(
        address indexed relayer,
        uint256 amount,
        address indexed slasher
    );
    event RelayerRemoved(address indexed relayer, address indexed by);
    event RoleUpdated(address indexed relayer, uint8 newRole);
    event ConfigUpdated(uint256 newMinStake, uint256 newUnstakeDelay);
    event TopologyFingerprintUpdated(
        bytes32 indexed newFingerprint,
        bytes32 indexed prevFingerprint
    );

    // --- ERRORS ---
    error ZeroAddress();
    error InvalidKey();
    error DuplicateKey();
    error InvalidAmount();
    error AlreadyRegistered();
    error NotRegistered();
    error InsufficientStake();
    error UnstakeAlreadyRequested();
    error UnstakeNotRequested();
    error UnstakeTooEarly();
    error EmptyString();
    error InvalidRole();

    constructor(
        address _admin,
        address _stakingToken,
        uint256 _minStake,
        uint256 _unstakeDelay
    ) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_stakingToken == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(CONFIG_ROLE, _admin);
        _grantRole(SLASHER_ROLE, _admin);

        stakingToken = IERC20(_stakingToken);
        minStakeAmount = _minStake;
        unstakeDelay = _unstakeDelay;

        // XOR identity: empty set = bytes32(0). No genesis hash needed.
    }

    // --- INTERNAL HELPERS ---

    /**
     * @dev XOR a node's identity hash into the topology fingerprint.
     *      Self-inverse: XOR to add, XOR again to remove.
     *      fingerprint = XOR(keccak256(abi.encodePacked(addr)) for each registered addr)
     * @param nodeAddress The node being added or removed
     */
    function _xorAddressIntoFingerprint(address nodeAddress) private {
        bytes32 prevFingerprint = topologyFingerprint;
        topologyFingerprint =
            prevFingerprint ^
            keccak256(abi.encodePacked(nodeAddress));
        emit TopologyFingerprintUpdated(topologyFingerprint, prevFingerprint);
    }

    // --- COMMUNITY REGISTRATION (STAKED) ---

    function register(
        bytes32 _sphinxKey,
        string calldata _url,
        string calldata _ingressUrl,
        string calldata _metadataUrl,
        uint256 _stakeAmount,
        uint8 _nodeRole
    ) external nonReentrant whenNotPaused {
        if (relayers[msg.sender].isRegistered) revert AlreadyRegistered();
        if (_stakeAmount < minStakeAmount) revert InsufficientStake();
        if (bytes(_url).length == 0) revert EmptyString();
        if (_sphinxKey == bytes32(0)) revert InvalidKey();
        if (sphinxKeyOwner[_sphinxKey] != address(0)) revert DuplicateKey();
        if (_nodeRole < ROLE_RELAY || _nodeRole > ROLE_FULL) revert InvalidRole();

        stakingToken.safeTransferFrom(msg.sender, address(this), _stakeAmount);

        relayers[msg.sender] = RelayerProfile({
            sphinxKey: _sphinxKey,
            url: _url,
            ingressUrl: _ingressUrl,
            metadataUrl: _metadataUrl,
            stakedAmount: _stakeAmount,
            unstakeRequestTime: 0,
            isRegistered: true
        });
        sphinxKeyOwner[_sphinxKey] = msg.sender;
        nodeRoles[msg.sender] = _nodeRole;

        relayerCount++;
        _xorAddressIntoFingerprint(msg.sender);
        emit RelayerRegistered(msg.sender, _sphinxKey, _url, _ingressUrl, _metadataUrl, _stakeAmount, _nodeRole);
    }

    // --- ADMIN REGISTRATION (PRIVILEGED) ---

    /**
     * @notice Bootstrap the network with trusted nodes (No stake required).
     * @dev BETA: Privileged relayers have no stake and cannot be financially slashed.
     *      Use forceUnregister() to remove misbehaving privileged nodes.
     */
    function registerPrivileged(
        address _relayer,
        bytes32 _sphinxKey,
        string calldata _url,
        string calldata _ingressUrl,
        string calldata _metadataUrl,
        uint8 _nodeRole
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (relayers[_relayer].isRegistered) revert AlreadyRegistered();
        if (_relayer == address(0)) revert ZeroAddress();
        if (bytes(_url).length == 0) revert EmptyString();
        if (_sphinxKey == bytes32(0)) revert InvalidKey();
        if (sphinxKeyOwner[_sphinxKey] != address(0)) revert DuplicateKey();
        if (_nodeRole < ROLE_RELAY || _nodeRole > ROLE_FULL) revert InvalidRole();

        relayers[_relayer] = RelayerProfile({
            sphinxKey: _sphinxKey,
            url: _url,
            ingressUrl: _ingressUrl,
            metadataUrl: _metadataUrl,
            stakedAmount: 0, // Trusted
            unstakeRequestTime: 0,
            isRegistered: true
        });
        sphinxKeyOwner[_sphinxKey] = _relayer;
        nodeRoles[_relayer] = _nodeRole;

        relayerCount++;
        _xorAddressIntoFingerprint(_relayer);
        emit PrivilegedRelayerRegistered(_relayer, _sphinxKey, _url, _ingressUrl, _metadataUrl, _nodeRole);
    }

    // --- MANAGEMENT ---

    function updateUrl(string calldata _newUrl) external {
        if (!relayers[msg.sender].isRegistered) revert NotRegistered();
        if (bytes(_newUrl).length == 0) revert EmptyString();
        relayers[msg.sender].url = _newUrl;
        emit RelayerUpdated(msg.sender, _newUrl);
    }

    function updateIngressUrl(string calldata _newIngressUrl) external {
        if (!relayers[msg.sender].isRegistered) revert NotRegistered();
        relayers[msg.sender].ingressUrl = _newIngressUrl;
        emit IngressUrlUpdated(msg.sender, _newIngressUrl);
    }

    function updateMetadataUrl(string calldata _newMetadataUrl) external {
        if (!relayers[msg.sender].isRegistered) revert NotRegistered();
        relayers[msg.sender].metadataUrl = _newMetadataUrl;
        emit MetadataUrlUpdated(msg.sender, _newMetadataUrl);
    }

    function updateRole(uint8 _newRole) external {
        if (!relayers[msg.sender].isRegistered) revert NotRegistered();
        if (_newRole < ROLE_RELAY || _newRole > ROLE_FULL) revert InvalidRole();
        nodeRoles[msg.sender] = _newRole;
        emit RoleUpdated(msg.sender, _newRole);
    }

    function rotateKey(bytes32 _newSphinxKey) external {
        if (!relayers[msg.sender].isRegistered) revert NotRegistered();
        if (_newSphinxKey == bytes32(0)) revert InvalidKey();
        if (sphinxKeyOwner[_newSphinxKey] != address(0)) revert DuplicateKey();

        delete sphinxKeyOwner[relayers[msg.sender].sphinxKey];
        sphinxKeyOwner[_newSphinxKey] = msg.sender;
        relayers[msg.sender].sphinxKey = _newSphinxKey;
        emit KeyRotated(msg.sender, _newSphinxKey);
    }

    function addStake(uint256 _amount) external nonReentrant whenNotPaused {
        if (!relayers[msg.sender].isRegistered) revert NotRegistered();
        if (_amount == 0) revert InvalidAmount();
        if (relayers[msg.sender].unstakeRequestTime > 0)
            revert UnstakeAlreadyRequested();

        stakingToken.safeTransferFrom(msg.sender, address(this), _amount);
        relayers[msg.sender].stakedAmount += _amount;
        emit StakeAdded(msg.sender, _amount);
    }

    // --- EXIT ---

    function requestUnstake() external {
        if (!relayers[msg.sender].isRegistered) revert NotRegistered();
        if (relayers[msg.sender].unstakeRequestTime > 0)
            revert UnstakeAlreadyRequested();

        relayers[msg.sender].unstakeRequestTime = block.timestamp;
        emit UnstakeRequested(msg.sender, block.timestamp + unstakeDelay);
    }

    function executeUnstake() external nonReentrant {
        RelayerProfile storage profile = relayers[msg.sender];
        if (!profile.isRegistered) revert NotRegistered();
        if (profile.unstakeRequestTime == 0) revert UnstakeNotRequested();
        if (block.timestamp < profile.unstakeRequestTime + unstakeDelay)
            revert UnstakeTooEarly();

        uint256 amount = profile.stakedAmount;
        delete sphinxKeyOwner[profile.sphinxKey];
        delete relayers[msg.sender];
        delete nodeRoles[msg.sender];
        relayerCount--;
        _xorAddressIntoFingerprint(msg.sender);

        if (amount > 0) {
            stakingToken.safeTransfer(msg.sender, amount);
        }
        emit Unstaked(msg.sender, amount);
    }

    // --- GOVERNANCE / SECURITY ---

    /**
     * @notice Financial Punishment.
     * Takes stake from a malicious node. Does NOT remove them (unless logic requires it).
     * @dev KNOWN LIMITATION (Beta): Privileged relayers (stakedAmount=0) are immune to
     *      financial slashing. For privileged relayers, use `forceUnregister()` instead.
     *      Production should require minimum stake for all relayers.
     */
    function slash(
        address _relayer,
        uint256 _amount
    ) external onlyRole(SLASHER_ROLE) {
        if (!relayers[_relayer].isRegistered) revert NotRegistered();

        uint256 currentStake = relayers[_relayer].stakedAmount;
        uint256 slashAmount = _amount > currentStake ? currentStake : _amount;

        if (slashAmount > 0) {
            relayers[_relayer].stakedAmount -= slashAmount;
            stakingToken.safeTransfer(msg.sender, slashAmount); // Send to Slasher/Admin
            emit Slashed(_relayer, slashAmount, msg.sender);
        }
    }

    /**
     * @notice Topology Cleanup.
     * NOTE: Any remaining stake is RETURNED to the owner to prevent locking.
     * If you want to burn it, call `slash()` *before* `forceUnregister()`.
     */
    function forceUnregister(
        address _relayer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!relayers[_relayer].isRegistered) revert NotRegistered();

        uint256 remainingStake = relayers[_relayer].stakedAmount;

        delete sphinxKeyOwner[relayers[_relayer].sphinxKey];
        delete relayers[_relayer];
        delete nodeRoles[_relayer];
        relayerCount--;
        _xorAddressIntoFingerprint(_relayer);

        if (remainingStake > 0) {
            stakingToken.safeTransfer(_relayer, remainingStake);
        }

        emit RelayerRemoved(_relayer, msg.sender);
    }

    /// @notice Get the node role for a registered relayer.
    /// @dev Returns ROLE_FULL (3) for unset values (backward compatibility).
    function getNodeRole(address _relayer) external view returns (uint8) {
        uint8 role = nodeRoles[_relayer];
        return role == 0 ? ROLE_FULL : role;
    }

    function updateConfig(
        uint256 _minStake,
        uint256 _unstakeDelay
    ) external onlyRole(CONFIG_ROLE) {
        if (_unstakeDelay < MIN_UNSTAKE_DELAY) revert InvalidAmount();
        minStakeAmount = _minStake;
        unstakeDelay = _unstakeDelay;
        emit ConfigUpdated(_minStake, _unstakeDelay);
    }
}
