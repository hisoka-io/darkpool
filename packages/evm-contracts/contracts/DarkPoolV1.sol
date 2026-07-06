// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "./Poseidon/Poseidon2.sol";
import {Field} from "./Poseidon/Field.sol";
import {MerkleTreeLib} from "./libraries/MerkleTreeLib.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlDefaultAdminRulesUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IHonkVerifierV1 {
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool);
}

/**
 * @title DarkPoolV1 (frozen storage baseline)
 * @notice Pinned reference layout for the upgrade-safety gate. `validateUpgrade(DarkPoolV1, DarkPool)`
 *         runs assertStorageUpgradeSafe against this copy, so any storage-incompatible change to the live
 *         DarkPool (including a namespace-internal field reorder/retype) fails the gate.
 * @dev This is a byte-for-byte storage copy of the shipped DarkPool: same ERC-7201 namespaces, same
 *      struct members in the same order, same InitParams. Update it deliberately ONLY when a real
 *      storage-compatible upgrade ships and becomes the new baseline. It is not deployed in production.
 */
contract DarkPoolV1 is
    Initializable,
    UUPSUpgradeable,
    AccessControlDefaultAdminRulesUpgradeable,
    PausableUpgradeable
{
    using SafeERC20 for IERC20;
    using MerkleTreeLib for MerkleTreeLib.Tree;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 private constant PROOF_TIMESTAMP_TOLERANCE = 5 minutes;

    uint256 private constant CIRCUIT_DEPOSIT = 0;
    uint256 private constant CIRCUIT_WITHDRAW = 1;
    uint256 private constant CIRCUIT_TRANSFER = 2;
    uint256 private constant CIRCUIT_JOIN = 3;
    uint256 private constant CIRCUIT_SPLIT = 4;
    uint256 private constant CIRCUIT_PUBLIC_CLAIM = 5;
    uint256 private constant CIRCUIT_COUNT = 6;

    uint32 private constant MERKLE_TREE_DEPTH = 32;

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private constant BJJ_A = 168700;
    uint256 private constant BJJ_D = 168696;
    uint256 private constant BN254_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error ZeroAddress();
    error InvalidInputsLength();
    error InvalidProof();
    error InvalidRoot();
    error TimestampInvalid();
    error NullifierAlreadySpent();
    error ValueZero();
    error ValueTooLarge();
    error MemoCollision();
    error MemoSpent();
    error MemoInvalid();
    error FeeOnTransferUnsupported();
    error OnlyRecipientMayPull();
    error UnknownCircuitId();
    error InvalidComplianceKeyPoint();
    error ReentrancyGuardReentrantCall();
    error ComplianceKeyStale(
        uint256 currentVersion,
        uint256 currentX,
        uint256 currentY
    );

    event NewNote(
        uint256 indexed leafIndex,
        bytes32 indexed commitment,
        uint256 ephemeralPK_x,
        uint256 ephemeralPK_y,
        bytes32[7] packedCiphertext
    );

    event NewPrivateMemo(
        uint256 indexed leafIndex,
        bytes32 indexed commitment,
        uint256 indexed tag,
        uint256 ephemeralPK_x,
        uint256 ephemeralPK_y,
        uint256 cekWrap,
        bytes32[7] packedCiphertext
    );

    event NewPublicMemo(
        bytes32 indexed memoId,
        address asset,
        uint256 value,
        uint256 timelock,
        uint256 salt
    );

    event Deposited(
        address indexed depositor,
        address indexed asset,
        uint256 value
    );

    event Withdrawal(
        bytes32 indexed nullifierHash,
        address indexed recipient,
        address relayer
    );
    event NullifierSpent(bytes32 indexed nullifierHash);
    event PublicMemoSpent(bytes32 indexed memoId);
    event VerifierUpdated(uint256 indexed circuitId, address verifier);
    event ComplianceKeyRotated(
        uint256 oldVersion,
        uint256 newVersion,
        uint256 newX,
        uint256 newY
    );

    /// @custom:storage-location erc7201:hisoka.darkpool.tree
    struct TreeStorage {
        MerkleTreeLib.Tree tree;
    }

    /// @custom:storage-location erc7201:hisoka.darkpool.nullifiers
    struct NullifierStorage {
        mapping(bytes32 => bool) isNullifierSpent;
    }

    /// @custom:storage-location erc7201:hisoka.darkpool.memos
    struct MemoStorage {
        mapping(bytes32 => bool) isValidPublicMemo;
        mapping(bytes32 => bool) isPublicMemoSpent;
    }

    /// @custom:storage-location erc7201:hisoka.darkpool.verifiers
    struct VerifierStorage {
        mapping(uint256 => address) verifiers;
    }

    /// @custom:storage-location erc7201:hisoka.darkpool.compliance
    struct ComplianceStorage {
        uint256 pkX;
        uint256 pkY;
        uint256 version;
    }

    /// @custom:storage-location erc7201:hisoka.darkpool.config
    struct ConfigStorage {
        address rewardPool;
    }

    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyStorage {
        uint256 status;
    }

    bytes32 private constant TREE_LOCATION =
        0xbdd00c81e71bd165e3ff2099ca204334ffd58a8d7225a33b4761542b7a86e200;
    bytes32 private constant NULLIFIERS_LOCATION =
        0xcb1d3464d85c75a880c4f95a3cfd4a5cd80b39c53862d4987d9ec14bb8af6700;
    bytes32 private constant MEMOS_LOCATION =
        0x79ab9646d487c514cf680928de0290895c9ad6720afd1f87136f293781b7ea00;
    bytes32 private constant VERIFIERS_LOCATION =
        0x204927e2223572a19571462c2dfb374afbbdb39e695632d6477721409dfb0b00;
    bytes32 private constant COMPLIANCE_LOCATION =
        0x4c6336ddd730b3b6886dcf6c397e5676dac845842540c4592f4e52cea8e9ae00;
    bytes32 private constant CONFIG_LOCATION =
        0x16730e3a2a45d0ba613b00104b5efdd24c73b2ac170740fe805c71a02b3bf500;
    bytes32 private constant REENTRANCY_LOCATION =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    function _treeStorage() private pure returns (TreeStorage storage $) {
        assembly {
            $.slot := TREE_LOCATION
        }
    }

    function _nullifierStorage()
        private
        pure
        returns (NullifierStorage storage $)
    {
        assembly {
            $.slot := NULLIFIERS_LOCATION
        }
    }

    function _memoStorage() private pure returns (MemoStorage storage $) {
        assembly {
            $.slot := MEMOS_LOCATION
        }
    }

    function _verifierStorage()
        private
        pure
        returns (VerifierStorage storage $)
    {
        assembly {
            $.slot := VERIFIERS_LOCATION
        }
    }

    function _complianceStorage()
        private
        pure
        returns (ComplianceStorage storage $)
    {
        assembly {
            $.slot := COMPLIANCE_LOCATION
        }
    }

    function _configStorage() private pure returns (ConfigStorage storage $) {
        assembly {
            $.slot := CONFIG_LOCATION
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

    struct InitParams {
        address depositVerifier;
        address withdrawVerifier;
        address transferVerifier;
        address joinVerifier;
        address splitVerifier;
        address publicClaimVerifier;
        address rewardPool;
        uint256 compliancePkX;
        uint256 compliancePkY;
        uint48 initialAdminDelay;
        address initialAdmin;
        address pauser;
        address upgrader;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(InitParams calldata p) external initializer {
        if (p.rewardPool == address(0)) revert ZeroAddress();
        if (p.pauser == address(0)) revert ZeroAddress();
        if (p.upgrader == address(0)) revert ZeroAddress();

        __AccessControlDefaultAdminRules_init(
            p.initialAdminDelay,
            p.initialAdmin
        );
        __Pausable_init();
        _reentrancyStorage().status = NOT_ENTERED;
        _grantRole(PAUSER_ROLE, p.pauser);
        _grantRole(UPGRADER_ROLE, p.upgrader);

        _setVerifier(CIRCUIT_DEPOSIT, p.depositVerifier);
        _setVerifier(CIRCUIT_WITHDRAW, p.withdrawVerifier);
        _setVerifier(CIRCUIT_TRANSFER, p.transferVerifier);
        _setVerifier(CIRCUIT_JOIN, p.joinVerifier);
        _setVerifier(CIRCUIT_SPLIT, p.splitVerifier);
        _setVerifier(CIRCUIT_PUBLIC_CLAIM, p.publicClaimVerifier);

        _requireValidComplianceKey(p.compliancePkX, p.compliancePkY);
        ComplianceStorage storage c = _complianceStorage();
        c.pkX = p.compliancePkX;
        c.pkY = p.compliancePkY;
        c.version = 1;

        _configStorage().rewardPool = p.rewardPool;

        _treeStorage().tree.init(MERKLE_TREE_DEPTH);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function setVerifier(
        uint256 circuitId,
        address newVerifier
    ) external onlyRole(UPGRADER_ROLE) {
        _setVerifier(circuitId, newVerifier);
    }

    function rotateComplianceKey(
        uint256 newX,
        uint256 newY
    ) external onlyRole(UPGRADER_ROLE) whenNotPaused {
        _requireValidComplianceKey(newX, newY);
        ComplianceStorage storage c = _complianceStorage();
        uint256 oldVersion = c.version;
        uint256 newVersion = oldVersion + 1;
        c.pkX = newX;
        c.pkY = newY;
        c.version = newVersion;
        emit ComplianceKeyRotated(oldVersion, newVersion, newX, newY);
    }

    function complianceKey()
        external
        view
        returns (uint256 x, uint256 y, uint256 version)
    {
        ComplianceStorage storage c = _complianceStorage();
        return (c.pkX, c.pkY, c.version);
    }

    function deposit(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 14) revert InvalidInputsLength();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!_verifier(CIRCUIT_DEPOSIT).verify(_proof, _publicInputs))
            revert InvalidProof();

        uint256 value = uint256(_publicInputs[5]);
        address asset = address(uint160(uint256(_publicInputs[6])));
        if (value == 0) revert ValueZero();

        uint256 bal0 = IERC20(asset).balanceOf(address(this));
        IERC20(asset).safeTransferFrom(msg.sender, address(this), value);
        if (IERC20(asset).balanceOf(address(this)) - bal0 != value)
            revert FeeOnTransferUnsupported();
        emit Deposited(msg.sender, asset, value);

        _insertNote(_publicInputs, 2, 3, 4, 7);
    }

    function withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 19) revert InvalidInputsLength();

        address recipient = address(uint160(uint256(_publicInputs[1])));
        if (recipient.code.length > 0 && msg.sender != recipient)
            revert OnlyRecipientMayPull();

        if (!_treeStorage().tree.isKnownRoot[_publicInputs[7]])
            revert InvalidRoot();

        _verifyProofTimestamp(uint256(_publicInputs[2]));
        _verifyComplianceKey(_publicInputs[4], _publicInputs[5]);

        if (!_verifier(CIRCUIT_WITHDRAW).verify(_proof, _publicInputs))
            revert InvalidProof();

        bytes32 nullifierHash = _publicInputs[6];
        _spendNullifier(nullifierHash);

        _insertNote(_publicInputs, 9, 10, 11, 12);

        uint256 withdrawValue = uint256(_publicInputs[0]);
        address asset = address(uint160(uint256(_publicInputs[8])));

        if (withdrawValue > 0) {
            IERC20(asset).safeTransfer(recipient, withdrawValue);
        }

        emit Withdrawal(nullifierHash, recipient, msg.sender);
    }

    function privateTransfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 27) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[4]])
            revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[0]));
        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);

        if (!_verifier(CIRCUIT_TRANSFER).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[3]);
        _insertMemo(_publicInputs);
        _insertNote(_publicInputs, 17, 18, 19, 20);
    }

    function join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 16) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[5]])
            revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[0]));
        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);

        if (!_verifier(CIRCUIT_JOIN).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[3]);
        _spendNullifier(_publicInputs[4]);
        _insertNote(_publicInputs, 6, 7, 8, 9);
    }

    function split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 25) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[4]])
            revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[0]));
        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);

        if (!_verifier(CIRCUIT_SPLIT).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[3]);
        _insertNote(_publicInputs, 5, 6, 7, 8);
        _insertNote(_publicInputs, 15, 16, 17, 18);
    }

    function publicTransfer(
        uint256 _ownerX,
        uint256 _ownerY,
        address _asset,
        uint256 _value,
        uint256 _timelock,
        uint256 _salt
    ) external nonReentrant whenNotPaused {
        if (_value == 0) revert ValueZero();
        if (_value > type(uint128).max) revert ValueTooLarge();

        Field.Type[] memory inputs = new Field.Type[](6);
        inputs[0] = Field.toField(_value);
        inputs[1] = Field.toField(uint256(uint160(_asset)));
        inputs[2] = Field.toField(_timelock);
        inputs[3] = Field.toField(_ownerX);
        inputs[4] = Field.toField(_ownerY);
        inputs[5] = Field.toField(_salt);

        bytes32 memoId = Field.toBytes32(Poseidon2.hash(inputs));

        MemoStorage storage m = _memoStorage();
        if (m.isValidPublicMemo[memoId]) revert MemoCollision();

        uint256 bal0 = IERC20(_asset).balanceOf(address(this));
        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _value);
        if (IERC20(_asset).balanceOf(address(this)) - bal0 != _value)
            revert FeeOnTransferUnsupported();
        m.isValidPublicMemo[memoId] = true;

        emit NewPublicMemo(memoId, _asset, _value, _timelock, _salt);
    }

    function publicClaim(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 14) revert InvalidInputsLength();

        bytes32 memoId = _publicInputs[0];
        MemoStorage storage m = _memoStorage();
        if (!m.isValidPublicMemo[memoId]) revert MemoInvalid();
        if (m.isPublicMemoSpent[memoId]) revert MemoSpent();

        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);
        _verifyProofTimestamp(uint256(_publicInputs[3]));

        if (!_verifier(CIRCUIT_PUBLIC_CLAIM).verify(_proof, _publicInputs))
            revert InvalidProof();

        m.isPublicMemoSpent[memoId] = true;
        emit PublicMemoSpent(memoId);

        _insertNote(_publicInputs, 4, 5, 6, 7);
    }

    function _setVerifier(uint256 circuitId, address newVerifier) internal {
        if (circuitId >= CIRCUIT_COUNT) revert UnknownCircuitId();
        if (newVerifier == address(0)) revert ZeroAddress();
        _verifierStorage().verifiers[circuitId] = newVerifier;
        emit VerifierUpdated(circuitId, newVerifier);
    }

    function _verifier(
        uint256 circuitId
    ) internal view returns (IHonkVerifierV1) {
        return IHonkVerifierV1(_verifierStorage().verifiers[circuitId]);
    }

    function _insertNote(
        bytes32[] calldata _publicInputs,
        uint256 leafIndex,
        uint256 epkXIndex,
        uint256 epkYIndex,
        uint256 ctStartIndex
    ) internal {
        bytes32 commitment = _publicInputs[leafIndex];
        uint256 insertedAt = _treeStorage().tree.insert(commitment);

        bytes32[7] memory ct;
        for (uint256 i = 0; i < 7; i++) {
            ct[i] = _publicInputs[ctStartIndex + i];
        }

        emit NewNote(
            insertedAt,
            commitment,
            uint256(_publicInputs[epkXIndex]),
            uint256(_publicInputs[epkYIndex]),
            ct
        );
    }

    function _insertMemo(bytes32[] calldata _publicInputs) internal {
        bytes32 commitment = _publicInputs[5];
        uint256 insertedAt = _treeStorage().tree.insert(commitment);

        bytes32[7] memory ct;
        for (uint256 i = 0; i < 7; i++) {
            ct[i] = _publicInputs[10 + i];
        }

        emit NewPrivateMemo(
            insertedAt,
            commitment,
            uint256(_publicInputs[8]),
            uint256(_publicInputs[6]),
            uint256(_publicInputs[7]),
            uint256(_publicInputs[9]),
            ct
        );
    }

    function _verifyComplianceKey(bytes32 px, bytes32 py) internal view {
        ComplianceStorage storage c = _complianceStorage();
        if (uint256(px) != c.pkX || uint256(py) != c.pkY) {
            revert ComplianceKeyStale(c.version, c.pkX, c.pkY);
        }
    }

    function _requireValidComplianceKey(uint256 x, uint256 y) private pure {
        if (x >= BN254_FR || y >= BN254_FR) revert InvalidComplianceKeyPoint();
        if (x == 0 && y == 1) revert InvalidComplianceKeyPoint();
        uint256 x2 = mulmod(x, x, BN254_FR);
        uint256 y2 = mulmod(y, y, BN254_FR);
        uint256 lhs = addmod(mulmod(BJJ_A, x2, BN254_FR), y2, BN254_FR);
        uint256 rhs = addmod(
            1,
            mulmod(mulmod(BJJ_D, x2, BN254_FR), y2, BN254_FR),
            BN254_FR
        );
        if (lhs != rhs) revert InvalidComplianceKeyPoint();
    }

    function _verifyProofTimestamp(uint256 timestamp) internal view {
        if (timestamp > block.timestamp + PROOF_TIMESTAMP_TOLERANCE)
            revert TimestampInvalid();
    }

    function _spendNullifier(bytes32 _nullifierHash) internal {
        NullifierStorage storage n = _nullifierStorage();
        if (n.isNullifierSpent[_nullifierHash]) revert NullifierAlreadySpent();
        n.isNullifierSpent[_nullifierHash] = true;
        emit NullifierSpent(_nullifierHash);
    }

    function verifier(uint256 circuitId) external view returns (address) {
        return _verifierStorage().verifiers[circuitId];
    }

    function rewardPool() external view returns (address) {
        return _configStorage().rewardPool;
    }

    function isNullifierSpent(
        bytes32 nullifierHash
    ) external view returns (bool) {
        return _nullifierStorage().isNullifierSpent[nullifierHash];
    }

    function isValidPublicMemo(bytes32 memoId) external view returns (bool) {
        return _memoStorage().isValidPublicMemo[memoId];
    }

    function isPublicMemoSpent(bytes32 memoId) external view returns (bool) {
        return _memoStorage().isPublicMemoSpent[memoId];
    }

    function isKnownRoot(bytes32 _root) external view returns (bool) {
        return _treeStorage().tree.isKnownRoot[_root];
    }

    function getCurrentRoot() external view returns (bytes32) {
        return _treeStorage().tree.getCurrentRoot();
    }

    function getMerklePath(
        uint256 _leafIndex
    ) external view returns (bytes32[32] memory) {
        return _treeStorage().tree.getMerklePath(_leafIndex);
    }

    function getNextLeafIndex() external view returns (uint256) {
        return _treeStorage().tree.nextLeafIndex;
    }

    function getSubtreeWithProof(
        uint256 treeLevel,
        uint256 positionAtLevel
    ) external view returns (bytes32[] memory proof, bytes32[] memory leafs) {
        return
            _treeStorage().tree.getSubtreeWithProof(treeLevel, positionAtLevel);
    }
}
