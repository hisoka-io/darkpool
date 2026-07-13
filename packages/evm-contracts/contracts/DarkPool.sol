// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "./Poseidon/Poseidon2.sol";
import {Field} from "./Poseidon/Field.sol";
import {MerkleTreeLib} from "./libraries/MerkleTreeLib.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
// solhint-disable-next-line max-line-length
import {AccessControlDefaultAdminRulesUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IHonkVerifier {
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool);
}

/**
 * @title Hisoka DarkPool
 * @notice Core contract for the Hisoka privacy protocol: verifies ZK spend proofs, manages the note tree,
 *         nullifiers, and compliance key. UUPS proxy with ERC-7201 namespaced storage.
 * @dev A standard spend and its FROST-multisig twin share one public-input layout, so each op-family routes
 *      through a single verify+effects helper parameterized by circuitId.
 */
contract DarkPool is
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
    uint256 private constant CIRCUIT_WITHDRAW_MULTISIG = 6;
    uint256 private constant CIRCUIT_TRANSFER_MULTISIG = 7;
    uint256 private constant CIRCUIT_SPLIT_MULTISIG = 8;
    uint256 private constant CIRCUIT_JOIN_MULTISIG = 9;
    uint256 private constant CIRCUIT_COUNT = 10;

    uint32 private constant MERKLE_TREE_DEPTH = 32;

    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    /// @dev BabyJubJub twisted Edwards params a*x^2 + y^2 == 1 + d*x^2*y^2 over BN254 Fr
    /// (noir-edwards v0.2.5 src/bjj.nr).
    uint256 private constant BJJ_A = 168700;
    uint256 private constant BJJ_D = 168696;
    /// @dev BN254 scalar field order; matches Poseidon/Field.sol PRIME and verifiers/*.sol MODULUS.
    uint256 private constant BN254_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    error ZeroAddress();
    error ZeroPauser();
    error ZeroUpgrader();
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
    error VerifierHasNoCode();
    error VerifierUnset(uint256 circuitId);
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
        bytes32[7] packedCiphertext
    );

    /// @dev `tag` is the recipient discovery key (view key .x), indexed so a recipient can fetch its memos.
    event NewPrivateMemo(
        uint256 indexed leafIndex,
        bytes32 indexed commitment,
        uint256 indexed tag,
        uint256 ephemeralPK_x,
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
    event GenesisSeeded(uint256 indexed chainId, bytes32 genesisLeaf);

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

    /// @dev Inlined OZ ReentrancyGuard, kept on OZ's canonical namespace for storage-compat if the base returns.
    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyStorage {
        uint256 status;
    }

    // ERC-7201: keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff)).
    // keccak256(abi.encode(uint256(keccak256("hisoka.darkpool.tree")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TREE_LOCATION =
        0xbdd00c81e71bd165e3ff2099ca204334ffd58a8d7225a33b4761542b7a86e200;
    // keccak256(abi.encode(uint256(keccak256("hisoka.darkpool.nullifiers")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant NULLIFIERS_LOCATION =
        0xcb1d3464d85c75a880c4f95a3cfd4a5cd80b39c53862d4987d9ec14bb8af6700;
    // keccak256(abi.encode(uint256(keccak256("hisoka.darkpool.memos")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MEMOS_LOCATION =
        0x79ab9646d487c514cf680928de0290895c9ad6720afd1f87136f293781b7ea00;
    // keccak256(abi.encode(uint256(keccak256("hisoka.darkpool.verifiers")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant VERIFIERS_LOCATION =
        0x204927e2223572a19571462c2dfb374afbbdb39e695632d6477721409dfb0b00;
    // keccak256(abi.encode(uint256(keccak256("hisoka.darkpool.compliance")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant COMPLIANCE_LOCATION =
        0x4c6336ddd730b3b6886dcf6c397e5676dac845842540c4592f4e52cea8e9ae00;
    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REENTRANCY_LOCATION =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

    // Genesis-leaf domain tag; reduced mod BN254_FR in _genesisLeaf.
    bytes32 private constant GENESIS_DOMAIN_TAG =
        keccak256("hisoka.darkpool.genesis");

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
        address withdrawMultisigVerifier;
        address transferMultisigVerifier;
        address splitMultisigVerifier;
        address joinMultisigVerifier;
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

    /// @notice One-time proxy init: grants governance roles, registers the verifiers, sets the compliance
    ///         key at version 1, and seeds the chain-specific genesis at index 0. Real notes start at index 1.
    function initialize(InitParams calldata p) external initializer {
        if (p.pauser == address(0)) revert ZeroPauser();
        if (p.upgrader == address(0)) revert ZeroUpgrader();

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
        _setVerifier(CIRCUIT_WITHDRAW_MULTISIG, p.withdrawMultisigVerifier);
        _setVerifier(CIRCUIT_TRANSFER_MULTISIG, p.transferMultisigVerifier);
        _setVerifier(CIRCUIT_SPLIT_MULTISIG, p.splitMultisigVerifier);
        _setVerifier(CIRCUIT_JOIN_MULTISIG, p.joinMultisigVerifier);

        _requireValidComplianceKey(p.compliancePkX, p.compliancePkY);
        ComplianceStorage storage c = _complianceStorage();
        c.pkX = p.compliancePkX;
        c.pkY = p.compliancePkY;
        c.version = 1;

        _treeStorage().tree.init(MERKLE_TREE_DEPTH);
        bytes32 genesis = _genesisLeaf();
        _treeStorage().tree.insert(genesis);
        emit GenesisSeeded(block.chainid, genesis);
    }

    /// @dev Genesis leaf at index 0 = Poseidon2(domain, chainid): chain-binds every root (blocks cross-chain
    /// replay) and is a non-spendable sentinel, so a spend with packed parents 0 is unambiguously a deposit.
    function _genesisLeaf() private view returns (bytes32) {
        uint256 domain = uint256(GENESIS_DOMAIN_TAG) % BN254_FR;
        Field.Type[] memory inputs = new Field.Type[](2);
        inputs[0] = Field.toField(domain);
        inputs[1] = Field.toField(block.chainid);
        return Field.toBytes32(Poseidon2.hash(inputs));
    }

    // solhint-disable no-empty-blocks
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
    // solhint-enable no-empty-blocks

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Point a circuit's verifier at a new address; a replacement MUST accept all pre-existing notes.
    function setVerifier(
        uint256 circuitId,
        address newVerifier
    ) external onlyRole(UPGRADER_ROLE) {
        _setVerifier(circuitId, newVerifier);
    }

    /// @notice Rotate the compliance public key (additive/versioned; old notes stay spendable). Callable
    ///         while paused so a compromised key can be replaced during a halt before unpausing.
    /// @dev Subgroup membership is NOT checked here (no BJJ scalar-mul lib in-repo); the circuit's
    ///      assert_valid_compliance_pk (shared/src/mint.nr) is the backstop, so a non-subgroup key gets no notes.
    function rotateComplianceKey(
        uint256 newX,
        uint256 newY
    ) external onlyRole(UPGRADER_ROLE) {
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

    /// @notice Deposit public assets into the shielded pool (funds a STANDARD or MULTISIG account).
    /// @dev Layout: [0,1] compliance; [2] leaf; [3] eph_pub.x; [4] value; [5] asset; [6..12] ciphertext.
    function deposit(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 13) revert InvalidInputsLength();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!_verifier(CIRCUIT_DEPOSIT).verify(_proof, _publicInputs))
            revert InvalidProof();

        uint256 value = uint256(_publicInputs[4]);
        address asset = address(uint160(uint256(_publicInputs[5])));
        if (value == 0) revert ValueZero();

        uint256 bal0 = IERC20(asset).balanceOf(address(this));
        IERC20(asset).safeTransferFrom(msg.sender, address(this), value);
        if (IERC20(asset).balanceOf(address(this)) - bal0 != value)
            revert FeeOnTransferUnsupported();
        emit Deposited(msg.sender, asset, value);

        _insertNote(_publicInputs, 2, 3, 6);
    }

    /// @notice Withdraw private assets to a public address (single-signer spend).
    function withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _withdraw(_proof, _publicInputs, CIRCUIT_WITHDRAW);
    }

    /// @notice FROST-multisig withdraw, authorized by a group signature (private witness).
    function withdrawMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _withdraw(_proof, _publicInputs, CIRCUIT_WITHDRAW_MULTISIG);
    }

    /// @notice Spend one note into a private memo to a recipient plus self change (single-signer).
    function privateTransfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _transfer(_proof, _publicInputs, CIRCUIT_TRANSFER);
    }

    /// @notice FROST-multisig private transfer (memo + self change), authorized by a group signature.
    function transferMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _transfer(_proof, _publicInputs, CIRCUIT_TRANSFER_MULTISIG);
    }

    /// @notice Join two notes into one (single-signer).
    function join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _join(_proof, _publicInputs, CIRCUIT_JOIN);
    }

    /// @notice FROST-multisig join (two notes into one), authorized by a group signature per input.
    function joinMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _join(_proof, _publicInputs, CIRCUIT_JOIN_MULTISIG);
    }

    /// @notice Split one note into two (single-signer).
    function split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _split(_proof, _publicInputs, CIRCUIT_SPLIT);
    }

    /// @notice FROST-multisig split (one note into two), authorized by a group signature.
    function splitMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _split(_proof, _publicInputs, CIRCUIT_SPLIT_MULTISIG);
    }

    /**
     * @dev Withdraw verify+effects shared by single-signer (id 1) and FROST-multisig (id 6).
     *      Layout: [0] value; [1] recipient; [2] intent_hash; [3,4] compliance; [5] nullifier; [6] root;
     *      [7] asset; [8] change leaf; [9] change eph_pub.x; [10..16] change ciphertext.
     *      Code-gate: a recipient with code (incl. EIP-7702-delegated EOA) must self-submit.
     *      No freshness bound by design: any historical known root is spendable; the nullifier set is the
     *      double-spend guard.
     */
    function _withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 17) revert InvalidInputsLength();

        address recipient = address(uint160(uint256(_publicInputs[1])));
        if (recipient.code.length > 0 && msg.sender != recipient)
            revert OnlyRecipientMayPull();

        if (!_treeStorage().tree.isKnownRoot[_publicInputs[6]])
            revert InvalidRoot();

        _verifyComplianceKey(_publicInputs[3], _publicInputs[4]);

        if (!_verifier(circuitId).verify(_proof, _publicInputs))
            revert InvalidProof();

        bytes32 nullifierHash = _publicInputs[5];
        _spendNullifier(nullifierHash);

        _insertNote(_publicInputs, 8, 9, 10);

        uint256 withdrawValue = uint256(_publicInputs[0]);
        address asset = address(uint160(uint256(_publicInputs[7])));

        if (withdrawValue > 0) {
            IERC20(asset).safeTransfer(recipient, withdrawValue);
        }

        emit Withdrawal(nullifierHash, recipient, msg.sender);
    }

    /**
     * @dev Transfer verify+effects (ids 2 / 7).
     *      Layout: [0,1] compliance; [2] nullifier; [3] root; [4] memo leaf; [5] memo eph_pub.x; [6] tag;
     *      [7] cek_wrap; [8..14] memo ciphertext; [15] change leaf; [16] change eph_pub.x;
     *      [17..23] change ciphertext.
     */
    function _transfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 24) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[3]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!_verifier(circuitId).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[2]);
        _insertMemoAt(_publicInputs, 4);
        _insertNote(_publicInputs, 15, 16, 17);
    }

    /**
     * @dev Join verify+effects (ids 3 / 9).
     *      Layout: [0,1] compliance; [2] nullifier_a; [3] nullifier_b; [4] root; [5] out leaf;
     *      [6] out eph_pub.x; [7..13] out ciphertext.
     */
    function _join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 14) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[4]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!_verifier(circuitId).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[2]);
        _spendNullifier(_publicInputs[3]);
        _insertNote(_publicInputs, 5, 6, 7);
    }

    /**
     * @dev Split verify+effects (ids 4 / 8).
     *      Layout: [0,1] compliance; [2] nullifier; [3] root; [4] out1 leaf; [5] out1 eph_pub.x;
     *      [6..12] out1 ciphertext; [13] out2 leaf; [14] out2 eph_pub.x; [15..21] out2 ciphertext.
     */
    function _split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 22) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[3]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!_verifier(circuitId).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[2]);
        _insertNote(_publicInputs, 4, 5, 6);
        _insertNote(_publicInputs, 13, 14, 15);
    }

    /// @notice Post a public memo redeemable by a designated key into the shielded pool.
    /// @dev memoId = Poseidon2(value, asset, timelock, ownerX, ownerY, salt) matches the public_claim circuit.
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

    /// @notice Claim a public memo into a shielded self note.
    /// @dev Layout: [0] memoId; [1,2] compliance; [3] current_timestamp; [4] leaf; [5] eph_pub.x;
    ///      [6..12] ciphertext. The circuit gates the memo timelock on [3]; the contract ceilings it near now.
    function publicClaim(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 13) revert InvalidInputsLength();

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

        _insertNote(_publicInputs, 4, 5, 6);
    }

    function _setVerifier(uint256 circuitId, address newVerifier) internal {
        if (circuitId >= CIRCUIT_COUNT) revert UnknownCircuitId();
        if (newVerifier == address(0)) revert ZeroAddress();
        if (newVerifier.code.length == 0) revert VerifierHasNoCode();
        _verifierStorage().verifiers[circuitId] = newVerifier;
        emit VerifierUpdated(circuitId, newVerifier);
    }

    function _verifier(
        uint256 circuitId
    ) internal view returns (IHonkVerifier) {
        address v = _verifierStorage().verifiers[circuitId];
        if (v == address(0)) revert VerifierUnset(circuitId);
        return IHonkVerifier(v);
    }

    function _insertNote(
        bytes32[] calldata _publicInputs,
        uint256 leafIndex,
        uint256 epkXIndex,
        uint256 ctStartIndex
    ) internal {
        bytes32 commitment = _publicInputs[leafIndex];
        uint256 insertedAt = _treeStorage().tree.insert(commitment);

        // verify() gates publicInputs.length == NUMBER_OF_PUBLIC_INPUTS upstream, so the 7 ciphertext words
        // from ctStartIndex are always in-range; copy them in one calldatacopy instead of a 7-iteration loop.
        bytes32[7] memory ct;
        assembly {
            calldatacopy(
                ct,
                add(_publicInputs.offset, mul(ctStartIndex, 0x20)),
                0xe0
            )
        }

        emit NewNote(
            insertedAt,
            commitment,
            uint256(_publicInputs[epkXIndex]),
            ct
        );
    }

    /// @dev Memo inputs are contiguous from `leafIndex`: leaf, eph_x, tag, cek_wrap, 7-word ciphertext.
    function _insertMemoAt(
        bytes32[] calldata _publicInputs,
        uint256 leafIndex
    ) internal {
        bytes32 commitment = _publicInputs[leafIndex];
        uint256 insertedAt = _treeStorage().tree.insert(commitment);

        // Contiguous ciphertext at leafIndex+4; verify() gates the input length upstream, so a single
        // calldatacopy of the 7 words is in-range and replaces the 7-iteration loop.
        bytes32[7] memory ct;
        assembly {
            calldatacopy(
                ct,
                add(_publicInputs.offset, mul(add(leafIndex, 4), 0x20)),
                0xe0
            )
        }

        emit NewPrivateMemo(
            insertedAt,
            commitment,
            uint256(_publicInputs[leafIndex + 2]),
            uint256(_publicInputs[leafIndex + 1]),
            uint256(_publicInputs[leafIndex + 3]),
            ct
        );
    }

    function _verifyComplianceKey(bytes32 px, bytes32 py) internal view {
        ComplianceStorage storage c = _complianceStorage();
        if (uint256(px) != c.pkX || uint256(py) != c.pkY) {
            revert ComplianceKeyStale(c.version, c.pkX, c.pkY);
        }
    }

    /// @dev On-curve + non-identity + coord-range. Not a subgroup check (see rotateComplianceKey backstop).
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

    /// @dev Ceilings a prover timestamp near now so a claimer cannot forge a future one to clear the timelock.
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

    function getNextLeafIndex() external view returns (uint256) {
        return _treeStorage().tree.nextLeafIndex;
    }
}
