// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "./Poseidon/Poseidon2.sol";
import {Field} from "./Poseidon/Field.sol";
import {MerkleTreeLib} from "./libraries/MerkleTreeLib.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
// OZ namespaced import path exceeds 120 chars and has no shorter alias.
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
 * @notice The core contract for the Hisoka privacy protocol.
 * @dev Leaf = Poseidon2 over secret note fields, so the contract cannot recompute it: every minting
 *      circuit emits the leaf and membership root as public outputs; the contract inserts the leaf and
 *      validates the root against isKnownRoot. Ciphertext integrity is the circuit's psi binding.
 *      A standard spend and its FROST-multisig twin share a byte-identical public-input layout (gpk, R, z
 *      and recipient keys are all private circuit witnesses), so each op-family routes through one
 *      verify+effects helper parameterized only by which verifier (circuitId) proves it.
 *      Cross-chain replay is defended by the chain-specific tree genesis (slot0): the reserved genesis leaf
 *      at index 0 is Poseidon2(domain, block.chainid), so every root is chain-specific and a spend (or its
 *      FROST signature over that root) cannot be replayed on another chain -- no per-circuit chain_id field.
 *      UUPS proxy: all mutable state lives in ERC-7201 namespaces so appending a config field can never
 *      shift the anonymity-set slots (tree/nullifiers/memos). Upgrades gated by UPGRADER_ROLE.
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

    /// @dev BabyJubJub twisted Edwards params: a*x^2 + y^2 == 1 + d*x^2*y^2 over BN254 Fr.
    /// noir-edwards v0.2.5 src/bjj.nr:6-10 (a=168700, d=168696).
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
        uint256 ephemeralPK_y,
        bytes32[7] packedCiphertext
    );

    /// @dev `tag` is the incoming Raven discovery key (recipient view key .x); `cekWrap` wraps the content
    /// key to the recipient. Indexed by tag so a recipient can fetch its memos by their static address tag.
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

    /// @dev Ported from OZ ReentrancyGuardUpgradeable: contracts-upgradeable 5.6.1 dropped that base once the
    /// non-upgradeable ReentrancyGuard became stateless, but upgrades-core still rejects its constructor, so
    /// the guard is inlined here against OZ's canonical namespace to stay storage-compatible if it returns.
    /// @custom:storage-location erc7201:openzeppelin.storage.ReentrancyGuard
    struct ReentrancyStorage {
        uint256 status;
    }

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

    // Domain separator for the chain-specific genesis leaf: keccak256("hisoka.darkpool.genesis") reduced.
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

    /**
     * @notice One-time proxy initialization. Grants roles to the passed-in governance addresses
     *         (never msg.sender), registers all 10 circuit verifiers, sets the compliance key at version 1,
     *         builds the merkle tree, and seeds the chain-specific genesis leaf at index 0. Callable exactly
     *         once (initializer). Real notes start at leaf index 1.
     */
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

    /// @dev Chain-specific reserved genesis leaf at index 0 = Poseidon2(domain, chainid). Makes every root
    /// chain-specific so a spend and its FROST signature over that root are non-replayable cross-chain
    /// without a per-circuit chain_id input. Index 0 is a permanent non-spendable sentinel (no circuit ever
    /// mints it), so a spend whose packed parents are 0 is unambiguously a deposit.
    function _genesisLeaf() private view returns (bytes32) {
        uint256 domain = uint256(GENESIS_DOMAIN_TAG) % BN254_FR;
        Field.Type[] memory inputs = new Field.Type[](2);
        inputs[0] = Field.toField(domain);
        inputs[1] = Field.toField(block.chainid);
        return Field.toBytes32(Poseidon2.hash(inputs));
    }

    // Body intentionally empty: the onlyRole(UPGRADER_ROLE) gate IS the upgrade authorization.
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

    /**
     * @notice Point a circuit's verifier at a new address (timelock-gated via UPGRADER_ROLE).
     * @dev The spend-side public-input layout and nullifier derivation are frozen invariants; a
     *      replacement verifier MUST accept all pre-existing notes (backward-compat is enforced off-chain).
     */
    function setVerifier(
        uint256 circuitId,
        address newVerifier
    ) external onlyRole(UPGRADER_ROLE) {
        _setVerifier(circuitId, newVerifier);
    }

    /**
     * @notice Rotate the compliance public key to a new BabyJubJub subgroup point.
     * @dev Additive/versioned: old notes stay spendable and old outputs stay decryptable off-chain against
     *      the prior key version. On-chain validation covers the curve equation, non-identity, and coord
     *      range. Prime-order-SUBGROUP membership is NOT checked here (needs a BJJ scalar-mul Solidity lib
     *      absent from this repo); the backstop is the circuit assert_valid_compliance_pk, which runs
     *      check_subgroup on every mint (packages/circuits/shared/src/mint.nr), so a non-subgroup key
     *      cannot receive notes.
     *      Callable WHILE PAUSED on purpose: a compromised compliance key can be rotated during a halt and the
     *      pool then unpaused under the new key, without resuming activity under the compromised key.
     */
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

    /**
     * @notice Deposit public assets into the shielded pool (funds a STANDARD or MULTISIG account; the
     *         account type is a private note witness, so the layout is identical either way).
     * @dev Layout: [0,1] compliance; [2] leaf; [3,4] eph_pub; [5] value; [6] asset; [7..13] ciphertext.
     */
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

    /**
     * @notice Withdraw private assets to a public address (single-signer spend).
     * @dev Routes through _withdraw with the standard verifier. Layout in _withdraw.
     */
    function withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _withdraw(_proof, _publicInputs, CIRCUIT_WITHDRAW);
    }

    /**
     * @notice FROST-multisig withdraw. The spend is authorized by a group signature (private witness); the
     *         signature binds the chain-specific root, so no per-circuit chain_id is needed. Byte-identical
     *         public-input layout to the single-signer withdraw.
     */
    function withdrawMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _withdraw(_proof, _publicInputs, CIRCUIT_WITHDRAW_MULTISIG);
    }

    /**
     * @notice Spend one note into a private memo to a recipient plus self change (single-signer).
     */
    function privateTransfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _transfer(_proof, _publicInputs, CIRCUIT_TRANSFER);
    }

    /**
     * @notice FROST-multisig private transfer (memo + self change), authorized by a group signature.
     */
    function transferMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _transfer(_proof, _publicInputs, CIRCUIT_TRANSFER_MULTISIG);
    }

    /**
     * @notice Join two notes into one (single-signer).
     */
    function join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _join(_proof, _publicInputs, CIRCUIT_JOIN);
    }

    /**
     * @notice FROST-multisig join (two notes into one), authorized by a group signature per input.
     */
    function joinMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _join(_proof, _publicInputs, CIRCUIT_JOIN_MULTISIG);
    }

    /**
     * @notice Split one note into two (single-signer).
     */
    function split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _split(_proof, _publicInputs, CIRCUIT_SPLIT);
    }

    /**
     * @notice FROST-multisig split (one note into two), authorized by a group signature.
     */
    function splitMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _split(_proof, _publicInputs, CIRCUIT_SPLIT_MULTISIG);
    }

    /**
     * @dev Withdraw verify+effects shared by the single-signer (id 1) and FROST-multisig (id 6) paths; the
     *      only difference is which verifier proves the spend. Drain-critical indices live here once.
     *      Layout: [0] value; [1] recipient; [2] intent_hash; [3,4] compliance; [5] nullifier; [6] root;
     *      [7] asset; [8] change leaf; [9,10] change eph_pub; [11..17] change ciphertext.
     *      Code-gate: a recipient with code must self-submit. An EIP-7702-delegated EOA reads as code
     *      (code.length>0), so it too is self-submit-only; over-restrictive in the safe direction (no loss).
     *      Freshness: a bare spend has NO freshness bound by design. Roots are never evicted (see
     *      MerkleTreeLib), so a proof against any historical known root stays valid; the nullifier set, not
     *      root recency, is the double-spend guard. Time-sensitive flows (adaptor/bundle) bind their own
     *      freshness via intent+deadline. A bounded recent-root window is a possible future addition.
     */
    function _withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 18) revert InvalidInputsLength();

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

        _insertNote(_publicInputs, 8, 9, 10, 11);

        uint256 withdrawValue = uint256(_publicInputs[0]);
        address asset = address(uint160(uint256(_publicInputs[7])));

        if (withdrawValue > 0) {
            IERC20(asset).safeTransfer(recipient, withdrawValue);
        }

        emit Withdrawal(nullifierHash, recipient, msg.sender);
    }

    /**
     * @dev Transfer verify+effects shared by the single-signer (id 2) and FROST-multisig (id 7) paths.
     *      Layout: [0,1] compliance; [2] nullifier; [3] root; [4] memo leaf; [5,6] memo eph_pub; [7] tag;
     *      [8] cek_wrap; [9..15] memo ciphertext; [16] change leaf; [17,18] change eph_pub;
     *      [19..25] change ciphertext.
     */
    function _transfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 26) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[3]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!_verifier(circuitId).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[2]);
        _insertMemoAt(_publicInputs, 4);
        _insertNote(_publicInputs, 16, 17, 18, 19);
    }

    /**
     * @dev Join verify+effects shared by the single-signer (id 3) and FROST-multisig (id 9) paths.
     *      Layout: [0,1] compliance; [2] nullifier_a; [3] nullifier_b; [4] root; [5] out leaf;
     *      [6,7] out eph_pub; [8..14] out ciphertext.
     */
    function _join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 15) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[4]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!_verifier(circuitId).verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[2]);
        _spendNullifier(_publicInputs[3]);
        _insertNote(_publicInputs, 5, 6, 7, 8);
    }

    /**
     * @dev Split verify+effects shared by the single-signer (id 4) and FROST-multisig (id 8) paths.
     *      Layout: [0,1] compliance; [2] nullifier; [3] root; [4] out1 leaf; [5,6] out1 eph_pub;
     *      [7..13] out1 ciphertext; [14] out2 leaf; [15,16] out2 eph_pub; [17..23] out2 ciphertext.
     */
    function _split(
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
        _insertNote(_publicInputs, 4, 5, 6, 7);
        _insertNote(_publicInputs, 14, 15, 16, 17);
    }

    /**
     * @notice Post a public memo redeemable by a designated key into the shielded pool.
     * @dev memoId = Poseidon2(value, asset, timelock, ownerX, ownerY, salt) matches the public_claim circuit.
     */
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

    /**
     * @notice Claim a public memo into a shielded self note.
     * @dev Layout: [0] memoId; [1,2] compliance; [3] current_timestamp; [4] leaf; [5,6] eph_pub;
     *      [7..13] ciphertext. current_timestamp is a real timelock gate (the circuit asserts it is at or
     *      past the memo timelock); the contract bounds it to roughly now so a claimer cannot satisfy the
     *      timelock with a fabricated future timestamp.
     */
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
    ) internal view returns (IHonkVerifier) {
        address v = _verifierStorage().verifiers[circuitId];
        if (v == address(0)) revert VerifierUnset(circuitId);
        return IHonkVerifier(v);
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

    /// @dev A memo's public inputs are contiguous from `leafIndex`: leaf, eph_x, eph_y, tag, cek_wrap,
    /// then a 7-word ciphertext. Both the standard (id 2) and multisig (id 7) transfer base the memo at 4.
    function _insertMemoAt(
        bytes32[] calldata _publicInputs,
        uint256 leafIndex
    ) internal {
        bytes32 commitment = _publicInputs[leafIndex];
        uint256 insertedAt = _treeStorage().tree.insert(commitment);

        bytes32[7] memory ct;
        for (uint256 i = 0; i < 7; i++) {
            ct[i] = _publicInputs[leafIndex + 5 + i];
        }

        emit NewPrivateMemo(
            insertedAt,
            commitment,
            uint256(_publicInputs[leafIndex + 3]),
            uint256(_publicInputs[leafIndex + 1]),
            uint256(_publicInputs[leafIndex + 2]),
            uint256(_publicInputs[leafIndex + 4]),
            ct
        );
    }

    function _verifyComplianceKey(bytes32 px, bytes32 py) internal view {
        ComplianceStorage storage c = _complianceStorage();
        if (uint256(px) != c.pkX || uint256(py) != c.pkY) {
            revert ComplianceKeyStale(c.version, c.pkX, c.pkY);
        }
    }

    /// @dev On-curve (twisted Edwards) + non-identity + coord-range check. Not a subgroup check; see
    /// rotateComplianceKey for the circuit-side backstop.
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

    /// @dev Bounds a prover-supplied timestamp to roughly now (+5min for latency/block variance). Used only
    /// by publicClaim, whose circuit gates the memo timelock against this value; the ceiling stops a claimer
    /// forging a future timestamp to clear the timelock early. Spends carry no timestamp and, by design, no
    /// freshness bound -- any historical known root remains spendable (see _withdraw); time-sensitive flows
    /// bound themselves via intent+deadline.
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
