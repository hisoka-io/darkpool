// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "./Poseidon/Poseidon2.sol";
import {Field} from "./Poseidon/Field.sol";
import {MerkleTreeLib} from "./libraries/MerkleTreeLib.sol";
import {IWithdrawRecipient} from "./interfaces/IWithdrawRecipient.sol";
import {IProofVerifier} from "./interfaces/IProofVerifier.sol";
import {IDarkPoolSettlement, NO_BOUND} from "./interfaces/IDarkPoolSettlement.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
// solhint-disable-next-line max-line-length
import {AccessControlDefaultAdminRulesUpgradeable} from "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlDefaultAdminRulesUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title Hisoka DarkPool
 * @notice Verifies ZK spend proofs and manages the note tree, nullifiers, and compliance key.
 * @dev A standard spend and its FROST-multisig twin share one public-input layout, hence one helper per
 *      op-family, parameterized by circuitId. Registered settlement modules spend and mint through `settle`,
 *      verified by a verifier DarkPool holds per module.
 */
contract DarkPool is
    IDarkPoolSettlement,
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

    uint256 private constant MAX_MODULE_NULLIFIERS = 16;
    uint256 private constant MAX_MODULE_OUTPUTS = 16;
    uint256 private constant MAX_MODULE_EXTRAS = 8;
    /// @dev Words per module output: leaf, eph_pub.x, 7-word ciphertext.
    uint256 private constant MODULE_OUTPUT_WORDS = 9;

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
    error TimelockTooLarge();
    error MemoCollision();
    error MemoSpent();
    error MemoInvalid();
    error FeeOnTransferUnsupported();
    error RecipientRejectedWithdraw(address recipient);
    error RecipientCannotAcceptWithdraw(address recipient);
    error UnknownCircuitId();
    error VerifierHasNoCode();
    error VerifierUnset(uint256 circuitId);
    error InvalidComplianceKeyPoint();
    error InvalidMemoOwnerPoint();
    error ReentrancyGuardReentrantCall();
    error ComplianceKeyStale(
        uint256 currentVersion,
        uint256 currentX,
        uint256 currentY
    );
    error NonCanonicalField();
    error UnknownModule(address controller);
    error ModuleNotActive(address controller);
    error ModuleAlreadyRegistered(address controller);
    error ModuleAlreadyEnabled(address controller);
    error ModuleAlreadyDisabled(address controller);
    error ControllerHasNoCode();
    error InvalidModuleLayout();

    event NewNote(
        uint256 indexed leafIndex,
        bytes32 indexed commitment,
        uint256 ephemeralPK_x,
        bytes32[7] packedCiphertext
    );

    /// @dev `tag` is the recipient discovery key (view key .x).
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
    event VerifierUpdated(
        uint256 indexed circuitId,
        address previousVerifier,
        address verifier
    );
    event ComplianceKeyRotated(
        uint256 oldVersion,
        uint256 newVersion,
        uint256 newX,
        uint256 newY
    );
    event GenesisSeeded(uint256 indexed chainId, bytes32 genesisLeaf);
    event ModuleRegistered(
        address indexed controller,
        address verifier,
        uint8 nullifierCount,
        uint8 outputCount,
        uint8 extraCount,
        uint32 maxPast,
        uint32 maxFuture
    );
    event ModuleVerifierUpdated(address indexed controller, address verifier);
    event ModuleEnabled(address indexed controller);
    event ModuleDisabled(address indexed controller, address by);
    /// @dev Emitted after the last insert, so it never splits an insert's log group.
    event ModuleSettled(
        address indexed controller,
        uint256 firstLeafIndex,
        uint256 outputCount
    );

    /// @notice A settlement module, keyed by its controller contract. Fits one storage slot.
    /// @dev Public-input layout fixed at registration: [0,1] compliance; [2] timestamp; [3..3+k-1]
    ///      nullifiers; [3+k] root; then `outputCount` x (leaf, eph_pub.x, ciphertext[7]); then `extraCount`
    ///      module words that DarkPool verifies but never reads.
    struct SettlementModule {
        address verifier;
        uint8 nullifierCount;
        uint8 outputCount;
        uint8 extraCount;
        uint32 maxPast;
        uint32 maxFuture;
        bool active;
    }

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

    /// @custom:storage-location erc7201:hisoka.darkpool.settlement
    struct SettlementStorage {
        mapping(address => SettlementModule) modules;
    }

    /// @dev Inlined OZ ReentrancyGuard on OZ's canonical namespace, for storage-compat if the base returns.
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
    // keccak256(abi.encode(uint256(keccak256("hisoka.darkpool.settlement")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant SETTLEMENT_LOCATION =
        0x75aee5824eaef0474f0a9f0cefdca7b78967e2ca8426d4fe1fe0dd6f6af34700;
    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.ReentrancyGuard")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REENTRANCY_LOCATION =
        0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;

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

    function _settlementStorage()
        private
        pure
        returns (SettlementStorage storage $)
    {
        assembly {
            $.slot := SETTLEMENT_LOCATION
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

    /// @notice One-time proxy init. Seeds the genesis leaf at index 0, so real notes start at index 1, and
    ///         announces compliance key version 1 with the same event every later rotation uses.
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
        emit ComplianceKeyRotated(0, 1, p.compliancePkX, p.compliancePkY);

        _treeStorage().tree.init(MERKLE_TREE_DEPTH);
        bytes32 genesis = _genesisLeaf();
        _treeStorage().tree.insert(genesis);
        emit GenesisSeeded(block.chainid, genesis);
    }

    /// @dev Poseidon2(domain, chainid) chain-binds every root against cross-chain replay, and is a
    /// non-spendable sentinel so a spend with packed parents 0 is unambiguously a deposit.
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

    /// @notice Halt every spend, deposit, and memo entrypoint. Compliance-key rotation stays open.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resume the halted entrypoints.
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

    /// @notice Register `controller` as a settlement module verified by `moduleVerifier`, with a public-input
    ///         layout of `nullifierCount` spends, `outputCount` notes and `extraCount` module words, and a
    ///         timestamp rule (`maxPast`, `maxFuture`; NO_BOUND disables a side). A controller registers once.
    function registerSettlementModule(
        address controller,
        address moduleVerifier,
        uint8 nullifierCount,
        uint8 outputCount,
        uint8 extraCount,
        uint32 maxPast,
        uint32 maxFuture
    ) external onlyRole(UPGRADER_ROLE) {
        if (controller == address(0)) revert ZeroAddress();
        // An EOA controller would reduce the module gate to whoever holds that key.
        if (controller.code.length == 0) revert ControllerHasNoCode();
        SettlementStorage storage s = _settlementStorage();
        if (s.modules[controller].verifier != address(0))
            revert ModuleAlreadyRegistered(controller);
        _requireVerifierCode(moduleVerifier);
        // A module that consumes no note would be a pure mint.
        if (
            nullifierCount == 0 ||
            nullifierCount > MAX_MODULE_NULLIFIERS ||
            outputCount == 0 ||
            outputCount > MAX_MODULE_OUTPUTS ||
            extraCount > MAX_MODULE_EXTRAS
        ) revert InvalidModuleLayout();

        s.modules[controller] = SettlementModule({
            verifier: moduleVerifier,
            nullifierCount: nullifierCount,
            outputCount: outputCount,
            extraCount: extraCount,
            maxPast: maxPast,
            maxFuture: maxFuture,
            active: true
        });
        emit ModuleRegistered(
            controller,
            moduleVerifier,
            nullifierCount,
            outputCount,
            extraCount,
            maxPast,
            maxFuture
        );
    }

    /// @notice Point a module at a new verifier; it must accept the module's registered public-input layout.
    function setModuleVerifier(
        address controller,
        address newVerifier
    ) external onlyRole(UPGRADER_ROLE) {
        SettlementModule storage m = _registeredModule(controller);
        _requireVerifierCode(newVerifier);
        m.verifier = newVerifier;
        emit ModuleVerifierUpdated(controller, newVerifier);
    }

    /// @notice Halt one module's settlements.
    function disableModule(address controller) external onlyRole(PAUSER_ROLE) {
        SettlementModule storage m = _registeredModule(controller);
        if (!m.active) revert ModuleAlreadyDisabled(controller);
        m.active = false;
        emit ModuleDisabled(controller, msg.sender);
    }

    /// @notice Resume a disabled module.
    function enableModule(
        address controller
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        SettlementModule storage m = _registeredModule(controller);
        if (m.active) revert ModuleAlreadyEnabled(controller);
        m.active = true;
        emit ModuleEnabled(controller);
    }

    /// @notice Registration of `controller`; an unregistered address returns a zero verifier.
    function settlementModule(
        address controller
    ) external view returns (SettlementModule memory) {
        return _settlementStorage().modules[controller];
    }

    /// @notice Rotate the compliance public key (versioned; old notes stay spendable). Callable while
    ///         paused so a compromised key can be replaced during a halt.
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

    /// @notice Current compliance public key and its version; notes must mint against this pair.
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

        _verifyProof(_verifier(CIRCUIT_DEPOSIT), _proof, _publicInputs);

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

    /// @notice Withdraw private assets to a public address.
    function withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _withdraw(_proof, _publicInputs, CIRCUIT_WITHDRAW);
    }

    /// @notice FROST-multisig withdraw, authorized by a group signature.
    function withdrawMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _withdraw(_proof, _publicInputs, CIRCUIT_WITHDRAW_MULTISIG);
    }

    /// @notice Spend one note into a private memo to a recipient plus self change.
    function privateTransfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _transfer(_proof, _publicInputs, CIRCUIT_TRANSFER);
    }

    /// @notice FROST-multisig private transfer, authorized by a group signature.
    function transferMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _transfer(_proof, _publicInputs, CIRCUIT_TRANSFER_MULTISIG);
    }

    /// @notice Join two notes into one.
    function join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _join(_proof, _publicInputs, CIRCUIT_JOIN);
    }

    /// @notice FROST-multisig join, authorized by a group signature per input.
    function joinMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _join(_proof, _publicInputs, CIRCUIT_JOIN_MULTISIG);
    }

    /// @notice Split one note into two.
    function split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _split(_proof, _publicInputs, CIRCUIT_SPLIT);
    }

    /// @notice FROST-multisig split, authorized by a group signature.
    function splitMultisig(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        _split(_proof, _publicInputs, CIRCUIT_SPLIT_MULTISIG);
    }

    /// @inheritdoc IDarkPoolSettlement
    /// @dev Effects follow the proof check: nullifiers in vector order, then outputs in vector order. No
    ///      token moves, so a module can only re-shape value its verifier proved conserved.
    function settle(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        SettlementModule memory m = _settlementStorage().modules[msg.sender];
        if (m.verifier == address(0)) revert UnknownModule(msg.sender);
        if (!m.active) revert ModuleNotActive(msg.sender);

        uint256 rootIndex = 3 + m.nullifierCount;
        if (
            _publicInputs.length !=
            rootIndex + 1 + MODULE_OUTPUT_WORDS * m.outputCount + m.extraCount
        ) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[rootIndex]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);
        _checkModuleTimestamp(
            uint256(_publicInputs[2]),
            m.maxPast,
            m.maxFuture
        );

        _verifyProof(m.verifier, _proof, _publicInputs);

        for (uint256 i = 3; i < rootIndex; ++i) {
            _spendNullifier(_publicInputs[i]);
        }
        uint256 firstLeafIndex = _treeStorage().tree.nextLeafIndex;
        uint256 end = rootIndex + 1 + MODULE_OUTPUT_WORDS * m.outputCount;
        for (uint256 b = rootIndex + 1; b < end; b += MODULE_OUTPUT_WORDS) {
            _insertNote(_publicInputs, b, b + 1, b + 2);
        }
        emit ModuleSettled(msg.sender, firstLeafIndex, m.outputCount);
    }

    /// @dev A contract recipient must affirm THIS pull. Proving it is merely the caller is not enough: an
    ///      adaptor induced to call the pool with attacker calldata satisfies that weaker test while pulling
    ///      a withdraw it never asked for. Failing to implement the interface is a rejection, by design.
    function _requireRecipientAccepts(
        address recipient,
        bytes32 nullifierHash,
        uint256 intentHash
    ) private {
        try
            IWithdrawRecipient(recipient).acceptWithdraw(
                nullifierHash,
                intentHash
            )
        returns (bytes4 magic) {
            if (magic != IWithdrawRecipient.acceptWithdraw.selector)
                revert RecipientRejectedWithdraw(recipient);
        } catch {
            revert RecipientCannotAcceptWithdraw(recipient);
        }
    }

    /// @dev Layout: [0] value; [1] recipient; [2] intent_hash; [3,4] compliance; [5] nullifier; [6] root;
    ///      [7] asset; [8] change leaf; [9] change eph_pub.x; [10..16] change ciphertext.
    ///      The code-gate covers EIP-7702-delegated EOAs, not just contracts. No root-freshness bound by
    ///      design: any historical known root is spendable, and the nullifier set is the double-spend guard.
    function _withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 17) revert InvalidInputsLength();

        address recipient = address(uint160(uint256(_publicInputs[1])));

        if (!_treeStorage().tree.isKnownRoot[_publicInputs[6]])
            revert InvalidRoot();

        _verifyComplianceKey(_publicInputs[3], _publicInputs[4]);

        _verifyProof(_verifier(circuitId), _proof, _publicInputs);

        bytes32 nullifierHash = _publicInputs[5];
        _spendNullifier(nullifierHash);

        // After the proof verifies and the nullifier is spent, so a recipient that reenters cannot double
        // spend, and before any token moves, so a rejection costs nothing. The code check also covers
        // EIP-7702-delegated EOAs, which is why it is a code-length test rather than a registry lookup.
        if (recipient.code.length > 0) {
            _requireRecipientAccepts(
                recipient,
                nullifierHash,
                uint256(_publicInputs[2])
            );
        }

        _insertNote(_publicInputs, 8, 9, 10);

        uint256 withdrawValue = uint256(_publicInputs[0]);
        address asset = address(uint160(uint256(_publicInputs[7])));

        if (withdrawValue > 0) {
            IERC20(asset).safeTransfer(recipient, withdrawValue);
        }

        emit Withdrawal(nullifierHash, recipient, msg.sender);
    }

    /// @dev Layout: [0,1] compliance; [2] nullifier; [3] root; [4] memo leaf; [5] memo eph_pub.x; [6] tag;
    ///      [7] cek_wrap; [8..14] memo ciphertext; [15] change leaf; [16] change eph_pub.x;
    ///      [17..23] change ciphertext.
    function _transfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 24) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[3]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        _verifyProof(_verifier(circuitId), _proof, _publicInputs);

        _spendNullifier(_publicInputs[2]);
        _insertMemoAt(_publicInputs, 4);
        _insertNote(_publicInputs, 15, 16, 17);
    }

    /// @dev Layout: [0,1] compliance; [2] nullifier_a; [3] nullifier_b; [4] root; [5] out leaf;
    ///      [6] out eph_pub.x; [7..13] out ciphertext.
    function _join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 14) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[4]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        _verifyProof(_verifier(circuitId), _proof, _publicInputs);

        _spendNullifier(_publicInputs[2]);
        _spendNullifier(_publicInputs[3]);
        _insertNote(_publicInputs, 5, 6, 7);
    }

    /// @dev Layout: [0,1] compliance; [2] nullifier; [3] root; [4] out1 leaf; [5] out1 eph_pub.x;
    ///      [6..12] out1 ciphertext; [13] out2 leaf; [14] out2 eph_pub.x; [15..21] out2 ciphertext.
    function _split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs,
        uint256 circuitId
    ) internal {
        if (_publicInputs.length != 22) revert InvalidInputsLength();
        if (!_treeStorage().tree.isKnownRoot[_publicInputs[3]])
            revert InvalidRoot();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        _verifyProof(_verifier(circuitId), _proof, _publicInputs);

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
        // public_claim compares the timelock `as u64`; an unbounded value truncates in-circuit and voids the lock.
        if (_timelock > type(uint64).max) revert TimelockTooLarge();
        // The memo stores no depositor, so an off-curve/identity owner burns the escrow unrecoverably.
        if (!_isValidBjjPoint(_ownerX, _ownerY)) revert InvalidMemoOwnerPoint();

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
    ///      [6..12] ciphertext.
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

        _verifyProof(_verifier(CIRCUIT_PUBLIC_CLAIM), _proof, _publicInputs);

        m.isPublicMemoSpent[memoId] = true;
        emit PublicMemoSpent(memoId);

        _insertNote(_publicInputs, 4, 5, 6);
    }

    function _setVerifier(uint256 circuitId, address newVerifier) internal {
        if (circuitId >= CIRCUIT_COUNT) revert UnknownCircuitId();
        _requireVerifierCode(newVerifier);
        VerifierStorage storage v = _verifierStorage();
        address previousVerifier = v.verifiers[circuitId];
        v.verifiers[circuitId] = newVerifier;
        emit VerifierUpdated(circuitId, previousVerifier, newVerifier);
    }

    function _requireVerifierCode(address candidate) private view {
        if (candidate == address(0)) revert ZeroAddress();
        if (candidate.code.length == 0) revert VerifierHasNoCode();
    }

    function _verifier(uint256 circuitId) internal view returns (address) {
        address v = _verifierStorage().verifiers[circuitId];
        if (v == address(0)) revert VerifierUnset(circuitId);
        return v;
    }

    function _registeredModule(
        address controller
    ) private view returns (SettlementModule storage m) {
        m = _settlementStorage().modules[controller];
        if (m.verifier == address(0)) revert UnknownModule(controller);
    }

    /// @dev Every word DarkPool stores, keys on or forwards is a BN254 field element. The checks run here, not
    ///      in the verifier, so a replacement verifier that reduces its inputs cannot make one nullifier into
    ///      two storage keys, one recipient into several addresses, or an unhashable leaf into the tree.
    function _verifyProof(
        address proofVerifier,
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) private view {
        uint256 nonCanonical;
        // The ABI decoder already bounded offset + 32 * length by calldatasize, so the reads stay in range.
        assembly ("memory-safe") {
            let end := add(_publicInputs.offset, shl(5, _publicInputs.length))
            for {
                let word := _publicInputs.offset
            } lt(word, end) {
                word := add(word, 0x20)
            } {
                nonCanonical := or(
                    nonCanonical,
                    iszero(lt(calldataload(word), BN254_FR))
                )
            }
        }
        if (nonCanonical != 0) revert NonCanonicalField();
        if (!IProofVerifier(proofVerifier).verify(_proof, _publicInputs))
            revert InvalidProof();
    }

    function _insertNote(
        bytes32[] calldata _publicInputs,
        uint256 leafIndex,
        uint256 epkXIndex,
        uint256 ctStartIndex
    ) internal {
        bytes32 commitment = _publicInputs[leafIndex];
        uint256 insertedAt = _treeStorage().tree.insert(commitment);

        // The caller's length check keeps this unchecked copy in range.
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

    /// @dev Memo inputs are contiguous from `leafIndex`: leaf, eph_x, tag, cek_wrap, 7-word ciphertext. The
    /// caller's length check keeps the unchecked copy in range.
    function _insertMemoAt(
        bytes32[] calldata _publicInputs,
        uint256 leafIndex
    ) internal {
        bytes32 commitment = _publicInputs[leafIndex];
        uint256 insertedAt = _treeStorage().tree.insert(commitment);

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

    /// @dev On-curve + non-identity + coord-range, NOT a subgroup check (no BJJ scalar-mul lib in-repo); the
    /// circuit's assert_valid_compliance_pk (shared/src/mint.nr) is the backstop, so a bad key gets no notes.
    function _isValidBjjPoint(
        uint256 x,
        uint256 y
    ) private pure returns (bool) {
        if (x >= BN254_FR || y >= BN254_FR) return false;
        if (x == 0 && y == 1) return false;
        uint256 x2 = mulmod(x, x, BN254_FR);
        uint256 y2 = mulmod(y, y, BN254_FR);
        uint256 lhs = addmod(mulmod(BJJ_A, x2, BN254_FR), y2, BN254_FR);
        uint256 rhs = addmod(
            1,
            mulmod(mulmod(BJJ_D, x2, BN254_FR), y2, BN254_FR),
            BN254_FR
        );
        return lhs == rhs;
    }

    function _requireValidComplianceKey(uint256 x, uint256 y) private pure {
        if (!_isValidBjjPoint(x, y)) revert InvalidComplianceKeyPoint();
    }

    /// @dev Ceilings a prover timestamp near now so a claimer cannot forge a future one to clear the timelock.
    function _verifyProofTimestamp(uint256 timestamp) internal view {
        if (timestamp > block.timestamp + PROOF_TIMESTAMP_TOLERANCE)
            revert TimestampInvalid();
    }

    /// @dev `ts` is unverified at this point and may be near 2^256, so the bounds use subtraction only.
    function _checkModuleTimestamp(
        uint256 ts,
        uint32 maxPast,
        uint32 maxFuture
    ) private view {
        if (
            maxPast != NO_BOUND &&
            ts < block.timestamp &&
            block.timestamp - ts > maxPast
        ) revert TimestampInvalid();
        if (
            maxFuture != NO_BOUND &&
            ts > block.timestamp &&
            ts - block.timestamp > maxFuture
        ) revert TimestampInvalid();
    }

    function _spendNullifier(bytes32 _nullifierHash) internal {
        NullifierStorage storage n = _nullifierStorage();
        if (n.isNullifierSpent[_nullifierHash]) revert NullifierAlreadySpent();
        n.isNullifierSpent[_nullifierHash] = true;
        emit NullifierSpent(_nullifierHash);
    }

    /// @notice Verifier bound to a circuit id; zero means spends of that circuit revert VerifierUnset, or that
    ///         the id is not a circuit.
    function verifier(uint256 circuitId) external view returns (address) {
        if (circuitId >= CIRCUIT_COUNT) return address(0);
        return _verifierStorage().verifiers[circuitId];
    }

    /// @notice Whether a nullifier has been spent; the double-spend guard.
    function isNullifierSpent(
        bytes32 nullifierHash
    ) external view returns (bool) {
        return _nullifierStorage().isNullifierSpent[nullifierHash];
    }

    /// @notice Whether a public memo was ever posted; stays true after a claim, so claimability is this
    /// AND NOT isPublicMemoSpent.
    function isValidPublicMemo(bytes32 memoId) external view returns (bool) {
        return _memoStorage().isValidPublicMemo[memoId];
    }

    /// @notice Whether a public memo has already been claimed.
    function isPublicMemoSpent(bytes32 memoId) external view returns (bool) {
        return _memoStorage().isPublicMemoSpent[memoId];
    }

    /// @notice Whether a root was ever current; any historical root is spendable.
    function isKnownRoot(bytes32 _root) external view returns (bool) {
        return _treeStorage().tree.isKnownRoot[_root];
    }

    /// @notice Latest note-tree root.
    function getCurrentRoot() external view returns (bytes32) {
        return _treeStorage().tree.getCurrentRoot();
    }

    /// @notice Index the next inserted note will occupy.
    function getNextLeafIndex() external view returns (uint256) {
        return _treeStorage().tree.nextLeafIndex;
    }
}
