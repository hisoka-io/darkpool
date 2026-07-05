// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "./Poseidon/Poseidon2.sol";
import {Field} from "./Poseidon/Field.sol";
import {MerkleTreeLib} from "./libraries/MerkleTreeLib.sol";

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {HonkVerifier as DepositVerifier} from "./verifiers/DepositVerifier.sol";
import {HonkVerifier as WithdrawVerifier} from "./verifiers/WithdrawVerifier.sol";
import {HonkVerifier as TransferVerifier} from "./verifiers/TransferVerifier.sol";
import {HonkVerifier as JoinVerifier} from "./verifiers/JoinVerifier.sol";
import {HonkVerifier as SplitVerifier} from "./verifiers/SplitVerifier.sol";
import {HonkVerifier as PublicClaimVerifier} from "./verifiers/PublicClaimVerifier.sol";

import {NoxRewardPool} from "./nox/NoxRewardPool.sol";

/**
 * @title Hisoka DarkPool
 * @notice The core contract for the Hisoka privacy protocol.
 * @dev Leaf = Poseidon2 over secret note fields, so the contract cannot recompute it: every minting
 *      circuit emits the leaf and membership root as public outputs; the contract inserts the leaf and
 *      validates the root against isKnownRoot. Ciphertext integrity is the circuit's psi binding.
 */
contract DarkPool is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using MerkleTreeLib for MerkleTreeLib.Tree;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 private constant PROOF_TIMESTAMP_TOLERANCE = 5 minutes;

    error ZeroAddress();
    error InvalidInputsLength();
    error InvalidComplianceKey();
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

    event NewNote(
        uint256 indexed leafIndex,
        bytes32 indexed commitment,
        uint256 ephemeralPK_x,
        uint256 ephemeralPK_y,
        bytes32[7] packedCiphertext
    );

    /// @dev `tag` is the incoming Raven discovery key (in_pub_j.x); `cekWrap` wraps the content key to the
    /// recipient. Indexed by tag so a recipient can fetch its memos by their static address tag.
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

    NoxRewardPool public immutable rewardPool;

    MerkleTreeLib.Tree internal merkleTree;

    DepositVerifier public immutable depositVerifier;
    WithdrawVerifier public immutable withdrawVerifier;
    TransferVerifier public immutable transferVerifier;
    JoinVerifier public immutable joinVerifier;
    SplitVerifier public immutable splitVerifier;
    PublicClaimVerifier public immutable publicClaimVerifier;

    mapping(bytes32 => bool) public isNullifierSpent;
    mapping(bytes32 => bool) public isValidPublicMemo;
    mapping(bytes32 => bool) public isPublicMemoSpent;

    uint256 public immutable COMPLIANCE_PK_X;
    uint256 public immutable COMPLIANCE_PK_Y;

    constructor(
        address _depositVerifier,
        address _withdrawVerifier,
        address _transferVerifier,
        address _joinVerifier,
        address _splitVerifier,
        address _publicClaimVerifier,
        address _rewardPool,
        uint256 _compliancePkX,
        uint256 _compliancePkY,
        address _admin
    ) {
        if (_depositVerifier == address(0)) revert ZeroAddress();
        if (_withdrawVerifier == address(0)) revert ZeroAddress();
        if (_transferVerifier == address(0)) revert ZeroAddress();
        if (_joinVerifier == address(0)) revert ZeroAddress();
        if (_splitVerifier == address(0)) revert ZeroAddress();
        if (_publicClaimVerifier == address(0)) revert ZeroAddress();
        if (_rewardPool == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);

        depositVerifier = DepositVerifier(_depositVerifier);
        withdrawVerifier = WithdrawVerifier(_withdrawVerifier);
        transferVerifier = TransferVerifier(_transferVerifier);
        joinVerifier = JoinVerifier(_joinVerifier);
        splitVerifier = SplitVerifier(_splitVerifier);
        publicClaimVerifier = PublicClaimVerifier(_publicClaimVerifier);

        rewardPool = NoxRewardPool(_rewardPool);

        COMPLIANCE_PK_X = _compliancePkX;
        COMPLIANCE_PK_Y = _compliancePkY;
        merkleTree.init(32, 100);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Deposit public assets into the shielded pool.
     * @dev Layout: [0,1] compliance; [2] leaf; [3,4] eph_pub; [5] value; [6] asset; [7..13] ciphertext.
     */
    function deposit(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 14) revert InvalidInputsLength();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!depositVerifier.verify(_proof, _publicInputs))
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
     * @notice Withdraw private assets to a public address.
     * @dev Layout: [0] value; [1] recipient; [2] ts; [3] intent; [4,5] compliance; [6] nullifier;
     *      [7] root; [8] asset; [9] change leaf; [10,11] change eph_pub; [12..18] change ciphertext.
     */
    function withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 19) revert InvalidInputsLength();

        address recipient = address(uint160(uint256(_publicInputs[1])));
        if (recipient.code.length > 0 && msg.sender != recipient)
            revert OnlyRecipientMayPull();

        if (!merkleTree.isKnownRoot[_publicInputs[7]]) revert InvalidRoot();

        _verifyProofTimestamp(uint256(_publicInputs[2]));
        _verifyComplianceKey(_publicInputs[4], _publicInputs[5]);

        if (!withdrawVerifier.verify(_proof, _publicInputs))
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

    /**
     * @notice Spend one note into a private memo to a recipient plus self change.
     * @dev Layout: [0] ts; [1,2] compliance; [3] nullifier; [4] root; [5] memo leaf; [6,7] memo eph_pub;
     *      [8] tag; [9] cek_wrap; [10..16] memo ciphertext; [17] change leaf; [18,19] change eph_pub;
     *      [20..26] change ciphertext.
     */
    function privateTransfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 27) revert InvalidInputsLength();
        if (!merkleTree.isKnownRoot[_publicInputs[4]]) revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[0]));
        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);

        if (!transferVerifier.verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[3]);
        _insertMemo(_publicInputs);
        _insertNote(_publicInputs, 17, 18, 19, 20);
    }

    /**
     * @notice Join two notes into one.
     * @dev Layout: [0] ts; [1,2] compliance; [3] nullifier_a; [4] nullifier_b; [5] root; [6] out leaf;
     *      [7,8] out eph_pub; [9..15] out ciphertext.
     */
    function join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 16) revert InvalidInputsLength();
        if (!merkleTree.isKnownRoot[_publicInputs[5]]) revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[0]));
        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);

        if (!joinVerifier.verify(_proof, _publicInputs)) revert InvalidProof();

        _spendNullifier(_publicInputs[3]);
        _spendNullifier(_publicInputs[4]);
        _insertNote(_publicInputs, 6, 7, 8, 9);
    }

    /**
     * @notice Split one note into two.
     * @dev Layout: [0] ts; [1,2] compliance; [3] nullifier; [4] root; [5] out1 leaf; [6,7] out1 eph_pub;
     *      [8..14] out1 ciphertext; [15] out2 leaf; [16,17] out2 eph_pub; [18..24] out2 ciphertext.
     */
    function split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 25) revert InvalidInputsLength();
        if (!merkleTree.isKnownRoot[_publicInputs[4]]) revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[0]));
        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);

        if (!splitVerifier.verify(_proof, _publicInputs)) revert InvalidProof();

        _spendNullifier(_publicInputs[3]);
        _insertNote(_publicInputs, 5, 6, 7, 8);
        _insertNote(_publicInputs, 15, 16, 17, 18);
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

        if (isValidPublicMemo[memoId]) revert MemoCollision();

        uint256 bal0 = IERC20(_asset).balanceOf(address(this));
        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _value);
        if (IERC20(_asset).balanceOf(address(this)) - bal0 != _value)
            revert FeeOnTransferUnsupported();
        isValidPublicMemo[memoId] = true;

        emit NewPublicMemo(memoId, _asset, _value, _timelock, _salt);
    }

    /**
     * @notice Claim a public memo into a shielded self note.
     * @dev Layout: [0] memoId; [1,2] compliance; [3] ts; [4] leaf; [5,6] eph_pub; [7..13] ciphertext.
     */
    function publicClaim(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 14) revert InvalidInputsLength();

        bytes32 memoId = _publicInputs[0];
        if (!isValidPublicMemo[memoId]) revert MemoInvalid();
        if (isPublicMemoSpent[memoId]) revert MemoSpent();

        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);
        _verifyProofTimestamp(uint256(_publicInputs[3]));

        if (!publicClaimVerifier.verify(_proof, _publicInputs))
            revert InvalidProof();

        isPublicMemoSpent[memoId] = true;
        emit PublicMemoSpent(memoId);

        _insertNote(_publicInputs, 4, 5, 6, 7);
    }

    function _insertNote(
        bytes32[] calldata _publicInputs,
        uint256 leafIndex,
        uint256 epkXIndex,
        uint256 epkYIndex,
        uint256 ctStartIndex
    ) internal {
        bytes32 commitment = _publicInputs[leafIndex];
        uint256 insertedAt = merkleTree.insert(commitment);

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
        uint256 insertedAt = merkleTree.insert(commitment);

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
        if (uint256(px) != COMPLIANCE_PK_X || uint256(py) != COMPLIANCE_PK_Y) {
            revert InvalidComplianceKey();
        }
    }

    /// @dev 5-minute tolerance for ZK proof timestamp freshness (network latency, block variance).
    function _verifyProofTimestamp(uint256 timestamp) internal view {
        if (timestamp > block.timestamp + PROOF_TIMESTAMP_TOLERANCE)
            revert TimestampInvalid();
    }

    function _spendNullifier(bytes32 _nullifierHash) internal {
        if (isNullifierSpent[_nullifierHash]) revert NullifierAlreadySpent();
        isNullifierSpent[_nullifierHash] = true;
        emit NullifierSpent(_nullifierHash);
    }

    function isKnownRoot(bytes32 _root) external view returns (bool) {
        return merkleTree.isKnownRoot[_root];
    }
    function getCurrentRoot() external view returns (bytes32) {
        return merkleTree.getCurrentRoot();
    }

    function getMerklePath(
        uint256 _leafIndex
    ) external view returns (bytes32[32] memory) {
        return merkleTree.getMerklePath(_leafIndex);
    }

    function getNextLeafIndex() external view returns (uint256) {
        return merkleTree.nextLeafIndex;
    }

    function getSubtreeWithProof(
        uint256 treeLevel,
        uint256 positionAtLevel
    ) external view returns (bytes32[] memory proof, bytes32[] memory leafs) {
        return merkleTree.getSubtreeWithProof(treeLevel, positionAtLevel);
    }
}
