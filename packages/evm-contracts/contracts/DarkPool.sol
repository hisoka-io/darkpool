// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "./Poseidon/Poseidon2.sol";
import {Field} from "./Poseidon/Field.sol";
import {MerkleTreeLib} from "./libraries/MerkleTreeLib.sol";

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {
    ReentrancyGuard
} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {HonkVerifier as DepositVerifier} from "./verifiers/DepositVerifier.sol";
import {
    HonkVerifier as WithdrawVerifier
} from "./verifiers/WithdrawVerifier.sol";
import {
    HonkVerifier as TransferVerifier
} from "./verifiers/TransferVerifier.sol";
import {HonkVerifier as JoinVerifier} from "./verifiers/JoinVerifier.sol";
import {HonkVerifier as SplitVerifier} from "./verifiers/SplitVerifier.sol";
import {
    HonkVerifier as PublicClaimVerifier
} from "./verifiers/PublicClaimVerifier.sol";
import {
    HonkVerifier as GasPaymentVerifier
} from "./verifiers/GasPaymentVerifier.sol";

import {NoxRewardPool} from "./nox/NoxRewardPool.sol";

/**
 * @title Hisoka DarkPool
 * @notice The core contract for the Hisoka privacy protocol.
 */
contract DarkPool is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using MerkleTreeLib for MerkleTreeLib.Tree;

    // --- ROLES ---
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // --- ERRORS ---
    error ZeroAddress();
    error InvalidInputsLength();
    error InvalidComplianceKey();
    error InvalidProof();
    error InvalidRoot();
    error TimestampInvalid();
    error NullifierAlreadySpent();
    error ValueZero();
    error MemoCollision();
    error MemoSpent();
    error MemoInvalid();

    // --- EVENTS ---
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
        uint256 indexed recipientP_x,
        uint256 ephemeralPK_x,
        uint256 ephemeralPK_y,
        bytes32[7] packedCiphertext,
        uint256 intermediateBob_x,
        uint256 intermediateBob_y,
        uint256 intermediateCompliance_x,
        uint256 intermediateCompliance_y
    );

    event NewPublicMemo(
        bytes32 indexed memoId,
        uint256 indexed ownerX,
        uint256 ownerY,
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
    event GasPaymentProcessed(
        bytes32 indexed nullifierHash,
        address indexed relayer,
        address indexed asset,
        uint256 amount,
        bytes32 executionHash
    );

    GasPaymentVerifier public immutable gasPaymentVerifier;
    NoxRewardPool public immutable rewardPool;

    // --- STATE ---
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
        address _gasPaymentVerifier,
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
        if (_gasPaymentVerifier == address(0)) revert ZeroAddress();
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

        gasPaymentVerifier = GasPaymentVerifier(_gasPaymentVerifier);
        rewardPool = NoxRewardPool(_rewardPool);

        COMPLIANCE_PK_X = _compliancePkX;
        COMPLIANCE_PK_Y = _compliancePkY;
        merkleTree.init(32, 100);
    }

    // --- ADMIN FUNCTIONS ---

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // --- ACTIONS ---

    /**
     * @notice Deposit public assets into the shielded pool.
     */
    function deposit(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 13) revert InvalidInputsLength();
        _verifyComplianceKey(_publicInputs[0], _publicInputs[1]);

        if (!depositVerifier.verify(_proof, _publicInputs))
            revert InvalidProof();

        Field.Type[] memory packed = new Field.Type[](7);
        bytes32[7] memory packedEvent;
        for (uint256 i = 0; i < 7; i++) {
            bytes32 val = _publicInputs[6 + i];
            packed[i] = Field.toField(uint256(val));
            packedEvent[i] = val;
        }

        bytes32 commitment = Field.toBytes32(Poseidon2.hash(packed));
        uint256 leafIndex = merkleTree.insert(commitment);

        uint256 value = uint256(_publicInputs[4]);
        address asset = address(uint160(uint256(_publicInputs[5])));
        if (value == 0) revert ValueZero();

        IERC20(asset).safeTransferFrom(msg.sender, address(this), value);
        emit Deposited(msg.sender, asset, value);

        emit NewNote(
            leafIndex,
            commitment,
            uint256(_publicInputs[2]),
            uint256(_publicInputs[3]),
            packedEvent
        );
    }

    /**
     * @notice Withdraw private assets to a public address.
     */
    function withdraw(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 18) revert InvalidInputsLength();

        bytes32 root = _publicInputs[2];
        if (!merkleTree.isKnownRoot[root]) revert InvalidRoot();

        _verifyProofTimestamp(uint256(_publicInputs[3]));
        _verifyComplianceKey(_publicInputs[5], _publicInputs[6]);

        if (!withdrawVerifier.verify(_proof, _publicInputs))
            revert InvalidProof();

        bytes32 nullifierHash = _publicInputs[7];
        _spendNullifier(nullifierHash);

        _processChange(_publicInputs, 10, 8, 9);

        uint256 withdrawValue = uint256(_publicInputs[0]);
        address recipient = address(uint160(uint256(_publicInputs[1])));
        address asset = address(uint160(uint256(_publicInputs[17])));

        if (withdrawValue > 0) {
            IERC20(asset).safeTransfer(recipient, withdrawValue);
        }

        emit Withdrawal(nullifierHash, recipient, msg.sender);
    }

    function privateTransfer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 31) revert InvalidInputsLength();
        if (!merkleTree.isKnownRoot[_publicInputs[0]]) revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[1]));
        _verifyComplianceKey(_publicInputs[2], _publicInputs[3]);

        if (!transferVerifier.verify(_proof, _publicInputs))
            revert InvalidProof();

        _spendNullifier(_publicInputs[8]);
        _processTransferMemo(_publicInputs);
        _processChange(_publicInputs, 24, 22, 23);
    }

    function join(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 16) revert InvalidInputsLength();
        if (!merkleTree.isKnownRoot[_publicInputs[0]]) revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[1]));
        _verifyComplianceKey(_publicInputs[2], _publicInputs[3]);

        if (!joinVerifier.verify(_proof, _publicInputs)) revert InvalidProof();

        _spendNullifier(_publicInputs[4]);
        _spendNullifier(_publicInputs[5]);
        _processChange(_publicInputs, 8, 6, 7);
    }

    function split(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 24) revert InvalidInputsLength();
        if (!merkleTree.isKnownRoot[_publicInputs[0]]) revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[1]));
        _verifyComplianceKey(_publicInputs[2], _publicInputs[3]);

        if (!splitVerifier.verify(_proof, _publicInputs)) revert InvalidProof();

        _spendNullifier(_publicInputs[4]);
        _processChange(_publicInputs, 7, 5, 6);
        _processChange(_publicInputs, 16, 14, 15);
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

        Field.Type[] memory inputs = new Field.Type[](6);
        inputs[0] = Field.toField(_value);
        inputs[1] = Field.toField(uint256(uint160(_asset)));
        inputs[2] = Field.toField(_timelock);
        inputs[3] = Field.toField(_ownerX);
        inputs[4] = Field.toField(_ownerY);
        inputs[5] = Field.toField(_salt);

        bytes32 memoId = Field.toBytes32(Poseidon2.hash(inputs));

        if (isValidPublicMemo[memoId]) revert MemoCollision();

        IERC20(_asset).safeTransferFrom(msg.sender, address(this), _value);
        isValidPublicMemo[memoId] = true;

        emit NewPublicMemo(
            memoId,
            _ownerX,
            _ownerY,
            _asset,
            _value,
            _timelock,
            _salt
        );
    }

    function publicClaim(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 13) revert InvalidInputsLength();

        bytes32 memoId = _publicInputs[0];
        if (!isValidPublicMemo[memoId]) revert MemoInvalid();
        if (isPublicMemoSpent[memoId]) revert MemoSpent();

        _verifyComplianceKey(_publicInputs[1], _publicInputs[2]);

        if (!publicClaimVerifier.verify(_proof, _publicInputs))
            revert InvalidProof();

        isPublicMemoSpent[memoId] = true;
        emit PublicMemoSpent(memoId);

        _processChange(_publicInputs, 5, 3, 4);
    }

    function payRelayer(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external nonReentrant whenNotPaused {
        if (_publicInputs.length != 18) revert InvalidInputsLength();

        if (!merkleTree.isKnownRoot[_publicInputs[0]]) revert InvalidRoot();
        _verifyProofTimestamp(uint256(_publicInputs[1]));
        _verifyComplianceKey(_publicInputs[6], _publicInputs[7]);

        if (!gasPaymentVerifier.verify(_proof, _publicInputs))
            revert InvalidProof();

        bytes32 nullifierHash = _publicInputs[8];
        _spendNullifier(nullifierHash);

        _processChange(_publicInputs, 11, 9, 10);

        uint256 paymentValue = uint256(_publicInputs[2]);
        address asset = address(uint160(uint256(_publicInputs[3])));
        address relayer = address(uint160(uint256(_publicInputs[4])));
        bytes32 executionHash = _publicInputs[5];

        if (paymentValue > 0) {
            IERC20(asset).forceApprove(address(rewardPool), paymentValue);
            rewardPool.depositRewards(asset, paymentValue);
        }

        emit GasPaymentProcessed(
            nullifierHash,
            relayer,
            asset,
            paymentValue,
            executionHash
        );
    }

    // --- INTERNAL PROCESSORS ---

    function _processTransferMemo(bytes32[] calldata _publicInputs) internal {
        Field.Type[] memory packedMemo = new Field.Type[](7);
        bytes32[7] memory packedMemoEvent;
        for (uint256 i = 0; i < 7; i++) {
            bytes32 val = _publicInputs[11 + i];
            packedMemo[i] = Field.toField(uint256(val));
            packedMemoEvent[i] = val;
        }
        bytes32 memoCommitment = Field.toBytes32(Poseidon2.hash(packedMemo));
        uint256 memoIndex = merkleTree.insert(memoCommitment);

        emit NewPrivateMemo(
            memoIndex,
            memoCommitment,
            uint256(_publicInputs[6]),
            uint256(_publicInputs[9]),
            uint256(_publicInputs[10]),
            packedMemoEvent,
            uint256(_publicInputs[18]),
            uint256(_publicInputs[19]),
            uint256(_publicInputs[20]),
            uint256(_publicInputs[21])
        );
    }

    function _processChange(
        bytes32[] calldata _publicInputs,
        uint256 ctStartIndex,
        uint256 epkXIndex,
        uint256 epkYIndex
    ) internal {
        Field.Type[] memory packedChange = new Field.Type[](7);
        bytes32[7] memory packedChangeEvent;
        for (uint256 i = 0; i < 7; i++) {
            bytes32 val = _publicInputs[ctStartIndex + i];
            packedChange[i] = Field.toField(uint256(val));
            packedChangeEvent[i] = val;
        }
        bytes32 changeCommitment = Field.toBytes32(
            Poseidon2.hash(packedChange)
        );
        uint256 changeIndex = merkleTree.insert(changeCommitment);

        emit NewNote(
            changeIndex,
            changeCommitment,
            uint256(_publicInputs[epkXIndex]),
            uint256(_publicInputs[epkYIndex]),
            packedChangeEvent
        );
    }

    function _verifyComplianceKey(bytes32 px, bytes32 py) internal view {
        if (uint256(px) != COMPLIANCE_PK_X || uint256(py) != COMPLIANCE_PK_Y) {
            revert InvalidComplianceKey();
        }
    }

    /// @dev 1-hour tolerance for ZK proof timestamp freshness (network latency, block variance).
    function _verifyProofTimestamp(uint256 timestamp) internal view {
        if (timestamp > block.timestamp + 1 hours) revert TimestampInvalid();
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
