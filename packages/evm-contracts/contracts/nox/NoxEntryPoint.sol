// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {NoxExecutionSandbox} from "./NoxExecutionSandbox.sol";

interface INoxRewardPoolExecution {
    function recordExecutionFee(
        bytes32 executionId,
        bytes32 paymentId,
        address exit,
        address asset,
        uint256 exitAmount,
        uint256 networkAmount
    ) external;
}

interface INoxPaymentAdapter {
    function pay(
        bytes32 executionId,
        bytes32 paymentId,
        address feeAsset,
        uint256 amount,
        bytes calldata paymentData
    ) external;
}

/**
 * @title NoxEntryPoint
 * @notice Immutable selected-exit settlement and one-shot action execution entry point.
 */
contract NoxEntryPoint is EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint8 public constant QUOTE_VERSION = 1;
    uint256 public constant MAX_TRACKED_ASSETS = 16;
    uint256 public constant MAX_RETURN_PREFIX_BYTES = 4096;
    uint256 public constant MAX_ACTION_CALLDATA_BYTES = 131_072;
    uint256 public constant MAX_PAYMENT_DATA_BYTES = 262_144;
    uint256 public constant ENTRYPOINT_GAS_RESERVE = 250_000;

    bytes32 public constant QUOTE_TYPEHASH =
        keccak256(
            // solhint-disable-next-line max-line-length
            "ExecutionQuote(uint8 quoteVersion,uint256 chainId,address entryPoint,address exitAddress,bytes32 clientIntentId,address paymentAdapter,bytes32 paymentId,address feeAsset,uint256 exitFee,uint256 networkFee,uint256 paymentGasLimit,address actionTarget,bytes32 actionCalldataHash,uint256 actionGasLimit,bytes32 trackedAssetsHash,uint256 maximumTransactionGas,uint256 maximumFeePerGas,uint256 returnDataLimit,uint64 validAfterUnix,uint64 validUntilUnix,uint256 quoteNonce)"
        );

    struct ExecutionQuote {
        uint8 quoteVersion;
        uint256 chainId;
        address entryPoint;
        address exitAddress;
        bytes32 clientIntentId;
        address paymentAdapter;
        bytes32 paymentId;
        address feeAsset;
        uint256 exitFee;
        uint256 networkFee;
        uint256 paymentGasLimit;
        address actionTarget;
        bytes32 actionCalldataHash;
        uint256 actionGasLimit;
        bytes32 trackedAssetsHash;
        uint256 maximumTransactionGas;
        uint256 maximumFeePerGas;
        uint256 returnDataLimit;
        uint64 validAfterUnix;
        uint64 validUntilUnix;
        uint256 quoteNonce;
    }

    struct ActionOutcome {
        bool success;
        uint256 returnDataLength;
        bytes32 returnPrefixHash;
    }

    address public immutable REWARD_POOL;
    address public immutable SANDBOX_IMPLEMENTATION;

    mapping(bytes32 => bool) public isExecutionConsumed;
    mapping(bytes32 => bool) public isPaymentConsumed;
    mapping(bytes32 => bool) public isClientIntentConsumed;

    error ZeroAddress();
    error RewardPoolHasNoCode();
    error SandboxImplementationHasNoCode();
    error InvalidQuoteVersion();
    error WrongChain();
    error WrongEntryPoint();
    error WrongExit();
    error InvalidQuoteSigner();
    error QuoteNotActive();
    error QuoteExpired();
    error InvalidIdentifier();
    error InvalidFee();
    error InvalidGasBounds();
    error GasPriceExceedsQuote();
    error ActionCalldataTooLarge();
    error PaymentDataTooLarge();
    error TooManyTrackedAssets();
    error InvalidTrackedAsset();
    error DuplicateTrackedAsset(address asset);
    error ActionHashMismatch();
    error TrackedAssetsHashMismatch();
    error InvalidActionTarget();
    error ExecutionAlreadyConsumed();
    error PaymentAlreadyConsumed();
    error ClientIntentAlreadyConsumed();
    error PaymentFailed();
    error IncorrectPaymentAmount(uint256 expected, uint256 received);
    error RewardPoolResidualBalance();
    error InsufficientExecutionGas();
    error SandboxExecutionFailed();

    event PaidExecutionSettled(
        bytes32 indexed executionId,
        bytes32 indexed paymentId,
        address indexed exit,
        address feeAsset,
        uint256 exitFee,
        uint256 networkFee,
        address actionTarget,
        bool actionSuccess,
        uint256 returnDataLength,
        bytes32 returnPrefixHash
    );

    constructor(
        address rewardPool,
        address sandboxImplementation
    ) EIP712("NoxEntryPoint", "1") {
        if (rewardPool == address(0) || sandboxImplementation == address(0))
            revert ZeroAddress();
        if (rewardPool.code.length == 0) revert RewardPoolHasNoCode();
        if (sandboxImplementation.code.length == 0)
            revert SandboxImplementationHasNoCode();
        REWARD_POOL = rewardPool;
        SANDBOX_IMPLEMENTATION = sandboxImplementation;
    }

    /// @notice EIP-712 execution identifier for a selected-exit quote.
    function executionId(
        ExecutionQuote calldata quote
    ) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(QUOTE_TYPEHASH, quote)));
    }

    /// @notice Address of the one-shot sandbox created for a client intent.
    function predictSandbox(
        bytes32 clientIntentId
    ) public view returns (address) {
        return
            Clones.predictDeterministicAddress(
                SANDBOX_IMPLEMENTATION,
                clientIntentId,
                address(this)
            );
    }

    /// @notice Acquire an exact protocol payment, reserve credits, and execute one bounded action.
    function execute(
        ExecutionQuote calldata quote,
        bytes calldata exitSignature,
        bytes calldata actionData,
        address[] calldata trackedAssets,
        bytes calldata paymentData
    ) external nonReentrant returns (ActionOutcome memory outcome) {
        bytes32 id = _validate(
            quote,
            exitSignature,
            actionData,
            trackedAssets,
            paymentData.length
        );

        isExecutionConsumed[id] = true;
        isPaymentConsumed[quote.paymentId] = true;
        isClientIntentConsumed[quote.clientIntentId] = true;

        address sandbox = Clones.cloneDeterministic(
            SANDBOX_IMPLEMENTATION,
            quote.clientIntentId
        );
        NoxExecutionSandbox(sandbox).initialize(quote.clientIntentId);

        _settlePayment(quote, id, paymentData);

        outcome = _callSandbox(sandbox, quote, actionData, trackedAssets);
        _emitSettlement(id, quote, outcome);
    }

    function _settlePayment(
        ExecutionQuote calldata quote,
        bytes32 id,
        bytes calldata paymentData
    ) private {
        uint256 requiredPayment = _feeTotal(quote.exitFee, quote.networkFee);
        IERC20 feeToken = IERC20(quote.feeAsset);
        uint256 startingBalance = feeToken.balanceOf(address(this));
        _callPaymentAdapter(quote, id, requiredPayment, paymentData);
        uint256 received = feeToken.balanceOf(address(this)) - startingBalance;
        if (received != requiredPayment)
            revert IncorrectPaymentAmount(requiredPayment, received);

        feeToken.forceApprove(REWARD_POOL, requiredPayment);
        INoxRewardPoolExecution(REWARD_POOL).recordExecutionFee(
            id,
            quote.paymentId,
            quote.exitAddress,
            quote.feeAsset,
            quote.exitFee,
            quote.networkFee
        );
        feeToken.forceApprove(REWARD_POOL, 0);
        if (feeToken.balanceOf(address(this)) != startingBalance)
            revert RewardPoolResidualBalance();
    }

    function _emitSettlement(
        bytes32 id,
        ExecutionQuote calldata quote,
        ActionOutcome memory outcome
    ) private {
        emit PaidExecutionSettled(
            id,
            quote.paymentId,
            quote.exitAddress,
            quote.feeAsset,
            quote.exitFee,
            quote.networkFee,
            quote.actionTarget,
            outcome.success,
            outcome.returnDataLength,
            outcome.returnPrefixHash
        );
    }

    function _validate(
        ExecutionQuote calldata quote,
        bytes calldata exitSignature,
        bytes calldata actionData,
        address[] calldata trackedAssets,
        uint256 paymentDataLength
    ) private view returns (bytes32 id) {
        if (quote.quoteVersion != QUOTE_VERSION) revert InvalidQuoteVersion();
        if (quote.chainId != block.chainid) revert WrongChain();
        if (quote.entryPoint != address(this)) revert WrongEntryPoint();
        if (quote.exitAddress != msg.sender) revert WrongExit();
        if (block.timestamp < quote.validAfterUnix) revert QuoteNotActive();
        if (
            quote.validUntilUnix < quote.validAfterUnix ||
            block.timestamp > quote.validUntilUnix
        ) revert QuoteExpired();
        if (quote.clientIntentId == bytes32(0) || quote.paymentId == bytes32(0))
            revert InvalidIdentifier();
        if (
            quote.paymentAdapter == address(0) ||
            quote.feeAsset == address(0) ||
            quote.actionTarget == address(0)
        ) revert ZeroAddress();
        if (_feeTotal(quote.exitFee, quote.networkFee) == 0)
            revert InvalidFee();
        uint256 boundedGas = _gasTotal(
            quote.paymentGasLimit,
            quote.actionGasLimit
        );
        if (
            quote.paymentGasLimit == 0 ||
            quote.actionGasLimit == 0 ||
            quote.maximumFeePerGas == 0 ||
            quote.returnDataLimit > MAX_RETURN_PREFIX_BYTES ||
            quote.maximumTransactionGas < boundedGas
        ) revert InvalidGasBounds();
        if (gasleft() < boundedGas) revert InsufficientExecutionGas();
        if (tx.gasprice > quote.maximumFeePerGas) revert GasPriceExceedsQuote();
        if (actionData.length > MAX_ACTION_CALLDATA_BYTES)
            revert ActionCalldataTooLarge();
        if (paymentDataLength > MAX_PAYMENT_DATA_BYTES)
            revert PaymentDataTooLarge();
        if (trackedAssets.length > MAX_TRACKED_ASSETS)
            revert TooManyTrackedAssets();
        if (keccak256(actionData) != quote.actionCalldataHash)
            revert ActionHashMismatch();
        if (keccak256(abi.encode(trackedAssets)) != quote.trackedAssetsHash)
            revert TrackedAssetsHashMismatch();

        address predicted = predictSandbox(quote.clientIntentId);
        if (
            quote.actionTarget == address(this) ||
            quote.actionTarget == SANDBOX_IMPLEMENTATION ||
            quote.actionTarget == predicted
        ) revert InvalidActionTarget();
        for (uint256 i; i < trackedAssets.length; ++i) {
            address asset = trackedAssets[i];
            if (asset == address(0)) revert InvalidTrackedAsset();
            for (uint256 j; j < i; ++j) {
                if (trackedAssets[j] == asset)
                    revert DuplicateTrackedAsset(asset);
            }
        }

        id = executionId(quote);
        (address signer, ECDSA.RecoverError recoverError, ) = ECDSA.tryRecover(
            id,
            exitSignature
        );
        if (
            recoverError != ECDSA.RecoverError.NoError ||
            signer != quote.exitAddress
        ) revert InvalidQuoteSigner();
        if (isExecutionConsumed[id]) revert ExecutionAlreadyConsumed();
        if (isPaymentConsumed[quote.paymentId]) revert PaymentAlreadyConsumed();
        if (isClientIntentConsumed[quote.clientIntentId])
            revert ClientIntentAlreadyConsumed();
    }

    function _callPaymentAdapter(
        ExecutionQuote calldata quote,
        bytes32 id,
        uint256 requiredPayment,
        bytes calldata paymentData
    ) private {
        bytes memory callData = abi.encodeCall(
            INoxPaymentAdapter.pay,
            (id, quote.paymentId, quote.feeAsset, requiredPayment, paymentData)
        );
        uint256 paymentGasLimit = quote.paymentGasLimit;
        address paymentAdapter = quote.paymentAdapter;
        bool ok;
        assembly {
            ok := call(
                paymentGasLimit,
                paymentAdapter,
                0,
                add(callData, 0x20),
                mload(callData),
                0,
                0
            )
        }
        if (!ok) revert PaymentFailed();
    }

    function _callSandbox(
        address sandbox,
        ExecutionQuote calldata quote,
        bytes calldata actionData,
        address[] calldata trackedAssets
    ) private returns (ActionOutcome memory outcome) {
        try
            NoxExecutionSandbox(sandbox).execute(
                quote.actionTarget,
                actionData,
                quote.actionGasLimit,
                trackedAssets,
                quote.returnDataLimit,
                SANDBOX_IMPLEMENTATION
            )
        returns (bool success, uint256 returnDataLength, bytes32 prefixHash) {
            outcome = ActionOutcome(success, returnDataLength, prefixHash);
        } catch {
            revert SandboxExecutionFailed();
        }
    }

    function _feeTotal(
        uint256 exitFee,
        uint256 networkFee
    ) private pure returns (uint256 total) {
        unchecked {
            total = exitFee + networkFee;
        }
        if (total < exitFee) revert InvalidFee();
    }

    function _gasTotal(
        uint256 paymentGasLimit,
        uint256 actionGasLimit
    ) private pure returns (uint256 total) {
        unchecked {
            total = paymentGasLimit + actionGasLimit;
            if (total < paymentGasLimit) revert InvalidGasBounds();
            uint256 withReserve = total + ENTRYPOINT_GAS_RESERVE;
            if (withReserve < total) revert InvalidGasBounds();
            total = withReserve;
        }
    }
}
