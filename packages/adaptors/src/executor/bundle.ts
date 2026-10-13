import { Fr } from "@hisoka/wallets";
import {
  AbiCoder,
  dataLength,
  getAddress,
  Interface,
  isHexString,
  keccak256,
} from "ethers";
import { AdaptorError } from "../errors.js";
import { BundleCall, BundleDomain, BuiltBundle } from "./types.js";
import {
  HOWL_WITHDRAW_ACTION_GAS_LIMIT,
  type HowlWithdrawProof,
} from "./howl-payment.js";

const BUNDLE_VERSION = 2n;

/** Field order MUST match the Solidity `BundleExecutor.BundleCall` struct, or the intent hash diverges. */
const BUNDLE_CALL_TUPLE =
  "tuple(address target, bytes data, uint256 value, bool requireSuccess, address approveToken, uint256 approveAmount, uint256 gasLimit, uint256 returnDataLimit)[]";

const REWARD_POOL_IFACE = new Interface([
  "function depositRewards(address asset, uint256 amount)",
]);

const BUNDLE_EXECUTOR_IFACE = new Interface([
  `function execute(bytes proof, bytes32[] publicInputs, ${BUNDLE_CALL_TUPLE} boundCalls, uint256 deadline, address[] trackedAssets, address[] recipients)`,
]);

const WITHDRAW_PUBLIC_INPUTS = 17;
const RECIPIENT_INPUT = 1;
const INTENT_INPUT = 2;

/** `BundleExecutor.POST_CALL_RESERVE_GAS`: gas the executor keeps back before forwarding a call. */
const POST_CALL_RESERVE_GAS = 60_000n;
/** Executor gas outside the pool withdraw, the bound calls and the tracked-asset checks. */
const BUNDLE_EXECUTE_OVERHEAD_GAS = 100_000n;
/** Executor gas per bound call outside the call's own limit, including the cold target access. */
const BUNDLE_CALL_OVERHEAD_GAS = 12_000n;
const BUNDLE_APPROVAL_GAS = 60_000n;
const BUNDLE_TRACKED_ASSET_GAS = 24_000n;
/** Memory cost of bound calldata is convex; this slope holds up to `BUNDLE_CALL_DATA_MAX_BYTES`. */
const BUNDLE_CALL_DATA_BYTE_GAS = 3n;
const BUNDLE_CALL_DATA_MAX_BYTES = 32_000n;

function callTuples(calls: readonly BundleCall[]) {
  return calls.map((c) => [
    c.target,
    c.data,
    c.value,
    c.requireSuccess,
    c.approveToken,
    c.approveAmount,
    c.gasLimit,
    c.returnDataLimit,
  ]);
}

function encodeBundle(
  domain: BundleDomain,
  boundCalls: readonly BundleCall[],
  deadline: bigint,
  trackedAssets: readonly string[],
  recipients: readonly string[],
): string {
  return AbiCoder.defaultAbiCoder().encode(
    [
      "uint256",
      "uint256",
      "address",
      "address",
      BUNDLE_CALL_TUPLE,
      "uint256",
      "address[]",
      "address[]",
    ],
    [
      BUNDLE_VERSION,
      domain.chainId,
      domain.executor,
      domain.darkPool,
      callTuples(boundCalls),
      deadline,
      trackedAssets,
      recipients,
    ],
  );
}

export function buildBundle(
  domain: BundleDomain,
  boundCalls: readonly BundleCall[],
  deadline: bigint,
  trackedAssets: readonly string[],
  recipients: readonly string[],
): BuiltBundle {
  const encodedBundle = encodeBundle(
    domain,
    boundCalls,
    deadline,
    trackedAssets,
    recipients,
  );
  const intentHash = new Fr(BigInt(keccak256(encodedBundle)) % Fr.MODULUS);
  return {
    intentHash,
    domain,
    boundCalls: [...boundCalls],
    deadline,
    trackedAssets: [...trackedAssets],
    recipients: [...recipients],
    encodedBundle,
  };
}

/** Calldata for `BundleExecutor.execute`; the proof must be the withdraw to the executor bound to this bundle. */
export function encodeBundleExecute(
  bundle: BuiltBundle,
  withdrawProof: HowlWithdrawProof,
): string {
  const inputs = withdrawProof.publicInputs;
  if (inputs.length !== WITHDRAW_PUBLIC_INPUTS) {
    throw new AdaptorError(
      `Bundle withdraw requires ${WITHDRAW_PUBLIC_INPUTS} public inputs, got ${inputs.length}`,
    );
  }
  inputs.forEach((input, index) => {
    if (!isHexString(input, 32)) {
      throw new AdaptorError(
        `Bundle withdraw public input ${index} must be exactly 32 bytes`,
      );
    }
  });
  if (
    BigInt(inputs[RECIPIENT_INPUT]!) !==
    BigInt(getAddress(bundle.domain.executor))
  ) {
    throw new AdaptorError(
      "Bundle withdraw recipient is not the bundle executor",
    );
  }
  if (BigInt(inputs[INTENT_INPUT]!) !== bundle.intentHash.toBigInt()) {
    throw new AdaptorError("Bundle withdraw intent does not bind this bundle");
  }
  return BUNDLE_EXECUTOR_IFACE.encodeFunctionData("execute", [
    withdrawProof.proof,
    inputs,
    callTuples(bundle.boundCalls),
    bundle.deadline,
    bundle.trackedAssets,
    bundle.recipients,
  ]);
}

/**
 * `actionGasLimit` for `BundleExecutor.execute` as a paid action. Each call is reserved the gas the executor
 * demands before forwarding it, so the result is an upper bound whatever the calls do within their limits.
 */
export function bundleActionGasLimit(bundle: BuiltBundle): bigint {
  let callGas = 0n;
  let callDataBytes = 0n;
  let approvals = 0n;
  for (const call of bundle.boundCalls) {
    callGas +=
      ((call.gasLimit + POST_CALL_RESERVE_GAS) * 64n + 62n) / 63n +
      BUNDLE_CALL_OVERHEAD_GAS;
    callDataBytes += BigInt(dataLength(call.data));
    if (call.approveAmount !== 0n) approvals += 1n;
  }
  if (callDataBytes > BUNDLE_CALL_DATA_MAX_BYTES) {
    throw new AdaptorError(
      `Bundle calldata of ${callDataBytes} bytes exceeds the ${BUNDLE_CALL_DATA_MAX_BYTES} bytes this gas bound covers`,
    );
  }
  return (
    HOWL_WITHDRAW_ACTION_GAS_LIMIT +
    BUNDLE_EXECUTE_OVERHEAD_GAS +
    callGas +
    approvals * BUNDLE_APPROVAL_GAS +
    BigInt(bundle.trackedAssets.length) * BUNDLE_TRACKED_ASSET_GAS +
    callDataBytes * BUNDLE_CALL_DATA_BYTE_GAS
  );
}

export function treasuryDepositCall(
  treasury: string,
  feeAsset: string,
  feeAmount: bigint,
  gasLimit: bigint,
): BundleCall {
  return {
    target: treasury,
    data: REWARD_POOL_IFACE.encodeFunctionData("depositRewards", [
      feeAsset,
      feeAmount,
    ]),
    value: 0n,
    requireSuccess: true,
    approveToken: feeAsset,
    approveAmount: feeAmount,
    gasLimit,
    returnDataLimit: 0n,
  };
}

export function buildFeePaymentBundle(
  domain: BundleDomain,
  feeAsset: string,
  feeAmount: bigint,
  treasury: string,
  deadline: bigint,
  feeCallGasLimit: bigint,
): BuiltBundle {
  return buildBundle(
    domain,
    [treasuryDepositCall(treasury, feeAsset, feeAmount, feeCallGasLimit)],
    deadline,
    [feeAsset],
    [],
  );
}

export interface SwapFeeBundleParams {
  readonly domain: BundleDomain;
  readonly router: string;
  readonly swapCalldata: string;
  readonly tokenIn: string;
  readonly amountIn: bigint;
  readonly tokenOut: string;
  readonly treasury: string;
  readonly feeAmount: bigint;
  readonly swapGasLimit: bigint;
  readonly feeCallGasLimit: bigint;
  /** MUST zero the remaining `tokenOut` or the residual assert reverts. */
  readonly distributionCalls?: readonly BundleCall[];
  readonly recipients: readonly string[];
  readonly deadline: bigint;
}

export function buildSwapFeeBundle(params: SwapFeeBundleParams): BuiltBundle {
  const swapCall: BundleCall = {
    target: params.router,
    data: params.swapCalldata,
    value: 0n,
    requireSuccess: true,
    approveToken: params.tokenIn,
    approveAmount: params.amountIn,
    gasLimit: params.swapGasLimit,
    returnDataLimit: 32n,
  };
  const feeCall = treasuryDepositCall(
    params.treasury,
    params.tokenOut,
    params.feeAmount,
    params.feeCallGasLimit,
  );
  const boundCalls = [swapCall, feeCall, ...(params.distributionCalls ?? [])];
  return buildBundle(
    params.domain,
    boundCalls,
    params.deadline,
    [params.tokenIn, params.tokenOut],
    params.recipients,
  );
}
