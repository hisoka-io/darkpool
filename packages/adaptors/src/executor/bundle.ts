import { Fr } from "@hisoka/wallets";
import { AbiCoder, Interface, keccak256 } from "ethers";
import { BundleCall, BundleDomain, BuiltBundle } from "./types.js";

const BUNDLE_VERSION = 2n;

/** Field order MUST match the Solidity `BundleExecutor.BundleCall` struct, or the intent hash diverges. */
const BUNDLE_CALL_TUPLE =
  "tuple(address target, bytes data, uint256 value, bool requireSuccess, address approveToken, uint256 approveAmount, uint256 gasLimit, uint256 returnDataLimit)[]";

const REWARD_POOL_IFACE = new Interface([
  "function depositRewards(address asset, uint256 amount)",
]);

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
      boundCalls.map((c) => [
        c.target,
        c.data,
        c.value,
        c.requireSuccess,
        c.approveToken,
        c.approveAmount,
        c.gasLimit,
        c.returnDataLimit,
      ]),
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
