import { Fr } from "@hisoka/wallets";
import { AbiCoder, Interface, keccak256 } from "ethers";
import { BundleCall, BuiltBundle } from "./types.js";

/** ABI tuple for `BundleExecutor.BundleCall`. Field order MUST match the Solidity struct, or the intent
 * hash diverges and the withdraw proof rejects. */
const BUNDLE_CALL_TUPLE =
  "tuple(address target, bytes data, uint256 value, bool requireSuccess, address approveToken, uint256 approveAmount)[]";

const REWARD_POOL_IFACE = new Interface([
  "function depositRewards(address asset, uint256 amount)",
]);

function encodeBundle(
  boundCalls: BundleCall[],
  deadline: bigint,
  assetsToClear: string[],
): string {
  return AbiCoder.defaultAbiCoder().encode(
    [BUNDLE_CALL_TUPLE, "uint256", "address[]"],
    [
      boundCalls.map((c) => [
        c.target,
        c.data,
        c.value,
        c.requireSuccess,
        c.approveToken,
        c.approveAmount,
      ]),
      deadline,
      assetsToClear,
    ],
  );
}

/** Encode a bundle and derive its intent hash, byte-identical to `BundleExecutor.intentHashOf`. */
export function buildBundle(
  boundCalls: BundleCall[],
  deadline: bigint,
  assetsToClear: string[],
): BuiltBundle {
  const encodedBundle = encodeBundle(boundCalls, deadline, assetsToClear);
  const intentHash = new Fr(BigInt(keccak256(encodedBundle)) % Fr.MODULUS);
  return { intentHash, boundCalls, deadline, assetsToClear, encodedBundle };
}

/** Bound call: NoxRewardPool.depositRewards(asset, amount) with exact approval. */
export function treasuryDepositCall(
  treasury: string,
  feeAsset: string,
  feeAmount: bigint,
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
  };
}

/** Mode 1: fee paid from the withdrawn asset; withdraw must land exactly feeAmount (Executor asserts zero residual). */
export function buildGasPaymentBundle(
  feeAsset: string,
  feeAmount: bigint,
  treasury: string,
  deadline: bigint,
): BuiltBundle {
  return buildBundle(
    [treasuryDepositCall(treasury, feeAsset, feeAmount)],
    deadline,
    [],
  );
}

export interface SwapFeeBundleParams {
  router: string;
  /** Pre-encoded router calldata that swaps tokenIn -> tokenOut into the Executor. */
  swapCalldata: string;
  tokenIn: string;
  amountIn: bigint;
  tokenOut: string;
  treasury: string;
  feeAmount: bigint;
  /** Calls that move remaining `tokenOut` out; MUST zero it or the residual assert reverts. */
  distributionCalls?: BundleCall[];
  deadline: bigint;
}

/** Mode 2: swap withdrawn asset, pay fee from proceeds (swap+fee requireSuccess), caller-supplied calls clear tokenOut. */
export function buildSwapFeeBundle(params: SwapFeeBundleParams): BuiltBundle {
  const swapCall: BundleCall = {
    target: params.router,
    data: params.swapCalldata,
    value: 0n,
    requireSuccess: true,
    approveToken: params.tokenIn,
    approveAmount: params.amountIn,
  };
  const feeCall = treasuryDepositCall(
    params.treasury,
    params.tokenOut,
    params.feeAmount,
  );
  const boundCalls = [swapCall, feeCall, ...(params.distributionCalls ?? [])];
  return buildBundle(boundCalls, params.deadline, [
    params.tokenIn,
    params.tokenOut,
  ]);
}
