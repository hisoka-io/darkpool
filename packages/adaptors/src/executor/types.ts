import { Fr } from "@hisoka/wallets";

/** One bound call in an Executor bundle. Mirrors the Solidity `BundleExecutor.BundleCall` struct exactly;
 * field order is load-bearing (it is part of the intent-hash preimage). */
export interface BundleCall {
  target: string;
  data: string;
  value: bigint;
  requireSuccess: boolean;
  approveToken: string;
  approveAmount: bigint;
}

/** intentHash goes into withdraw proof public input 2 (BundleExecutor.INTENT_IDX); execute recomputes and rebinds it. */
export interface BuiltBundle {
  intentHash: Fr;
  boundCalls: BundleCall[];
  deadline: bigint;
  assetsToClear: string[];
  encodedBundle: string;
}
