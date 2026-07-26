import { Fr } from "@hisoka/wallets";

export interface BundleCall {
  target: string;
  data: string;
  value: bigint;
  requireSuccess: boolean;
  approveToken: string;
  approveAmount: bigint;
}

/** intentHash lands at withdraw public input 2 (BundleExecutor.INTENT_IDX); execute recomputes and rebinds it. */
export interface BuiltBundle {
  intentHash: Fr;
  boundCalls: BundleCall[];
  deadline: bigint;
  assetsToClear: string[];
  encodedBundle: string;
}
