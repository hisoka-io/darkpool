import { Fr } from "@hisoka/wallets";

export interface BundleCall {
  readonly target: string;
  readonly data: string;
  readonly value: bigint;
  readonly requireSuccess: boolean;
  readonly approveToken: string;
  readonly approveAmount: bigint;
  readonly gasLimit: bigint;
  readonly returnDataLimit: bigint;
}

export interface BundleDomain {
  readonly chainId: bigint;
  readonly executor: string;
  readonly darkPool: string;
}

/** intentHash lands at withdraw public input 2 (BundleExecutor.INTENT_IDX); execute recomputes and rebinds it. */
export interface BuiltBundle {
  readonly intentHash: Fr;
  readonly domain: BundleDomain;
  readonly boundCalls: BundleCall[];
  readonly deadline: bigint;
  readonly trackedAssets: string[];
  readonly recipients: string[];
  readonly encodedBundle: string;
}
