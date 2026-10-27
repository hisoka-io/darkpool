import type { Fr } from "@aztec/foundation/fields";

export interface PoolCall {
  readonly to: string;
  readonly data: string;
}

/**
 * What the runtime confirms from logs afterwards, independent of what the submitter reports: every input
 * nullifier spent and every expected leaf inserted, in one block.
 */
export interface SubmissionContext {
  readonly planId: string;
  readonly nullifiers: readonly Fr[];
  readonly commitments: readonly Fr[];
  /** The fee note this action leased, when it pays a relayer from the pool (the Nox path). */
  readonly fee?: FeeWithdrawProver;
}

/**
 * Proves the fee withdraw from the action's leased fee note through the runtime's own pipeline checks
 * (pinned witness, root check, self-mint preflight for the change, local verify, public-input binding).
 */
export interface FeeWithdrawProver {
  readonly nullifier: Fr;
  readonly assetId: Fr;
  readonly value: bigint;
  prove(
    amount: bigint,
    recipient: string,
    intentHash: Fr,
  ): Promise<{
    readonly proof: string;
    readonly publicInputs: readonly string[];
  }>;
}

export type SubmissionOutcome =
  | {
      readonly status: "included";
      readonly txHash: string;
      readonly blockNumber: number;
    }
  | {
      readonly status: "reverted";
      readonly txHash: string;
      readonly blockNumber: number;
      readonly reason: string;
    }
  | {
      readonly status: "not-sent";
      readonly stage: string;
      readonly detail: string;
      /** The pool's custom error when a simulation reverted with one. */
      readonly errorName?: string;
    }
  | {
      readonly status: "unknown";
      readonly detail: string;
      /** Passed back on a retry so it resumes instead of paying or sending twice; null when none exists. */
      readonly resumeToken: string | null;
    };

export interface SubmitterPort {
  submit(
    call: PoolCall,
    context: SubmissionContext,
  ): Promise<SubmissionOutcome>;
}
