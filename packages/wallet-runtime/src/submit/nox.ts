import { howlPaymentSource } from "@hisoka/adaptors";
import { getBytes } from "ethers";
import { describeCause } from "../errors.js";
import type {
  FeeWithdrawProver,
  PoolCall,
  SubmissionContext,
  SubmissionOutcome,
  SubmitterPort,
} from "./ports.js";

/**
 * The members of nox-client's `executePaid` options this submitter sets, copied structurally because the
 * package that exports `executePaid` is not published yet. A fee source from `@hisoka/adaptors`
 * (`howlPaymentSource`) already has the `payment` shape.
 */
export interface NoxPaidOptions {
  readonly chainId: bigint;
  readonly entryPoint: string;
  readonly action: {
    readonly target: string;
    readonly data: Uint8Array;
    readonly gasLimit?: bigint;
  };
  readonly payment: {
    readonly adapter: string;
    readonly feeAsset: string;
    readonly paymentId: Uint8Array;
    readonly gasLimit: bigint;
    readonly paymentDataLength: number;
    checkAction?(action: { readonly data: Uint8Array }): void;
    buildPaymentData(args: {
      readonly executionId: Uint8Array;
      readonly amount: bigint;
      readonly feeAsset: string;
    }): Promise<Uint8Array>;
  };
  readonly maxTotalFee: bigint;
  readonly intentSalt: Uint8Array;
  readonly preflight: {
    call(
      tx: {
        readonly from?: string;
        readonly to: string;
        readonly data: string;
        readonly gas?: bigint;
        readonly gasPrice?: bigint;
      },
      block: bigint | "latest",
    ): Promise<string>;
    estimateGas(tx: {
      readonly from: string;
      readonly to: string;
      readonly data: string;
    }): Promise<bigint>;
  };
  readonly pending?: {
    readonly executionId: string;
    readonly validUntilUnix: bigint;
  };
}

/** `executePaid`'s result union, the members this submitter reads. */
export type NoxPaidResult =
  | {
      readonly status: "settled";
      readonly executionId: string;
      readonly transactionHash: string;
      readonly blockNumber: bigint;
    }
  | {
      readonly status: "paid-action-failed";
      readonly executionId: string;
      readonly transactionHash: string;
      readonly blockNumber: bigint;
      readonly returnPrefixHash: string;
    }
  | { readonly status: "dry-run"; readonly executionId: string }
  | {
      readonly status: "not-paid";
      readonly stage: string;
      readonly code: string;
      readonly detail: string;
    }
  | {
      readonly status: "unknown";
      readonly executionId: string | null;
      readonly validUntilUnix: bigint | null;
      readonly detail: string;
    };

/** The app binds this to nox-client: `{ execute: (o) => executePaid(client, o) }`. */
export interface NoxPaidExecutor {
  execute(options: NoxPaidOptions): Promise<NoxPaidResult>;
}

export interface NoxSubmitterDeps {
  readonly executor: NoxPaidExecutor;
  readonly chainId: bigint;
  readonly entryPoint: string;
  /** The `HowlPaymentAdapter` instance built on `withdraw`. */
  readonly paymentAdapter: string;
  /** Overrides the payment gas limit derived from the withdraw verifier profile. */
  readonly paymentGasLimit?: bigint;
  readonly maxTotalFee: bigint;
  /** Kept with the plan and reused on every retry of the same action. */
  readonly intentSalt: Uint8Array;
  readonly preflight: NoxPaidOptions["preflight"];
  readonly actionGasLimit?: bigint;
}

/** The resume token of an `unknown` paid result. */
export function encodeNoxResume(pending: {
  readonly executionId: string;
  readonly validUntilUnix: bigint;
}): string {
  return JSON.stringify({
    executionId: pending.executionId,
    validUntilUnix: pending.validUntilUnix.toString(),
  });
}

export function decodeNoxResume(
  token: string,
): { readonly executionId: string; readonly validUntilUnix: bigint } | null {
  try {
    const raw = JSON.parse(token) as {
      executionId?: unknown;
      validUntilUnix?: unknown;
    };
    if (
      typeof raw.executionId !== "string" ||
      !/^0x[0-9a-fA-F]{64}$/.test(raw.executionId) ||
      typeof raw.validUntilUnix !== "string" ||
      !/^\d+$/.test(raw.validUntilUnix)
    ) {
      return null;
    }
    return {
      executionId: raw.executionId,
      validUntilUnix: BigInt(raw.validUntilUnix),
    };
  } catch {
    return null;
  }
}

/**
 * Sends a pool call as a Nox paid action. The fee is a withdraw from a separate fee note, leased with the
 * action's inputs and never one of them, and proved by the pipeline only once the quote names the
 * execution id it must bind. An `unknown` result carries the execution id and validity in its
 * resume token, and a retry passes it back as `pending` so it resumes instead of paying twice.
 */
export class NoxSubmitter implements SubmitterPort {
  /** Unknown executions to resume, by the plan that sent them: another action must never inherit one. */
  readonly #pending = new Map<
    string,
    { readonly executionId: string; readonly validUntilUnix: bigint }
  >();

  constructor(private readonly deps: NoxSubmitterDeps) {}

  /** The fee source for one action: its leased fee note, proved through the runtime's pipeline. */
  #paymentFrom(fee: FeeWithdrawProver): NoxPaidOptions["payment"] {
    const asset = fee.assetId.toBigInt();
    return howlPaymentSource({
      adapter: this.deps.paymentAdapter,
      feeAsset: `0x${asset.toString(16).padStart(40, "0")}`,
      feeNoteNullifier: `0x${fee.nullifier.toBigInt().toString(16).padStart(64, "0")}`,
      feeNoteValue: fee.value,
      proveFeeWithdraw: async (amount, recipient, intentHash) => {
        const proof = await fee.prove(amount, recipient, intentHash);
        return { proof: proof.proof, publicInputs: proof.publicInputs };
      },
      ...(this.deps.paymentGasLimit === undefined
        ? {}
        : { gasLimit: this.deps.paymentGasLimit }),
    });
  }

  /** Resumes, on the next submit for `planId`, the paid execution an earlier run of that plan left `unknown`. */
  resume(planId: string, token: string): boolean {
    const pending = decodeNoxResume(token);
    if (pending === null) return false;
    this.#pending.set(planId, pending);
    return true;
  }

  async submit(
    call: PoolCall,
    context: SubmissionContext,
  ): Promise<SubmissionOutcome> {
    if (context.fee === undefined) {
      return {
        status: "not-sent",
        stage: "payment",
        detail: `plan ${context.planId} leased no fee note, so nothing can pay the relayer`,
      };
    }
    let payment: NoxPaidOptions["payment"];
    try {
      payment = this.#paymentFrom(context.fee);
    } catch (cause) {
      return {
        status: "not-sent",
        stage: "payment",
        detail: `the fee note cannot pay: ${describeCause(cause)}`,
      };
    }
    const pending = this.#pending.get(context.planId);
    const result = await this.deps.executor.execute({
      chainId: this.deps.chainId,
      entryPoint: this.deps.entryPoint,
      action: {
        target: call.to,
        data: getBytes(call.data),
        ...(this.deps.actionGasLimit === undefined
          ? {}
          : { gasLimit: this.deps.actionGasLimit }),
      },
      payment,
      maxTotalFee: this.deps.maxTotalFee,
      intentSalt: this.deps.intentSalt,
      preflight: this.deps.preflight,
      ...(pending === undefined ? {} : { pending }),
    });
    if (result.status !== "unknown") this.#pending.delete(context.planId);
    switch (result.status) {
      case "settled":
        return {
          status: "included",
          txHash: result.transactionHash,
          blockNumber: Number(result.blockNumber),
        };
      case "paid-action-failed":
        return {
          status: "reverted",
          txHash: result.transactionHash,
          blockNumber: Number(result.blockNumber),
          reason: `the fee was paid and the action failed (return prefix ${result.returnPrefixHash})`,
        };
      case "dry-run":
        return {
          status: "not-sent",
          stage: "dry-run",
          detail: `execution ${result.executionId} was simulated only`,
        };
      case "not-paid":
        return {
          status: "not-sent",
          stage: result.stage,
          detail: `${result.code}: ${result.detail}`,
        };
      case "unknown":
        return {
          status: "unknown",
          detail: result.detail,
          resumeToken:
            result.executionId === null || result.validUntilUnix === null
              ? null
              : encodeNoxResume({
                  executionId: result.executionId,
                  validUntilUnix: result.validUntilUnix,
                }),
        };
    }
  }
}
