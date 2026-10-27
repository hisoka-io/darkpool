import { DARK_POOL_INTERFACE } from "../abi.js";
import { parseSafeNumber, type JsonRpc } from "../chain/rpc.js";
import { describeCause } from "../errors.js";
import type {
  PoolCall,
  SubmissionContext,
  SubmissionOutcome,
  SubmitterPort,
} from "./ports.js";

export interface DirectSubmitterDeps {
  readonly rpc: JsonRpc;
  /** The account that signs, used as `from` in the simulation. */
  readonly from: string;
  /**
   * An EIP-1193 signer or a relayer: sends the call and returns its transaction hash. A throw counts as "not
   * sent" only when it is a user rejection (EIP-1193 `4001`); any other throw may follow a broadcast.
   */
  readonly sendTransaction: (call: PoolCall) => Promise<string>;
  readonly pollIntervalMs: number;
  readonly receiptTimeoutMs: number;
}

/** The revert payload a node attaches to an `eth_call` error, wherever its client library put it. */
function revertData(error: unknown): string | null {
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (
    typeof current === "object" &&
    current !== null &&
    !seen.has(current)
  ) {
    seen.add(current);
    const data = (current as { readonly data?: unknown }).data;
    if (typeof data === "string" && /^0x[0-9a-fA-F]*$/.test(data)) return data;
    if (typeof data === "object" && data !== null) {
      const nested = (data as { readonly data?: unknown }).data;
      if (typeof nested === "string" && /^0x[0-9a-fA-F]*$/.test(nested))
        return nested;
    }
    current =
      (current as { readonly error?: unknown }).error ??
      (current as { readonly cause?: unknown }).cause;
  }
  return null;
}

function errorNameOf(data: string | null): string | null {
  if (data === null || data.length < 10) return null;
  try {
    return DARK_POOL_INTERFACE.parseError(data)?.name ?? null;
  } catch {
    return null;
  }
}

/** EIP-1193 `4001`, or ethers' `ACTION_REJECTED`: the user refused to sign, so nothing was broadcast. */
const USER_REJECTED_CODES: ReadonlySet<unknown> = new Set([
  4001,
  "ACTION_REJECTED",
]);

function refusedBeforeSigning(error: unknown): boolean {
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (
    typeof current === "object" &&
    current !== null &&
    !seen.has(current)
  ) {
    seen.add(current);
    if (USER_REJECTED_CODES.has((current as { readonly code?: unknown }).code))
      return true;
    current =
      (current as { readonly error?: unknown }).error ??
      (current as { readonly cause?: unknown }).cause;
  }
  return false;
}

/**
 * Sends a pool call from an app-supplied signer: simulates it at `latest` first, so a call the pool would
 * reject (a stale compliance key, a spent nullifier, an unknown root) is never broadcast and comes back with
 * the pool's error name; then sends it and waits for the receipt.
 */
export class DirectSubmitter implements SubmitterPort {
  constructor(private readonly deps: DirectSubmitterDeps) {}

  async submit(
    call: PoolCall,
    _context: SubmissionContext,
  ): Promise<SubmissionOutcome> {
    try {
      await this.deps.rpc("eth_call", [
        { from: this.deps.from, to: call.to, data: call.data },
        "latest",
      ]);
    } catch (cause) {
      const errorName = errorNameOf(revertData(cause));
      return {
        status: "not-sent",
        stage: "simulation",
        detail: `eth_call reverted: ${errorName ?? describeCause(cause)}`,
        ...(errorName === null ? {} : { errorName }),
      };
    }

    let txHash: string;
    try {
      txHash = await this.deps.sendTransaction(call);
    } catch (cause) {
      if (refusedBeforeSigning(cause)) {
        return {
          status: "not-sent",
          stage: "send",
          detail: describeCause(cause),
        };
      }
      // The signer may have broadcast before it failed, so the notes stay leased until the sweep settles it.
      return {
        status: "unknown",
        detail: `sending failed after the call may have been broadcast: ${describeCause(cause)}`,
        resumeToken: null,
      };
    }

    const deadline = Date.now() + this.deps.receiptTimeoutMs;
    while (Date.now() < deadline) {
      let receipt: unknown;
      try {
        receipt = await this.deps.rpc("eth_getTransactionReceipt", [txHash]);
      } catch (cause) {
        return {
          status: "unknown",
          detail: `receipt read for ${txHash} failed: ${describeCause(cause)}`,
          resumeToken: txHash,
        };
      }
      if (typeof receipt === "object" && receipt !== null) {
        const r = receipt as { status?: unknown; blockNumber?: unknown };
        const blockNumber = parseSafeNumber(
          r.blockNumber,
          "receipt.blockNumber",
        );
        return r.status === "0x1"
          ? { status: "included", txHash, blockNumber }
          : {
              status: "reverted",
              txHash,
              blockNumber,
              reason: `receipt status ${String(r.status)}`,
            };
      }
      await new Promise((resolve) =>
        setTimeout(resolve, this.deps.pollIntervalMs),
      );
    }
    return {
      status: "unknown",
      detail: `no receipt for ${txHash} within ${this.deps.receiptTimeoutMs}ms`,
      resumeToken: txHash,
    };
  }
}
