export const RUNTIME_ERROR_CODES = [
  "CONFIG_INVALID",
  "DEPLOYMENT_MISMATCH",
  "RPC_TRANSPORT",
  "RPC_CAPABILITY",
  "RPC_RESPONSE_INVALID",
  "HEAD_REORGED",
  "LOG_GAP",
  "TREE_ROOT_MISMATCH",
  "GENESIS_MISMATCH",
  "REORG_TOO_DEEP",
  "DISCOVERY_UNAVAILABLE",
  "DISCOVERY_PROTOCOL",
  "DISCOVERY_OCCURRENCE_CAP",
  "LEAF_MISMATCH",
  "NOTE_UNOPENABLE",
  "COMPLIANCE_V1_UNKNOWN",
  "COMPLIANCE_HISTORY_INVALID",
  "WITNESS_MISMATCH",
  "ROOT_PIN_MISMATCH",
  "ROOT_UNKNOWN",
  "LEASE_HELD",
  "PLAN_UNKNOWN",
  "STORE_CORRUPT",
  "NOT_WRITER",
  "PSS_UNAVAILABLE",
  "PROOF_FAILED",
  "PROOF_UNVERIFIED",
  "PUBLIC_INPUT_MISMATCH",
  "INPUT_SPENT",
  "SIMULATION_REVERTED",
  "SUBMIT_FAILED",
  "SUBMIT_UNKNOWN",
  "QUOTE_REJECTED",
  "ENTROPY_EXHAUSTED",
] as const;

export type RuntimeErrorCode = (typeof RUNTIME_ERROR_CODES)[number];

/**
 * The one error type the runtime throws. `context` names the quantities involved so a caller can act on
 * the failure without parsing the message; errors from wallets and pss-client ride along as `cause`.
 */
export class WalletRuntimeError extends Error {
  readonly code: RuntimeErrorCode;
  readonly context: Readonly<Record<string, string>>;

  constructor(
    code: RuntimeErrorCode,
    message: string,
    context: Readonly<Record<string, string>> = {},
    cause?: unknown,
  ) {
    super(`${code}: ${message}`, cause === undefined ? undefined : { cause });
    this.name = "WalletRuntimeError";
    this.code = code;
    this.context = Object.freeze({ ...context });
  }
}

export function describeCause(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
