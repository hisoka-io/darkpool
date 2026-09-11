import { ProtocolParseError } from "../errors.js";

export const CIRCUIT_IDS = Object.freeze([
  "deposit",
  "withdraw",
  "transfer",
  "split",
  "join",
  "public_claim",
  "withdraw_multisig",
  "transfer_multisig",
  "split_multisig",
  "join_multisig",
  "swap_intent",
  "swap_settle",
] as const);

export type CircuitId = (typeof CIRCUIT_IDS)[number];

export const STANDARD_CIRCUIT_IDS = Object.freeze([
  "deposit",
  "withdraw",
  "transfer",
  "split",
  "join",
  "public_claim",
] as const);

export type StandardCircuitId = (typeof STANDARD_CIRCUIT_IDS)[number];

const PUBLIC_INPUT_COUNT_BY_CIRCUIT: Readonly<Record<CircuitId, number>> =
  Object.freeze({
    deposit: 13,
    withdraw: 17,
    transfer: 24,
    split: 22,
    join: 14,
    public_claim: 13,
    withdraw_multisig: 17,
    transfer_multisig: 24,
    split_multisig: 22,
    join_multisig: 14,
    swap_intent: 27,
    swap_settle: 42,
  });

export function parseCircuitIdAtPath(value: unknown, path: string): CircuitId {
  if (
    typeof value !== "string" ||
    !CIRCUIT_IDS.some((circuit) => circuit === value)
  ) {
    throw new ProtocolParseError(
      "INVALID_CIRCUIT_ID",
      path,
      "expected a supported circuit id",
    );
  }
  return value as CircuitId;
}

export function parseStandardCircuitIdAtPath(
  value: unknown,
  path: string,
): StandardCircuitId {
  if (
    typeof value !== "string" ||
    !STANDARD_CIRCUIT_IDS.some((circuit) => circuit === value)
  ) {
    throw new ProtocolParseError(
      "INVALID_CIRCUIT_ID",
      path,
      "expected a supported standard circuit id",
    );
  }
  return value as StandardCircuitId;
}

export function parseCircuitId(value: unknown): CircuitId {
  return parseCircuitIdAtPath(value, "$");
}

export function publicInputCountForCircuit(circuit: CircuitId): number {
  return PUBLIC_INPUT_COUNT_BY_CIRCUIT[circuit];
}
