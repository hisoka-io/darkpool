import { parseDeploymentRef, type DeploymentRef } from "@hisoka/howl-protocol";
import { MAX_OCCURRENCES_PER_TAG } from "@hisoka/wallets";
import { WalletRuntimeError, describeCause } from "./errors.js";

/** How far behind `latest` a read is taken: a fixed block depth, or the node's own `safe`/`finalized` tag. */
export type ConfirmationPolicy =
  | { readonly kind: "depth"; readonly blocks: number }
  | { readonly kind: "tag"; readonly tag: "safe" | "finalized" };

export interface ChainConfig {
  /** The only source of deployment identity. Pool addresses reported by Raven, PSS or an indexer are checked against it. */
  readonly deployment: DeploymentRef;
  readonly confirmations: {
    /** A note is selectable, and a spend's tree state is pinned, at this head. */
    readonly spendableNotes: ConfirmationPolicy;
    /**
     * Must be depth 0. A counter only moves forward, so a depth can only delay an advance, and an index reissued
     * after an unconfirmed note used it reuses a DEM pad.
     */
    readonly counterAdvance: ConfirmationPolicy;
    /** Notes and cursors reach PSS only up to this head, so a shallower reorg never touches PSS. */
    readonly pssWrite: ConfirmationPolicy;
  };
  /** Block span of one `eth_getLogs` request. */
  readonly logRangeBlocks: number;
  /** Deepest rewind walked block by block before a full re-index from the deployment block. */
  readonly maxReorgBlocks: number;
  /** Matched positions per discovery tag above which discovery fails loud. */
  readonly maxOccurrencesPerTag: number;
  readonly rpcTimeoutMs: number;
}

export const HARDHAT_CHAIN_ID = 31337n;

/** Test chain only: instant blocks, no reorgs worth waiting for. Real chains take every value from app config. */
const HARDHAT_LOG_RANGE_BLOCKS = 10_000;
const HARDHAT_MAX_REORG_BLOCKS = 64;
const HARDHAT_RPC_TIMEOUT_MS = 30_000;

/** Public receiving indices derived per scan window, and the extension past the highest match. */
export const PUBLIC_MEMO_INDEX_WINDOW = 20;
/** Recognition derives one key per index, so the window is bounded. */
export const MAX_PUBLIC_MEMO_INDEX = 1_000_000;

const CONFIG_FIELDS = [
  "deployment",
  "confirmations",
  "logRangeBlocks",
  "maxReorgBlocks",
  "maxOccurrencesPerTag",
  "rpcTimeoutMs",
] as const;
const CONFIRMATION_FIELDS = [
  "spendableNotes",
  "counterAdvance",
  "pssWrite",
] as const;

function invalid(field: string, value: unknown, why: string): never {
  throw new WalletRuntimeError(
    "CONFIG_INVALID",
    `chain config ${field} ${why} (got ${render(value)})`,
    { field, value: render(value) },
  );
}

function render(value: unknown): string {
  if (typeof value === "bigint") return value.toString();
  if (value === undefined) return "undefined";
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactRecord(
  value: unknown,
  fields: readonly string[],
  path: string,
): Record<string, unknown> {
  if (!isRecord(value)) invalid(path, value, "must be an object");
  for (const field of fields) {
    if (!(field in value) || value[field] === undefined) {
      invalid(
        `${path}.${field}`,
        undefined,
        "is required; there is no default",
      );
    }
  }
  for (const key of Object.keys(value)) {
    if (!fields.includes(key)) {
      invalid(`${path}.${key}`, value[key], "is not a chain config field");
    }
  }
  return value;
}

function integer(
  value: unknown,
  path: string,
  min: number,
  max = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < min ||
    value > max
  ) {
    invalid(path, value, `must be an integer in [${min}, ${max}]`);
  }
  return value;
}

function policy(value: unknown, path: string): ConfirmationPolicy {
  if (!isRecord(value)) invalid(path, value, "must be a confirmation policy");
  if (value.kind === "depth") {
    exactRecord(value, ["kind", "blocks"], path);
    return {
      kind: "depth",
      blocks: integer(value.blocks, `${path}.blocks`, 0),
    };
  }
  if (value.kind === "tag") {
    exactRecord(value, ["kind", "tag"], path);
    if (value.tag !== "safe" && value.tag !== "finalized") {
      invalid(`${path}.tag`, value.tag, 'must be "safe" or "finalized"');
    }
    return { kind: "tag", tag: value.tag };
  }
  return invalid(`${path}.kind`, value.kind, 'must be "depth" or "tag"');
}

/** Refuses any config with a missing, unknown or out-of-range field. A real chain gets no defaults. */
export function validateChainConfig(input: unknown): ChainConfig {
  const record = exactRecord(input, CONFIG_FIELDS, "config");

  let deployment: DeploymentRef;
  try {
    deployment = parseDeploymentRef(record.deployment);
  } catch (cause) {
    throw new WalletRuntimeError(
      "CONFIG_INVALID",
      `chain config deployment is not a DeploymentRef: ${describeCause(cause)}`,
      { field: "config.deployment", value: render(record.deployment) },
      cause,
    );
  }
  integer(
    Number(deployment.deployment_block),
    "config.deployment.deployment_block",
    0,
  );

  const confirmations = exactRecord(
    record.confirmations,
    CONFIRMATION_FIELDS,
    "config.confirmations",
  );
  const counterAdvance = policy(
    confirmations.counterAdvance,
    "config.confirmations.counterAdvance",
  );
  if (counterAdvance.kind !== "depth" || counterAdvance.blocks !== 0) {
    invalid(
      "config.confirmations.counterAdvance",
      counterAdvance,
      'must be { kind: "depth", blocks: 0 }: a delayed counter advance can reissue an ephemeral index',
    );
  }

  return Object.freeze({
    deployment,
    confirmations: Object.freeze({
      spendableNotes: policy(
        confirmations.spendableNotes,
        "config.confirmations.spendableNotes",
      ),
      counterAdvance,
      pssWrite: policy(confirmations.pssWrite, "config.confirmations.pssWrite"),
    }),
    logRangeBlocks: integer(record.logRangeBlocks, "config.logRangeBlocks", 1),
    maxReorgBlocks: integer(record.maxReorgBlocks, "config.maxReorgBlocks", 0),
    maxOccurrencesPerTag: integer(
      record.maxOccurrencesPerTag,
      "config.maxOccurrencesPerTag",
      1,
      MAX_OCCURRENCES_PER_TAG,
    ),
    rpcTimeoutMs: integer(record.rpcTimeoutMs, "config.rpcTimeoutMs", 1),
  });
}

/** The one preset: a local Hardhat chain (31337), every depth 0. Refuses any other chain id. */
export function HARDHAT_CHAIN_CONFIG(deployment: DeploymentRef): ChainConfig {
  if (BigInt(deployment.chain_id) !== HARDHAT_CHAIN_ID) {
    invalid(
      "deployment.chain_id",
      deployment.chain_id,
      `must be ${HARDHAT_CHAIN_ID} for the Hardhat preset; real chains are configured explicitly`,
    );
  }
  const instant: ConfirmationPolicy = { kind: "depth", blocks: 0 };
  return validateChainConfig({
    deployment,
    confirmations: {
      spendableNotes: instant,
      counterAdvance: instant,
      pssWrite: instant,
    },
    logRangeBlocks: HARDHAT_LOG_RANGE_BLOCKS,
    maxReorgBlocks: HARDHAT_MAX_REORG_BLOCKS,
    maxOccurrencesPerTag: MAX_OCCURRENCES_PER_TAG,
    rpcTimeoutMs: HARDHAT_RPC_TIMEOUT_MS,
  });
}

/** `deploymentAnchor` wherever the wallets API asks for one, and the first block every log read starts at. */
export function deploymentBlock(config: ChainConfig): number {
  return Number(config.deployment.deployment_block);
}
