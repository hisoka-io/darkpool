import type { Point } from "@zk-kit/baby-jubjub";
import {
  completeComplianceHistory,
  ComplianceKeyError,
  type CompleteComplianceHistory,
  type ComplianceKeyRotation,
} from "@hisoka/wallets";
import { DARK_POOL_INTERFACE, EVENT_TOPICS } from "../abi.js";
import type { ChainReader } from "../chain/chainReader.js";
import {
  readAtStableHead,
  type LogSource,
  type RawLog,
} from "../chain/logs.js";
import { invalidResponse, type BlockRef } from "../chain/rpc.js";
import { deploymentBlock, type ChainConfig } from "../config.js";
import { describeCause, WalletRuntimeError } from "../errors.js";
import { runtimeKey, type RuntimeStore } from "../store/runtimeStore.js";

export interface ComplianceHistoryDeps {
  readonly config: ChainConfig;
  readonly chain: Pick<
    ChainReader,
    "latest" | "blockByNumber" | "complianceKey"
  >;
  readonly logs: LogSource;
  readonly store: RuntimeStore;
}

export interface ComplianceHistoryRead {
  readonly history: CompleteComplianceHistory;
  /** Every rotation up to this block is in `history`, and the current key was read at it. */
  readonly head: BlockRef;
}

interface Rotation {
  readonly oldVersion: number;
  readonly newVersion: number;
  readonly x: bigint;
  readonly y: bigint;
  readonly block: number;
}

interface Snapshot {
  readonly upper: { readonly number: number; readonly hash: string };
  readonly genesis: Point<bigint>;
  readonly rotations: readonly Rotation[];
}

// 2: cached rotations keep the initialization event, so a resumed read keys version 1 by its block.
const CACHE_VERSION = 2;

/**
 * The complete compliance-key history, from the pool's own logs (version 1 from the deployment block, then
 * every `ComplianceKeyRotated` keyed by its block) and checked against `complianceKey()` at the same head.
 *
 * Read at `latest`, not a confirmed head: a rotation that later reorgs away only adds a key to try, and a mint
 * must use the key current at execution. The result is cached with the hash of its head; the next read
 * resumes from there when that block is still canonical, and starts over from the deployment block when not.
 */
export async function readComplianceHistory(
  deps: ComplianceHistoryDeps,
): Promise<ComplianceHistoryRead> {
  const cacheKey = runtimeKey(deps.config.deployment, "complianceHistory");
  const cached = parseSnapshot(await deps.store.get(cacheKey));
  const firstBlock = deploymentBlock(deps.config);

  const { head, value } = await readAtStableHead(
    deps.chain,
    async (head, logsTo) => {
      if (firstBlock > head.number) {
        v1Unknown(
          firstBlock,
          `the configured deployment block ${firstBlock} is above the chain head ${head.number}: wrong deployment block, wrong chain, or a node that is behind`,
        );
      }
      const base =
        cached !== null && (await resumable(deps.chain, cached, head))
          ? cached
          : null;
      const from = base === null ? firstBlock : base.upper.number + 1;
      const fresh = (
        from <= head.number
          ? await logsTo([EVENT_TOPICS.ComplianceKeyRotated], from)
          : []
      ).map(decodeRotation);

      let genesis: Point<bigint>;
      let rotations: readonly Rotation[];
      if (base === null) {
        ({ genesis, rotations } = await splitVersionOne(
          deps,
          fresh,
          firstBlock,
        ));
      } else {
        const reinit = fresh.find((r) => r.oldVersion === 0);
        if (reinit !== undefined) {
          v1Unknown(
            firstBlock,
            `a second version-1 event at block ${reinit.block}`,
          );
        }
        genesis = base.genesis;
        rotations = [...base.rotations, ...fresh];
      }
      const current = await deps.chain.complianceKey(head);
      return { genesis, rotations, current };
    },
    deps.logs,
  );

  let history: CompleteComplianceHistory;
  try {
    history = completeComplianceHistory({
      genesisPk: value.genesis,
      rotations: value.rotations.map(
        (r): ComplianceKeyRotation => ({
          oldVersion: r.oldVersion,
          newVersion: r.newVersion,
          newX: r.x,
          newY: r.y,
          blockNumber: r.block,
        }),
      ),
      currentPk: value.current.point,
      currentVersion: value.current.version,
    });
  } catch (cause) {
    throw new WalletRuntimeError(
      "COMPLIANCE_HISTORY_INVALID",
      `compliance history to block ${head.number} is not complete: ${describeCause(cause)}`,
      {
        reason: cause instanceof ComplianceKeyError ? cause.reason : "UNKNOWN",
      },
      cause,
    );
  }

  await deps.store.set(
    cacheKey,
    serializeSnapshot({
      upper: { number: head.number, hash: head.hash },
      genesis: value.genesis,
      rotations: value.rotations,
    }),
  );
  return { history, head };
}

function v1Unknown(firstBlock: number, why: string, cause?: unknown): never {
  throw new WalletRuntimeError(
    "COMPLIANCE_V1_UNKNOWN",
    `cannot establish the version-1 compliance key at deployment block ${firstBlock}: ${why}`,
    { deploymentBlock: String(firstBlock) },
    cause,
  );
}

/**
 * Version 1 comes from the `ComplianceKeyRotated(0, 1, x, y)` that `initialize` emits in the deployment block.
 * That event stays at the head of the returned rotations so the history keys version 1 from its block.
 * A pool initialized before that event existed has none; its version-1 key is then read from state at the
 * deployment block (an archive read), which is only sound when no rotation landed in that same block.
 */
async function splitVersionOne(
  deps: ComplianceHistoryDeps,
  fresh: readonly Rotation[],
  firstBlock: number,
): Promise<{ genesis: Point<bigint>; rotations: readonly Rotation[] }> {
  const inits = fresh.filter((r) => r.oldVersion === 0);
  if (inits.length > 0) {
    const init = inits[0];
    if (inits.length > 1 || init !== fresh[0]) {
      v1Unknown(
        firstBlock,
        `${inits.length} version-1 events, the first at log position ${fresh.indexOf(init)}`,
      );
    }
    if (init.newVersion !== 1 || init.block !== firstBlock) {
      v1Unknown(
        firstBlock,
        `the initialization event sets version ${init.newVersion} at block ${init.block}; the configured deployment block is wrong`,
      );
    }
    return { genesis: [init.x, init.y], rotations: fresh };
  }

  const sameBlock = fresh.find((r) => r.block === firstBlock);
  if (sameBlock !== undefined) {
    v1Unknown(
      firstBlock,
      `rotation ${sameBlock.oldVersion}->${sameBlock.newVersion} in the deployment block hides the version-1 key from state`,
    );
  }
  let key: { readonly point: Point<bigint>; readonly version: number };
  try {
    key = await deps.chain.complianceKey(
      await deps.chain.blockByNumber(firstBlock),
    );
  } catch (cause) {
    return v1Unknown(
      firstBlock,
      `no initialization event, and the state read at the deployment block failed (it needs an archive node): ${describeCause(cause)}`,
      cause,
    );
  }
  if (key.version !== 1) {
    v1Unknown(
      firstBlock,
      `no initialization event, and state at the deployment block holds version ${key.version}`,
    );
  }
  return { genesis: key.point, rotations: fresh };
}

async function resumable(
  chain: Pick<ChainReader, "blockByNumber">,
  cached: Snapshot,
  head: BlockRef,
): Promise<boolean> {
  if (cached.upper.number > head.number) return false;
  if (cached.upper.number === head.number)
    return cached.upper.hash === head.hash;
  try {
    return (
      (await chain.blockByNumber(cached.upper.number)).hash ===
      cached.upper.hash
    );
  } catch (e) {
    if (e instanceof WalletRuntimeError && e.code === "RPC_RESPONSE_INVALID")
      return false;
    throw e;
  }
}

function decodeRotation(log: RawLog): Rotation {
  let args: readonly unknown[];
  try {
    const parsed = DARK_POOL_INTERFACE.parseLog({
      topics: [...log.topics],
      data: log.data,
    });
    if (parsed === null || parsed.name !== "ComplianceKeyRotated")
      throw new Error("not a rotation");
    args = [...parsed.args];
  } catch (cause) {
    return invalidResponse(
      "eth_getLogs ComplianceKeyRotated",
      log,
      `does not decode: ${describeCause(cause)}`,
    );
  }
  const [oldVersion, newVersion, x, y] = args;
  if (
    typeof oldVersion !== "bigint" ||
    typeof newVersion !== "bigint" ||
    typeof x !== "bigint" ||
    typeof y !== "bigint" ||
    oldVersion > BigInt(Number.MAX_SAFE_INTEGER) ||
    newVersion > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    return invalidResponse(
      "eth_getLogs ComplianceKeyRotated",
      log,
      "has out-of-range fields",
    );
  }
  return {
    oldVersion: Number(oldVersion),
    newVersion: Number(newVersion),
    x,
    y,
    block: log.blockNumber,
  };
}

function serializeSnapshot(s: Snapshot): string {
  return JSON.stringify({
    v: CACHE_VERSION,
    upper: s.upper,
    genesis: s.genesis.map(String),
    rotations: s.rotations.map((r) => ({
      ...r,
      x: String(r.x),
      y: String(r.y),
    })),
  });
}

/** A cache that does not parse is ignored: the chain is the source, the cache only saves reads. */
function parseSnapshot(raw: string | null): Snapshot | null {
  if (raw === null) return null;
  try {
    const s = JSON.parse(raw) as {
      v: unknown;
      upper: { number: unknown; hash: unknown };
      genesis: unknown[];
      rotations: {
        oldVersion: unknown;
        newVersion: unknown;
        x: unknown;
        y: unknown;
        block: unknown;
      }[];
    };
    if (s.v !== CACHE_VERSION) return null;
    const int = (v: unknown): number => {
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0)
        throw new Error("int");
      return v;
    };
    const big = (v: unknown): bigint => {
      if (typeof v !== "string" || !/^\d+$/.test(v)) throw new Error("bigint");
      return BigInt(v);
    };
    if (typeof s.upper.hash !== "string" || s.genesis.length !== 2) return null;
    return {
      upper: { number: int(s.upper.number), hash: s.upper.hash },
      genesis: [big(s.genesis[0]), big(s.genesis[1])],
      rotations: s.rotations.map((r) => ({
        oldVersion: int(r.oldVersion),
        newVersion: int(r.newVersion),
        x: big(r.x),
        y: big(r.y),
        block: int(r.block),
      })),
    };
  } catch {
    return null;
  }
}
