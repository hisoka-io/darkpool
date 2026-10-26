import type { ChainConfig } from "../config.js";
import { WalletRuntimeError } from "../errors.js";
import type { ChainReader } from "./chainReader.js";
import {
  invalidResponse,
  parseHash,
  parseSafeNumber,
  quantity,
  RpcClient,
  type BlockRef,
  type JsonRpc,
} from "./rpc.js";

export interface RawLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
  readonly blockNumber: number;
  readonly blockHash: string;
  readonly logIndex: number;
  readonly transactionHash: string;
  readonly removed: boolean;
}

export interface LogQuery {
  /** topic0 alternatives. Nothing else is filtered on. */
  readonly topic0: readonly [string, ...string[]];
  readonly fromBlock: number;
  readonly toBlock: number;
}

export interface LogSource {
  /** Every pool log with one of the topic0 values in `[fromBlock, toBlock]`, ordered by (block, logIndex). */
  logs(query: LogQuery): Promise<readonly RawLog[]>;
}

/**
 * `eth_getLogs` over the pool, filtered by address and topic0 only. Filtering on an indexed argument (leaf
 * index, tag, commitment, nullifier, memoId) would tell the node which notes are ours.
 */
export class RpcLogSource implements LogSource {
  private readonly pool: string;
  private readonly rangeBlocks: number;

  constructor(
    private readonly client: RpcClient,
    config: ChainConfig,
  ) {
    this.pool = config.deployment.dark_pool.toLowerCase();
    this.rangeBlocks = config.logRangeBlocks;
  }

  static over(rpc: JsonRpc, config: ChainConfig): RpcLogSource {
    return new RpcLogSource(new RpcClient(rpc, config.rpcTimeoutMs), config);
  }

  async logs(query: LogQuery): Promise<readonly RawLog[]> {
    const { fromBlock, toBlock } = query;
    const wanted = new Set(query.topic0.map((t) => t.toLowerCase()));
    const out: RawLog[] = [];
    for (let from = fromBlock; from <= toBlock; from += this.rangeBlocks) {
      const to = Math.min(toBlock, from + this.rangeBlocks - 1);
      const raw = await this.client.request("eth_getLogs", [
        {
          address: this.pool,
          topics: [[...wanted]],
          fromBlock: quantity(from),
          toBlock: quantity(to),
        },
      ]);
      if (!Array.isArray(raw)) {
        invalidResponse("eth_getLogs", raw, "is not an array");
      }
      for (const entry of raw) {
        const log = parseLog(entry);
        if (log.address !== this.pool) {
          invalidResponse(
            "eth_getLogs",
            entry,
            `is from ${log.address}, not the pool`,
          );
        }
        if (!wanted.has(log.topics[0] ?? "")) {
          invalidResponse(
            "eth_getLogs",
            entry,
            "carries a topic0 that was not asked for",
          );
        }
        if (log.blockNumber < from || log.blockNumber > to) {
          invalidResponse(
            "eth_getLogs",
            entry,
            `is outside the requested range [${from}, ${to}]`,
          );
        }
        out.push(log);
      }
    }
    return out.sort(
      (a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex,
    );
  }
}

function parseLog(entry: unknown): RawLog {
  if (typeof entry !== "object" || entry === null) {
    invalidResponse("eth_getLogs", entry, "entry is not a log");
  }
  const log = entry as Record<string, unknown>;
  const { address, topics, data } = log;
  if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    invalidResponse("eth_getLogs", entry, "has no address");
  }
  if (!Array.isArray(topics) || topics.length === 0) {
    invalidResponse("eth_getLogs", entry, "has no topics");
  }
  if (typeof data !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(data)) {
    invalidResponse("eth_getLogs", entry, "has no hex data");
  }
  return Object.freeze({
    address: address.toLowerCase(),
    topics: Object.freeze(
      topics.map((t) => parseHash(t, "eth_getLogs.topics")),
    ),
    data,
    blockNumber: parseSafeNumber(log.blockNumber, "eth_getLogs.blockNumber"),
    blockHash: parseHash(log.blockHash, "eth_getLogs.blockHash"),
    logIndex: parseSafeNumber(log.logIndex, "eth_getLogs.logIndex"),
    transactionHash: parseHash(
      log.transactionHash,
      "eth_getLogs.transactionHash",
    ),
    removed: log.removed === true,
  });
}

/** Logs with one of the topic0 values from `fromBlock` up to the pinned head. */
export type LogsToHead = (
  topic0: readonly [string, ...string[]],
  fromBlock: number,
) => Promise<readonly RawLog[]>;

/** A read of every log up to one head, its result, and that head. */
export interface StableRead<T> {
  readonly head: BlockRef;
  readonly value: T;
}

/** Attempts before a read that keeps straddling a reorg gives up. */
export const MAX_STABLE_READ_ATTEMPTS = 3;

class Reorged extends Error {}

async function stillCanonical(
  chain: Pick<ChainReader, "blockByNumber">,
  head: BlockRef,
): Promise<boolean> {
  try {
    return (await chain.blockByNumber(head.number)).hash === head.hash;
  } catch (e) {
    // A reorg onto a shorter fork leaves no block at the old height.
    if (e instanceof WalletRuntimeError && e.code === "RPC_RESPONSE_INVALID")
      return false;
    throw e;
  }
}

/**
 * Runs `read` against `latest` and accepts the result only if that head is still canonical afterwards and no
 * log came back `removed`. Any reorg at or below the head replaces the block at its height, so the re-check
 * catches a fetch that mixed two forks. A removed log is never applied; it restarts the read.
 */
export async function readAtStableHead<T>(
  chain: Pick<ChainReader, "latest" | "blockByNumber">,
  read: (head: BlockRef, logs: LogsToHead) => Promise<T>,
  source: LogSource,
): Promise<StableRead<T>> {
  let lastHead: BlockRef | undefined;
  for (let attempt = 1; attempt <= MAX_STABLE_READ_ATTEMPTS; attempt++) {
    const head = await chain.latest();
    lastHead = head;
    const logs: LogsToHead = async (topic0, fromBlock) => {
      const result = await source.logs({
        topic0,
        fromBlock,
        toBlock: head.number,
      });
      if (result.some((l) => l.removed)) throw new Reorged();
      return result;
    };
    let value: T;
    try {
      value = await read(head, logs);
    } catch (e) {
      if (e instanceof Reorged) continue;
      throw e;
    }
    if (await stillCanonical(chain, head)) return { head, value };
  }
  throw new WalletRuntimeError(
    "HEAD_REORGED",
    `the head left the canonical chain during each of ${MAX_STABLE_READ_ATTEMPTS} reads (last head ${lastHead?.number ?? "none"})`,
    {
      attempts: String(MAX_STABLE_READ_ATTEMPTS),
      head: String(lastHead?.number ?? ""),
    },
  );
}
