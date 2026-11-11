// The pool's own logs, read straight from the chain in windows the public Fuji endpoint accepts (it refuses an
// eth_getLogs over more than 100 blocks). One cache serves every independent check: the per-wallet chain scans, the
// root each Raven path must fold to, and the public-memo ledger. Nothing here reads Raven.
import {
  EventLog,
  type Contract,
  type EventFragment,
  type Log,
  type Provider,
} from "ethers";

const RETRYABLE =
  /429|rate|too many|timeout|timed ?out|ECONNRESET|ECONNREFUSED|ETIMEDOUT|502|503|504|relay:|Fork Error|could not coalesce/i;

export async function withRetry<T>(
  what: string,
  fn: () => Promise<T>,
  attempts = 8,
): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (i >= attempts || !RETRYABLE.test(msg))
        throw new Error(`${what}: ${msg} (attempt ${i} of ${attempts})`);
      await new Promise((r) => setTimeout(r, Math.min(30_000, 1_000 * 2 ** i)));
    }
  }
}

type TopicFilter = (string | string[] | null)[];

function topicMatches(log: Log, topics: TopicFilter): boolean {
  return topics.every((want, i) => {
    if (want === null || want === undefined) return true;
    const got = log.topics[i]?.toLowerCase();
    if (got === undefined) return false;
    return Array.isArray(want)
      ? want.some((w) => w.toLowerCase() === got)
      : want.toLowerCase() === got;
  });
}

export class PoolLogs {
  #logs: Log[] = [];
  #scannedTo: number;

  constructor(
    readonly provider: Provider,
    readonly pool: Contract,
    readonly startBlock: number,
    readonly maxBlocks: number,
  ) {
    if (!Number.isSafeInteger(maxBlocks) || maxBlocks < 1)
      throw new Error(
        `PoolLogs: maxBlocks must be a positive integer (got ${maxBlocks})`,
      );
    this.#scannedTo = startBlock - 1;
  }

  get scannedTo(): number {
    return this.#scannedTo;
  }

  /** Reads every pool log from the last scanned block to the head. Avalanche blocks are final once accepted. */
  async refresh(): Promise<number> {
    const head = await withRetry("head block", () =>
      this.provider.getBlockNumber(),
    );
    const address = await this.pool.getAddress();
    while (this.#scannedTo < head) {
      const fromBlock = this.#scannedTo + 1;
      const toBlock = Math.min(head, fromBlock + this.maxBlocks - 1);
      const logs = await withRetry(`pool logs ${fromBlock}..${toBlock}`, () =>
        this.provider.getLogs({ address, fromBlock, toBlock }),
      );
      for (const l of logs) if (!l.removed) this.#logs.push(l);
      this.#scannedTo = toBlock;
    }
    return head;
  }

  byTopic(topic0: string): Log[] {
    const t = topic0.toLowerCase();
    return this.#logs.filter((l) => l.topics[0]?.toLowerCase() === t);
  }

  /** Decoded events of one name, in chain order. */
  events(name: string): EventLog[] {
    const fragment = this.pool.interface.getEvent(name);
    if (fragment === null)
      throw new Error(`PoolLogs: the pool ABI has no event ${name}`);
    return this.byTopic(fragment.topicHash).map(
      (l) => new EventLog(l, this.pool.interface, fragment as EventFragment),
    );
  }

  /**
   * The pool as Howl's ScanEngine and PublicMemoScanner read it, with `queryFilter` served from this cache. Every
   * other member is the real contract, so a scanner's provider reads (chain time) still go to the chain.
   */
  view(): Contract {
    const pool = this.pool;
    const queryFilter = async (
      filter: { getTopicFilter(): Promise<TopicFilter> },
      fromBlock: number = 0,
      toBlock?: number,
    ): Promise<EventLog[]> => {
      if (toBlock !== undefined && toBlock > this.#scannedTo)
        throw new Error(
          `PoolLogs: asked for logs to ${toBlock}, cache reaches ${this.#scannedTo}; refresh first`,
        );
      const topics = await filter.getTopicFilter();
      const topic0 = topics[0];
      if (typeof topic0 !== "string")
        throw new Error(
          "PoolLogs: a scanner filter must name exactly one event",
        );
      const fragment = pool.interface.getEvent(topic0);
      if (fragment === null)
        throw new Error(
          `PoolLogs: the pool ABI has no event with topic ${topic0}`,
        );
      return this.#logs
        .filter(
          (l) =>
            l.blockNumber >= fromBlock &&
            (toBlock === undefined || l.blockNumber <= toBlock) &&
            topicMatches(l, topics),
        )
        .map((l) => new EventLog(l, pool.interface, fragment as EventFragment));
    };
    return new Proxy(pool, {
      // the contract keys its internals on itself, so its getters must see the real object as `this`
      get(target, prop) {
        if (prop === "queryFilter") return queryFilter;
        return Reflect.get(target, prop, target);
      },
    });
  }
}
