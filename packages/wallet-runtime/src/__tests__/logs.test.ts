import { describe, expect, it } from "vitest";
import { EVENT_TOPICS } from "../abi.js";
import { RpcChainReader } from "../chain/chainReader.js";
import {
  readAtStableHead,
  RpcLogSource,
  MAX_STABLE_READ_ATTEMPTS,
} from "../chain/logs.js";
import { WalletRuntimeError } from "../errors.js";
import { configFor, FakeChain, POOL } from "./fixtures/chain.js";

const CONFIG = configFor(3, { kind: "depth", blocks: 0 }, 10);

function memoSpent(chain: FakeChain, block: number, id: number): void {
  chain.emit(block, "PublicMemoSpent", [
    `0x${id.toString(16).padStart(64, "0")}`,
  ]);
}

describe("log source", () => {
  it("filters by pool address and topic0 only, and covers [from, to] in exact chunks", async () => {
    const chain = new FakeChain(40);
    const source = RpcLogSource.over(chain.rpc, CONFIG);
    await source.logs({
      topic0: [EVENT_TOPICS.NewPublicMemo, EVENT_TOPICS.PublicMemoSpent],
      fromBlock: 10,
      toBlock: 34,
    });
    const filters = chain.calls
      .filter((c) => c.method === "eth_getLogs")
      .map((c) => c.params[0] as Record<string, unknown>);
    expect(filters.map((f) => [f.fromBlock, f.toBlock])).toEqual([
      ["0xa", "0x13"],
      ["0x14", "0x1d"],
      ["0x1e", "0x22"],
    ]);
    for (const f of filters) {
      expect(Object.keys(f).sort()).toEqual([
        "address",
        "fromBlock",
        "toBlock",
        "topics",
      ]);
      expect(f.address).toBe(POOL);
      const topics = f.topics as unknown[];
      expect(topics).toHaveLength(1);
      expect(new Set(topics[0] as string[])).toEqual(
        new Set([EVENT_TOPICS.NewPublicMemo, EVENT_TOPICS.PublicMemoSpent]),
      );
    }
  });

  it("orders results by block and log index whatever order the node used", async () => {
    const chain = new FakeChain(20);
    memoSpent(chain, 12, 1);
    memoSpent(chain, 5, 2);
    memoSpent(chain, 12, 3);
    memoSpent(chain, 18, 4);
    const logs = await RpcLogSource.over(chain.rpc, CONFIG).logs({
      topic0: [EVENT_TOPICS.PublicMemoSpent],
      fromBlock: 0,
      toBlock: 20,
    });
    expect(logs.map((l) => [l.blockNumber, l.logIndex])).toEqual([
      [5, 0],
      [12, 0],
      [12, 1],
      [18, 0],
    ]);
  });

  it("rejects a log from another address or outside the requested range", async () => {
    const chain = new FakeChain(20);
    memoSpent(chain, 12, 1);
    const lying = async (
      method: string,
      params: readonly unknown[],
    ): Promise<unknown> => {
      const out = await chain.rpc(method, params);
      return method === "eth_getLogs"
        ? (out as Record<string, unknown>[]).map((l) => ({
            ...l,
            address: `0x${"11".repeat(20)}`,
          }))
        : out;
    };
    const err = await RpcLogSource.over(lying, CONFIG)
      .logs({
        topic0: [EVENT_TOPICS.PublicMemoSpent],
        fromBlock: 0,
        toBlock: 20,
      })
      .catch((e: unknown) => e);
    expect((err as WalletRuntimeError).code).toBe("RPC_RESPONSE_INVALID");
  });

  it("never applies a removed log: the read restarts and succeeds once the node stops sending it", async () => {
    const chain = new FakeChain(20);
    memoSpent(chain, 12, 1);
    chain.emit(13, "PublicMemoSpent", [`0x${"00".repeat(31)}02`], true);
    const real = RpcLogSource.over(chain.rpc, CONFIG);
    let fetches = 0;
    let reads = 0;
    const result = await readAtStableHead(
      RpcChainReader.over(chain.rpc, CONFIG),
      async (_head, logsTo) => {
        reads += 1;
        const logs = await logsTo([EVENT_TOPICS.PublicMemoSpent], 0);
        return logs.map((l) => l.blockNumber);
      },
      {
        logs: async (q) => {
          fetches += 1;
          const all = await real.logs(q);
          expect(all.some((l) => l.removed)).toBe(true);
          return fetches === 1 ? all : all.filter((l) => !l.removed);
        },
      },
    );
    expect(reads).toBe(2);
    expect(result.value).toEqual([12]);
  });

  it("restarts a read whose head was reorged away, and gives up with HEAD_REORGED", async () => {
    const chain = new FakeChain(20);
    const reader = RpcChainReader.over(chain.rpc, CONFIG);
    const source = RpcLogSource.over(chain.rpc, CONFIG);
    let reorgs = 1;
    const read = () =>
      readAtStableHead(
        reader,
        async (head, logsTo) => {
          await logsTo([EVENT_TOPICS.PublicMemoSpent], 0);
          if (reorgs > 0) {
            reorgs -= 1;
            chain.reorgFrom(head.number - 1);
          }
          return head.number;
        },
        source,
      );
    const ok = await read();
    expect(ok.head.hash).toBe(chain.blocks[chain.head]!.hash);

    reorgs = MAX_STABLE_READ_ATTEMPTS;
    const err = await read().catch((e: unknown) => e);
    expect((err as WalletRuntimeError).code).toBe("HEAD_REORGED");
  });
});
