import { beforeAll, describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { publicKey, type DarkAccount } from "@hisoka/wallets";
import { foldPath } from "@hisoka/wallets/tx";
import { EVENT_TOPICS } from "../abi.js";
import { SelfIndexDiscovery } from "../adapters/selfIndex/selfIndex.js";
import { RpcChainReader } from "../chain/chainReader.js";
import { RpcLogSource, type LogSource, type RawLog } from "../chain/logs.js";
import { configFor } from "./fixtures/chain.js";
import {
  evenIncomingIndex,
  evenSelfIndex,
  memoTo,
  selfNote,
} from "./fixtures/mint.js";
import { accounts, COMPLIANCE_PK, DEPLOY, SimPool } from "./fixtures/pool.js";
import { MemoryStore } from "./fixtures/store.js";
import { WalletRuntimeError } from "../errors.js";

let alice: DarkAccount;
let bob: DarkAccount;
let selfIdx: number[];
let inIdx: number;

beforeAll(async () => {
  ({ alice, bob } = await accounts());
  const first = await evenSelfIndex(alice, 0);
  selfIdx = [first, await evenSelfIndex(alice, first + 1)];
  inIdx = await evenIncomingIndex(bob, 0);
});

function open(
  pool: SimPool,
  opts: { logs?: LogSource; store?: MemoryStore; depth?: number } = {},
) {
  const config =
    opts.depth === undefined
      ? pool.config
      : configFor(DEPLOY, { kind: "depth", blocks: opts.depth });
  return SelfIndexDiscovery.open({
    config,
    chain: RpcChainReader.over(pool.chain.rpc, config),
    logs: opts.logs ?? RpcLogSource.over(pool.chain.rpc, config),
    store: opts.store ?? new MemoryStore(),
  });
}

/** A log source that rewrites the logs the real one returns. */
function tampered(
  pool: SimPool,
  edit: (logs: readonly RawLog[]) => readonly RawLog[],
): LogSource {
  const real = RpcLogSource.over(pool.chain.rpc, pool.config);
  return { logs: async (q) => edit(await real.logs(q)) };
}

async function code(p: Promise<unknown>): Promise<string> {
  const e = await p.then(
    () => null,
    (err: unknown) => err,
  );
  expect(e).toBeInstanceOf(WalletRuntimeError);
  return (e as WalletRuntimeError).code;
}

async function populated(height = 60): Promise<{ pool: SimPool; tags: Fr[] }> {
  const pool = await SimPool.create(height);
  const pk = COMPLIANCE_PK[0]!;
  const a = await selfNote(alice, selfIdx[0]!, 10n, pk);
  const b = await selfNote(alice, selfIdx[1]!, 20n, pk);
  const memo = await memoTo(bob, inIdx, 30n, pk, 7n);
  await pool.insertSelf(10, a);
  await pool.insertMemo(12, memo);
  await pool.insertSelf(14, b);
  // A second row under the first tag: a coincidental match must still be served as a position.
  await pool.insertSelf(16, await selfNote(alice, selfIdx[0]!, 11n, pk));
  return { pool, tags: [a.tag, memo.tag, b.tag] };
}

describe("self-index discovery", () => {
  it("replays every leaf, matches the pool's (n, root), and serves every position with its block", async () => {
    const { pool, tags } = await populated();
    const index = await open(pool);
    const head = await index.sync();
    expect(head.leafCount).toBe(5);
    expect(head.root.equals(pool.root())).toBe(true);
    expect(head.rewoundTo).toBeUndefined();

    const [first, memo, second] = await index.match(tags);
    expect(first!.positions).toEqual([1, 4]);
    expect(first!.records.map((r) => r.leafIndex)).toEqual([1, 4]);
    expect(first!.blocks.map((b) => b?.number)).toEqual([10, 16]);
    expect(memo!.positions).toEqual([2]);
    expect(memo!.records[0]!.recordKind).toBe(1);
    expect(second!.positions).toEqual([3]);
    expect((await index.match([new Fr(12345n)]))[0]!.positions).toEqual([]);
    expect((await index.leafAt(2)).toString()).toBe(
      pool.leaves[2]!.leaf.toString(),
    );
    expect(await index.leafAt(9)).toBe("unheld");
  });

  it("gives paths at the head size, the confirmed size and any other size, each folding to that tree's root", async () => {
    const { pool } = await populated();
    const index = await open(pool, { depth: 45 });
    await index.sync();
    // Head 60, depth 45: confirmed head 15 holds leaves 0..3.
    expect(index.confirmedLeafCount).toBe(4);
    for (const size of [5, 4, 3]) {
      const w = await index.witness(2, size);
      expect(w.leafCount).toBe(size);
      expect((await foldPath(w.leaf, 2, w.siblings)).equals(w.root)).toBe(true);
    }
    const atConfirmed = await index.witness(1, 4);
    const atHead = await index.witness(1, 5);
    expect(atConfirmed.root.equals(atHead.root)).toBe(false);
    expect(atHead.root.equals(pool.root())).toBe(true);
    expect(await code(index.witness(5, 5))).toBe("WITNESS_MISMATCH");
  });

  it("fails LOG_GAP when a LeafInserted log is missing", async () => {
    const { pool } = await populated();
    const logs = tampered(pool, (all) => {
      const inserts = all.filter(
        (l) => l.topics[0] === EVENT_TOPICS.LeafInserted,
      );
      return all.filter((l) => l !== inserts[2]);
    });
    expect(await code((await open(pool, { logs })).sync())).toBe("LOG_GAP");
  });

  it("fails LOG_GAP when a leaf has no note event", async () => {
    const { pool } = await populated();
    const logs = tampered(pool, (all) => {
      const notes = all.filter((l) => l.topics[0] === EVENT_TOPICS.NewNote);
      return all.filter((l) => l !== notes[1]);
    });
    expect(await code((await open(pool, { logs })).sync())).toBe("LOG_GAP");
  });

  it("fails TREE_ROOT_MISMATCH when a LeafInserted root is not the replayed root", async () => {
    const { pool } = await populated();
    const logs = tampered(pool, (all) =>
      all.map((l) =>
        l.topics[0] === EVENT_TOPICS.LeafInserted &&
        l.topics[1] === `0x${"0".repeat(63)}3`
          ? { ...l, data: `${l.data.slice(0, 66)}${"11".repeat(32)}` }
          : l,
      ),
    );
    expect(await code((await open(pool, { logs })).sync())).toBe(
      "TREE_ROOT_MISMATCH",
    );
  });

  it("fails TREE_ROOT_MISMATCH when the log source drops the newest leaf whole", async () => {
    const { pool } = await populated();
    const logs = tampered(pool, (all) =>
      all.filter((l) => l.blockNumber !== 16),
    );
    expect(await code((await open(pool, { logs })).sync())).toBe(
      "TREE_ROOT_MISMATCH",
    );
  });

  it("fails GENESIS_MISMATCH when GenesisSeeded names another leaf", async () => {
    const { pool } = await populated();
    const logs = tampered(pool, (all) =>
      all.map((l) =>
        l.topics[0] === EVENT_TOPICS.GenesisSeeded
          ? { ...l, data: `0x${"22".repeat(32)}` }
          : l,
      ),
    );
    expect(await code((await open(pool, { logs })).sync())).toBe(
      "GENESIS_MISMATCH",
    );
  });

  it("rewinds to the newest canonical block on a reorg and finds a note re-mined at another index", async () => {
    const { pool, tags } = await populated(20);
    const index = await open(pool);
    await index.sync();
    const pk = COMPLIANCE_PK[0]!;
    pool.reorgFrom(13);
    // The reorged chain mines a different note first, then alice's second note one index later.
    await pool.insertMemo(13, await memoTo(bob, inIdx, 31n, pk, 9n));
    await pool.insertSelf(14, await selfNote(alice, selfIdx[1]!, 20n, pk));
    const head = await index.sync();
    expect(head.rewoundTo).toBe(3);
    expect(head.ancestor?.number).toBe(12);
    expect(head.leafCount).toBe(5);
    expect(head.root.equals(pool.root())).toBe(true);
    const [first, , second] = await index.match(tags);
    expect(first!.positions).toEqual([1]);
    expect(second!.positions).toEqual([4]);
    expect(second!.blocks[0]?.hash).toBe(pool.chain.blocks[14]!.hash);
  });

  it("re-indexes from the deployment block after a reorg deeper than maxReorgBlocks", async () => {
    const { pool } = await populated();
    const index = await open(pool);
    await index.sync();
    pool.reorgFrom(15);
    const head = await index.sync();
    expect(head.rewoundTo).toBe(0);
    expect(head.ancestor).toBeUndefined();
    expect(head.leafCount).toBe(4);
    expect(head.root.equals(pool.root())).toBe(true);
  });

  it("retries a sync whose head reorged mid-read and never applies a half-read", async () => {
    const { pool } = await populated();
    const real = RpcLogSource.over(pool.chain.rpc, pool.config);
    let reorged = false;
    const logs: LogSource = {
      logs: async (q) => {
        const out = await real.logs(q);
        if (!reorged) {
          reorged = true;
          pool.reorgFrom(15);
          await pool.insertSelf(
            15,
            await selfNote(alice, selfIdx[0]!, 12n, COMPLIANCE_PK[0]!),
          );
        }
        return out;
      },
    };
    const index = await open(pool, { logs });
    const head = await index.sync();
    expect(head.leafCount).toBe(5);
    expect(head.root.equals(pool.root())).toBe(true);
  });

  it("restores from its store without a new full download", async () => {
    const { pool, tags } = await populated();
    const store = new MemoryStore();
    const first = await open(pool, { store });
    await first.sync();
    const again = await open(pool, { store });
    expect(again.leafCount).toBe(5);
    expect((await again.match(tags))[0]!.positions).toEqual([1, 4]);
    pool.chain.mine(2);
    pool.chain.calls.length = 0;
    await again.sync();
    const ranges = pool.chain.calls
      .filter((c) => c.method === "eth_getLogs")
      .map((c) => Number((c.params[0] as { fromBlock: string }).fromBlock));
    expect(Math.min(...ranges)).toBe(61);
  });

  it("files a memo under its recipient tag and a self note under its own ephemeral x", async () => {
    const { pool, tags } = await populated();
    const index = await open(pool);
    await index.sync();
    const inPub = await bob.getIncomingPub(BigInt(inIdx));
    expect(tags[1]!.toBigInt()).toBe(inPub[0]);
    const eph = await alice.getSelfEphemeral(BigInt(selfIdx[0]!));
    expect(tags[0]!.toBigInt()).toBe(publicKey(eph)[0]);
  });
});
